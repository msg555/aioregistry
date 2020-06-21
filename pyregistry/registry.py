"""
Module implementing a client for the v2 docker registry API.

See https://docs.docker.com/registry/spec/api/
"""
import abc
from collections import OrderedDict
from functools import partialmethod
import hashlib
import itertools
import json
import logging
from multiprocessing.pool import ThreadPool as Pool
import re
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
import urllib

import requests

from .auth import CredentialStore, DictCredentialStore

LOGGER = logging.getLogger(__name__)


def _split_quote(s: str, dels: str, quotes: str = '"', escape: str = "\\") -> List[str]:
    """
    Split s by any character present in dels. However treat anything
    surrounded by a character in quotes as a literal. Additionally
    any character preceeded by escape is treated as a literal.

    Returns a list of split tokens with the split delimeter between each token.
    The length of the result will always be odd with the even indexed elements
    being the split data and the odd indexed elements being the delimeters
    between the even elements.

    _split_quote('a="b,c",d=f', '=,') => ['a', '=', 'b,c', ',', 'd', '=', 'f']
    """
    part: List[str] = []
    result: List[str] = []

    quote = None
    for ch in s:
        if part and part[-1] == escape:
            part[-1] = ch
        elif quote and ch == quote:
            quote = None
        elif quote:
            part.append(ch)
        elif ch in dels:
            result.append("".join(part))
            result.append(ch)
            part.clear()
        elif ch in quotes:
            quote = ch
        else:
            part.append(ch)
    result.append("".join(part))

    return result


def _is_digest_ref(ref: str) -> bool:
    """
    Returns true if ref is a disgest ref.
    """
    return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", ref))


def chunk_streamer(
    data_stream: Iterable[Sequence], chunk_size: int
) -> Iterable[Iterable[Sequence]]:
    """
    Given a generator that yields iterables generates a sequence of
    generators that each yield chunk_size iterables (with the
    possible exception of the last generator).

    Note that each yielded generator must be consumed before the next generator
    should be accessed.
    """

    class ChunkStreamState:
        """
        Maintains state within the generators.
        """

        def __init__(self, data_stream: Iterable[Sequence]) -> None:
            self.stream_consumed = False
            self.stream_iter = iter(data_stream)
            self.data_carry: Optional[Sequence] = None
            self.generator_active = False

    def _stream_chunk(state: ChunkStreamState, chunk_size: int) -> Iterator[Sequence]:
        """
        Yield chunk_size items from data_stream.
        """
        total_len = 0
        while True:
            if state.data_carry is None:
                try:
                    chunk = next(state.stream_iter)
                except StopIteration:
                    state.stream_consumed = True
                    break
            else:
                chunk = state.data_carry
                state.data_carry = None

            if total_len + len(chunk) > chunk_size:
                pivot = chunk_size - total_len
                state.data_carry = chunk[pivot:]
                chunk = chunk[:pivot]

            total_len += len(chunk)
            if not chunk:
                break

            yield chunk

            if total_len == chunk_size and state.data_carry:
                break

        state.generator_active = False

    state = ChunkStreamState(data_stream)
    while not state.stream_consumed:
        if state.generator_active:
            raise Exception("Previous generator must be consumed first")
        state.generator_active = True
        yield _stream_chunk(state, chunk_size)


class RegistryAuthenticator:
    """
    Wrapper around registry HTTP requests that invokes the necessary
    auth endpoint if needed. This is used by the docker.io registry.

    See https://docs.docker.com/registry/spec/auth/token/
    """

    def __init__(self) -> None:
        self.access_tokens: Dict[Tuple[str, str], str] = {}

    @staticmethod
    def auth_key(url: str) -> Tuple[str, str]:
        """
        Returns a hashable key for the domain covered by the registry url.
        """
        url_data = urllib.parse.urlparse(url)
        path_parts = url_data.path.split("/")
        return (url_data.hostname, "/".join(path_parts[0:4]))

    def request(
        self,
        url: str,
        *,
        method="GET",
        auth: Optional[str] = None,
        headers: Mapping[str, str] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Makes a request to a registry
        """
        auth_key = self.auth_key(url)
        headers = dict(headers or {})
        for attempt in range(2):
            # Select auth mode.
            auth_token = self.access_tokens.get(auth_key)
            basic_auth = None
            if auth_token:
                headers["Authorization"] = "Bearer " + auth_token
            else:
                basic_auth = auth

            if basic_auth:
                kwargs["auth"] = basic_auth
            else:
                kwargs.pop("auth", None)

            # Attempt to make request.
            resp = requests.request(method, url, headers=headers, **kwargs)

            if attempt > 0 or resp.status_code != 401:
                break

            # Attempt to generate new auth token if we got a 401.
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if not www_auth.startswith("Bearer "):
                break
            auth_parts = _split_quote(www_auth[7:], "=,")
            auth_args = {
                auth_parts[i]: auth_parts[i + 2]
                for i in range(0, len(auth_parts) - 2, 4)
            }
            realm = auth_args.pop("realm")

            auth_resp = requests.get(
                realm + "?" + urllib.parse.urlencode(auth_args), auth=auth
            )
            if auth_resp.status_code != 200:
                break

            self.access_tokens[auth_key] = auth_resp.json()["access_token"]

        return resp

    head = partialmethod(request, method="HEAD")
    get = partialmethod(request, method="GET")
    post = partialmethod(request, method="POST")
    put = partialmethod(request, method="PUT")
    patch = partialmethod(request, method="PATCH")
    delete = partialmethod(request, method="DELETE")


class Manifest(metaclass=abc.ABCMeta):
    """
    Represents a manifest loaded into memory.
    """

    def __init__(self, response: requests.Response) -> None:
        self.content = json.loads(response.text, object_pairs_hook=OrderedDict)
        self._digest = response.headers.get("Docker-Content-Digest")

    def serialize(self, strip_signature=False) -> bytes:
        """
        Serialize the manifest into its canonical form.
        """
        hash_content = self.content
        if (
            strip_signature
            and isinstance(self, ManifestV1)
            and "signatures" in hash_content
        ):
            hash_content = OrderedDict(hash_content)
            del hash_content["signatures"]

        return json.dumps(hash_content, indent=3, separators=(",", ": ")).encode(
            "UTF-8"
        )

    def digest(self) -> str:
        """
        Return the digest of the manifest in HASHALG:HASH format.
        """
        if self._digest is None:
            h = hashlib.sha256()
            h.update(self.serialize(strip_signature=True))
            self._digest = "sha256:" + h.hexdigest()
        return self._digest

    @classmethod
    @abc.abstractmethod
    def media_types(cls) -> Tuple[str, ...]:
        """
        Returns a tuple of media types for the manifest type.
        """

    def media_type(self) -> str:
        """
        Return the media type of this manifest.
        """
        return self.media_types()[0]

    @abc.abstractmethod
    def sub_objects(
        self, registry: "Registry", repo: List[str]
    ) -> Iterable["RegistryBlobRef"]:
        """
        Returns all refs underneath this manifest.
        """


class ManifestV1(Manifest):
    """
    Represents the schema1 manifest.

    See https://docs.docker.com/registry/spec/manifest-v2-1/
    """

    @classmethod
    def media_types(cls) -> Tuple[str, ...]:
        """
        Returns a tuple of media types for the manifest type.
        """
        return (
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
            "application/vnd.docker.distribution.manifest.v1+json",
        )

    def sub_objects(
        self, registry: "Registry", repo: List[str]
    ) -> Iterable["RegistryBlobRef"]:
        """
        Returns all the blob refs underneath this manifest.
        """
        return (
            RegistryBlobRef(registry, repo, layer["blobSum"])
            for layer in self.content["fsLayers"]
        )

    def media_type(self) -> str:
        """
        Returns the media type of this manifest. This depends on whether the
        "signatures" payload is present.
        """
        if "signatures" in self.content:
            return self.media_types()[0]
        return self.media_types()[1]


class ManifestV2(Manifest):
    """
    Represents a schema2 manifest.

    See https://docs.docker.com/registry/spec/manifest-v2-2/
    """

    @classmethod
    def media_types(cls) -> Tuple[str, ...]:
        """
        Returns a tuple of media types for the manifest type.
        """
        return ("application/vnd.docker.distribution.manifest.v2+json",)

    def sub_objects(
        self, registry: "Registry", repo: List[str]
    ) -> Iterable["RegistryBlobRef"]:
        """
        Returns all the blobs underneath this manifest.
        """
        objects = [RegistryBlobRef(registry, repo, self.content["config"]["digest"])]
        for layer in self.content["layers"]:
            objects.append(RegistryBlobRef(registry, repo, layer["digest"]))
        return objects


class ManifestListV2(Manifest):
    """
    Represents a schema2 manifest list.

    See https://docs.docker.com/registry/spec/manifest-v2-2/
    """

    @classmethod
    def media_types(cls) -> Tuple[str, ...]:
        """
        Returns a tuple of media types for the manifest type.
        """
        return ("application/vnd.docker.distribution.manifest.list.v2+json",)

    def sub_objects(
        self, registry: "Registry", repo: List[str]
    ) -> Iterable["RegistryBlobRef"]:
        """
        Returns all the refs underneath this manifest. The manifest list
        can have both other manifests and blobs underneath it.
        """
        objects: List[RegistryBlobRef] = []
        for manifest in self.content["manifests"]:
            media_type = manifest.get("mediaType", "")
            if media_type in MANIFEST_MEDIA_TYPE_MAP:
                objects.append(RegistryManifestRef(registry, repo, manifest["digest"]))
            else:
                objects.append(RegistryBlobRef(registry, repo, manifest["digest"]))
        return objects


MANIFEST_TYPES = (ManifestV1, ManifestV2, ManifestListV2)
MANIFEST_MEDIA_TYPE_MAP = dict(
    (media_type, manifest_type)
    for manifest_type in MANIFEST_TYPES
    for media_type in manifest_type.media_types()
)


class Registry:
    """
    Represents a docker registry.
    """

    def __init__(
        self,
        host: str,
        port=443,
        is_https=True,
        verify: Optional[str] = None,
        client_cert: Optional[str] = None,
        user: Optional[Tuple[str, str]] = None,
        host_alias: Optional[str] = None,
        requester: Optional[RegistryAuthenticator] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.is_https = is_https
        self.verify = verify
        self.client_cert = client_cert
        self.user = user
        self.host_alias = host_alias or host + ":" + str(port)
        self.requester = requester or RegistryAuthenticator()

    def __str__(self) -> str:
        """
        Return the name of this registry.
        """
        return self.host_alias

    def url(self) -> str:
        """
        Returns the base url of the registry.
        """
        return "{}://{}:{}".format(
            "https" if self.is_https else "http", self.host, self.port
        )

    def request(
        self, url: str, method="GET", has_host=False, raise_for_status=True, **kwargs
    ) -> requests.Response:
        """
        Makes a request to the registry.
        """
        request_kwargs = dict(
            verify=self.verify,
            auth=self.user,
            headers={"Accept": ",".join(MANIFEST_MEDIA_TYPE_MAP) + ", */*"},
            allow_redirects=True,
        )
        request_kwargs["headers"].update(  # type: ignore
            kwargs.pop("headers", {})
        )
        request_kwargs.update(kwargs)
        if not has_host:
            url = self.url() + url

        resp = self.requester.request(  # type: ignore
            url, method=method, **request_kwargs
        )
        if raise_for_status:
            resp.raise_for_status()
        return resp

    head = partialmethod(request, method="HEAD")
    get = partialmethod(request, method="GET")
    post = partialmethod(request, method="POST")
    put = partialmethod(request, method="PUT")
    patch = partialmethod(request, method="PATCH")
    delete = partialmethod(request, method="DELETE")


class BlobCopyPair:
    """
    Simple data structure to hold a pair of blob refs.
    """

    def __init__(self, src: "RegistryBlobRef", dst: "RegistryBlobRef") -> None:
        self.src = src
        self.dst = dst


class RegistryBlobRef:
    """
    Represents a blob ref on a registry.
    """

    OBJECT_TYPE = "blobs"

    def __init__(self, registry: Registry, repo: List[str], ref: str) -> None:
        self.registry = registry
        self.repo = repo
        self.ref = ref

    def url(self) -> str:
        """
        Returns the path component of the blob url underneath the registry.
        """
        return "/v2/{}/{}/{}".format("/".join(self.repo), self.OBJECT_TYPE, self.ref)

    def upload_url(self, upload_uuid: str = "") -> str:
        """
        Returns the url path that should be used to initiate a blob upload.
        """
        return "/v2/{}/{}/uploads/{}".format(
            "/".join(self.repo), self.OBJECT_TYPE, upload_uuid
        )

    @staticmethod
    def sub_objects() -> Iterable["RegistryBlobRef"]:
        """
        Returns any refs underneath this ref. This just applies to
        manifest refs.
        """
        return ()

    def digest(self) -> str:
        """
        Returns the digest of this ref. For blobs this is just the same as the
        ref itself.
        """
        return self.ref

    def get_copy_pairs(
        self, registry: Registry, repo: str, ref: Optional[str] = None
    ) -> Iterable[BlobCopyPair]:
        """
        Returns the list of object pairs that need to be copied to copy this
        object. For blobs this is always just the blob itself.
        """
        return itertools.chain(
            *(
                sub_object.get_copy_pairs(registry, repo)
                for sub_object in self.sub_objects()
            ),
            (BlobCopyPair(self, type(self)(registry, repo, ref or self.digest())),),
        )

    def copy(self, dst: "RegistryBlobRef") -> None:
        """
        Copies this object and all sub objects to dst's registry.

        All objects will be copied by digest except dst itself which
        will use whatever ref it is set as.
        """
        copy_pairs = list(self.get_copy_pairs(dst.registry, dst.repo, dst.ref))
        blob_copy_pairs = [
            pair for pair in copy_pairs if not isinstance(pair.src, RegistryManifestRef)
        ]
        manifest_copy_pairs = [
            pair for pair in copy_pairs if isinstance(pair.src, RegistryManifestRef)
        ]

        # Copy all the blobs in parallel.
        with Pool() as pool:
            pool.map(_copy_object_pair, blob_copy_pairs)

        # Copy all the manifests. These need to be done in serial to avoid any
        # dependency issues.
        for pair in manifest_copy_pairs:
            _copy_object_pair(pair)

    def copy_object(self, dst: "RegistryBlobRef") -> None:
        """
        Copy the blob to dst.
        """
        # Check if the destination already exists.
        if dst.registry.head(dst.url(), raise_for_status=False).status_code == 200:
            LOGGER.info("Blob %s already exists", dst)
            return

        start_push_resp = dst.registry.post(dst.upload_url())
        upload_location = start_push_resp.headers["Location"]

        for chunk in chunk_streamer(self.content_stream(), 10 * 2 ** 20):
            post_resp = dst.registry.patch(
                upload_location,
                data=chunk,
                headers={"Content-Type": "application/octet-stream"},
                has_host=True,
            )
            upload_location = post_resp.headers["Location"]

        dst.registry.put(upload_location + "&digest=" + self.digest(), has_host=True)

        LOGGER.info("Copied blob %s -> %s", self, dst)

    def content_stream(self, chunk_size=2 ** 16) -> Iterable[bytes]:
        """
        Returns a generator that yields byte array data that makes up the blob.

        This is the preferred way to interact with blobs as they could
        potentially be too large to fit into memory.
        """
        resp = self.registry.get(self.url(), stream=True)
        return resp.iter_content(chunk_size=chunk_size)

    def content(self) -> bytes:
        """
        Return the raw byte array content of the blob.
        """
        return b"".join(self.content_stream())

    def name(self, truncate=True) -> str:
        """
        Return the full blob name.
        """
        repo_name = str(self.registry) + "/" + "/".join(self.repo)
        if _is_digest_ref(self.ref):
            return repo_name + "@" + (self.ref[7:23] if truncate else self.ref)
        return repo_name + ":" + self.ref

    def __str__(self) -> str:
        """
        Return a human friendly version identifier of the blob.
        """
        return self.name()


class RegistryManifestRef(RegistryBlobRef):
    """
    Represents a manifest ref in a registry.
    """

    OBJECT_TYPE = "manifests"

    def __init__(self, *args, **kwargs) -> None:
        super(RegistryManifestRef, self).__init__(*args, **kwargs)
        self._manifest: Optional[Manifest] = None

    def manifest(self) -> Any:
        """
        Fetches and returns the manifest JSON object behind this ref.
        """
        if self._manifest is None:
            resp = self.registry.get(self.url())

            content_type = resp.headers.get("Content-Type", "")
            self._manifest = MANIFEST_MEDIA_TYPE_MAP.get(  # type: ignore
                content_type, ManifestV1
            )(resp)
        return self._manifest

    def digest(self) -> str:
        """
        Returns the digest of the image manifest.
        """
        if _is_digest_ref(self.ref):
            return self.ref
        return self.manifest().digest()

    def exists(self) -> bool:
        """
        Query the source respository and return if the manifest is found.
        """
        resp = self.registry.head(self.url(), raise_for_status=False)
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    def sub_objects(self) -> Iterable[RegistryBlobRef]:
        """
        Returns all blob refs underneath this manifest. This could potentially
        be other manifests in the case of manifest lists.
        """
        return self.manifest().sub_objects(self.registry, self.repo)

    def copy_object(self, dst) -> None:
        """
        Copies the manifest to dst.
        """
        dst.registry.put(
            dst.url(),
            data=self.manifest().serialize(),
            headers={"Content-Type": self.manifest().media_type()},
        )
        LOGGER.info("Copied manifest %s -> %s", self, dst)


def parse_image_name(
    name: str,
    verify: Optional[str] = None,
    client_cert: Optional[str] = None,
    user: Optional[Tuple[str, str]] = None,
    cred_store: CredentialStore = None,
) -> RegistryManifestRef:
    """
    Extract out the registry host, image repo, and tag from an image string.

    urllib.parse does not work appropriately for this task.
    """
    cred_store = cred_store or DictCredentialStore({})

    # Extract protocol if present. If no protocol is present it will be
    # set to a default value depending on the hostname.
    prot = None
    prot_start = name.find("://")
    if prot_start != -1:
        prot = name[0:prot_start].lower()
        name = name[prot_start + 3 :]

    # Extract the registry host if the first token looks like a hostname. If a
    # protocol scheme was present always treat the first token as the host.
    reg_part, *slash_parts = name.split("/")
    if prot is not None or (
        (":" in reg_part or "." in reg_part or reg_part == "localhost") and slash_parts
    ):
        host_alias = (prot + "://" if prot else "") + reg_part

        # Extract port
        port = None
        port_start = reg_part.rfind(":")
        if port_start != -1:
            port = int(reg_part[port_start + 1 :])
            reg_part = reg_part[0:port_start]

        # If no prot specified fill in default
        if prot is None:
            if port == 80:
                prot = "http"
            elif port == 443:
                prot = "https"
            else:
                prot = "http" if reg_part in ("localhost", "127.0.0.1") else "https"

        if prot not in ("http", "https"):
            raise ValueError("unknown registry protocol")

        if port is None:
            port = 443 if prot == "https" else 80

        registry = Registry(
            reg_part.lower(),
            port=port,
            is_https=prot == "https",
            verify=verify,
            client_cert=client_cert,
            user=cred_store.get(host_alias) or user,
            host_alias=host_alias,
        )
    else:
        registry = Registry(
            "registry-1.docker.io",
            port=443,
            is_https=True,
            verify=verify,
            client_cert=client_cert,
            user=cred_store.get("docker.io") or user,
            host_alias="docker.io",
        )

        slash_parts.insert(0, reg_part)

        # Bare images with no slash are prefixed with library. e.g.
        # ubuntu becomes docker.io/library/ubuntu:latest.
        if len(slash_parts) == 1:
            slash_parts.insert(0, "library")

    if not slash_parts:
        raise ValueError("No repo name")

    # Extract out the tag specifier.
    tag = "latest"
    try:
        tag_start = next(i for i, ch in enumerate(slash_parts[-1]) if ch in ":@")
    except StopIteration:
        tag_start = -1

    if tag_start != -1:
        tag = slash_parts[-1][tag_start + 1 :]
        slash_parts[-1] = slash_parts[-1][0:tag_start]

    return RegistryManifestRef(registry, slash_parts, tag)


def parse_user(user: str) -> Optional[Tuple[str, str]]:
    """
    Parses username and password in user:pass format.
    """
    if not user:
        return None

    col_pos = user.find(":")
    if col_pos == -1:
        return (user, "")
    return (user[0:col_pos], user[col_pos + 1 :])


def _copy_object_pair(pair: BlobCopyPair) -> None:
    """
    Helper function to invoke copy_object based on the dict passed.
    """
    pair.src.copy_object(pair.dst)
