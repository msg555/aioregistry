"""
Module implementing a client for the v2 docker registry API.

See https://docs.docker.com/registry/spec/api/
"""
import asyncio
import hashlib
import json
import logging
import ssl
from typing import (
    AsyncIterable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)
import urllib.parse

import aiohttp

from .auth import (
    CredentialStore,
    DictCredentialStore,
)
from .exceptions import RegistryException
from .models import (
    Descriptor,
    MANIFEST_TYPE_MAP,
    Manifest,
    Registry,
    RegistryBlobRef,
    RegistryManifestRef,
)
from .parsing import split_quote
from .utils import (
    ReleaseableAsyncContextManager,
    async_generator_buffer,
)

LOGGER = logging.getLogger(__name__)


class AsyncRegistryClient:
    """
    Class that holds network session and context information.
    """

    _ACCEPT_HEADER = ",".join(MANIFEST_TYPE_MAP) + ", */*"
    _DEFAULT_REGISTRY = Registry(
        host="registry-1.docker.io",
        host_alias="docker.io",
    )
    _DEFAULT_TIMEOUT = aiohttp.ClientTimeout(
        total=None,
        connect=None,
        sock_connect=10,
        sock_read=10,
    )

    def __init__(
        self,
        *,
        session: Optional[aiohttp.ClientSession] = None,
        creds: Optional[CredentialStore] = None,
        timeout: Optional[aiohttp.ClientTimeout] = None,
        default_registry: Optional[Registry] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.custom_session = bool(session)
        self.session = session or aiohttp.ClientSession()
        self.timeout = timeout or self._DEFAULT_TIMEOUT
        self.default_registry = default_registry or self._DEFAULT_REGISTRY
        self.ssl_context = ssl_context
        self.access_tokens: Dict[Tuple[str, str], str] = {}
        self.creds = creds or DictCredentialStore({})

    async def __aenter__(self) -> "AsyncRegistryClient":
        return self

    async def __aexit__(self, exc_type, exc_value, exc_traceback) -> None:
        if not self.custom_session:
            await self.session.close()

    async def _request(
        self,
        method: str,
        registry: Registry,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
        has_host: bool = False,
    ):
        """
        Make a request to a registry, applying the appropriate credentials.

        Returns an async context manager that yields an aiohttp response.
        """
        # Parse URL and determine the the authentication key for any
        # authentication tokens.
        url = path if has_host else f"{registry.url}/{path}"
        url_data = urllib.parse.urlparse(url)
        path_parts = url_data.path.split("/")
        auth_key = (url_data.hostname or "", "/".join(path_parts[0:4]))

        # Lookup any basic auth credentials to supply.
        if not registry and url_data.hostname is None:
            raise ValueError("No registry or hostname provided")

        auth = None
        creds = await self.creds.get(
            registry.host_alias or registry.host if registry else url_data.hostname  # type: ignore
        )

        if creds is not None:
            auth = aiohttp.BasicAuth(creds[0], password=creds[1])

        # Attempt to make the request twice. If the first attempt fails with a
        # 401 try to get an authentication token and then try again.
        first_attempt = True
        while True:
            all_headers = dict(headers or {})
            all_headers["Accept"] = self._ACCEPT_HEADER

            basic_auth = None
            auth_token = self.access_tokens.get(auth_key)
            if auth_token is None:
                basic_auth = auth
            else:
                all_headers["Authorization"] = "Bearer " + auth_token

            acm = ReleaseableAsyncContextManager(
                self.session.request(
                    method,
                    url,
                    auth=basic_auth,
                    headers=all_headers,
                    data=data,
                    timeout=self.timeout,
                    ssl=self.ssl_context,
                )
            )
            async with acm as response:
                if not first_attempt or response.status != 401:
                    return acm.release()

            www_auth = response.headers.get("WWW-Authenticate", "")
            if not www_auth.startswith("Bearer "):
                raise RegistryException("Failed to make request, unauthorized")

            auth_parts = split_quote(www_auth[7:], "=,")
            auth_args = {
                auth_parts[i]: auth_parts[i + 2]
                for i in range(0, len(auth_parts) - 2, 4)
            }
            realm = auth_args.pop("realm", "")
            if realm is None:
                raise RegistryException("Expected authentication realm")

            query_parts = []
            if service := auth_args.get("service"):
                query_parts.append(("service", service))
            query_parts.extend(
                ("scope", scope)
                for scope in auth_args.get("scope", "").split(" ")
                if scope
            )

            async with self.session.get(
                realm + "?" + urllib.parse.urlencode(query_parts),
                auth=auth,
                timeout=self.timeout,
                ssl=self.ssl_context,
            ) as auth_resp:
                if auth_resp.status != 200:
                    raise RegistryException("Failed to generate authentication token")
                self.access_tokens[auth_key] = (await auth_resp.json())["access_token"]

            first_attempt = False

    async def ref_lookup(self, ref: RegistryBlobRef) -> Optional[Descriptor]:
        """
        Attempts to lookup the requested ref and return a :class:`Descriptor`
        representation. The descriptor includes the media type, digest, and
        size information of the object.

        If the registry returns a 404 Not Found or 401 Unauthorized this method
        will return None. Any other failure to retrieve metadata about the
        object will raise an exception.
        """
        registry = ref.registry or self.default_registry
        try:
            async with await self._request("HEAD", registry, ref.url) as response:
                if response.status in (401, 404):
                    return None
                if response.status != 200:
                    raise RegistryException("Unexpected response from registry")

                # Extract digest
                if ref.is_digest_ref():
                    digest = ref.ref
                else:
                    digest = response.headers.get("Docker-Content-Digest")
                    if digest is None:
                        raise RegistryException("No digest given by server for tag ref")

                # Extract media type
                media_type = response.headers.get("Content-Type")
                if media_type is None:
                    raise RegistryException("No content type given by server")

                # Extract size
                size = response.headers.get("Content-Length")
                if size is None:
                    raise RegistryException("No content length given by server")
                try:
                    isize = int(size)
                except ValueError as exc:
                    raise RegistryException(
                        "Invalid content length given by server"
                    ) from exc

                return Descriptor(
                    mediaType=media_type,
                    size=isize,
                    digest=digest,
                )
        except aiohttp.ClientError as exc:
            raise RegistryException("failed to contact registry") from exc

    async def ref_content_stream(
        self,
        ref: RegistryBlobRef,
        chunk_size: int = 2 ** 20,
    ) -> AsyncIterable[bytes]:
        """
        Stream the contents of `ref` as an async iterable of `chunk_size` bytes
        objects. The last chunk may be smaller than `chunk_size`.
        """
        registry = ref.registry or self.default_registry
        try:
            async with await self._request("GET", registry, ref.url) as response:
                if response.status != 200:
                    raise RegistryException(
                        f"Unexpected response from registry HTTP {response.status}"
                    )

                cur_chunk: List[bytes] = []
                cur_chunk_size = 0
                async for chunk in response.content.iter_chunked(chunk_size):
                    need = chunk_size - cur_chunk_size
                    cur_chunk_size += len(chunk)
                    if len(chunk) >= need:
                        yield b"".join(cur_chunk) + chunk[:need]

                        cur_chunk.clear()
                        if need < len(chunk):
                            cur_chunk.append(chunk[need:])
                        cur_chunk_size -= chunk_size
                    else:
                        cur_chunk.append(chunk)

        except aiohttp.ClientError as exc:
            raise RegistryException("failed to contact registry") from exc

        if cur_chunk:
            yield b"".join(cur_chunk)

    async def manifest_download(self, ref: RegistryManifestRef) -> Manifest:
        """
        Attempt to download a manifest.
        """
        registry = ref.registry or self.default_registry
        try:
            async with await self._request("GET", registry, ref.url) as response:
                if response.status != 200:
                    raise RegistryException(
                        f"Unexpected response from registry HTTP {response.status}"
                    )
                try:
                    manifest_data = json.loads(await response.text(encoding="utf-8"))
                except ValueError as exc:
                    raise RegistryException(
                        "Failed decoding JSON response from registry"
                    ) from exc
        except aiohttp.ClientError as exc:
            raise RegistryException("failed to contact registry") from exc

        return Manifest.parse(
            manifest_data,
            media_type=response.headers.get("Content-Type"),
        )

    async def manifest_write(
        self, ref: RegistryManifestRef, manifest: Manifest
    ) -> None:
        """
        Write a manifest to a registry. If `ref.ref` is empty or is a digest
        ref, then `ref.ref` will be ignored and the manifest will be pushed
        untagged using the digest of `manifest.canonical()`.
        """
        if not ref.ref or ref.is_digest_ref():
            ref = ref.copy(update=dict(ref=manifest.digest))
        async with await self._request(
            "PUT",
            ref.registry or self.default_registry,
            ref.url,
            data=manifest.canonical(),
            headers={"Content-Type": manifest.get_media_type()},
        ) as response:
            if response.status // 100 != 2:
                raise RegistryException("Failed to copy manifest")

    async def blob_write(
        self, ref: RegistryBlobRef, data: AsyncIterable[bytes]
    ) -> RegistryBlobRef:
        """
        Writes a blob to the registry. The digest will be calculated
        automatically while uploading, ignoring `ref.ref`. A copy of
        `ref` with `ref.ref` set to the calculated digest will be returned.
        """
        # Perform the blob upload flow, POST -> PATCH -> PUT
        registry = ref.registry or self.default_registry
        async with await self._request(
            "POST",
            registry,
            ref.upload_url(),
        ) as response:
            if response.status // 100 != 2:
                raise RegistryException(
                    "Unexpected response attempting to start blob copy"
                )
            upload_location = response.headers["Location"]

        hsh = hashlib.sha256()
        async for chunk in async_generator_buffer(data, 4):
            hsh.update(chunk)
            async with await self._request(
                "PATCH",
                registry,
                upload_location,
                data=chunk,
                headers={"Content-Type": "application/octet-stream"},
                has_host=True,
            ) as response:
                if response.status // 100 != 2:
                    raise RegistryException("Unexpected response writing blob data")
                upload_location = response.headers["Location"]
        digest = "sha256:" + hsh.hexdigest()

        async with await self._request(
            "PUT",
            registry,
            f"{upload_location}&digest={digest}",
            has_host=True,
        ) as response:
            if response.status // 100 != 2:
                raise RegistryException("Unexpected response ending blob copy")

        return ref.copy(update=dict(ref=digest))

    async def registry_repos(self, registry: Optional[Registry]) -> List[str]:
        """
        Return a list of all repos for the given registry. It is up to the
        registry implementation to determine what if any repo names will
        be returned.
        """
        async with await self._request(
            "GET",
            registry or self.default_registry,
            "/v2/_catalog",
        ) as response:
            try:
                return (await response.json())["repositories"]
            except ValueError as exc:
                raise RegistryException("Unexpected response getting repos") from exc

    async def registry_repo_tags(
        self, registry: Optional[Registry], repo: List[str]
    ) -> List[str]:
        """
        Return a list of all tags for the given repo name.
        """
        async with await self._request(
            "GET",
            registry or self.default_registry,
            f"/v2/{'/'.join(repo)}/tags/list",
        ) as response:
            try:
                return (await response.json())["tags"]
            except ValueError as exc:
                raise RegistryException(
                    "Unexpected response getting repo tags"
                ) from exc

    async def copy_refs(self, src: RegistryBlobRef, dst: RegistryBlobRef) -> bool:
        """
        Copy the blob src to dst. Returns True if any data was copied and
        False if the content already existed.
        """
        if src.OBJECT_TYPE != dst.OBJECT_TYPE:
            raise ValueError("Cannot copy ref to different object type")
        if dst.is_digest_ref():
            if src.ref != dst.ref:
                raise ValueError(
                    "Cannot copy to a content address that does not match the source"
                )

        if src == dst:
            LOGGER.info("skipping copy of identical refs")
            return False

        # Check if ref already exists
        if src.is_digest_ref():
            if await self.ref_lookup(dst) is not None:
                LOGGER.info("Skipping copy %s -> %s - already exists", src, dst)
                return False

        if isinstance(src, RegistryManifestRef):
            manifest = await self.manifest_download(src)

            await asyncio.gather(
                *(
                    self.copy_refs(
                        RegistryManifestRef(
                            registry=src.registry, repo=src.repo, ref=digest
                        ),
                        RegistryManifestRef(
                            registry=dst.registry, repo=dst.repo, ref=digest
                        ),
                    )
                    for digest in manifest.get_manifest_dependencies()
                ),
                *(
                    self.copy_refs(
                        RegistryBlobRef(
                            registry=src.registry, repo=src.repo, ref=digest
                        ),
                        RegistryBlobRef(
                            registry=dst.registry, repo=dst.repo, ref=digest
                        ),
                    )
                    for digest in manifest.get_blob_dependencies()
                ),
            )
            assert isinstance(dst, RegistryManifestRef)
            await self.manifest_write(dst, manifest)

            LOGGER.info("Copied manifest %s -> %s", src, dst)
            return True

        # Attempt mount if blobs come from the same registry.
        if src.registry == dst.registry:
            query_str = urllib.parse.urlencode(
                {
                    "from": "/".join(src.repo),
                    "mount": dst.ref,
                }
            )
            async with await self._request(
                "POST",
                dst.registry or self.default_registry,
                f"v2/{'/'.join(dst.repo)}/blobs/uploads/?{query_str}",
            ) as response:
                if response.status == 201:
                    LOGGER.info(
                        "Mounted blob %s from %s",
                        dst.ref,
                        "/".join(src.repo),
                    )
                    return True
                LOGGER.warning(
                    "mount failed with status %s, trying copy",
                    response.status,
                )
                raise Exception("no")

        await self.blob_write(dst, self.ref_content_stream(src))
        LOGGER.info("Copied blob %s -> %s", src, dst)
        return True
