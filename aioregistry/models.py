import hashlib
import re
from typing import (
    Any,
    Dict,
    List,
    Optional,
)

from pydantic import (
    BaseModel,
    Field,
)

try:
    from typing import Literal
except ImportError:
    # python 3.7 compatibility
    from typing_extensions import Literal  # type: ignore


# https://docs.docker.com/registry/spec/manifest-v2-2/
# https://github.com/opencontainers/image-spec/blob/main/media-types.md#compatibility-matrix
MANIFEST_TYPE_MAP = {}


class Descriptor(BaseModel, frozen=True):
    """
    Generic descriptor model used throughout the manifest definitions. These
    objects point to a content addressed object stored elsewhere.
    """

    media_type: str = Field(..., alias="mediaType")
    size: int
    digest: str
    urls: List[str] = []
    annotations: Dict[str, str] = {}


class Manifest(BaseModel, frozen=True):
    """
    Base Manifest class that supplies some useful methods.
    """

    @classmethod
    def __init_subclass__(cls):
        for media_type in getattr(cls, "_MEDIA_TYPES", ()):
            MANIFEST_TYPE_MAP[media_type] = cls

    @classmethod
    def parse(
        cls,
        data: Any,
        *,
        media_type: Optional[str] = None,
    ) -> "Manifest":
        """
        Attempt to parse data as a manifest object. If the media type is
        known it can be specified to only try the specified media type.
        """
        if media_type is None:
            if not isinstance(data, dict):
                raise ValueError("data is not a dict")
            media_type = data.get("mediaType")
            if media_type is None:
                raise ValueError("data has no media type and none given")

        manifest_cls = MANIFEST_TYPE_MAP.get(media_type)
        if manifest_cls is None:
            raise ValueError(f"Unknown media type {repr(media_type)}")
        return manifest_cls(**data)

    @property
    def digest(self) -> str:
        """
        Compute the manifest digest using its canonicalized form. This may
        differ from the digest used on the registry if the server was using
        a different canonicalization (which at this point seems likely).
        """
        digest = self.__dict__.get("_digest")
        if digest is not None:
            return digest

        h = hashlib.sha256()
        h.update(self.canonical().encode("utf-8"))
        digest = "sha256:" + h.hexdigest()
        self.__dict__["_digest"] = digest
        return digest

    def canonical(self) -> str:
        """
        Calculate the canonical JSON representation.
        """
        if self.get_media_type().startswith("application/vnd.docker."):
            return self.json(
                exclude_unset=True,
                indent=3,
                separators=(",", ": "),
                ensure_ascii=False,
                by_alias=True,
            )
        return self.json(
            exclude_unset=True,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            by_alias=True,
        )

    def get_media_type(self) -> str:
        """
        Returns the media type of the manifest. Most manifest types have a
        media_type member that this is fulfilled with but V1 schema manifests
        lack this field which this method compensates for.
        """
        # pylint: disable=no-member
        if isinstance(self, ManifestV1):
            return self._MEDIA_TYPES[0]
        return self.media_type  # type: ignore

    def get_manifest_dependencies(self) -> List[str]:
        """Return a list of manifest dependency digests."""
        return []

    def get_blob_dependencies(self) -> List[str]:
        """Return a list of blob dependency digests."""
        return []


class ManifestListV2S2(Manifest):
    """
    Manifest list type
    """

    _MEDIA_TYPES = (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )

    class ManifestListItem(Descriptor):
        """Container class for a sub-manifest in a manifest list"""

        class PlatformData(BaseModel):
            """Container class for platform data in a manifest list"""

            architecture: str
            os: str
            os_version: str = Field("", alias="os.version")
            os_features: List[str] = Field([], alias="os.features")
            variant: str = ""
            features: List[str] = []

        platform: Optional[PlatformData] = None

    schema_version: Literal[2] = Field(..., alias="schemaVersion")
    media_type: Optional[Literal[_MEDIA_TYPES]] = Field(  # type: ignore
        _MEDIA_TYPES[0], alias="mediaType"
    )
    manifests: List[ManifestListItem]
    annotations: Dict[str, str] = {}

    def get_manifest_dependencies(self) -> List[str]:
        """Return a list of manifest dependency digests."""
        return [manifest.digest for manifest in self.manifests]


class ManifestV2S2(Manifest):
    """
    Single image manifest
    """

    _MEDIA_TYPES = (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )

    schema_version: Literal[2] = Field(..., alias="schemaVersion")
    media_type: Literal[_MEDIA_TYPES] = Field(_MEDIA_TYPES[0], alias="mediaType")  # type: ignore
    config: Descriptor
    layers: List[Descriptor]

    def get_blob_dependencies(self) -> List[str]:
        """Return a list of manifest dependency digests."""
        result = [layer.digest for layer in self.layers]
        result.append(self.config.digest)
        return result


class ManifestV1(Manifest):
    """
    Legacy manifest type.

    Although we can accept signed V1 manifests there is no support for verifiying
    the signatures attached. Currently the signatures are just dropped. Since this
    is a legacy media type support is unlikely to be added.
    """

    _MEDIA_TYPES = (
        "application/vnd.docker.distribution.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
    )

    class BlobData(BaseModel):
        """Container class for manifest blob data"""

        blob_sum: str = Field(..., alias="blobSum")

    class HistoryData(BaseModel):
        """Container class for manifest history data"""

        v1_compatibility: str = Field(..., alias="v1Compatibility")

    name: str
    tag: str
    architecture: str
    fsLayers: List[BlobData]
    history: List[HistoryData]
    schemaVersion: int


class Registry(BaseModel, frozen=True):
    """
    Represents a docker registry.
    """

    host: str
    port: int = 443
    prot: str = "https"
    host_alias: Optional[str] = None

    def __str__(self) -> str:
        if self.host_alias is not None:
            return self.host_alias
        default_prot, default_port = "https", 443
        if self.host == "localhost":
            default_prot, default_port = "http", 80
        if self.prot == default_prot and self.port == default_port:
            return self.host
        if self.prot == default_prot and self.port not in (80, 443):
            return f"{self.host}:{self.port}"
        if self.prot != default_prot and default_port + self.port == 80 + 443:
            return f"{self.host}:{self.port}"
        return f"{self.prot}://{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """
        Returns the base url of the registry.
        """
        return f"{self.prot}://{self.host}:{self.port}"


class RegistryBlobRef(BaseModel, frozen=True):
    """
    Represents a blob ref on a registry.
    """

    OBJECT_TYPE = "blobs"

    registry: Optional[Registry]
    repo: List[str]
    ref: str

    @property
    def url(self) -> str:
        """
        Returns the path component of the blob url underneath the registry.
        """
        return f"v2/{'/'.join(self.repo)}/{self.OBJECT_TYPE}/{self.ref}"

    def upload_url(self, upload_uuid: str = "") -> str:
        """
        Returns the url path that should be used to initiate a blob upload.
        """
        return "v2/{}/{}/uploads/{}".format(
            "/".join(self.repo), self.OBJECT_TYPE, upload_uuid
        )

    def is_digest_ref(self) -> bool:
        """
        Returns true if ref is a disgest ref.
        """
        return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", self.ref))

    def __str__(self) -> str:
        return self.name(truncate=True)

    def name(self, *, truncate=False, include_ref=True) -> str:
        """Return the full blob name"""
        repo_name = "/".join(self.repo)
        if self.registry:
            repo_name = f"{self.registry}/{repo_name}"
        if not include_ref:
            return repo_name
        if self.is_digest_ref():
            return f"{repo_name}@{self.ref[7:14] if truncate else self.ref}"
        return f"{repo_name}:{self.ref}"


class RegistryManifestRef(RegistryBlobRef):
    """
    Represents a manifest ref in a registry.
    """

    OBJECT_TYPE = "manifests"
