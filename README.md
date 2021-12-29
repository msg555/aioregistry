# PyRegistry

PyRegistry is a Python library and CLI tool for inspecting and copying container image data
from and between registries.

This library primarily focuses on being a useful tool for dealing with container image
registries. It has very limited support for interpretation of the objects stored within.
Manifest data is presented simply as a JSON object and blob data can be accessed through
a raw byte stream.

# Library usage

## Find sub-manifest based on platform.
```python
from pyregistry import (
    ManifestListV2,
    parse_image_name,
)

manifest = parse_image_name("alpine").manifest()

if isinstance(manifest, ManifestListV2):
    for sub_manifest in manifest.content["manifests"]:
        if sub_manifest.get("platform", ()).get("architecture") == "amd64":
            manifest = parse_image_name("alpine").manifest()
            break
    else:
        raise Exception("Found no matching platform")
else:
    print("Not a manifest list")
```

## Download layers of an image

```python
import io
import tarfile

manifest = manifest_ref.manifest()

for layer in manifest.content["layers"]:
    assert layer["mediaType"] == "application/vnd.docker.image.rootfs.diff.tar.gzip"
    blob_ref = RegistryBlobRef(manifest_ref.registry, manifest_ref.repo, layer["digest"])

    # For example we just download into memory. In practice don't do this.
    blob_data = io.BytesIO(b"".join(blob_ref.content_stream()))
    with tarfile.open(mode="r|*", fileobj=blob_data) as tar:
        for tarinfo in tar.getmembers():
            print(tarinfo.name)
```

# CLI copy tool

```sh
# By default it will pull credentials based on ~/.docker/config.json 
python -m pyregistry --src ubuntu:18.04 --dst my.private.registry/my-repo:my-tag
```

```sh
# Copy all tags matching regex
python -m pyregistry --src ubuntu --dst my.private.registry/my-repo --tag-pattern '18\..*'
