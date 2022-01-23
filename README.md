 pyregistry

pyregistry is a Python library and CLI tool for inspecting and copying container image data
from and between registries.

This library primarily focuses on being a useful tool for dealing with container image
registries. It has very limited support for interpretation of the objects stored within.

# Library usage

## Find sub-manifest based on platform.
```python
async with AsyncRegistryClient() as client:
    manifest_ref = parse_image_name("alpine")
    manifest = await client.manifest_download(manifest_ref)

    if isinstance(manifest, ManifestListV2S2):
        for sub_manifest in manifest.manifests:
            if sub_manifest.platform.architecture == "amd64":
                manifest_ref.ref = sub_manifest.digest
                manifest = await client.manifest_download(manifest_ref)
                break
        else:
            raise Exception("Found no matching platform")
    else:
        print("Not a manifest list")
```

## Download layers of an image

```python
for layer in manifest.layers:
    assert layer.media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip"
    blob_ref = RegistryBlobRef(manifest_ref.registry, manifest_ref.repo, layer.digest)

    # For example we just download into memory. In practice don't do this.
    blob_data = io.BytesIO(
        b"".join([chunk async for chunk in client.ref_content_stream(blob_ref)])
    )
    with tarfile.open(mode="r|*", fileobj=blob_data) as tar:
        for tarinfo in tar.getmembers():
            print(tarinfo.name)
```

# CLI copy tool

```sh
# By default it will pull credentials based on ~/.docker/config.json 
python -m aioregistry ubuntu:18.04 my.private.registry/my-repo:my-tag
```

```sh
# Copy all tags matching regex
python -m aioregistry ubuntu my.private.registry/my-repo --tag-pattern '18\..*'
