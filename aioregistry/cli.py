#!/usr/bin/env python3
"""
Script entrypoint for copying images between registries.
"""

import argparse
import json
import logging
import re
import ssl
import sys
from typing import Any, Callable, Dict, Optional, Tuple

import pydantic

try:
    from tqdm import tqdm  # type: ignore
    from tqdm.contrib.logging import logging_redirect_tqdm  # type: ignore
except ImportError:
    tqdm = None
    logging_redirect_tqdm = None

from .auth import CredentialStore, DockerCredentialStore, default_credential_store
from .client import AsyncRegistryClient
from .models import RegistryBlobRef, RegistryManifestRef
from .parsing import parse_image_name


def parse_args():
    """
    Setup and parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Copy/inspect registry images",
    )
    parser.add_argument("src", help="Source registry image")
    parser.add_argument("dst", nargs="?", help="Dest registry image")
    parser.add_argument(
        "--blob",
        required=False,
        const=True,
        action="store_const",
        default=False,
        help="Copy/inspect a blob instead of a manifest",
    )
    parser.add_argument(
        "--tag-pattern",
        action="append",
        help="Copy/inspect all tags matching regex. Not compatible with --blob",
    )
    parser.add_argument(
        "--descriptor",
        required=False,
        const=True,
        action="store_const",
        default=False,
        help="Print a descriptor of the objects instead of the objects themselves",
    )
    parser.add_argument(
        "--auth-config",
        required=False,
        default=None,
        help="Path to Docker credential config file",
    )
    parser.add_argument(
        "--insecure",
        required=False,
        const=True,
        action="store_const",
        default=False,
        help="Disable server certificate verification",
    )
    parser.add_argument(
        "--cafile",
        required=False,
        default=None,
        help="SSL context CA file",
    )
    parser.add_argument(
        "--capath",
        required=False,
        default=None,
        help="SSL context CA directory",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
    )
    return parser.parse_args()


def setup_logging(verbose: int) -> None:
    """
    Setup logging configuration for CLI
    """
    log_level = logging.WARN
    if verbose > 1:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )


def _convert_to_blob_ref(ref: RegistryManifestRef) -> RegistryBlobRef:
    """
    Convert a manifest ref into a blob ref of the same repo/ref.
    """
    if not ref.is_digest_ref():
        sys.stderr.write("Can only copy/inspect blobs by digest")
        sys.exit(1)
    return RegistryBlobRef(
        registry=ref.registry,
        repo=ref.repo,
        ref=ref.ref,
    )


async def main() -> int:
    """
    CLI entrypoint that copies an image between two registries.
    """
    args = parse_args()
    setup_logging(args.verbose)

    if logging_redirect_tqdm is not None:
        with logging_redirect_tqdm():
            return await _main(args)

    return await _main(args)


async def _main(args) -> int:
    """
    Helper CLI entrypoint after logging setup and arguments parsed.
    """
    creds: CredentialStore
    if args.auth_config:
        with open(args.auth_config, "r") as fauth:
            creds = DockerCredentialStore(json.load(fauth))
    else:
        creds = default_credential_store()  # pylint: disable=redefined-variable-type

    ssl_ctx = ssl.create_default_context(
        cafile=args.cafile,
        capath=args.capath,
    )
    if args.insecure:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    src_ref = parse_image_name(args.src)

    progress_map: Dict[int, Tuple[Any, int]] = {}

    async def _progress(src, dst, bytes_total, bytes_written):
        # pylint: disable=unused-argument
        if tqdm is None:
            print(
                f"Copying {dst} {bytes_written}/{bytes_total} {100*bytes_written/bytes_total:.1f}%"
            )
        else:
            t, bytes_last = progress_map.get(id(dst), (None, 0))
            if t is None:
                t = tqdm(
                    desc=dst.ref[7:15],
                    total=bytes_total,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                ).__enter__()
            t.update(bytes_written - bytes_last)
            progress_map[id(dst)] = (t, bytes_written)
            if bytes_written == bytes_total:
                with t:
                    pass

    async with AsyncRegistryClient(creds=creds, ssl_context=ssl_ctx) as client:

        def _convert_object(obj: Optional[pydantic.BaseModel]):
            if obj is None:
                return None
            return obj.dict(
                exclude_unset=True,
                by_alias=True,
            )

        get_object: Callable = (
            client.ref_lookup if args.descriptor else client.manifest_download
        )

        if not args.dst:
            if args.blob:
                if args.descriptor:
                    result = _convert_object(
                        await client.ref_lookup(_convert_to_blob_ref(src_ref))
                    )
                else:
                    _, content_stream = await client.ref_content_stream(
                        _convert_to_blob_ref(src_ref)
                    )
                    async for chunk in content_stream:
                        sys.stdout.buffer.write(chunk)
                    return 0

            elif args.tag_pattern:
                result = {}
                for tag in await client.registry_repo_tags(
                    src_ref.registry, src_ref.repo
                ):
                    if not any(re.match(pat, tag) for pat in args.tag_pattern):
                        continue
                    the_ref = src_ref.copy(update=dict(ref=tag))
                    result[tag] = _convert_object(await get_object(the_ref))
            else:
                result = _convert_object(await get_object(src_ref))
            json.dump(result, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        dst_ref = parse_image_name(args.dst)
        if args.blob:
            await client.copy_refs(
                _convert_to_blob_ref(src_ref),
                _convert_to_blob_ref(dst_ref),
                layer_progress=_progress,
            )
        elif args.tag_pattern:
            for tag in await client.registry_repo_tags(src_ref.registry, src_ref.repo):
                if not any(re.match(pat, tag) for pat in args.tag_pattern):
                    continue
                print(f"Copying {src_ref} to {dst_ref}")
                await client.copy_refs(
                    src_ref.copy(update=dict(ref=tag)),
                    dst_ref.copy(update=dict(ref=tag)),
                    layer_progress=_progress,
                )
        else:
            await client.copy_refs(src_ref, dst_ref, layer_progress=_progress)

    return 0
