#!/usr/bin/env python3
"""
Script entrypoint for copying images between registries.
"""

import argparse
import json
import logging
import os
import re
import ssl
import sys

from .auth import DockerCredentialStore
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
        "--auth-config",
        required=False,
        default=os.path.expanduser("~/.docker/config.json"),
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


async def main() -> None:
    """
    CLI entrypoint that copies an image between two registries.
    """
    args = parse_args()
    setup_logging(args.verbose)

    creds = None
    if args.auth_config:
        with open(args.auth_config, "r") as fauth:
            creds = DockerCredentialStore(json.load(fauth))

    ssl_ctx = ssl.create_default_context(
        cafile=args.cafile,
        capath=args.capath,
    )
    if args.insecure:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    src_ref = parse_image_name(args.src)

    async with AsyncRegistryClient(creds=creds, ssl_context=ssl_ctx) as client:
        if not args.dst:
            if args.blob:
                async for chunk in client.ref_content_stream(
                    _convert_to_blob_ref(src_ref)
                ):
                    sys.stdout.buffer.write(chunk)
                return

            if args.tag_pattern:
                result = {}
                for tag in await client.registry_repo_tags(
                    src_ref.registry, src_ref.repo
                ):
                    if not any(re.match(pat, tag) for pat in args.tag_pattern):
                        continue
                    the_ref = src_ref.copy(update=dict(ref=tag))
                    result[tag] = (await client.manifest_download(the_ref)).dict(
                        exclude_unset=True,
                        by_alias=True,
                    )
            else:
                result = (await client.manifest_download(src_ref)).dict(
                    exclude_unset=True,
                    by_alias=True,
                )
            json.dump(result, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return

        dst_ref = parse_image_name(args.dst)
        if args.blob:
            await client.copy_refs(src_ref, _convert_to_blob_ref(dst_ref))
        if args.tag_pattern:
            for tag in await client.registry_repo_tags(src_ref.registry, src_ref.repo):
                if not any(re.match(pat, tag) for pat in args.tag_pattern):
                    continue
                print(f"Copying {src_ref} to {dst_ref}")
                await client.copy_refs(
                    src_ref.copy(update=dict(ref=tag)),
                    dst_ref.copy(update=dict(ref=tag)),
                )
        else:
            await client.copy_refs(src_ref, dst_ref)
