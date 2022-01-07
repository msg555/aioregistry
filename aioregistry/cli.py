#!/usr/bin/env python3
"""
Script entrypoint for copying images between registries.
"""

import argparse
import json
import logging
import os
import re
import sys

from .auth import DockerCredentialStore
from .client import AsyncRegistryClient
from .parsing import parse_image_name


async def main() -> None:
    """
    CLI entrypoint that copies an image between two registries.
    """
    parser = argparse.ArgumentParser(
        description="Copy images between registries. If no dest image is given"
        " this will simply output the src manifest"
    )
    parser.add_argument("--src", required=True, help="Source registry image")
    parser.add_argument(
        "--src-ca", required=False, default=None, help="Source CA certificate"
    )
    parser.add_argument("--dst", required=False, help="Dest registry image")
    parser.add_argument(
        "--dst-ca", required=False, default=None, help="Dest CA certificate"
    )
    parser.add_argument(
        "--tag-pattern",
        action="append",
        help="Instead of just copying the given tag copy all tags matching a regex pattern",
    )
    parser.add_argument(
        "--auth-config",
        required=False,
        default=os.path.expanduser("~/.docker/config.json"),
        help="Path to Docker credential config file",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
    )
    args = parser.parse_args()

    log_level = logging.WARN
    if args.verbose > 1:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )

    creds = None
    if args.auth_config:
        with open(args.auth_config, "r") as fauth:
            creds = DockerCredentialStore(json.load(fauth))

    async with AsyncRegistryClient(creds=creds) as client:
        src_ref = parse_image_name(args.src)
        if not args.dst:
            if args.tag_pattern:
                result = {}
                for tag in await client.registry_repo_tags(
                    src_ref.registry, src_ref.repo
                ):
                    if not any(re.match(pat, tag) for pat in args.tag_pattern):
                        continue
                    src_ref.ref = tag
                    result[tag] = (await client.manifest_download(src_ref)).dict(
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
        if args.tag_pattern:
            for tag in await client.registry_repo_tags(src_ref.registry, src_ref.repo):
                if not any(re.match(pat, tag) for pat in args.tag_pattern):
                    continue
                src_ref.ref = tag
                dst_ref.ref = tag
                print(f"Copying {src_ref} to {dst_ref}")
                await client.copy_refs(src_ref, dst_ref)
        else:
            await client.copy_refs(src_ref, dst_ref)
