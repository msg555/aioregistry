from typing import List, Optional

from .models import (
    Registry,
    RegistryManifestRef,
)


def parse_image_name(name: str) -> RegistryManifestRef:
    """
    Extract out the registry host, image repo, and tag from an image string.

    urllib.parse does not work appropriately for this task.
    """
    # Extract protocol if present. If no protocol is present it will be
    # set to a default value depending on the hostname.
    prot = None
    prot_start = name.find("://")
    if prot_start != -1:
        prot = name[0:prot_start].lower()
        name = name[prot_start + 3 :]

    # Extract the registry host if the first token looks like a hostname. If a
    # protocol scheme was present always treat the first token as the host.
    registry: Optional[Registry]
    reg_part, *slash_parts = name.split("/")
    if prot is not None or (
        (":" in reg_part or "." in reg_part or reg_part == "localhost") and slash_parts
    ):
        reg_part = reg_part.lower()
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

        if reg_part == "docker.io":
            reg_part = "registry-1.docker.io"

        registry = Registry(
            host=reg_part,
            port=port,
            prot=prot,
            host_alias=host_alias if host_alias != reg_part else None,
        )
    else:
        registry = None
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

    return RegistryManifestRef(registry=registry, repo=slash_parts, ref=tag)


def split_quote(s: str, dels: str, quotes: str = '"', escape: str = "\\") -> List[str]:
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
