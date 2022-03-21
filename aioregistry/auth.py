"""
Defines the CredentialStore interface responsible for providing authentication
to registries.
"""
import abc
import asyncio
import base64
import json
import logging
import os
import subprocess
from typing import Any, Mapping, Optional, Tuple

LOGGER = logging.getLogger(__name__)


class CredentialStore(metaclass=abc.ABCMeta):
    """
    Interface for accessing a registry credential store.
    """

    @abc.abstractmethod
    async def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        If credentials for the given host are available returns a
        (user, password) tuple containing those credentials. Otherwise
        returns None if no credentials exist for the requested host.

        If the credentials represent an identity token the `user` part of
        the tuple will be "<token>".
        """


class DockerCredentialStore(CredentialStore):
    """
    Implements a credential store that understands the containers auth
    config format. See
    https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
    for more information on this format.
    """

    HOST_REMAP = {
        "docker.io": "https://index.docker.io/v1/",
    }

    def __init__(self, config) -> None:
        self.default_store = config.get("credsStore")
        self.host_stores = config.get("credHelpers", {})
        self.auths = {
            host: tuple(base64.b64decode(auth["auth"]).decode().split(":", 1))
            for host, auth in config.get("auths", {}).items()
            if auth.get("auth")
        }

    @classmethod
    def from_file(cls, path: str) -> "DockerCredentialStore":
        """
        Load the docker config from a file.

        Raises FileNotFoundError if the file could not be opened.
        """
        with open(path, "r", encoding="utf-8") as fconfig:
            return cls(json.load(fconfig))

    @staticmethod
    async def _query_helper(store: str, host: str) -> Any:
        """
        Query the passed storage helper and return the parsed JSON results.

        If the invocation fails or the resutls are not a valid JSON document
        None will be returned instead.
        """
        LOGGER.info("Querying %s for %s", store, host)

        # Query the storage helper.
        try:
            presult = await asyncio.create_subprocess_exec(
                "docker-credential-{}".format(store),
                "get",
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            stdout, _ = await presult.communicate(host.encode("utf-8"))
            if presult.returncode != 0:
                return None
        except OSError:
            return None
        try:
            return json.loads(stdout.decode("utf-8"))
        except ValueError:
            return None

    async def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Gets the credentials for the host. First it checks if the credentials
        are stored literally or have been cached in self.auths. Next we check if
        there is a host specific credential store configured, otherwise we default
        to the global credential store helper. If either of those things exist
        we'll attempt to query the helper and cache the result if the program
        exits correctly.
        """
        # If there is a remap for the host try that first, then try the host
        # itself.
        remap_host = self.HOST_REMAP.get(host)
        if remap_host is not None:
            if remap_result := await self.get(remap_host):
                return remap_result

        # Return credentials from cache if they exist.
        auth = self.auths.get(host, False)
        if auth is not False:
            return auth  # type: ignore

        # Determine what storage helper we should use.
        store = self.host_stores.get(host, self.default_store)
        if store is None:
            return None

        # Query the storage helper.
        result = await self._query_helper(store, host)
        if result is None:
            return None

        username = result.get("Username")
        password = result.get("Secret")

        # Cache and return results.
        result = None
        if username and password:
            result = (username, password)
        self.auths[host] = result
        return result


class DictCredentialStore(CredentialStore):
    """
    Simple in-memory dictionary backed credential store.
    """

    def __init__(self, auth_map: Mapping[str, Tuple[str, str]]) -> None:
        self.auth_map = dict(auth_map)

    async def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Return the credentials in the dict if they exist.
        """
        return self.auth_map.get(host)


class ChainedCredentialStore(CredentialStore):
    """
    Chains multiple other credential stores together. The earliest providers
    will be queried first. If credentials are successfully returned by a
    provider no other providers in the chain will be queried.
    """

    def __init__(self, *providers: CredentialStore) -> None:
        self.providers = list(providers)

    async def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Find the first provider with credentials for the host.
        """
        for provider in self.providers:
            creds = await provider.get(host)
            if creds is not None:
                return creds
        return None


def default_credential_store() -> CredentialStore:
    """
    Creates a credential stored that queries all the paths described in
    https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
    """
    paths = []
    if runtime_dir := os.getenv("XDG_RUNTIME_DIR", ""):
        paths.append(os.path.join(runtime_dir, "containers/auth.json"))
    if config_home := os.getenv("XDG_CONFIG_HOME", ""):
        paths.append(os.path.join(config_home, ".config/containers/auth.json"))
    elif home_dir := os.getenv("HOME", ""):
        paths.append(os.path.join(home_dir, ".config/containers/auth.json"))
    if home_dir := os.getenv("HOME", ""):
        paths.append(os.path.join(home_dir, ".docker/config.json"))
        paths.append(os.path.join(home_dir, ".dockercfg"))

    providers = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fconfig:
                providers.append(DockerCredentialStore(json.load(fconfig)))
        except FileNotFoundError:
            pass
    return ChainedCredentialStore(*providers)
