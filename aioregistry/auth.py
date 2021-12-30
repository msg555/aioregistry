"""
Defines the CredentialStore interface responsible for providing authentication
to registries.
"""
import abc
import base64
import json
import logging
import locale
import os
import subprocess
from typing import Any, Mapping, Optional, Tuple

LOGGER = logging.getLogger(__name__)


class CredentialStore(metaclass=abc.ABCMeta):
    """
    Interface for accessing a registry credential store.
    """

    @abc.abstractmethod
    def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        If credentials for the given host are available returns a
        (user, password) tuple containing those credentials. Otherwise
        returns None if no credentials exist for the requested host.

        If the credentials represent an identity token the `user` part of
        the tuple will be "<token>".
        """


class DockerCredentialStore(CredentialStore):
    """
    Implements a credential store that understands the Docker credential config
    format. See
    https://docs.docker.com/engine/reference/commandline/login/#credentials-store
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
    def from_file(cls, path=None) -> "DockerCredentialStore":
        """
        Load the docker config from a file. If `path` is None then the default
        path for docker config will be used.

        Raises FileNotFoundError if the file could not be opened.
        """
        path = path or os.path.expanduser("~/.docker/config.json")
        with open(path, "r") as fconfig:
            return cls(json.load(fconfig))

    @staticmethod
    def _query_helper(store: str, host: str) -> Any:
        """
        Query the passed storage helper and return the parsed JSON results.

        If the invocation fails or the resutls are not a valid JSON document
        None will be returned instead.
        """
        LOGGER.info("Querying %s for %s", store, host)

        # Query the storage helper.
        try:
            presult = subprocess.run(
                ("docker-credential-{}".format(store), "get"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                input=host,
                encoding=locale.getpreferredencoding(),
                check=True,
            )
        except OSError:
            return None
        try:
            return json.loads(presult.stdout)
        except ValueError:
            return None

    def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Gets the credentials for the host. First it checks if the credentials
        are stored literally or have been cached in self.auths. Next we check if
        there is a host specific credential store configured, otherwise we default
        to the global credential store helper. If either of those things exist
        we'll attempt to query the helper and cache the result if the program
        exits correctly.
        """
        host = self.HOST_REMAP.get(host, host)

        # Return credentials from cache if they exist.
        auth = self.auths.get(host, False)
        if auth is not False:
            return auth  # type: ignore

        # Determine what storage helper we should use.
        store = self.host_stores.get(host, self.default_store)
        if store is None:
            return None

        # Query the storage helper.
        result = self._query_helper(store, host)
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

    def get(self, host: str) -> Optional[Tuple[str, str]]:
        """
        Return the credentials in the dict if they exist.
        """
        return self.auth_map.get(host)
