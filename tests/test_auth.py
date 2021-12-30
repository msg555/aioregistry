"""
Tests for the aioregistry.auth module
"""
import base64
import unittest
from unittest.mock import patch

from aioregistry.auth import (
    DictCredentialStore,
    DockerCredentialStore,
)


class AuthTest(unittest.TestCase):
    """
    aioregistry.auth tests
    """

    def test_dict_store(self):
        """
        Test that dict cred store does yields the configured auths.
        """
        creds = {
            "test.io": ("myuser", "mypass"),
            "docker.io": ("myuser1", "mypass2"),
        }
        cred_store = DictCredentialStore(creds)

        for host, auth in creds.items():
            self.assertEqual(
                cred_store.get(host),
                auth,
            )

        self.assertIsNone(cred_store.get("other.io"))

    def test_docker_auth_map(self):
        """
        Test that basic docker auth config works.
        """
        creds = {
            "test.io": ("myuser", "mypass"),
            "https://index.docker.io/v1/": ("myuser1", "mypass2"),
        }
        cred_store = DockerCredentialStore(
            {
                "auths": {
                    host: {"auth": base64.b64encode(":".join(auth).encode()).decode()}
                    for host, auth in creds.items()
                }
            }
        )

        for host, auth in creds.items():
            self.assertEqual(
                cred_store.get(host),
                auth,
            )

        self.assertIsNone(cred_store.get("other.io"))

    def test_docker_cred_helper(self):
        """
        Test using credential helper configurations.
        """
        cred_store = DockerCredentialStore(
            {
                "auths": {"test.io": {}},
                "credsStore": "test-store",
                "credHelpers": {"reg1": "helper1", "reg2": "helper2"},
            }
        )

        def _test_query(
            cred_helper, host, user, password, expect_cached=False, query_host=None
        ):
            query_host = query_host or host
            with patch("aioregistry.auth.DockerCredentialStore._query_helper") as qhelp:
                qhelp.return_value = {"Username": user, "Secret": password}
                self.assertEqual(
                    cred_store.get(host),
                    (user, password) if user else None,
                )
                if expect_cached:
                    qhelp.assert_not_called()
                else:
                    qhelp.assert_called_once_with(cred_helper, query_host)

        _test_query("test-store", "test.io", "user1", "pass1")
        _test_query("test-store", "test.io", "user1", "pass1", expect_cached=True)
        _test_query(
            "test-store",
            "docker.io",
            "user2",
            "pass2",
            query_host="https://index.docker.io/v1/",
        )
        _test_query("helper1", "reg1", "user3", "pass3")
        _test_query("helper2", "reg2", "", "")
        _test_query("helper2", "reg2", "", "", expect_cached=True)
