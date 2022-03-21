"""
Tests for the Registry library.
"""
import asyncio
import unittest

from aioregistry.client import AsyncRegistryClient
from aioregistry.exceptions import RegistryException
from aioregistry.models import Descriptor, Registry
from aioregistry.parsing import parse_image_name


def asyncio_run(corofunc):
    """
    Simple decorator that starts an event loop to run a coroutine function.
    """

    def invoke(*args, **kwargs):
        return asyncio.run(corofunc(*args, **kwargs))

    return invoke


class RegistryTest(unittest.TestCase):
    """
    Tests for the Registry library.
    """

    def _check_image(self, name, registry, repo, ref="latest") -> None:
        """
        Test assertions an image name parse.
        """
        manifest_ref = parse_image_name(name)
        self.assertEqual(manifest_ref.registry, registry)
        self.assertEqual(manifest_ref.repo, repo)
        self.assertEqual(manifest_ref.ref, ref)

    def test_parse_image_ref_handling(self) -> None:
        """Test handling of refs"""
        # Test basic ref handling
        self._check_image(
            "ubuntu",
            None,
            ["library", "ubuntu"],
        )
        self._check_image(
            "docker.io/library/ubuntu",
            Registry(
                host="registry-1.docker.io",
                port=443,
                prot="https",
                host_alias="docker.io",
            ),
            ["library", "ubuntu"],
        )
        self._check_image(
            "ubuntu:18.04",
            None,
            ["library", "ubuntu"],
            ref="18.04",
        )
        self._check_image(
            "ubuntu@sha256:9b1702dcfe32c873a770a32cfd306dd7fc1c4fd134adfb783db68defc8894b3c",
            None,
            ["library", "ubuntu"],
            ref="sha256:9b1702dcfe32c873a770a32cfd306dd7fc1c4fd134adfb783db68defc8894b3c",
        )
        self._check_image(
            "cbir.clinc.ai/clinc/worker/gpu:v0.7.9",
            Registry(host="cbir.clinc.ai"),
            ["clinc", "worker", "gpu"],
            ref="v0.7.9",
        )

    def test_parse_image_localhost_handling(self) -> None:
        """Test handling of localhost hosted image names"""
        # localhost is special
        self._check_image(
            "localhost/msg",
            Registry(host="localhost", port=80, prot="http"),
            ["msg"],
        )
        self._check_image(
            "notahost/msg",
            None,
            ["notahost", "msg"],
        )
        self._check_image(
            "isa.host/msg",
            Registry(host="isa.host"),
            ["msg"],
        )

        # Test localhost/isahost with different explicit ports.
        self._check_image(
            "localhost:555/msg",
            Registry(
                host="localhost", port=555, prot="http", host_alias="localhost:555"
            ),
            ["msg"],
        )
        self._check_image(
            "isahost:555/msg",
            Registry(host="isahost", port=555, prot="https", host_alias="isahost:555"),
            ["msg"],
        )
        self._check_image(
            "localhost:443/msg",
            Registry(
                host="localhost", port=443, prot="https", host_alias="localhost:443"
            ),
            ["msg"],
        )
        self._check_image(
            "isahost:443/msg",
            Registry(host="isahost", port=443, prot="https", host_alias="isahost:443"),
            ["msg"],
        )
        self._check_image(
            "localhost:80/msg",
            Registry(host="localhost", port=80, prot="http", host_alias="localhost:80"),
            ["msg"],
        )
        self._check_image(
            "isahost:80/msg",
            Registry(host="isahost", port=80, prot="http", host_alias="isahost:80"),
            ["msg"],
        )

    def test_parse_image_explicit_protocol(self) -> None:
        """Test handling of localhost hosted image names"""
        # Explicit protocol
        self._check_image(
            "http://localhost/msg",
            Registry(
                host="localhost", port=80, prot="http", host_alias="http://localhost"
            ),
            ["msg"],
        )
        self._check_image(
            "http://isahost/msg",
            Registry(host="isahost", port=80, prot="http", host_alias="http://isahost"),
            ["msg"],
        )
        self._check_image(
            "https://localhost/msg",
            Registry(
                host="localhost", port=443, prot="https", host_alias="https://localhost"
            ),
            ["msg"],
        )
        self._check_image(
            "https://isahost/msg",
            Registry(
                host="isahost", port=443, prot="https", host_alias="https://isahost"
            ),
            ["msg"],
        )

        self._check_image(
            "myregistry:555/msg",
            Registry(
                host="myregistry", port=555, prot="https", host_alias="myregistry:555"
            ),
            ["msg"],
        )
        self._check_image(
            "localhost:443/msg",
            Registry(
                host="localhost", port=443, prot="https", host_alias="localhost:443"
            ),
            ["msg"],
        )

    def test_registry_str(self) -> None:
        """
        Test Registry's string representation
        """
        self.assertEqual(str(Registry(host="abc")), "abc")
        self.assertEqual(str(Registry(host="abc-123", host_alias="abc")), "abc")
        self.assertEqual(str(Registry(host="abc", port=80, prot="http")), "abc:80")
        self.assertEqual(
            str(Registry(host="abc", port=80, prot="https")), "https://abc:80"
        )
        self.assertEqual(
            str(Registry(host="abc", port=443, prot="http")), "http://abc:443"
        )
        self.assertEqual(str(Registry(host="abc", port=443, prot="https")), "abc")
        self.assertEqual(
            str(Registry(host="abc", port=555, prot="http")), "http://abc:555"
        )
        self.assertEqual(str(Registry(host="abc", port=555, prot="https")), "abc:555")

        self.assertEqual(str(Registry(host="localhost")), "localhost:443")
        self.assertEqual(
            str(Registry(host="localhost", port=80, prot="http")), "localhost"
        )
        self.assertEqual(
            str(Registry(host="localhost", port=80, prot="https")),
            "https://localhost:80",
        )
        self.assertEqual(
            str(Registry(host="localhost", port=443, prot="http")),
            "http://localhost:443",
        )
        self.assertEqual(
            str(Registry(host="localhost", port=443, prot="https")), "localhost:443"
        )
        self.assertEqual(
            str(Registry(host="localhost", port=555, prot="http")), "localhost:555"
        )
        self.assertEqual(
            str(Registry(host="localhost", port=555, prot="https")),
            "https://localhost:555",
        )

    @asyncio_run
    async def test_exists(self) -> None:
        """Test behavior of ManifestRef.exists()"""
        async with AsyncRegistryClient() as client:
            self.assertEqual(
                await client.ref_lookup(parse_image_name("msg555/ubuntu:_test_tag_")),
                Descriptor(
                    mediaType="application/vnd.docker.distribution.manifest.list.v2+json",
                    digest="sha256:d789606e6a1d43b506fc816023ab94f67117ca66488590e99e53369f61dd1477",
                    size=2035,
                ),
            )
            self.assertIsNone(
                await client.ref_lookup(parse_image_name("msg555/ubuntu:_fake_tag_"))
            )
            with self.assertRaises(RegistryException):
                await client.ref_lookup(
                    parse_image_name("fake.repo/msg555/ubuntu:_fake_tag_")
                )


if __name__ == "__main__":
    unittest.main()
