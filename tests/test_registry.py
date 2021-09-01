"""
Tests for the Registry library.
"""
import itertools
import unittest

import requests

from pyregistry.registry import (
    Registry,
    chunk_streamer,
    parse_image_name,
    parse_user,
)


class RegistryTest(unittest.TestCase):
    """
    Tests for the Registry library.
    """

    def test_parse_user(self) -> None:
        """Test parse_user"""
        self.assertIs(parse_user(""), None)
        self.assertEqual(parse_user("msg"), ("msg", ""))
        self.assertEqual(parse_user("msg:pwd"), ("msg", "pwd"))
        self.assertEqual(parse_user("msg:pwd:moo"), ("msg", "pwd:moo"))
        self.assertEqual(parse_user("msg user:pwd moo"), ("msg user", "pwd moo"))

    def _check_image(
        self, name, host, repo, ref="latest", port=443, is_https=True, host_alias=None
    ) -> None:
        """
        Test assertions an image name parse.
        """
        host_alias = host_alias or host + ":" + str(port)
        manifest_ref = parse_image_name(name)
        self.assertEqual(manifest_ref.registry.host, host)
        self.assertEqual(manifest_ref.registry.port, port)
        self.assertEqual(manifest_ref.registry.is_https, is_https)
        self.assertEqual(manifest_ref.registry.host_alias, host_alias)
        self.assertEqual(manifest_ref.repo, repo)
        self.assertEqual(manifest_ref.ref, ref)

    def test_parse_image_ref_handling(self) -> None:
        """Test handling of refs"""
        # Test basic ref handling
        self._check_image(
            "ubuntu",
            "registry-1.docker.io",
            ["library", "ubuntu"],
            host_alias="docker.io",
        )
        self._check_image(
            "ubuntu:18.04",
            "registry-1.docker.io",
            ["library", "ubuntu"],
            ref="18.04",
            host_alias="docker.io",
        )
        self._check_image(
            "ubuntu@sha256:9b1702dcfe32c873a770a32cfd"
            "306dd7fc1c4fd134adfb783db68defc8894b3c",
            "registry-1.docker.io",
            ["library", "ubuntu"],
            ref="sha256:9b1702dcfe32c873a770a32cfd"
            "306dd7fc1c4fd134adfb783db68defc8894b3c",
            host_alias="docker.io",
        )
        self._check_image(
            "cbir.clinc.ai/clinc/worker/gpu:v0.7.9",
            "cbir.clinc.ai",
            ["clinc", "worker", "gpu"],
            port=443,
            ref="v0.7.9",
            host_alias="cbir.clinc.ai",
        )

    def test_parse_image_localhost_handling(self) -> None:
        """Test handling of localhost hosted image names"""
        # localhost is special
        self._check_image(
            "localhost/msg",
            "localhost",
            ["msg"],
            port=80,
            is_https=False,
            host_alias="localhost",
        )
        self._check_image(
            "notahost/msg",
            "registry-1.docker.io",
            ["notahost", "msg"],
            host_alias="docker.io",
        )
        self._check_image("isa.host/msg", "isa.host", ["msg"], host_alias="isa.host")

        # Test localhost/isahost with different explicit ports.
        self._check_image(
            "localhost:555/msg",
            "localhost",
            ["msg"],
            port=555,
            is_https=False,
            host_alias="localhost:555",
        )
        self._check_image(
            "isahost:555/msg",
            "isahost",
            ["msg"],
            port=555,
            is_https=True,
            host_alias="isahost:555",
        )
        self._check_image(
            "localhost:443/msg",
            "localhost",
            ["msg"],
            port=443,
            is_https=True,
            host_alias="localhost:443",
        )
        self._check_image(
            "isahost:443/msg",
            "isahost",
            ["msg"],
            port=443,
            is_https=True,
            host_alias="isahost:443",
        )
        self._check_image(
            "localhost:80/msg",
            "localhost",
            ["msg"],
            port=80,
            is_https=False,
            host_alias="localhost:80",
        )
        self._check_image(
            "isahost:80/msg",
            "isahost",
            ["msg"],
            port=80,
            is_https=False,
            host_alias="isahost:80",
        )

    def test_parse_image_explicit_protocol(self) -> None:
        """Test handling of localhost hosted image names"""
        # Explicit protocol
        self._check_image(
            "http://localhost/msg",
            "localhost",
            ["msg"],
            port=80,
            is_https=False,
            host_alias="http://localhost",
        )
        self._check_image(
            "http://isahost/msg",
            "isahost",
            ["msg"],
            port=80,
            is_https=False,
            host_alias="http://isahost",
        )
        self._check_image(
            "https://localhost/msg",
            "localhost",
            ["msg"],
            port=443,
            is_https=True,
            host_alias="https://localhost",
        )
        self._check_image(
            "https://isahost/msg",
            "isahost",
            ["msg"],
            port=443,
            is_https=True,
            host_alias="https://isahost",
        )

        self._check_image(
            "myregistry:555/msg",
            "myregistry",
            ["msg"],
            port=555,
            is_https=True,
            host_alias="myregistry:555",
        )
        self._check_image(
            "localhost:443/msg",
            "localhost",
            ["msg"],
            port=443,
            is_https=True,
            host_alias="localhost:443",
        )

    def _test_copy_pairs(self) -> None:
        """Test copy pairs"""
        # Note this test actually queries docker.io for manifest data. It does
        # not download any layer data nor write any data.
        expected_shas = (
            "4c108a37151f54439950335c409802e948883e00c93fdb751d206c9a9674c1f6",
            "5b7339215d1d5f8e68622d584a224f60339f5bef41dbd74330d081e912f0cddd",
            "14ca88e9f6723ce82bc14b241cda8634f6d19677184691d086662641ab96fe68",
            "a31c3b1caad473a474d574283741f880e37c708cc06ee620d3e93fa602125ee0",
            "b054a26005b7f3b032577f811421fab5ec3b42ce45a4012dfa00cf6ed6191b0f",
            "eb70667a801686f914408558660da753cde27192cd036148e58258819b927395",
            "e37fc27e0a1c7033d1d6725b271b9fd6de1286028cab7c0e3bdbf4411aa8b1e7",
            "890bdf70a444971b59240478f3073e23d165e3ba40106d3d4e94a57e52f9f715",
            "d7984ec58db25dba3b1eb769446c440c608e2a35869a13b6a57ba069134f28e1",
            "69dd89700a6c256d7ddae21c28adf3ded21abb73838795b0a1a5c3b12556da0b",
            "0af11110095b961ce4addaca6fbf8afe199d233b510f48cdd196b4c0b4029576",
            "09a066942d6dc6b5d9f88c707f1197748cb620bd0b322484ed327253cab2ac1a",
            "3c1de3d39dd66d71ef688133f7ffc8b4757ed9f8383adf7dc0c84b547ef7bd85",
            "85df13e07ac866f0749412605b4d04aef859d2d116979e1dad9da5093585ce3c",
            "8627bf1c6512dd26e72f564465b94d24232e3221dc649211b6c2169cd9bae0f7",
            "c99ec04f469874c69bd01d057f54593e5346d90cfba712152008d76624217ddb",
            "dbc2e75663b5f54850089251d728dea5cb0b29b1e95e1bc0785c801bd2dc3092",
            "fcf80b2fae669da66e29b272d768451f7d2b1641c26a250b7adf83bf0dafb452",
            "cf5ff47c2b80aec3ebd29b66a23fe67c95ef99fa1e6371f7044638b61e3dac83",
            "3245b5a2a588d6e4eef6ef141d6a38071aa4d1617100cc2feace80b721e75274",
            "d0d75e9a49d317af603cf3ed3fd0ac05c131074504b43af468073d51021f9bcd",
            "3f40a38fc4ff69c71a6542dfb6acbdf6e5e3be25f0f94659ee85f2e120e37d82",
            "fe0423e7d050e37d4651190300ea074bd25a8ac7977ab897205fd1df44889605",
            "30fe694bccc16b8d61c21f92ebc24065ef3ff7e87a8891eb9a7d3657fe1f3d94",
            "4dc4a19dc1271abc8daffce96513470c1cb3a909784bdc92f838bd4ffb6f92ac",
            "ef5b5b197566d2f3081c54f8e5ce315ef1bb409a622708e21f26f8a316324dc9",
            "5fb5943989879ea71f39058451b18a9cfe7c8d63d5e98bea0f8ce8398b662cfd",
            "03367c790f847a4fb9da497ba924c531b08ed840ced5ddebd576b1e617fdeabc",
            "7a0dfc04432356cee71730dc1476c35948bcaa233371a0bee11cf8be333b28da",
            "b11b1467edefe08a02b4eb3799cb7df8f19a25f0b2da2ef837b993ad2c750c3c",
            "7ebc7802c8d928c19cc7c3ea9a2f1e3e582ae8100aa515c74ec5dbe432ab3ad0",
            "3e0ab3b7390d02875ba6655704ba528f120405db6e19a6c8014bacd27a2a2b07",
            "8641916778260cb4957d491680516450d36f7590247405e9657afbd7ab582a71",
            "c9dae6e8c4d6bcdbd01ec8e9e91d209bc0d0fb0e392fdb4ef5075d1e322fd3ac",
            "756f46ae05c783e37b80e6d459322ed9643102a8da1ca620233c21a601cce8e4",
            "2250c49a818ed4162862b23d6c7e470e64d6a83d68a38615c1666126bd42993c",
            "d789606e6a1d43b506fc816023ab94f67117ca66488590e99e53369f61dd1477",
        )

        manifest_ref = parse_image_name("msg555/ubuntu:_test_tag_")

        test_registry = Registry("myregistry")
        copy_pairs = list(
            manifest_ref.get_copy_pairs(test_registry, ["test_repo"], ref="dest_tag")
        )

        # Make sure all src/dst have the right registry and repo.
        for copy_pair in copy_pairs:
            self.assertIs(copy_pair.src.registry, manifest_ref.registry)
            self.assertIs(copy_pair.dst.registry, test_registry)
            self.assertEqual(copy_pair.src.repo, ["msg555", "ubuntu"])
            self.assertEqual(copy_pair.dst.repo, ["test_repo"])

        # Make sure we got all the digests we expected.
        self.assertCountEqual(
            (copy_pair.src.digest()[7:] for copy_pair in copy_pairs), expected_shas
        )

        # Make sure all the dest refs match the source digest.
        manifest_pair = copy_pairs.pop()
        for copy_pair in copy_pairs:
            self.assertEqual(copy_pair.src.ref, copy_pair.src.digest())
            self.assertEqual(copy_pair.dst.ref, copy_pair.src.digest())

        # Make sure the source and dest manifest ref matches.
        self.assertEqual(manifest_pair.src.ref, "_test_tag_")
        self.assertEqual(manifest_pair.dst.ref, "dest_tag")

    def test_chunk_streamer(self) -> None:
        """Test the chunk_streamer implementation"""

        def _test(seq, chunk_size, expected):
            """
            Test that chunk_streamer breaks up 'seq' into 'expected' chunks.
            """
            for gen, exp in zip(chunk_streamer(seq, chunk_size), expected):
                self.assertSequenceEqual(list(itertools.chain(*gen)), exp)

        _test("0123456789", 2, ["01", "23", "45", "67", "89"])
        _test("0123456789", 3, ["012", "345", "678", "9"])
        _test("", 3, [])
        _test("ab", 3, ["ab"])
        _test("01234", 1, ["0", "1", "2", "3", "4"])
        _test(
            (range(29997), range(29997, 100000)),
            1000,
            [range(s, s + 1000) for s in range(0, 100000, 1000)],
        )

    def test_exists(self) -> None:
        """Test behavior of ManifestRef.exists()"""
        self.assertEqual(parse_image_name("msg555/ubuntu:_test_tag_").exists(), True)
        self.assertEqual(parse_image_name("msg555/ubuntu:_fake_tag_").exists(), False)
        self.assertRaises(
            requests.exceptions.RequestException,
            parse_image_name("fake.repo/msg555/ubuntu:_fake_tag_").exists,
        )


if __name__ == "__main__":
    unittest.main()
