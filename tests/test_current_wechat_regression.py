import unittest
from pathlib import Path

from wechat_offset_generator.macho import MachOImage
from wechat_offset_generator.recognizers import (
    recognize_resource_cache_policy,
    recognize_scene_hook,
)


ROOT = Path(__file__).resolve().parents[1]


class CurrentWeChatRegressionTests(unittest.TestCase):
    def test_arm64_offsets_are_recognized(self):
        image = MachOImage.from_path(ROOT / "WeChatAppEx Framework.arm64")

        scene = recognize_scene_hook(image)
        cache = recognize_resource_cache_policy(image)

        self.assertEqual(scene.address, 0x8DD44B4)
        self.assertEqual(scene.struct_offset, 0x5A0)
        self.assertEqual(scene.scene_offset, 0x1C8)
        self.assertEqual(cache.address, 0x3697418)
        self.assertEqual(cache.confidence, "high")

    def test_x64_resource_cache_policy_is_recognized(self):
        image = MachOImage.from_path(ROOT / "WeChatAppEx Framework.x86_64")

        cache = recognize_resource_cache_policy(image)

        self.assertEqual(cache.address, 0x3E78770)
        self.assertEqual(cache.confidence, "high")


if __name__ == "__main__":
    unittest.main()
