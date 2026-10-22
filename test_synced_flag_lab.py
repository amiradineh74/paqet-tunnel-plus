import unittest
from synced_flag_lab import PROFILES, set_flags, add_probe, WINDOW_SEC, STABILITY_WINDOW_SEC, PROBE_OFFSET, PROBE_COUNT, PROBE_EVERY

CFG='''role: "client"\nforward:\n  - listen: ":2053"\n    target: "91.107.145.169:2053"\n    protocol: "tcp"\nnetwork:\n  tcp:\n    local_flag: ["S"]\n    remote_flag: ["PA"]\ntransport:\n  kcp:\n    key: "DUMMY_KEY"\n'''

class FlagLabTests(unittest.TestCase):
    def test_all_profiles_change_only_two_flags(self):
        for name,cl,cr,sl,sr in PROFILES:
            changed=set_flags(CFG,cl,cr)
            self.assertIn(f'local_flag: ["{cl}"]',changed)
            self.assertIn(f'remote_flag: ["{cr}"]',changed)
            self.assertEqual(set_flags(changed,'S','PA'),CFG)
    def test_loopback_probe_preserves_existing_forward(self):
        changed=add_probe(CFG,39871,'91.107.145.169',22)
        self.assertIn('listen: "127.0.0.1:39871"',changed)
        self.assertIn('target: "91.107.145.169:22"',changed)
        self.assertIn('listen: ":2053"',changed)
        self.assertEqual(changed.count('forward:'),1)
    def test_creates_forward_if_absent(self):
        txt=CFG.replace('forward:\n  - listen: ":2053"\n    target: "91.107.145.169:2053"\n    protocol: "tcp"\n','')
        self.assertIn('forward:\n  - listen:',add_probe(txt,39871,'91.107.145.169',22))
    def test_refuses_duplicate_flags(self):
        with self.assertRaises(ValueError):
            set_flags(CFG+'    local_flag: ["S"]\n','PA','PA')
    def test_rejects_invalid_probe(self):
        with self.assertRaises(ValueError):
            add_probe(CFG,22,'91.107.145.169',22)
    def test_time_windows(self):
        self.assertGreater(WINDOW_SEC,PROBE_OFFSET+(PROBE_COUNT-1)*PROBE_EVERY+4)
        self.assertGreater(STABILITY_WINDOW_SEC,PROBE_OFFSET+39*7+4)

if __name__=='__main__':
    unittest.main()
