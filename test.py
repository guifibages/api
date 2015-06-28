import unittest
import api

tests = [
    dict(text="""PING 10.228.44.1 (10.228.44.1): 56 data bytes
64 bytes from 10.228.44.1: icmp_seq=0 ttl=63 time=0.843 ms
64 bytes from 10.228.44.1: icmp_seq=1 ttl=63 time=0.424 ms
--- 10.228.44.1 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.424/0.633/0.843/0.210 ms""",
         parsed=dict(packets='2', received='2', loss="0%")),
    dict(text="""PING 10.228.44.1 (10.228.44.1): 56 data bytes
64 bytes from 10.228.44.1: icmp_seq=0 ttl=63 time=0.843 ms
64 bytes from 10.228.44.1: icmp_seq=1 ttl=63 time=0.424 ms
--- 10.228.44.1 ping statistics ---
2 packets transmitted, 1 packets received, 50% packet loss
round-trip min/avg/max/stddev = 0.424/0.633/0.843/0.210 ms""",
         parsed=dict(packets='2', received='1', loss="50%")),
    dict(text="""PING 10.228.44.111 (10.228.44.111): 56 data bytes
92 bytes from 10.228.44.99: Destination Host Unreachable
92 bytes from 10.228.44.99: Destination Host Unreachable
--- 10.228.44.111 ping statistics ---
2 packets transmitted, 0 packets received, 100% packet loss""",
         parsed=dict(packets='2', received='0', loss="100%"))]


class ParsePing(unittest.TestCase):
    def doTest(self, i):
        parsed = api.parse_ping(tests[i]['text'])
        self.assertIsInstance(parsed, dict)
        for k in parsed.keys():
            self.assertEqual(parsed[k], tests[i]['parsed'][k])

    def test_0(self):
        self.doTest(0)

    def test_50(self):
        self.doTest(1)

    def test_100(self):
        self.doTest(2)


if __name__ == '__main__':
    unittest.main()
