import unittest
from mcp_server.tools.cvss_scorer import get_cvss_scores

class TestCVSSScorer(unittest.TestCase):
    def test_v3_vector(self):
        vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        result = get_cvss_scores(vector)
        self.assertIn('base_score', result)
        self.assertEqual(result['base_score'], 9.8)
        self.assertEqual(result['severity'], 'Critical')

    def test_v2_vector(self):
        vector = 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'
        result = get_cvss_scores(vector)
        self.assertIn('base_score', result)
        self.assertEqual(result['base_score'], 7.5)

    def test_invalid_vector(self):
        vector = 'INVALID_VECTOR'
        result = get_cvss_scores(vector)
        self.assertIn('error', result)

if __name__ == '__main__':
    unittest.main()
