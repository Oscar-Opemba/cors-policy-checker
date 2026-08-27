import unittest
from unittest.mock import patch
from app import analyze

class TestCORSEdgeCases(unittest.TestCase):
    @patch('security_utils.assert_public_resolution')
    def test_rejects_credential_bearing_origin(self, _resolve):
        result = analyze({'url':'https://example.com/api','origin':'https://user:pass@example.net'})
        self.assertIn('error', result)

if __name__ == '__main__': unittest.main()
