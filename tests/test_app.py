import unittest
from unittest.mock import patch
from app import analyze

class TestCORS(unittest.TestCase):
    @patch('security_utils.assert_public_resolution')
    def test_rejects_missing_origin(self, _resolve):
        self.assertIn('error', analyze({'url':'https://example.com','origin':''}))

if __name__ == '__main__': unittest.main()
