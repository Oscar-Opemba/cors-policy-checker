import unittest
from app import analyze

class TestCORS(unittest.TestCase):
    def test_rejects_missing_origin(self):
        self.assertIn('error', analyze({'url':'https://example.com','origin':''}))

if __name__ == '__main__': unittest.main()
