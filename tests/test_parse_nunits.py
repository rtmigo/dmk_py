import unittest

from dmk._main import parse_n_units


class TastParseN(unittest.TestCase):
    def test(self):
        self.assertEqual(parse_n_units("10"), 10)
        self.assertEqual(parse_n_units("10K"), 10240)
        self.assertEqual(parse_n_units("10k"), 10240)
        self.assertEqual(parse_n_units("10M"), 10485760)

    def test_errors(self):
        with self.assertRaises(ValueError):
            parse_n_units("")
        with self.assertRaises(ValueError):
            parse_n_units("  ")
        with self.assertRaises(ValueError):
            parse_n_units("anything")
        with self.assertRaises(ValueError):
            parse_n_units("123x")

if __name__ == "__main__":
    unittest.main()