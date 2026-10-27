import unittest
from simulator.geography import distance_m, within_range


class GeographyTests(unittest.TestCase):
    def test_euclidean_distance(self):
        self.assertAlmostEqual(distance_m({"x": 0, "y": 0}, {"x": 3, "y": 4}), 5.0)

    def test_exact_range_is_included(self):
        self.assertTrue(within_range({"x": 0, "y": 0}, {"x": 300, "y": 400}, 500))

    def test_outside_range_is_excluded(self):
        self.assertFalse(within_range({"x": 0, "y": 0}, {"x": 501, "y": 0}, 500))

    def test_negative_range_rejected(self):
        with self.assertRaises(ValueError):
            within_range({"x": 0, "y": 0}, {"x": 1, "y": 0}, -1)


if __name__ == "__main__":
    unittest.main()
