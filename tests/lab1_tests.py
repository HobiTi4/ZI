import unittest
from unittest.mock import patch, mock_open, MagicMock
import math

# Import functions from the business logic module
from labs.lab1 import LCG, calculate_period, cesaro_test, run_lab1_algorithm


class TestLab1Logic(unittest.TestCase):

    def test_lcg_generation_variant_1(self):
        lcg = LCG(m=1023, a=32, c=0, x0=2)
        self.assertEqual(lcg.next(), 64)
        self.assertEqual(lcg.next(), 2)
        self.assertEqual(lcg.next(), 64)
        self.assertEqual(lcg.next(), 2)

    def test_calculate_period(self):

        period_v1 = calculate_period(m=1023, a=32, c=0, x0=2)
        self.assertEqual(period_v1, 2)

    def test_cesaro_test_zero_coprime(self):
        mock_gen = MagicMock(side_effect=[64, 2, 64, 2, 64, 2])

        pi_result = cesaro_test(mock_gen, 3)

        self.assertEqual(pi_result, 0)

    def test_cesaro_test_perfect_coprime(self):

        mock_gen = MagicMock(side_effect=[3, 5, 7, 11])
        pi_result = cesaro_test(mock_gen, 2)

        self.assertAlmostEqual(pi_result, math.sqrt(6), places=3)


if __name__ == "__main__":
    unittest.main()