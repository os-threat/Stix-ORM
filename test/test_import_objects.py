
import logging
import unittest

from stix2.v20 import Identity

from stix.module.parsing.parse_objects import dict_to_stix


class TestParseObject(unittest.TestCase):


    def test_sco_to_data(self):
        pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()