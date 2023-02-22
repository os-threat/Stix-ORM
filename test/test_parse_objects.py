import logging
import unittest

from stix2.v20 import Identity

from stix.module.authorise import import_type_factory
from stix.module.parsing.parse_objects import dict_to_stix2


class TestParseObject(unittest.TestCase):


    def test_dict_to_stix(self):

        import_type = import_type_factory.get_default_import()

        stix_dict = {'type': 'identity',
                     'spec_version': '2.1',
                     'id': 'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff',
                     'created': '2015-05-10T16:27:17.760Z',
                     'modified': '2015-05-10T16:27:17.760Z',
                     'name': 'Adversary Bravo',
                     'description': 'Adversary Bravo is a threat actor that utilizes phishing attacks.',
                     'identity_class': 'unknown'}

        result = dict_to_stix2(stix_dict,
                      allow_custom=False,
                      import_type=import_type)

        assert result._inner['type'] == 'identity'
        assert result._inner['spec_version'] == '2.1'
        assert result._inner['id'] == 'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff'
        assert result._inner['description'] == 'Adversary Bravo is a threat actor that utilizes phishing attacks.'
        assert result._inner['identity_class'] == 'unknown'

    def test_dict_to_stix_2(self):

        import_type = import_type_factory.get_default_import()
        obj = {'type': 'relationship', 'spec_version': '2.1', 'id': 'relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad', 'created_by_ref': 'identity--e5f1b90a-d9b6-40ab-81a9-8a29df4b6b65', 'created': '2016-04-06T20:06:37.000Z', 'modified': '2016-04-06T20:06:37.000Z', 'relationship_type': 'indicates', 'source_ref': 'indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f', 'target_ref': 'malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b'}
        result = dict_to_stix2(obj,
                               allow_custom=False,
                               import_type=import_type)

        assert result._inner['type'] == 'relationship'
        assert result._inner['spec_version'] == '2.1'
        assert result._inner['id'] == 'relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad'



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()
