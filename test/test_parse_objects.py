import logging
import unittest

from stix2.v20 import Identity

from stix.module.parsing.parse_objects import dict_to_stix2


class TestParseObject(unittest.TestCase):


    def test_dict_to_stix(self):

        expected = {'type': 'identity', 'spec_version': '2.1', 'id': 'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff', 'created': '2015-05-10T16:27:17.760Z', 'modified': '2015-05-10T16:27:17.760Z', 'name': 'Adversary Bravo', 'description': 'Adversary Bravo is a threat actor that utilizes phishing attacks.', 'identity_class': 'unknown', 'revoked': False}
        import_type = {'STIX21': True,
                       'CVE': False,
                       'identity': False,
                       'location': False,
                       'rules': False,
                       'ATT&CK': False,
                        'ATT&CK_Versions': ['12.0'],
                       'ATT&CK_Domains': ['enterprise-attack', 'mobile-attack', 'ics-attack'],
                        'CACAO': False}

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



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        filename="test.log")
    loader = unittest.TestLoader()
    unittest.main()
