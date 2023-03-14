from stix2patterns.validator import run_validator
from stix2patterns.v21.pattern import Pattern
from dendrol import Pattern as TreePattern
import unittest

class TestDatabase(unittest.TestCase):

    def test_validator(self):

        pattern = "[file-object:hashes.md5 = '79054025255fb1a26e4bc422aef54eb4']"
        ok = run_validator(pattern)

    def test_qualifiers(self):
        examples = [
            (u"[foo:bar = 1]", set()),
            (u"[foo:bar = 1] REPEATS 5 TIMES", set([u"REPEATS 5 TIMES"])),
            (u"[foo:bar = 1] WITHIN 10.3 SECONDS", set([u"WITHIN 10.3 SECONDS"])),
            (u"[foo:bar = 1] WITHIN 123 SECONDS", set([u"WITHIN 123 SECONDS"])),
            (u"[foo:bar = 1] START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'",
             set([u"START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'"])),
            (u"[foo:bar = 1] REPEATS 1 TIMES AND [foo:baz = 2] WITHIN 1.23 SECONDS",
             set([u"REPEATS 1 TIMES", u"WITHIN 1.23 SECONDS"])),
            (
            u"([foo:bar = 1] START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z' AND [foo:abc < h'12ab']) WITHIN 22 SECONDS "
            u"OR [frob:baz NOT IN (1,2,3)] REPEATS 31 TIMES",
            set([u"START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'",
                 u"WITHIN 22 SECONDS", u"REPEATS 31 TIMES"]))
        ]

        for example in examples:
            pattern = example[0]
            expected_qualifiers = example[1]
            compiled_pattern = Pattern(pattern)
            pattern_data = compiled_pattern.inspect()
            self.assertEqual(pattern_data.qualifiers,expected_qualifiers)

    def test_observation_operations(self):
        '''
        Each example provides: on the left the pattern string and on the right the list of logical operators
        Returns:

        '''
        examples = [
            (u"[foo:bar = 1]", set()),
            (u"[foo:bar = 1] AND [foo:baz > 25.2]", set([u"AND"])),
            (u"[foo:bar = 1] OR [foo:baz != 'hello']", set([u"OR"])),
            (u"[foo:bar = 1] FOLLOWEDBY [foo:baz IN (1,2,3)]", set([u"FOLLOWEDBY"])),
            (u"[foo:bar = 1] AND [foo:baz = 22] OR [foo:abc = '123']", set([u"AND", u"OR"])),
            (u"[foo:bar = 1] OR ([foo:baz = false] FOLLOWEDBY [frob:abc LIKE '123']) WITHIN 46.1 SECONDS",
             set([u"OR", u"FOLLOWEDBY"]))
        ]

        for example in examples:
            pattern = example[0]
            expected_obs_ops = example[1]
            compiled_pattern = Pattern(pattern)
            pattern_data = compiled_pattern.inspect()
            self.assertEqual(pattern_data.observation_ops,expected_obs_ops)

    def test_dict_tree(self):
        pattern = TreePattern("[domain-name:value = 'http://xyz.com/download']")

        print(pattern.print_dict_tree())
