import os, json, sys
import logging
import pathlib
import re


from stix2 import (v21, parse)
from pathlib import Path

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink, TypeDBSource

loggers = [logging.getLogger()]  # get the root logger
loggers = loggers + [logging.getLogger(name) for name in logging.root.manager.loggerDict]

for l in loggers:
    if l.name.startswith('stix.module'):
        # you can change verbosity here if needed
        '''
        l.setLevel(logging.DEBUG)
        '''

format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s'
formatter = logging.Formatter(format)
logger = logging.getLogger(__name__)


stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

file_handler = logging.FileHandler('oasis_cert.log', mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stdout_handler)
profile_cache = {}


def verify_file(file_path, sink_db):
    with open(file_path, mode="r", encoding="utf-8") as file:

        check_list = []

        logger.info(f"Run check on file {file_path.name}")
        json_blob = json.load(file)

        if isinstance(json_blob, list):
            input_ids = set()
            for json_dict in json_blob:
                # stix_obj = parse(item)
                sink_db.add(json_dict)
                input_ids.add(json_dict['id'])
                '''
                return_dict = source_db.get(stix_obj.id)
                return_obj = parse(return_dict)
                cmp = StixComparator()
                check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                return check
                '''

            output_ids = sink_db.get_stix_ids()
            tot_insert = len(output_ids)
            input_list = ','.join(list(input_ids))
            output_list = ','.join(list(output_ids))
            logger.debug(f'File = {file_path.name} in {file_path.parent.name}')
            logger.debug(f'Input IDS = {input_list}')
            logger.debug(f'Output IDS = {output_list}')

            if input_ids == set(output_ids):
                check_list.append(True)
                logger.debug(f'Check STIX ID Passed')
            else:
                logger.debug(f'Check STIX ID Failed')
                check_list.append(False)
        else:
            bundle = parse(json_blob)
            input_ids = set()
            for stix_obj in bundle.objects:
                sink_db.add(stix_obj)
                stix_obj.add(stix_obj['id'])
                '''
                return_dict = self._typedbSource.get(stix_obj.id)
                return_obj = parse(return_dict)
                cmp = StixComparator()
                check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                logger.info(f'OK properties {p_ok}')
                logger.info(f'KO properties {p_not}')
                self.assertTrue(check)
                '''

            output_ids = sink_db.get_stix_ids()
            tot_insert = len(output_ids)
            input_list = ','.join(list(input_ids))
            output_list = ','.join(list(output_ids))
            logger.debug(f'File = {file_path.name} in {file_path.parent.name}')
            logger.debug(f'Input IDS = {input_list}')
            logger.debug(f'Output IDS = {output_list}')

            if input_ids == set(output_ids):
                check_list.append(True)
                logger.debug(f'Check STIX ID Passed')
            else:
                check_list.append(False)
                logger.debug(f'Check STIX ID Failed')

        return check_list


def verify_files(directory, sink_db, source_db):
    """ Load and verify the file

    Args:
        fullname (): folder path
    """
    path = Path(directory)
    check_list = []
    if path.is_dir():
        for file_path in path.iterdir():
            try:
                file_checks = verify_file(file_path, sink_db)
            except Exception as ins_e:
                logger.error(ins_e)
                sys.exit(1)

            try:
                # clean up the database for next test
                new_ids = sink_db.get_stix_ids()
                sink_db.delete(new_ids)
                check_list = check_list + file_checks
            except Exception as read_e:
                logger.error(read_e)
                sys.exit(1)

        return check_list
    else:
        logger.error(f'{directory} not a folder')





def run_profile(connection, short, profile):
    logger.info(f'Title {profile["title"]}')
    results = {}

    if 'level1' in profile:
        count = 0
        for level in profile['level1']:
            key = level['dir'] + level['sub_dir']
            if key in profile_cache:
                if level['sub_dir'] == 'consumer_test':
                    results[f'[{short}.C1]'] = profile_cache[key]
                elif level['sub_dir'] == 'producer_test':
                    results[f'[{short}.P1]'] = profile_cache[key]

                logger.info('Cache hit level 1')
                continue
            import_type = import_type_factory.get_attack_import()
            # let's reset the database for each level
            sink_db = TypeDBSink(connection=connection, clear=True, import_type=import_type)
            source_db = TypeDBSource(connection=connection, import_type=import_type)

            sub_dir= pathlib.Path(__file__).parents[2].joinpath('data', 'stix_cert_data', level['dir'], level['sub_dir'])
            assert os.path.exists(str(sub_dir))

            logger.info(f"Test folder {sub_dir.parent.name}/{sub_dir.name}")
            checks = verify_files(sub_dir, sink_db, source_db)

            if checks is None:
                logger.warning('No checks were run')
                continue
            else:
                count += 1

            if level['sub_dir'] == 'consumer_test':
                consumer_passed = all(checks)
                logger.info(f'Consumer Passed = {consumer_passed}')

                if consumer_passed:
                    results[f'[{short}.C1]'] = 'Passed'
                else:
                    results[f'[{short}.C1]'] = 'Failed'

                profile_cache[key] = results[f'[{short}.C1]']

            elif level['sub_dir'] == 'producer_test':
                producer_passed = all(checks)
                logger.info(f'Producer Passed = {producer_passed}')

                if producer_passed:
                    results[f'[{short}.P1]'] = 'Passed'
                else:
                    results[f'[{short}.P1]'] = 'Failed'

                profile_cache[key] = results[f'[{short}.P1]']

        logger.info(f'\tTotal level 1 checks {count}')

    if 'level2' in profile:
        count = 0
        for level in profile['level2']:
            key = level['dir'] + level['sub_dir']
            if key in profile_cache:
                if level['sub_dir'] == 'consumer_test':
                    results[f'[{short}.C2]'] = profile_cache[key]
                elif level['sub_dir'] == 'producer_test':
                    results[f'[{short}.P2]'] = profile_cache[key]

                logger.info('Cache hit level 2')
                continue

            import_type = import_type_factory.get_attack_import()
            # let's reset the database for each level
            sink_db = TypeDBSink(connection=connection, clear=True, import_type=import_type)
            source_db = TypeDBSource(connection=connection, import_type=import_type)

            sub_dir = pathlib.Path(__file__).parents[2].joinpath('data', 'stix_cert_data', level['dir'],
                                                                 level['sub_dir'])
            assert os.path.exists(str(sub_dir))

            logger.info(f"Test folder {sub_dir.parent.name}/{sub_dir.name}")
            checks = verify_files(sub_dir, sink_db, source_db)

            if checks is None:
                logger.warning('No checks were run')
                continue
            else:
                count += 1

            if level['sub_dir'] == 'consumer_test':
                consumer_passed = all(checks)
                logger.info(f'Consumer Passed = {consumer_passed}')

                if consumer_passed:
                    results[f'[{short}.C2]'] = 'Passed'
                else:
                    results[f'[{short}.C2]'] = 'Failed'

                profile_cache[key] = results[f'[{short}.C2]']

            elif level['sub_dir'] == 'producer_test':
                producer_passed = all(checks)
                logger.info(f'Producer Passed = {producer_passed}')

                if producer_passed:
                    results[f'[{short}.P2]'] = 'Passed'
                else:
                    results[f'[{short}.P2]'] = 'Failed'

                profile_cache[key] = results[f'[{short}.P2]']

        logger.info(f'\tTotal level 2 checks {count}')

    return results
