# -*- coding: utf-8 -*-

import os,json,sys
import logging
import re
from stix.module.typedb_lib import TypeDBSink, TypeDBSource
from dbconfig import connection
from stix2 import (v21, parse)
from pathlib import Path

loggers = [logging.getLogger()]  # get the root logger
loggers = loggers + [logging.getLogger(name) for name in logging.root.manager.loggerDict]

for l in loggers:
    if l.name.startswith('stix.module'):
        # you can change verbosity here if needed
        '''
        l.setLevel(logging.DEBUG)
        '''

format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s'
formatter = logging.Formatter(format )
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

file_handler = logging.FileHandler('oasis_cert.log',mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stdout_handler)

def load_personas(file_path='./data/stix_cert_data/stix_cert_persona_dict.json'):
    logger.info(f'Loading file {file_path}')
    with open(file_path, mode="r", encoding="utf-8") as file:
        d = json.load(file)
        logger.info(f"Loaded {len(d.keys())} profiles")
        return d


def load_template(file_path='./oasis/cert_template.txt'):
    logger.info(f'Loading file {file_path}')
    with open(file_path, mode="r", encoding="utf-8") as file:
        t = file.read()
        m = re.findall(r"\[[a-z0-9\.]+\]", t,re.IGNORECASE|re.MULTILINE)

        logger.info(f"Loaded {len(m)} profiles")
        return t,m


def run_profiles(config:dict,template,tags,out_file):
    report = template

    for profile in config.keys():
        # let's reset the database for each profile
        sink_db = TypeDBSink(connection=connection, clear=True, import_type="STIX21")
        # get all the initial STIX IDs (only markings should be there)
        base_ids = sink_db.get_stix_ids()
        # markings should be automatically ignored
        assert len(base_ids) == 0

        logger.info(f'Checking profile {profile}')
        result = run_profile(profile,config[profile])
        logger.info(result)

        for code in result.keys():
            if code in tags:
                logger.info(f'Asserting flag {code}')
                report = report.replace(code,result[code])
    # now write the report
    with open(out_file,'w') as file:
        file.write(report)


def verify_file(file_path,sink_db):
    with open(file_path, mode="r", encoding="utf-8") as file:

        check_list = []

        logger.info(f"Run check on file {file_path.name}")
        json_blob = json.load(file)

        if isinstance(json_blob, list):
            input_ids = set()
            for json_dict in json_blob:
                #stix_obj = parse(item)
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
                stix_obj.add(stix_obj ['id'])
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

def verify_files(directory,sink_db,source_db):
    """ Load and verify the file

    Args:
        fullname (): folder path
    """
    path = Path(directory)
    check_list = []
    if path.is_dir():
        for file_path in path.iterdir():
            try:
                file_checks = verify_file(file_path,sink_db)
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

# contains a cache as most test are repeated between levels
profile_cache = {}

def run_profile(short,profile):
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

            # let's reset the database for each level
            sink_db = TypeDBSink(connection=connection, clear=True, import_type="STIX21")
            source_db = TypeDBSource(connection=connection, import_type="STIX21")

            sub_dir = Path.cwd()/'data'/'stix_cert_data'/level['dir']/level['sub_dir']
            logger.info(f"Test folder {sub_dir.parent.name}/{sub_dir.name}")
            checks = verify_files(sub_dir,sink_db,source_db)

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

            # let's reset the database for each level
            sink_db = TypeDBSink(connection=connection, clear=True, import_type="STIX21")

            sub_dir = Path.cwd()/'data'/'stix_cert_data'/level['dir']/level['sub_dir']
            logger.info(f"Test folder {sub_dir.parent.name}/{sub_dir.name}")
            checks = verify_files(sub_dir,sink_db,source_db)

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

def sanity_check(path:Path):
    quotes = ['\u201c', '\u201d']
    p = path.glob('**/*.json')
    files = [x for x in p if x.is_file()]
    logger.info('Checking %d files' % len(files))
    json_fails = []
    stix_fails = []
    quote_fails = []
    for file_path in files:
        #print(file_path)
        with open(file_path, mode="r", encoding="utf-8") as file:
            content = file.read()
            checks = [True for c in quotes if c in content]
            if any(checks): quote_fails.append(file_path)

        if file_path.name!='stix_cert_persona_dict.json':
            with open(file_path, mode="r", encoding="utf-8") as file:
                try:
                    json_blob = json.load(file)
                except Exception as e:
                    json_fails.append((file_path,str(e)))
                    continue

                try:
                    if isinstance(json_blob, list):
                        for json_dict in json_blob:
                            stix_obj = parse(json_dict)
                    elif isinstance(json_blob, dict):
                        stix_obj = parse(json_dict)
                    else:
                        logger.error(f'Error on json type {type(json_blob)}')
                except Exception as e:
                    stix_fails.append((file_path,str(e)))
                    continue

    logger.error(f'Files with unicode quotes =  {len(quote_fails)}')
    logger.error(f'Files with broken json = {len(json_fails)}')
    logger.error(f'Files with broken stix = {len(stix_fails)}')



if __name__ == '__main__':
    cwd = Path.cwd()

    logger.info(f'Running tests in {cwd}')
    tests = load_personas(file_path=Path.joinpath(cwd,'data','stix_cert_data','stix_cert_persona_dict.json'))
    logger.info(f'Running sanity checks in {cwd}')
    sanity_check(path=Path.joinpath(cwd,'data','stix_cert_data'))
    template,tags = load_template(file_path=Path.joinpath(cwd,'oasis','cert_template.txt'))
    logger.info(f"Profiles: {list(tests.keys())}")
    run_profiles(tests,template,tags,out_file=Path.joinpath(cwd,'oasis','report.txt'))
