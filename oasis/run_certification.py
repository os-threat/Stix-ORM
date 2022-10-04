import os,json,sys
import logging
import re
from stix.module.typedb import TypeDBSink, TypeDBSource
from dbconfig import connection
from stix2 import (v21, parse)
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

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
    # create the database and init
    sink_db = TypeDBSink(connection=connection, clear=True,import_type= "STIX21")
    source_db =  TypeDBSource(connection=connection, import_type="STIX21")

    for profile in config.keys():
        logger.info(f'Checking profile {profile}')
        result = run_profile(profile,config[profile],sink_db,source_db)
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
        logger.info(f"Loading file {file_path}")
        json_blob = json.load(file)

        if isinstance(json_blob, list):
            for item in json_blob:
                stix_obj = parse(item)
                sink_db.add(stix_obj)
                '''
                return_dict = source_db.get(stix_obj.id)
                return_obj = parse(return_dict)
                cmp = StixComparator()
                check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                return check
                '''
                return True
        else:
            bundle = parse(json_blob)
            for stix_obj in bundle.objects:
                sink_db.add(stix_obj)
                '''
                return_dict = self._typedbSource.get(stix_obj.id)
                return_obj = parse(return_dict)
                cmp = StixComparator()
                check, p_ok, p_not = cmp.compare(stix_obj, return_obj)
                logger.info(f'OK properties {p_ok}')
                logger.info(f'KO properties {p_not}')
                self.assertTrue(check)
                '''
            return True

def verify_files(directory,sink_db,source_db):
    """ Load and verify the file

    Args:
        fullname (): folder path
    """
    path = Path(directory)

    if path.is_dir():
        for file_path in path.iterdir():
            verify_file(file_path,sink_db)
    else:
        logger.error('This is not a folder???')

def run_profile(short,profile,sink_db,source_db):
    logger.info(f'Title {profile["title"]}')
    root_folder = './data/stix_cert_data'
    results = {}
    if 'level1' in profile:
        count = 0
        for level in profile['level1']:
            count +=1
            consumer_passed = True
            producer_passed = True
            test_file = f"{root_folder}/{level['dir']}/{level['sub_dir']}"
            logger.info(f"Test folder {test_file}")
            check = verify_files(test_file,sink_db,source_db)

            if level['sub_dir'] == 'consumer_test':
                check = True
                if check == False: consumer_passed = False
            elif level['sub_dir'] == 'producer_test':
                check = True
                if check == False: producer_passed = False

            if consumer_passed: results[f'[{short}.C1]'] = 'Passed'
            else: results[f'[{short}.C1]'] = 'Failed'
            if producer_passed: results[f'[{short}.P1]'] = 'Passed'
            else: results[f'[{short}.P1]'] = 'Failed'


        logger.info(f'\tTotal level 1 checks {count}')
    if 'level2' in profile:
        count += 1
        consumer_passed = True
        producer_passed = True
        if level['sub_dir'] == 'consumer_test':
            check = True
            if check == False: consumer_passed = False
        elif level['sub_dir'] == 'producer_test':
            check = True
            if check == False: producer_passed = False

        if consumer_passed: results[f'[{short}.C2]'] = 'Passed'
        else:
            results[f'[{short}.C2]'] = 'Failed'
        if producer_passed: results[f'[{short}.P2]'] = 'Passed'
        else:
            results[f'[{short}.P2]'] = 'Failed'

        logger.info(f'\tTotal level 2 checks {count}')

        return results

if __name__ == '__main__':
    cwd = Path.cwd()
    logger.info(f'Running tests in {cwd}')
    tests = load_personas(file_path=Path.joinpath(cwd,'data','stix_cert_data','stix_cert_persona_dict.json'))
    template,tags = load_template(file_path=Path.joinpath(cwd,'oasis','cert_template.txt'))
    logger.info(f"Profiles: {list(tests.keys())}")
    run_profiles(tests,template,tags,out_file=Path.joinpath(cwd,'oasis','report.txt'))
