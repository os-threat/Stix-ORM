import os,json,sys
import logging
import re
from stix.module.typedb import TypeDBSink, TypeDBSource
from dbconfig import connection

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
    typedb = TypeDBSink(connection, True, "STIX21")

    for profile in config.keys():
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

def run_profile(short,profile):
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
            logger.info(f"Test file {test_file}")
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
