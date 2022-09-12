import os,json,sys
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

def load_personas(file_path='./data/stix_cert_data/stix_cert_persona_dict.json'):
    logger.info(f'Loading file {file_path}')
    with open(file_path, mode="r", encoding="utf-8") as file:
        d = json.load(file)
        logger.info(f"Loaded {len(d.keys())} profiles")
        return d



# if this file is run directly, then start here
if __name__ == '__main__':
    tests = load_personas()
    logger.info(f"Profiles: {list(tests.keys())}")
