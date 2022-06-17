import json
from pathlib import Path
import os
from glob import glob

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)

# Read in the file
with open('stql.py', 'r') as file :
  codefile = file.read()

# TODO: load all the objects
for file_path in glob(f'{dir_path}/definitions/stix21/data/*.json'):
    dict_name = Path(file_path).stem
    # then replace the dictionary in the code
    print(dict_name)