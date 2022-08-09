import json
from pathlib import Path
import os
from glob import glob

path = os.path.abspath(__file__)
dir_path = os.path.dirname(path)

# Read in the file
with open('stql_old.py', 'r') as file :
  old_file = file.read()
  new_file = old_file

# TODO: load all the objects
for file_path in glob(f'{dir_path}/definitions/stix21/data/*.json'):
    dict_name = Path(file_path).stem
    # then replace the dictionary in the code
    print(dict_name)

    for i,line in enumerate(old_file.splitlines()):
      if dict_name in line:
        print('Line %d' % i)
    new_file = new_file.replace(dict_name,f"stix_models[\"{dict_name}\"]")

# Read in the file
with open('stql.py', 'w') as file :
  file.write(new_file)