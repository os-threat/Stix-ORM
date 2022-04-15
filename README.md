# Stix <-> TypeDB ORM

# Explanation of Repo
This Repo is designed to make it easy to build, test and play with the Stix <-> TypeDB ORM. It is based around the OASIS Stix2 Python Library, and is an implementation of their datastore api (https://stix2.readthedocs.io/en/latest/api/stix2.datastore.html).

The implementation is minimal, it enables TypeDB to be setup as a Stix2 DataSink and DataSource, with implementation of both the DataSink init and  add methods, and the DataSource init and get methods.

A number of features from the library are not developed yet, including combining the DataSource and DataSink into a DataStore, running filters on queries, loading from files and other methods.

## Installation
Download and install using

    pipenv install

then start the virtual environment with 

    pipenv shell    

## Contents
There are 3 directories and some local files.

### 1. Stix Directory
The Stix directory contains the actual module needed to be integrated with the Stix2 python library. 

The module sub-drectory has two files:
- Typedb.py: Our implementation of https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/datastore/filesystem.py. 
- stql.py: Handles all of the translation tasks for the typedb file. The file is split into four sections:
1. Convert Stix to TypeQL Match, Insert: Lines 1-735
2. Dispatch Dicts: Lines 735 - 1,980
3. Retrieve Stage 2: Intermediate to Final Shape: Lines 1,980 to 2,580
4. Retrieve Stage 1: TypeDB to Intermediate Shape: Lines 2,580 to 3,120

The schema sub directory has 3 files:
- cti-schema-v2.tql - updated Tomas schema
- cti-rules.tql - updated Tomas rules
- initialise.py - updated initialise file

### 2. Data Directory
The data directory contains all of the test examples harvested from the web

- examples dir: Stix examples harvested from https://oasis-open.github.io/cti-documentation/stix/examples
- standard dir: Stix examples harvested from chapters 3, 4, 5, 6 and 7 of the official Stix webpage https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html. Contains sub directory of Issues (e.g. cyclical relations)
- threat_reports dir: Stix examples harvested from the threat reports section of https://oasis-open.github.io/cti-documentation/stix/examples
- mitre dir: Stix examples harvested from https://github.com/mitre-attack/attack-stix-data WARNING ATT&CK EXTENSIONS NOT IMPLEMENTED YET. DO NOT USE
- appendix_c dir: Appendix C examples from the main documentation page https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wwok3b866yjl 


### 3. Docs Directory
There are some markdown docs that contain incomplete documentation describing the transform between TypeDB and Stix names and structures,

### 4. Local Files
There are four local files:
- test.py: Enables loading of individual data files, and retrieving of a single Stix_id
- check_dir.py: Enables each data file in a a directory to be loaded into TypeDB, and then every object to be sequentially retrieved and printed. The process handles files with either bundles or lists of objects. 
- export_test.json: An export of the intermediate form of the last object to be retrieved from the datastore
- export_final.json: An export of the final form of the last object to be retrieved from the datastore
