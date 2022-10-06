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

## Suggested Experiments
Examine and run the granular marking example with

    python test.py
    
Notice how the granular marking input example, has different markings for each of the items in a list? Compare those indexes to the TypeQL statements and the final output. See how the indexes and the list are now reversed?

Examine how the ORM handles different shaped objects in the various directories. Check out:
- examples directory: Granular markings versus Data Markings
- standard directory: Email_mime, file_binary, file_ntfs_stream, network_ext_HTTP_request, X509_cert_v3_ext
- threat_reports director: Check out the final report, and the size of the auto-generated relation

To do this, use 

    python check_dir.py

and scroll through the logging output. Change the directory name as needed to change the directory focus

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
- test.py: Enables loading of individual data files, and retrieving of a single Stix_id. It is currently set to examine the Granular Markings and how polymorphic lists mean outputs lose their absolute order, but retain their relative order.
- check_dir.py: Enables each data file in a a directory to be loaded into TypeDB, and then every object to be sequentially retrieved and printed. The process handles files with either bundles or lists of objects. 
- export_test.json: An export of the intermediate form of the last object to be retrieved from the datastore
- export_final.json: An export of the final form of the last object to be retrieved from the datastore

### 5. Code information

TypeDB:
- init() - create clean database with schema and marking objects loaded
- add() - can add single objects, lists and bundles
- get() - can get single object based on id
- get_all_ids() - get all of the stix ids in the database as a list (except for marking objects)
- delete () - delete a list of sitx ids, orders the records and checks for missing dependencies and circular references


Raw STIX method:

dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(local_obj, self.import_type)

Returned description:
* dep_match: the matches needed for the new object that are dependent on other objects, already inserted
* dep_insert: the inserts needed for the new objects that are dependent on matches with existing objects
* indep-ql: the inserts for the new object that are indepdpent of other objects
* core_ql: statements describing the main  object and its stix id
* dep_obj: The dependency object for this objects, used to order it in a list. Contains its own id, and a list of all of the ids it is dependent on (i.e. dependent objects must be added before, or deleted after, this object)

