# Mutex Cyber Obervable Object

**Stix and TypeQL Object Type:**  `mutex`

The Mutex object represents the properties of a mutual exclusion (mutex) object.

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f92nr9plf58y)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
|  type                 |            stix-type              |      Required       |  stix-attribute-string    |   attribute    |
|  id                   |             stix-id               |      Required       |  stix-attribute-string    |   attribute    |
|  spec_version         |           spec-version            |      Optional       |  stix-attribute-string    |   attribute    |
|  object_marking_refs  |      object-marking:marked        |      Optional       |   embedded     |relation |
|  granular_markings    |     granular-marking:marked       |      Optional       |   embedded     |relation |
| defanged |defanged |      Optional       |stix-attribute-boolean |   attribute    |
|  extensions           |               n/a                 |        n/a          |           n/a             |      n/a       |
| name |name |      Required       |  stix-attribute-string    |   attribute    |

## The Example Mutex in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "mutex",  
    "spec_version": "2.1",  
    "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",  
    "name": "__CLEANSWEEP__"  
  }
```


## Inserting the Example Mutex in TypeQL
The TypeQL insert statement
```typeql
insert 
    $mutex isa mutex,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has name $name;
    
    $stix-type "mutex";
    $spec-version "2.1";
    $stix-id "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300";
    $name "__CLEANSWEEP__";
```

## Retrieving the Example Mutex in TypeQL
The typeQL match statement

```typeql
match
    $a isa mutex,
        has stix-id "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Mutex Example](./img/mutex.png)

## Retrieving the Example Mutex  in Python
The Python retrieval statement

```python
from stix.module.typedb_lib import TypeDBSink, TypeDBSource

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = {
    "STIX21": True,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": False,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}

typedb = TypeDBSource(connection, import_type)
stix_obj = typedb.get("mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300")
```

