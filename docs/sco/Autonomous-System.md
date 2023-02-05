# Autonomous-System Cyber Obervable Object

**Stix and TypeQL Object Type:**  `autonomous-system`

This object represents the properties of an Autonomous System (AS).

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_27gux0aol9e3)
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
| number |number |Required |  stix-attribute-integer    |   attribute    |
| name |name |      Optional       |  stix-attribute-string    |   attribute    |
| rir |rir |      Optional       |  stix-attribute-string    |   attribute    |

## The Example Autonomous-System in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "autonomous-system",  
    "spec_version": "2.1",  
    "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",  
    "number": 15139,  
    "name": "Slime Industries",  
    "rir": "ARIN"  
  }
```


## Inserting the Example Autonomous-System in TypeQL
The TypeQL insert statement
```typeql
insert 
    $autonomous-system isa autonomous-system,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has number $number,
        has name $name,
        has rir $rir;
    
    $stix-type "autonomous-system";
    $spec-version "2.1";
    $stix-id "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74";
    $number 15139;
    $name "Slime Industries";
    $rir "ARIN";
```

## Retrieving the Example Autonomous-System in TypeQL
The typeQL match statement

```typeql
match
    $a isa autonomous-system,
        has stix-id "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Autonomous-System Example](./img/autonomous-system.png)

## Retrieving the Example Autonomous-System  in Python
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
stix_obj = typedb.get("autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74")
```

