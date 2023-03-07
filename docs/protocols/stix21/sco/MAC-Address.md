# MAC-Address Cyber Obervable Object

**Stix and TypeQL Object Type:**  `mac-addr`

The MAC Address object represents a single Media Access Control (MAC) address.

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
| value |stix-value |      Optional       |  stix-attribute-string    |   attribute    |

## The Example MAC-Address in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "mac-addr",  
    "spec_version": "2.1",  
    "id": "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00",  
    "value": "d2:fb:49:24:37:18"  
  }
```


## Inserting the Example MAC-Address in TypeQL
The TypeQL insert statement
```typeql
insert 
    $mac-addr isa mac-addr,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has stix-value $stix-value;
    
    $stix-type "mac-addr";
    $spec-version "2.1";
    $stix-id "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00";
    $stix-value "d2:fb:49:24:37:18";
```

## Retrieving the Example MAC-Address in TypeQL
The typeQL match statement

```typeql
match
    $a isa mac-addr,
        has stix-id "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![MAC-Address Example](./img/mac-addr.png)

## Retrieving the Example MAC-Address  in Python
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
stix_obj = typedb.get("mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00")
```

