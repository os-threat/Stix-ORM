# Software Cyber Obervable Object

**Stix and TypeQL Object Type:**  `software`

The Software object represents high-level properties associated with software, including software products.

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7rkyhtkdthok)
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
| name |name |      Optional       |  stix-attribute-string    |   attribute    |
| �cpe |cpe |      Optional       |  stix-attribute-string    |   attribute    |
| �swid |swid |      Optional       |  stix-attribute-string    |   attribute    |
| �languages |language |      Optional       |  stix-attribute-string    |   attribute    |
| �vendor |vendor |      Optional       |  stix-attribute-string    |   attribute    |
| �version |version; |      Optional       |  stix-attribute-string    |   attribute    |

## The Example Software in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "software",  
    "spec_version": "2.1",  
    "id": "software--a1827f6d-ca53-5605-9e93-4316cd22a00a",  
    "name": "Word",  
    "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",    
    "version": "2002",  
    "vendor": "Microsoft"  
  }
```


## Inserting the Example Software in TypeQL
The TypeQL insert statement
```typeql
insert 
    $software isa software,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has name $name,
        has cpe $cpe,
        has vendor $vendor,
        has version $version;
    
    $stix-type "software";
    $spec-version "2.1";
    $stix-id "software--a1827f6d-ca53-5605-9e93-4316cd22a00a";
    $name "Word";
    $cpe "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*";
    $vendor "Microsoft";
    $version "2002";
```

## Retrieving the Example Software in TypeQL
The typeQL match statement

```typeql
match
    $a isa software,
        has stix-id  "software--a1827f6d-ca53-5605-9e93-4316cd22a00a",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Software Example](./img/software.png)

## Retrieving the Example Software  in Python
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
stix_obj = typedb.get("software--a1827f6d-ca53-5605-9e93-4316cd22a00a")
```

