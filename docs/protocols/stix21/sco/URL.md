# URL Cyber Obervable Object

**Stix and TypeQL Object Type:**  `url`

The URL object represents the properties of a uniform resource locator (URL).

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0)
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

## The Example URL in JSON
The original JSON, accessible in the Python environment
```json
{  
    "type": "url",  
    "spec_version": "2.1",  
    "id": "url--c1477287-23ac-5971-a010-5c287877fa60",  
    "value": "https://example.com/research/index.html"  
  }
```


## Inserting the Example URL in TypeQL
The TypeQL insert statement
```typeql
insert 
    $url isa url,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has stix-value $stix-value;
    
    $stix-type "url";
    $spec-version "2.1";
    $stix-id "url--c1477287-23ac-5971-a010-5c287877fa60";
    $stix-value "https://example.com/research/index.html";
```

## Retrieving the Example URL in TypeQL
The typeQL match statement

```typeql
match
    $a isa url,
        has stix-id  "url--c1477287-23ac-5971-a010-5c287877fa60",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![URL Example](./img/url.png)

## Retrieving the Example URL  in Python
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
stix_obj = typedb.get("url--c1477287-23ac-5971-a010-5c287877fa60")
```

