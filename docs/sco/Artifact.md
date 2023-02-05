# Artifact Cyber Obervable Object

**Stix and TypeQL Object Type:**  `artifact`

The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload.

One of payload_bin or url MUST be provided. It is incumbent on object creators to ensure that the URL is accessible for downstream consumers

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_4jegwl6ojbes)
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
| mime_type         |mime_type         |      Optional       |  stix-attribute-string    |   attribute    |
| payload_bin |payload_bin |      Optional       |  stix-attribute-string    |   attribute    |
| url |url |      Optional       |  stix-attribute-string    |   attribute    |
| hashes |hashes:owner |      Optional       |   embedded     |relation |
| encryption_algorithm |encryption_algorithm |      Optional       |  stix-attribute-string    |   attribute    |
| decryption_key |decryption_key |      Optional       |  stix-attribute-string    |   attribute    |

## The Example Artifact in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "artifact",  
    "spec_version": "2.1",  
    "id": "artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee",  
    "mime_type": "image/jpeg",  
    "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI== ..."  
  }
```


## Inserting the Example Artifact in TypeQL
The TypeQL insert statement
```typeql
insert 
    $artifact isa artifact,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has mime-type $mime-type,
        has payload-bin $payload-bin;
    
    $stix-type "artifact";
    $spec-version "2.1";
    $stix-id "artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee";
    $mime-type "image/jpeg";
    $payload-bin "VBORw0KGgoAAAANSUhEUgAAADI== ...";
```

## Retrieving the Example Artifact in TypeQL
The typeQL match statement

```typeql
match
    $a isa artifact,
        has stix-id  "artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee",
        has $b;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Artifact Example](./img/artifact.png)

## Retrieving the Example Artifact  in Python
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
stix_obj = typedb.get("artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee")
```

