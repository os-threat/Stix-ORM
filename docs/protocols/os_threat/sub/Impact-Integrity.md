# Impact-Integrity Extension Object

**Stix and TypeQL Object Type:**  `integrity`

Every Impact MUST have an extension that has the same value of the impact_category. The Integrity Extension tracks the alteration in information assets.

The Python class name for the Integrity Extension is Integrity. The Integrity extension MUST be accompanied by the extension-definition—?7cc33dd6-f6a1-489b-98ea-522d351d71b9 as its extension ID, with the Python class name of ImpactCoreExt..

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| alteration |alteration |Required |  stix-attribute-string    |   attribute    |
| information_type |information-type |Required |  stix-attribute-string    |   attribute    |
| record_count |record-count |Optional |  stix-attribute-integer    |   attribute    |
| record_size |record-size |Optional |  stix-attribute-integer    |   attribute    |

## The Example Impact-Integrity in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "impact",
    "spec_version": "2.1",
    "id": "impact--704fcda9-8d2d-49d8-a521-1c11f848e33e",
    "created": "2023-11-11T08:45:49.914967Z",
    "modified": "2023-11-11T08:45:49.914967Z",
    "impact_category": "integrity",
    "criticality": 99,
    "description": "The credentials were modified",
    "end_time": "2023-11-11T08:45:49.914967Z",
    "impacted_entity_counts": {
          "computers-personal": 2
    },
    "recoverability": "regular",
    "start_time": "2023-11-11T08:45:49.914967Z",
    "extensions": {
          "extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9": {
                "extension_type": "new-sdo"
          },
          "integrity": {
                "alteration": "partial-modification",
                "information_type": "credentials-user",
                "record_count": 2,
                "record_size": 2000
          }
    }
}
```


## Inserting the Example Impact-Integrity in TypeQL
The TypeQL insert statement
```typeql
insert $impact isa impact,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified,
 has impact-category $impact-category,
 has criticality $criticality,
 has description $description,
 has end-time $end-time,
 has recoverability $recoverability,
 has start-time $start-time;

 $stix-type "impact";
 $spec-version "2.1";
 $stix-id "impact--704fcda9-8d2d-49d8-a521-1c11f848e33e";
 $created 2023-11-11T08:45:49.914;
 $modified 2023-11-11T08:45:49.914;
 $impact-category "integrity";
 $criticality 99;
 $description "The credentials were modified";
 $end-time 2023-11-11T08:45:49.914;
 $recoverability "regular";
 $start-time 2023-11-11T08:45:49.914;


 $entity-key0 isa entity-key;  $entity-key0 "computers-personal";
 $entity-key0 has entity-value 2;
 $impact-counter (impact-driver:$impact, counters: $entity-key0) isa impact-counter;

 $impact-extension isa impact-extension,
 has extension-type $extension-type;

 $extension-type "new-sdo";

 $impact-ext0 (impact-base:$impact, impact-spec:$impact-extension) isa impact-ext;

 $integrity isa integrity,
 has alteration $alteration,
 has information-type $information-type,
 has record-count $record-count,
 has record-size $record-size;

 $alteration "partial-modification";
 $information-type "credentials-user";
 $record-count 2;
 $record-size 2000;

 $integrity-imp1 (impact-base:$impact, integrity-impact:$integrity) isa integrity-imp;
```

## Retrieving the Example Impact-Integrity in TypeQL
The typeQL match statement

```typeql
match 
   $a isa impact, 
      has stix-id  "impact--704fcda9-8d2d-49d8-a521-1c11f848e33e",
      has $b;
   $c isa stix-sub-object,
      has $d;
   $e (owner:$a, pointed-to:$c) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Impact-Integrity Example](./img/integrity.png)

## Retrieving the Example Impact-Integrity  in Python
The Python retrieval statement

```python
from stixorm.module.typedb import TypeDBSink, TypeDBSource
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
stix_obj = typedb.get("impact--704fcda9-8d2d-49d8-a521-1c11f848e33e")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
