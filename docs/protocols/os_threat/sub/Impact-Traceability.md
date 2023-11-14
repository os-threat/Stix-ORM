# Impact-Traceability Extension Object

**Stix and TypeQL Object Type:**  `traceability`

Every Impact MUST have an extension that has the same value of the impact_category. The Traceability Extension tracks whether the traces left by the threat-actor, are sufficient to enable attribution.

The Python class name for the Traceability Extension is Traceability. The Traceability extension MUST be accompanied by the extension-definition—?7cc33dd6-f6a1-489b-98ea-522d351d71b9 as its extension ID, with the Python class name of ImpactCoreExt..

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| traceability_impact |traceability-type |Required |  stix-attribute-string    |   attribute    |

## The Example Impact-Traceability in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "impact",
    "spec_version": "2.1",
    "id": "impact--79459a66-7dc3-4218-95a1-a4511edeff30",
    "created": "2023-11-11T08:45:49.926967Z",
    "modified": "2023-11-11T08:45:49.926967Z",
    "impact_category": "traceability",
    "criticality": 99,
    "description": "We can reconstruct the attack from the data remaining",
    "end_time": "2023-11-11T08:45:49.926967Z",
    "impacted_entity_counts": {
          "computers-personal": 2
    },
    "recoverability": "regular",
    "start_time": "2023-11-11T08:45:49.926967Z",
    "extensions": {
          "extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9": {
                "extension_type": "new-sdo"
          },
          "traceability": {
                "traceability_impact": "provable-accountability"
          }
    }
}
```


## Inserting the Example Impact-Traceability in TypeQL
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
 $stix-id "impact--79459a66-7dc3-4218-95a1-a4511edeff30";
 $created 2023-11-11T08:45:49.926;
 $modified 2023-11-11T08:45:49.926;
 $impact-category "traceability";
 $criticality 99;
 $description "We can reconstruct the attack from the data remaining";
 $end-time 2023-11-11T08:45:49.926;
 $recoverability "regular";
 $start-time 2023-11-11T08:45:49.926;


 $entity-key0 isa entity-key;  $entity-key0 "computers-personal";
 $entity-key0 has entity-value 2;
 $impact-counter (impact-driver:$impact, counters: $entity-key0) isa impact-counter;

 $impact-extension isa impact-extension,
 has extension-type $extension-type;

 $extension-type "new-sdo";

 $impact-ext0 (impact-base:$impact, impact-spec:$impact-extension) isa impact-ext;

 $traceability isa traceability,
 has traceability-type $traceability-type;

 $traceability-type "provable-accountability";

 $traceability-imp1 (impact-base:$impact, traceability-impact:$traceability) isa traceability-imp;
```

## Retrieving the Example Impact-Traceability in TypeQL
The typeQL match statement

```typeql
match 
   $a isa impact, 
      has stix-id  "impact--79459a66-7dc3-4218-95a1-a4511edeff30",
      has $b;
   $c isa stix-sub-object,
      has $d;
   $e (owner:$a, pointed-to:$c) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Impact-Traceability Example](./img/traceability.png)

## Retrieving the Example Impact-Traceability  in Python
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
stix_obj = typedb.get("impact--79459a66-7dc3-4218-95a1-a4511edeff30")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
