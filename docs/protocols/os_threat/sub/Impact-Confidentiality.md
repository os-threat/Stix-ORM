# Impact-Confidentiality Extension Object

**Stix and TypeQL Object Type:**  `confidentiality`

Every Impact MUST have an extension that has the same value of the impact_category. The confidentiality extension tracks the type of information and the type of loss involved as the impact. 

The Python class name for the Confidentiality Extension is Confidentiality. The Confidentiality extension MUST be accompanied by the extension-definition—?7cc33dd6-f6a1-489b-98ea-522d351d71b9 as its extension ID, with the Python class name of ImpactCoreExt..

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| information_type |information-type |Required |  stix-attribute-string    |   attribute    |
| loss_type |loss-type |Required |  stix-attribute-string    |   attribute    |
| record_count |record-count |Optional |  stix-attribute-integer    |   attribute    |
| record_size |record-size |Optional |  stix-attribute-integer    |   attribute    |

## The Example Impact-Confidentiality in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "impact",
    "spec_version": "2.1",
    "id": "impact--74e754cb-1fa6-4685-bbd2-77770b3e1816",
    "created": "2023-11-11T08:45:49.907971Z",
    "modified": "2023-11-11T08:45:49.907971Z",
    "impact_category": "confidentiality",
    "criticality": 99,
    "description": "Two Laptops had credentials stolen",
    "end_time": "2023-11-11T08:45:49.907971Z",
    "impacted_entity_counts": {
          "computers-personal": 2
    },
    "recoverability": "regular",
    "start_time": "2023-11-11T08:45:49.907971Z",
    "extensions": {
          "extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9": {
                "extension_type": "new-sdo"
          },
          "confidentiality": {
                "information_type": "credentials-user",
                "loss_type": "exploited-loss",
                "record_count": 2,
                "record_size": 2000
          }
    }
}
```


## Inserting the Example Impact-Confidentiality in TypeQL
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
 $stix-id "impact--74e754cb-1fa6-4685-bbd2-77770b3e1816";
 $created 2023-11-11T08:45:49.907;
 $modified 2023-11-11T08:45:49.907;
 $impact-category "confidentiality";
 $criticality 99;
 $description "Two Laptops had credentials stolen";
 $end-time 2023-11-11T08:45:49.907;
 $recoverability "regular";
 $start-time 2023-11-11T08:45:49.907;


 $entity-key0 isa entity-key;  $entity-key0 "computers-personal";
 $entity-key0 has entity-value 2;
 $impact-counter (impact-driver:$impact, counters: $entity-key0) isa impact-counter;

 $impact-extension isa impact-extension,
 has extension-type $extension-type;

 $extension-type "new-sdo";

 $impact-ext0 (impact-base:$impact, impact-spec:$impact-extension) isa impact-ext;

 $confidentiality isa confidentiality,
 has information-type $information-type,
 has loss-type $loss-type,
 has record-count $record-count,
 has record-size $record-size;

 $information-type "credentials-user";
 $loss-type "exploited-loss";
 $record-count 2;
 $record-size 2000;

 $confidentiality-imp1 (impact-base:$impact, confidentiality-impact:$confidentiality) isa confidentiality-imp;
```

## Retrieving the Example Impact-Confidentiality in TypeQL
The typeQL match statement

```typeql
match 
   $a isa impact, 
      has stix-id  "impact--74e754cb-1fa6-4685-bbd2-77770b3e1816",
      has $b;
   $c isa stix-sub-object,
      has $d;
   $e (owner:$a, pointed-to:$c) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Impact-Confidentiality Example](./img/confidentiality.png)

## Retrieving the Example Impact-Confidentiality  in Python
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
stix_obj = typedb.get("impact--74e754cb-1fa6-4685-bbd2-77770b3e1816")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
