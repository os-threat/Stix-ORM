# Impact-Availability Extension Object

**Stix and TypeQL Object Type:**  `availability`

Every Impact MUST have an extension that has the same value of the impact_category. The Availability Extension tracks the impact of availability in assets

The Python class name for the Availability Extension is Availability. The Availability extension MUST be accompanied by the extension-definition—?7cc33dd6-f6a1-489b-98ea-522d351d71b9 as its extension ID, with the Python class name of ImpactCoreExt..

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| availability_impact |impacted-availability |Required |  stix-attribute-string    |   attribute    |

## The Example Impact-Availability in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "impact",
    "spec_version": "2.1",
    "id": "impact--22f44c3f-7af8-4bdd-9ce8-eda54209acc9",
    "created": "2023-11-11T08:45:49.902967Z",
    "modified": "2023-11-11T08:45:49.902967Z",
    "impact_category": "availability",
    "criticality": 99,
    "description": "Two Laptops and 3 Servers are stuffed",
    "end_time": "2023-11-11T08:45:49.902967Z",
    "impacted_entity_counts": {
          "computers-personal": 2,
          "computers-server": 3
    },
    "recoverability": "regular",
    "start_time": "2023-11-11T08:45:49.902967Z",
    "extensions": {
          "extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9": {
                "extension_type": "new-sdo"
          },
          "availability": {
                "availability_impact": 99
          }
    }
}
```


## Inserting the Example Impact-Availability in TypeQL
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
 $stix-id "impact--22f44c3f-7af8-4bdd-9ce8-eda54209acc9";
 $created 2023-11-11T08:45:49.902;
 $modified 2023-11-11T08:45:49.902;
 $impact-category "availability";
 $criticality 99;
 $description "Two Laptops and 3 Servers are stuffed";
 $end-time 2023-11-11T08:45:49.902;
 $recoverability "regular";
 $start-time 2023-11-11T08:45:49.902;


 $entity-key0 isa entity-key;  $entity-key0 "computers-personal";
 $entity-key0 has entity-value 2;
 $entity-key1 isa entity-key;  $entity-key1 "computers-server";
 $entity-key1 has entity-value 3;
 $impact-counter (impact-driver:$impact, counters: $entity-key0, counters: $entity-key1) isa impact-counter;

 $impact-extension isa impact-extension,
 has extension-type $extension-type;

 $extension-type "new-sdo";

 $impact-ext0 (impact-base:$impact, impact-spec:$impact-extension) isa impact-ext;

 $availability isa availability,
 has impacted-availability $impacted-availability;

 $impacted-availability 99;

 $availability-imp1 (impact-base:$impact, availability-impact:$availability) isa availability-imp;
```

## Retrieving the Example Impact-Availability in TypeQL
The typeQL match statement

```typeql
match 
   $a isa impact, 
      has stix-id  "impact--22f44c3f-7af8-4bdd-9ce8-eda54209acc9",
      has $b;
   $c isa stix-sub-object,
      has $d;
   $e (owner:$a, pointed-to:$c) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Impact-Availability Example](./img/availability.png)

## Retrieving the Example Impact-Availability  in Python
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
stix_obj = typedb.get("impact--22f44c3f-7af8-4bdd-9ce8-eda54209acc9")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
