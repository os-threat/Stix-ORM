# Sighting-Alert Extension Object

**Stix and TypeQL Object Type:**  `sighting-alert`

The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Alert can be issued by a system or a user. Generally, when an Alert is issued, it is not known whether it is actually nefarious. Alerts are often used to initiailise an incident. Conceivably, once an Alert is qualified as a true positive, it could be joined to another Alert from another Incident. 

Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. The Python class name is SightingAlert. It MUST be accompanied by the extension definition with extension-definition—?0d76d6d9-16ca-43fd-bd41-4f800ba8fc43 as its extension ID. The Python class name is SightingEvidence.

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| name |name |Required |  stix-attribute-string    |   attribute    |
| log |log |Required |  stix-attribute-string    |   attribute    |
| system_id |system-id |Required |  stix-attribute-string    |   attribute    |
| source |source |Optional |  stix-attribute-string    |   attribute    |
| product |product |Optional |  stix-attribute-string    |   attribute    |
| format |format |Optional |  stix-attribute-string    |   attribute    |

## The Example Sighting-Alert in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--db6e5af2-437d-46dc-a831-b972f02674de",
    "created": "2023-11-12T13:19:14.223465Z",
    "modified": "2023-11-12T13:19:14.223465Z",
    "sighting_of_ref": "indicator--277f623c-3468-4ba3-9b83-165f3b3827c1",
    "observed_data_refs": [
          "observed-data--f55a1b66-865d-4079-bc3b-1ffb8c7a9ab4"
    ],
    "extensions": {
          "extension-definition--0d76d6d9-16ca-43fd-bd41-4f800ba8fc43": {
                "extension_type": "property-extension"
          },
          "sighting-alert": {
                "name": "user-report",
                "log": "I have found a suspicious email"
          }
    }
}
```


## Inserting the Example Sighting-Alert in TypeQL
The TypeQL insert statement
```typeql
 match
 $indicator0 isa indicator, has stix-id "indicator--277f623c-3468-4ba3-9b83-165f3b3827c1";
 $observed-data0 isa observed-data, has stix-id "observed-data--f55a1b66-865d-4079-bc3b-1ffb8c7a9ab4";

insert_tql string?-> insert
$sighting (sighting-of:$indicator0, observed:$observed-data0) isa sighting,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified;

 $stix-type "sighting";
 $spec-version "2.1";
 $stix-id "sighting--db6e5af2-437d-46dc-a831-b972f02674de";
 $created 2023-11-12T13:19:14.223;
 $modified 2023-11-12T13:19:14.223;

 $evidence-extension isa evidence-extension,
 has extension-type $extension-type;

 $extension-type "property-extension";

 $evidence-ext0 (evidence-base:$sighting, evidence-spec:$evidence-extension) isa evidence-ext;

 $alert-evidence isa alert-evidence,
 has name $name,
 has log $log;

 $name "user-report";
 $log "I have found a suspicious email";

 $alert-ext1 (sighting-base:$sighting, alert-extension:$alert-evidence) isa alert-ext;
```

## Retrieving the Example Sighting-Alert in TypeQL
The typeQL match statement

```typeql
match 
   $a ($role:$b) isa sighting,
      has stix-id  "sighting--db6e5af2-437d-46dc-a831-b972f02674de",
      has $c;
   $d isa stix-sub-object, 
      has $e;
   $f (owner:$a, pointed-to:$d) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Sighting-Alert Example](./img/sighting-alert.png)

## Retrieving the Example Sighting-Alert  in Python
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
stix_obj = typedb.get("sighting--db6e5af2-437d-46dc-a831-b972f02674de")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
