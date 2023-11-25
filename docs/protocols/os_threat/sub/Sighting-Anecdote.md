# Sighting-Anecdote Extension Object

**Stix and TypeQL Object Type:**  `sighting-anecdote`

The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Anecdote can be issued only by a person. Generally, when an Anecdote is issued, it is not known whether it is actually nefarious. Anecdotes are used to initiailise an incident. Conceivably, an Anecdote may also be issued that defines an Impact, rather than an Event Anecdotes are expected to have low confidence and result in the need to do tasks to increase the confidence.

 Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. The Python class name is SightingAnecdote. The Python class name is SightingAlert. It MUST be accompanied by the extension definition with extension-definition—?0d76d6d9-16ca-43fd-bd41-4f800ba8fc43 as its extension ID. The Python class name is SightingEvidence.

[Reference in Stix2.1 Standard](https://github.com/os-threat/cti-stix-common-objects/blob/main/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc)
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| person_name |person-name |Required |  stix-attribute-string    |   attribute    |
| person_context |person-context |Required |  stix-attribute-string    |   attribute    |
| report_submission |report-submission |Required |  stix-attribute-string    |   attribute    |

## The Example Sighting-Anecdote in JSON
The original JSON, accessible in the Python environment
```json
{
    "type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--8d8513f2-1e84-40f0-97a6-b8b4263ccb40",
    "created": "2023-11-12T13:19:14.245749Z",
    "modified": "2023-11-12T13:19:14.245749Z",
    "sighting_of_ref": "identity--27c2fdc0-bf9c-46d8-aab1-658948cd2ed6",
    "observed_data_refs": [
          "observed-data--e41ba03b-548d-4675-ba7e-b0844e1d9ee1"
    ],
    "extensions": {
          "extension-definition--0d76d6d9-16ca-43fd-bd41-4f800ba8fc43": {
                "extension_type": "property-extension"
          },
          "sighting-anecdote": {
                "person_name": "Naive Smith",
                "person_context": "employee",
                "report_submission": "interview"
          }
    }
}
```


## Inserting the Example Sighting-Anecdote in TypeQL
The TypeQL insert statement
```typeql
match
 $identity0 isa identity, has stix-id "identity--27c2fdc0-bf9c-46d8-aab1-658948cd2ed6";
 $observed-data0 isa observed-data, has stix-id "observed-data--e41ba03b-548d-4675-ba7e-b0844e1d9ee1";
insert
$sighting (sighting-of:$identity0, observed:$observed-data0) isa sighting,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified;

 $stix-type "sighting";
 $spec-version "2.1";
 $stix-id "sighting--8d8513f2-1e84-40f0-97a6-b8b4263ccb40";
 $created 2023-11-12T13:19:14.245;
 $modified 2023-11-12T13:19:14.245;

 $evidence-extension isa evidence-extension,
 has extension-type $extension-type;

 $extension-type "property-extension";

 $evidence-ext0 (evidence-base:$sighting, evidence-spec:$evidence-extension) isa evidence-ext;

 $anecdote-evidence isa anecdote-evidence,
 has person-name $person-name,
 has person-context $person-context,
 has report-submission $report-submission;

 $person-name "Naive Smith";
 $person-context "employee";
 $report-submission "interview";

 $anecdote-ext1 (sighting-base:$sighting, anecdote-extension:$anecdote-evidence) isa anecdote-ext;
```

## Retrieving the Example Sighting-Anecdote in TypeQL
The typeQL match statement

```typeql
match 
   $a ($role:$b) isa sighting,
      has stix-id  "sighting--8d8513f2-1e84-40f0-97a6-b8b4263ccb40",
      has $c;
   $d isa stix-sub-object, 
      has $e;
   $f (owner:$a, pointed-to:$d) isa embedded;
```


will retrieve the example attack-pattern object in Vaticle Studio
![Sighting-Anecdote Example](./img/sighting-anecdote.png)

## Retrieving the Example Sighting-Anecdote  in Python
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
stix_obj = typedb.get("sighting--8d8513f2-1e84-40f0-97a6-b8b4263ccb40")
```

 

[Back to OS-Threat Stix Extensions Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
