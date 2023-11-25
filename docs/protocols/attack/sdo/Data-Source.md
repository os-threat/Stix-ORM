# Data-Source Domain Object

**Stix and TypeQL Object Type:**  `x-mitre-data-source`

A Data Source in ATT&CK is defined by an x-mitre-data-source object. As a custom STIX type they follow only the generic STIX Domain Object pattern.

[Reference in Stix2.1 Standard](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#data-sources )
## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

|  Stix 2.1 Property    |           Schema Name             | Required  Optional  |      Schema Object  Type | Schema Parent  |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
|  type                 |            stix-type              |      Required       |  stix-attribute-string    |   attribute    |
|  id                   |             stix-id               |      Required       |  stix-attribute-string    |   attribute    |
|  spec_version         |           spec-version            |      Required       |  stix-attribute-string    |   attribute    |
|  created              |             created               |      Required       | stix-attribute-timestamp  |   attribute    |
|  modified             |             modified              |      Required       | stix-attribute-timestamp  |   attribute    |
|  name                 |               name                |      Required       |  stix-attribute-string    |   attribute    |
|  description          |           description             |      Optional       |  stix-attribute-string    |   attribute    |
|  aliases              |            stix-role              |      Optional       |  stix-attribute-string    |   attribute    |
|  kill_chain_phases    | kill-chain-usage:kill-chain-used  |      Optional       |   embedded     |relation |
|  created_by_ref       |        created-by:created         |      Optional       |   embedded     |relation |
| x_mitre_version |x-mitre-version |Required |  stix-attribute-string    |   attribute    |
| x_mitre_contributors |x-mitre-contributors |Required |  stix-attribute-string    |   attribute    |
| x_mitre_modified_by_ref |x-mitre-modified-by-ref:modified |Required |   embedded     |relation |
| x_mitre_platforms |x-mitre-platforms |Required |  stix-attribute-string    |   attribute    |
| x_mitre_collection_layers |x-mitre-collection-layers |Required |  stix-attribute-string    |   attribute    |
| x_mitre_domains |x-mitre-domains |Required |  stix-attribute-string    |   attribute    |
| x_mitre_attack_spec_version |x-mitre-attack-spec-version |Required |  stix-attribute-string    |   attribute    |
| tactic_refs |tactic-refs |Required |  stix-attribute-string    |   attribute    |
| x_mitre_deprecated |x-mitre-deprecated |Optonal |  stix-attribute-boolean   |   attribute    |
|  revoked              |             revoked               |      Optional       |  stix-attribute-boolean   |   attribute    |
|  labels               |              labels               |      Optional       |  stix-attribute-string    |   attribute    |
|  confidence           |            confidence             |      Optional       |  stix-attribute-integer   |   attribute    |
|  lang                 |               lang                |      Optional       |  stix-attribute-string    |   attribute    |
|  external_references  | external-references:referencing   |      Optional       |   embedded     |relation |
|  object_marking_refs  |      object-marking:marked        |      Optional       |   embedded     |relation |
|  granular_markings    |     granular-marking:marked       |      Optional       |   embedded     |relation |
|  extensions           |               n/a                 |        n/a          |           n/a             |      n/a       |

## The Example Data-Source in JSON
The original JSON, accessible in the Python environment
```json
{
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "modified": "2021-11-10T09:30:48.693951Z",
    "name": "Active Directory",
    "x_mitre_version": "1.0",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "type": "x-mitre-data-source",
    "x_mitre_platforms": [
        "Windows",
        "Azure AD"
    ],
    "id": "x-mitre-data-source--d6188aac-17db-4861-845f-57c369f9b4c8",
    "description": "A database and set of services that allows administrators to manage permissions, access to network resources, and stored data objects (user, group, application, or devices)(Citation: Microsoft AD DS Getting Started)",
    "x_mitre_collection_layers": [
        "Host",
        "Cloud Control Plane"
    ],
    "x_mitre_contributors": [
        "Center for Threat-Informed Defense (CTID)"
    ],
    "created": "2021-10-20T15:05:19.274110Z",
    "external_references": [
        {
            "url": "https://attack.mitre.org/datasources/DS0026",
            "external_id": "DS0026",
            "source_name": "mitre-attack"
        },
        {
            "url": "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/ad-ds-getting-started",
            "description": "Foulds, I. et al. (2018, August 7). AD DS Getting Started. Retrieved September 23, 2021.",
            "source_name": "Microsoft AD DS Getting Started"
        }
    ],
    "spec_version": "2.1",
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_domains": [
        "enterprise-attack"
    ],
    "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
}
```


## Inserting the Example Data-Source in TypeQL
The TypeQL insert statement
```typeql
match  $identity0 isa identity, has stix-id "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5";
 $identity1 isa identity, has stix-id "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5";
 $attack-marking03 isa attack-marking, has stix-id "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168";
 
insert $data-source isa data-source,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified,
 has name $name,
 has description $description,
 has x-mitre-version $x-mitre-version,
 has x-mitre-contributors $x_mitre_contributors0,
 has x-mitre-domains $x_mitre_domains0,
 has x-mitre-attack-spec-version $x-mitre-attack-spec-version,
 has x-mitre-deprecated $x-mitre-deprecated,
 has x-mitre-platforms $x_mitre_platforms0,
 has x-mitre-platforms $x_mitre_platforms1,
 has x-mitre-collection-layers $x_mitre_collection_layers0,
 has x-mitre-collection-layers $x_mitre_collection_layers1;

 $stix-type "x-mitre-data-source";
 $spec-version "2.1";
 $stix-id "x-mitre-data-source--d6188aac-17db-4861-845f-57c369f9b4c8";
 $created 2021-10-20T15:05:19.274;
 $modified 2021-11-10T09:30:48.693;
 $name "Active Directory";
 $description "A database and set of services that allows administrators to manage permissions, access to network resources, and stored data objects (user, group, application, or devices)(Citation: Microsoft AD DS Getting Started)";
 $x-mitre-version "1.0";
 $x_mitre_contributors0 "Center for Threat-Informed Defense (CTID)";
 $x_mitre_domains0 "enterprise-attack";
 $x-mitre-attack-spec-version "2.1.0";
 $x-mitre-deprecated false;
 $x_mitre_platforms0 "Windows";
 $x_mitre_platforms1 "Azure AD";
 $x_mitre_collection_layers0 "Host";
 $x_mitre_collection_layers1 "Cloud Control Plane";


 $created-by0 (created:$data-source, creator:$identity0) isa created-by;

 $x-mitre-modified-by-ref1 (modified:$data-source, modifier:$identity1) isa x-mitre-modified-by-ref;
$external-reference0 isa external-reference,
 has source-name "mitre-attack",
 has url-link "https://attack.mitre.org/datasources/DS0026",
 has external-id "DS0026";
$external-reference1 isa external-reference,
 has source-name "Microsoft AD DS Getting Started",
 has description "Foulds, I. et al. (2018, August 7). AD DS Getting Started. Retrieved September 23, 2021.",
 has url-link "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/ad-ds-getting-started";

 $external-references (referenced:$data-source, referencing:$external-reference0, referencing:$external-reference1) isa external-references;

 $object-marking3 (marked:$data-source, marking:$attack-marking03) isa object-marking;
```

## Retrieving the Example Data-Source in TypeQL
The typeQL match statement

```typeql
match  
   $a isa matrix,
      has stix-id   "x-mitre-data-source--d6188aac-17db-4861-845f-57c369f9b4c8",
      has $b;
   $c isa stix-sub-object,
      has $d;
   $e (owner:$a, pointed-to:$c) isa embedded;
   $f (owner:$a, pointed-to:$g) isa embedded; 
```


will retrieve the example attack-pattern object in Vaticle Studio
![Data-Source Example](./img/data-source.png)

## Retrieving the Example Data-Source  in Python
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
stix_obj = typedb.get( "x-mitre-data-source--d6188aac-17db-4861-845f-57c369f9b4c8")
```

 

[Back to MITRE ATT&CK Overview](../overview.md)
 

[Back to All Protocols Overview](../../overview.md)
 

[Back to Overview Doc](../../../overview.md)
