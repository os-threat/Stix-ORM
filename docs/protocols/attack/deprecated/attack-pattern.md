# Attack-Pattern Domain Object

Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed. An example of an attack pattern is "spear phishing": a common type of attack where an attacker sends a carefully crafted e-mail message to a party with the intent of getting them to click a link or open an attachment to deliver malware. Attack Patterns can also be more specific; spear phishing as practiced by a particular threat actor (e.g., they might generally say that the target won a contest) can also be an Attack Pattern. 

The Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks such as CAPEC. 

[Reference in Stix2.1 Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy) 


## Stix 2.1 Properties Converted to TypeQL
Mapping of the Stix Attack Pattern Properties to TypeDB

| Stix 2.1 Property   |           Schema Name            | Required  Optional |      Schema Object       | Schema Parent |
|:--------------------|:--------------------------------:|:------------------:|:------------------------:|:-------------:|
| type                |            stix-type             |      Required      |  stix-attribute-string   |   attribute   |
| id                  |             stix-id              |      Required      |  stix-attribute-string   |   attribute   |
| spec_version        |           spec-version           |      Required      |  stix-attribute-string   |   attribute   |
| created             |             created              |      Required      | stix-attribute-timestamp |   attribute   |
| modified            |             modified             |      Required      | stix-attribute-timestamp |   attribute   |
| name                |               name               |      Required      |  stix-attribute-string   |   attribute   |
| description         |           description            |      Optional      |  stix-attribute-string   |   attribute   |
| aliases             |            stix-role             |      Optional      |  stix-attribute-string   |   attribute   |
| kill_chain_phases   | kill-chain-usage:kill-chain-used |      Optional      |     kill-chain-usage     |   embedded    |
| created_by_ref      |        created-by:created        |      Optional      |        created-by        |   embedded    |
| revoked             |             revoked              |      Optional      |  stix-attribute-boolean  |   attribute   |
| labels              |              labels              |      Optional      |  stix-attribute-string   |   attribute   |
| confidence          |            confidence            |      Optional      |  stix-attribute-integer  |   attribute   |
| lang                |               lang               |      Optional      |  stix-attribute-string   |   attribute   |
| external_references | external-references:referencing  |      Optional      |   external-references    |   embedded    |
| object_marking_refs |      object-marking:marked       |      Optional      |      object-marking      |   embedded    |
| granular_markings   |     granular-marking:marked      |      Optional      |     granular-marking     |   embedded    |
| extensions          |               n/a                |        n/a         |           n/a            |      n/a      |


## Attack Pattern Example in JSON
The original JSON, accessible in the Python environment

```json
{
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--8ac90ff3-ecf8-4835-95b8-6aea6a623df5",
    "created": "2015-05-07T14:22:14.760Z",
    "modified": "2015-05-07T14:22:14.760Z",
    "name": "Phishing",
    "description": "Spear phishing used as a delivery mechanism for malware.",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mandiant-attack-lifecycle-model",
            "phase_name": "initial-compromise"
        }
    ],
    "external_references": [
        {
            "source_name": "capec",
            "description": "phishing",
            "url": "https://capec.mitre.org/data/definitions/98.html",
            "external_id": "CAPEC-98"
        }
    ]
}
```

## Attack Pattern Example Insert Statement in TypeQL
The TypeQL insert statement

```typeql
insert 
    $attack-pattern isa attack-pattern,
        has stix-type $stix-type,
        has spec-version $spec-version,
        has stix-id $stix-id,
        has created $created,
        has modified $modified,
        has name $name,
        has description $description;
    
    $stix-type "attack-pattern";
    $spec-version "2.1";
    $stix-id "attack-pattern--8ac90ff3-ecf8-4835-95b8-6aea6a623df5";
    $created 2015-05-07T14:22:14.760;
    $modified 2015-05-07T14:22:14.760;
    $name "Phishing";
    $description "Spear phishing used as a delivery mechanism for malware.";
    
    $kill-chain-phase0 isa kill-chain-phase,
        has kill-chain-name "mandiant-attack-lifecycle-model",
        has phase-name "initial-compromise";
    
    $kill-chain-usage (kill-chain-used:$attack-pattern, kill-chain-using:$kill-chain-phase0) isa kill-chain-usage;
    
    $external-reference0 isa external-reference,
        has source-name "capec",
        has description "phishing",
        has url-link "https://capec.mitre.org/data/definitions/98.html",
        has external-id "CAPEC-98";
    
    $external-references (referenced:$attack-pattern, referencing:$external-reference0) isa external-references;
```


## Retrieving the Example Attack-Pattern in TypeQL
The typeQL match statement

```typeql
match
    $a isa attack-pattern,
        has stix-id "attack-pattern--8ac90ff3-ecf8-4835-95b8-6aea6a623df5",
        has $b;
    $c isa stix-sub-object,
        has $d;
    $e (owner:$a, pointed-to:$c) isa embedded;
```

will retrieve the example attack-pattern object in Vaticle Studio
![Attack Pattern Example](../sdo/img/attack-pattern.png)


## Rtrieving the Example Attack-Pattern in Python
The Python retrieval statement

```python
from stix.module.typedb import TypeDBSink, TypeDBSource

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
stix_obj = typedb.get("attack-pattern--8ac90ff3-ecf8-4835-95b8-6aea6a623df5")

```

