# Rationale for Mapping Stix 2.1 Objects to TypeQL

Stix 2.1 is a complicated domain. Numbers enclosed in brackets indicate the relevant section from the stix 2.1 specification (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)

# 4. Stix Domain Object Types

A lof of stuff in here


-------------------------------------------------------------------------------------------------------------------------

## 4.1 Attack Pattern Domain Object
Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed. An example of an attack pattern is "spear phishing": a common type of attack where an attacker sends a carefully crafted e-mail message to a party with the intent of getting them to click a link or open an attachment to deliver malware. Attack Patterns can also be more specific; spear phishing as practiced by a particular threat actor (e.g., they might generally say that the target won a contest) can also be an Attack Pattern. 

The Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks such as CAPEC. (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy) 

### 4.1.1 Properties
Mapping of the Stix Attack Pattern Properties to TypeDB

 Stix 2.1 Property| Schema Object | Schema Name | Required  Optional |
| :--- | :----: | :---: | :----: |
| type | stix-object | stix-type| Required |
| spec_version | stix-core-object | spec-version | Required |
| id | stix-object | stix-id | Required |
| created | stix-domain-object | created| Required |
| modified | stix-domain-object | modified| Required |
| name | attack-pattern | name | Required | 
| description | attack-pattern | description | Optional |
| aliases | attack-pattern | stix-role | Optional |
| kill_chain_phases | attack-pattern | identity sub-class | Optional |
| created_by_ref | stuff | stuff | Optional |
| revoked | stix-domain-object | revoked | Optional |
| labels | stix-domain-object | labels | Optional |
| confidence | stix-domain-object | confidence | Optional |
| lang | stix-domain-object | langs | Optional |
| external_references | stix-domain-object | external-referencing:referencing | Optional |
| object_marking_refs | stix-core-object | object-marking:marked | Optional |
| granular_markings | granular-marking | granular-marking:marked | Optional |
| extensions | stix-core-object | extensions | Optional |

### 4.1.2 Relationships
Mapping of the Stix Attack Pattern Relationships to TypeDB



-------------------------------------------------------------------------------------------------------------------------

## 4.2 Campaign Domain Object
A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set. (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_pcpvfz4ik6d6)

Campaigns are often attributed to an intrusion set and threat actors. The threat actors may reuse known infrastructure from the intrusion set or may set up new infrastructure specific for conducting that campaign. 

Campaigns can be characterized by their objectives and the incidents they cause, people or resources they target, and the resources (infrastructure, intelligence, Malware, Tools, etc.) they use. 

For example, a Campaign could be used to describe a crime syndicate's attack using a specific variant of malware and new C2 servers against the executives of ACME Bank during the summer of 2016 in order to gain secret information about an upcoming merger with another bank.

### 4.1.1 Properties
Mapping of the Stix Campaign Properties to TypeDB


### 4.1.2 Relationships
Mapping of the Stix Campaign Relationships to TypeDB



-------------------------------------------------------------------------------------------------------------------------

## 4.3 Course of Action Domain Object

### 4.1.1 Properties
Mapping of the Stix Course of Action Properties to TypeDB


### 4.1.2 Relationships
Mapping of the Stix Course of Action Relationships to TypeDB



-------------------------------------------------------------------------------------------------------------------------

## 4.2 Grouping Domain Object

### 4.1.1 Properties
Mapping of the Stix Grouping Properties to TypeDB


### 4.1.2 Relationships
Mapping of the Stix Grouping Relationships to TypeDB



-------------------------------------------------------------------------------------------------------------------------

## 4.5 Identity Domain Object
Mapping of the Stix Identity Data Standard to typeQL. For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>`
    `the stix2.v21 python library https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sdo.py`
    

### 4.5.1 Properties
Mapping of the Stix Identity Data Properties to typeQL.

 Stix 2.1 Property| Schema Object | Schema Name | Required  Optional |
| :--- | :----: | :---: | :----: |
| type | stix-object | stix-type| Required |
| spec_version | stix-core-object | spec-version | Required |
| id | stix-object | stix-id | Required |
| created_by_ref | stuff | stuff | Optional |
| created | stix-domain-object | created| Required |
| modified | stix-domain-object | modified| Required |
| name | identity | name | Required | 
| description | identity | description | Optional |
| roles | identity | stix-role | Optional |
| identity_class | identity | identity sub-class | Optional |
| sectors | identity | sector |  Optional |
| contact_information | identity | contact-information | Optional |
| revoked | stix-domain-object | revoked | Optional |
| labels | stix-domain-object | labels | Optional |
| confidence | stix-domain-object | confidence | Optional |
| lang | stix-domain-object | langs | Optional |
| external_references | stix-domain-object | external-referencing:referencing | Optional |
| object_marking_refs | stix-core-object | object-marking:marked | Optional |
| granular_markings | granular-marking | granular-marking:marked | Optional |
| extensions | stix-core-object | extensions | Optional |


### 4.5.2 Relationships
Mapping of the Stix Identity Data Relationships to typeQL.

|Source | Relationship type | Target | TypeQL Relation | Threat-Actor Role | Defined-on |
| :-------- | :----------- | :---------- | :--------- | :-------------- | :--------- | 
| identity | derived-from | identity | derivation | derivation:derived-from | stix-core-object |
| identity | duplicate-of | identity | duplicate | duplicate:duplicated-object | stix-core-object |
| identity | related-to | identity | relatedness | relatedness:related-to | stix-core-object |
| threat-actor | attributed-to | identity | attribution | attribution:attributed | identity |
| threat-actor | impersonates | identity | impersonate | impersonate:impersonating | identity |
| identity | located-at | location | located-at | located-at:locating | identity |
| attack-pattern, campaign, intrusion-set, malware, threat-actor, tool | targets | identity, location, vulnerability | target | target:targetted | identity |


------------------------------------------------------------------------------------------------------------------

## 4.6 Incident Domain Object

### 4.6.1 Properties
Mapping of the Stix Incident Properties to TypeDB


### 4.6.2 Relationships
Mapping of the Stix Incident Relationships to TypeDB



------------------------------------------------------------------------------------------------------------------

## 4.7 Indicator Domain Object

### 4.7.1 Properties
Mapping of the Stix Indicator Properties to TypeDB


### 4.7.2 Relationships
Mapping of the Stix Indicator Relationships to TypeDB



------------------------------------------------------------------------------------------------------------------

## 4.8 Infrastructure Domain Object
### 4.8.1 Properties
Mapping of the Stix Infrastructure Properties to TypeDB


### 4.8.2 Relationships
Mapping of the Stix Infrastructure Relationships to TypeDB


------------------------------------------------------------------------------------------------------------------
## 4.17 Threat Actor Domain Object
Mapping of the Stix Threat-Actor Data Standard to typeQL. For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k017w16zutw>`
    `the stix2.v21 python library https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sdo.py`

### 4.17.1 Properties
Mapping of the Stix Threat-Actor Data Properties to typeQL.

| Stix 2.1 Property| Schema Object | Schema Name | Required  Optional |
| :--- | :----: | :---: | :----: |
| type | stix-object | stix-type| Required |
| spec_version | stix-core-object | spec-version | Required |
| id | stix-object | stix-id | Required |
| created_by_ref | stuff | stuff | Optional |
| created | stix-domain-object | created| Required |
| modified | stix-domain-object | modified| Required |
| name | threat-actor | name | Required | 
| description | threat-actor | description | Optional |
| threat_actor_types | threat-actor | threat-actor-type | Optional |
| aliases | threat-actor | alias | Optional |
| first_seen | threat-actor | first-seen | Optional |
| last_seen | threat-actor | last-seen | Optional |
| roles | threat-actor | stix-role | Optional |
| goals | threat-actor | goals | Optional |
| sophistication | threat-actor | sophistication |  Optional |
| resource_level | threat-actor | resource-level | Optional |
| primary_motivation | threat-actor |primary-motivation | Optional |
| secondary_motivations | threat-actor | secondary-motivations | Optional |
| personal_motivations | threat-actor | personal-motivations | Optional |
| revoked | stix-domain-object | revoked | Optional |
| labels | stix-domain-object | labels | Optional |
| confidence | stix-domain-object | confidence | Optional |
| lang | stix-domain-object | langs | Optional |
| external_references | stix-domain-object | external-referencing:referencing | Optional |
| object_marking_refs | stix-core-object | object-marking:marked | Optional |
| granular_markings | granular-marking | granular-marking:marked | Optional |
| extensions | stix-core-object | extensions | Optional |

### 4.17.2 Threat-Actor Relationships
Mapping of the Stix Threat-Actor Relationships to typeQL.

|Source | Relationship type | Target | TypeQL Relation | Threat-Actor Role | Defined-on |
| :-------- | :----------- | :---------- | :--------- | :-------------- | :--------- | 
| threat-actor | derived-from | threat-actor | derivation | derivation:derived-from | stix-core-object |
| threat-actor | duplicate-of | threat-actor | duplicate | duplicate:duplicated-object | stix-core-object |
| threat-actor | related-to | threat-actor | relatedness | relatedness:related-to | stix-core-object |
| threat-actor | attributed-to | identity | attribution | attribution:attributing | threat-actor |
| campaign, intrusion-set | attributed-to | threat-actor | attribution | attribution:attributed | threat-actor |
| threat-actor | compromises | infrastructure | compromise | compromise:compromising | threat-actor |
| threat-actor | hosts, owns | infrastructure | host, ownership | host:hosting, ownership:owning | threat-actor |
| threat-actor | impersonates | identity | impersonate | impersonate:impersonating | threat-actor |
| threat-actor | located-at | location | located-at | located-at:locating | threat-actor |
| threat-actor | targets | identity, location, vulnerability | attribution | attribution:attributing | threat-actor |
| threat-actor | uses | attack-pattern, infrastructure, malware, tool | attribution | use:used-by | threat-actor |
| malware | authored-by | threat-actor  | authorship | authorship:authored | threat-actor |
| indicator | indicates | threat-actor  | what | how | where |


------------------------------------------------------------------------------------------------------------------


# 5. Stix Relationships

## 5.1 Relationship Core
The Relationship object is used to link together two SDOs or SCOs in order to describe how they are related to each other. If SDOs and SCOs are considered "nodes" or "vertices" in the graph, the Relationship Objects (SROs) represent "edges" (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cqhkqvhnlgfh). 

STIX defines many relationship types to link together SDOs and SCOs. These relationships are contained in the "Relationships" table under each SDO and SCO definition. Relationship types defined in the specification SHOULD be used to ensure consistency. An example of a specification-defined relationship is that an indicator indicates a campaign. That relationship type is listed in the Relationships section of the Indicator SDO definition.

 

| Stix Property | Typeql Name | Required - Optional |
| :---: | :---: | :---: |
| type | stix-type | Required |
| spec_version | spec-version | Required |
| id | stix-id | Required |
| created_by_ref | stuff here | Optional |
| created | created | Required|
| modified | modified | Required |
| relationship_type | relation class | Required |
| description | description | Optional |
| source_ref | source role | Required |
| target_ref | target role | Required |
| start_time | start-time | Optional |
| stop_time | stop-time | Optional |
| revoked | revoked | Optional |
| labels | labels | Optional |
| confidence | confidence | Optional |
| lang | lang | Optional |
| external_references |  external-references:referencing | Optional |
| object_marking_refs | object-marking:marked | Optional |
| granular_markings | granular-marking:marked | Optional |
| extensions | extensions | Optional |


## 5.2 Relationship Types

The Stix relationships consist of one relationship record, with many different relation_type fields. In the typeql mapping, each relationship type is converted into a sub-class of the stix-core-relationship, with custom parameters for the soruce and target, as shown in the table below.


| stix relation type | typeql relation name | source role | target role |
| :-------- | :----------- | :---------- | :--------- |
| delivers | delivers | delivering | delivered |
| targets | targets | targetter | targetted |
| uses | uses | used-by | used |
| attributed-to | attributed-to | result | fault-of |
| compromises | compromises | compromising | compromised |
| originates-from | originates-from | originating | originated-from |
| investigates | investigates | investigating | investigated |
| mitigates | mitigates | mitigator | mitigated |
| located-at | located-at | locating | located |
| indicates | indicates | indicating | indicated |
| based-on | based-on | basing-on | basis |
| communicates-with | communicates-with | communicating | communicated |
| consists-of | consist | consisting | consisted |
| controls | control | controlling | controlled |
| has | have | having | had |
| hosts | hosts | hosting | hosted | 
| owns | ownership | owning | owned |
| authored-by | authored-by | authoring | authored |
| beacons-to | beacon | beaconing-to | beaconed-to |
| exfiltrate-to | exfiltrate | exfiltrating-to | exfiltrated-to |
| downloads | download | downloading | downloaded |
| drops | drop | dropping | dropped |
| exploits | exploit | exploiting | exploited |
| variant-of | variant | variant-source | variant-target |
| characterizes | characterise | characterising | characterised |
| analysis-of | av-analysis | analysing | analysed |
| static-analysis-of | static-analysis | analysing | analysed |
| dynamic-analysis-of | dynamic-analysis | analysing | analysed |
| impersonates | impersonates | impersonating | impersonated |

## 5.3 Analysis Relation

A superset of the standard relation. It links malware analysis (analysing) to malware (analysed) and:
- host vm - an identifier for a SCO software object - property : host_vm_ref 
- operating system - an identifier for a SCO software object - property : operating_system_ref 
- installed software - an identifier for a SCO software object - property : installed_software_refs 
- captured sco - an identifier for a SCO software object - property : analysis_sco_refs 


```
	analysis sub stix-core-relationship,
		relates analysing as source,
		relates analysed as target,

		relates hosts-vm, 
		relates operating-system,
		relates installed-software,
		relates captured-sco;

		av-analysis sub analysis;
		static-analysis sub analysis;
		dynamic-analysis sub analysis;
```
