## 1 Introduction
There are a series of Best Practices defined by OASIS, some very useful Practices are not included. Many descisions were made to avoid duplication, but they were based on different data storage types (e.g. JSON database), which are not normalised. Thus OS-Threat should be able to improve on the OASIS standards, as it can more effectively avoid duplication. ([OASIS Best Practices](https://docs.oasis-open.org/cti/stix-bp/v1.0.0/stix-bp-v1.0.0.html))

## 2 General Best Practice

### 2.1 Support Interoperability
The main goal for OASIS is really interoperability between different systems, but for OS-Threat its more important to:
1. Leverage the unique features of TypeDB, for example normalised data attributes
2. Transform the diverse feed types, poorly framed data and temporal changes into a single cohesive data platform
3. Provide a detailed rationale for every decision and process

### 2.2 Use Common Object Repositiories
Where possible we should use commn objects, which should be written in only once. All references should then link to these objects.

These common objects currently include:
- MITRE ATT&CK ([ATT&CK-Data](https://github.com/mitre-attack/attack-stix-data))
- OASIS Stix Common Objects, mostly the identity, location and marking-definitions ([OASIS-CTI-Common](https://github.com/oasis-open/cti-stix-common-objects/tree/main/objects))
- Stix Enums, which are controlled vocabulary lists that are not currently implemented until TypeDB support arrives ([Stix Vocabularies](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_izngjy1g98l2))

==Features:==
- [ ] ==Current Feature:== Build Support for Common Objects
- [ ] ==Future Feature:== Build Support for Stix Vocabulary

### 2.3 Avoid Deprecated and Reserved Terms
Definitely convert v2.0 Cyber Observable Containers into v2.1 Cyber Observable Objects. This has implications for integrating with Stix Shifter and Kestrel.

The Section 7.3 Extension Definition mechanism should be used instead of the custom objects, custom properties and custom extension method. Note that we do not support this mechanism, and instead support the ATT&CK custom object approach. This could be the subject of a future feature epic.

==Features:==
- [ ] ==Current Feature:== Convert Stix-Shifter Cyber Ocservable Containers to Cyber Observable Objects
- [ ] ==Future Feature:== Build Support for Stix Vocabulary

### 2.4 Restrict Alowed Content within Trust Groups
The Best Practice is to enable Trust Groups to be setup, one expects through marking. This is not currently available and needs to be implemented as a feature.

==Features:==
- [ ] ==Future Feature:== Build Support for Trust Groups

## 3 Best Practices for General Stix Concepts

### 3.1 Versioning
Stix objects may evolve over time and can be updated only by the object creator, as specified by the `created_by_ref` field. The version of an object is specified by 3 fields:
- stix-id
- modified
- revoked

But not all objects have these fields, and can be versioned. If a material change is required, then a new object can be made.

#### 3.1.1 Temporal Records
Some thought needs to be put in to determine whether a history is to be maintained. Assume we wish to retain a history  of sightings, then there are three options:
1. We must maintain a temporal record per feed in the Kestral ProgresSql DB
2. The temporal log needs to be replicated in sightings or observable objects in TypeDB, so every observation imported generates two records, the observable and the record of the observable. This is actually a best practice anyway
3. When an observable is revoked, duplicated or updated by a feed channel, then rules need to be established to define what the responses should be. In general if the observable is revoked by a channel, and not used by any other feed, then it should be deleted. But how should this happen?

We need to develop a set of rules for how to handle all of the various scenarios for each feed.

==Features:==
- [ ] ==Current Feature:==  We need a set of rules to define all of the interactions for each different type of feed

| Situation| Best Practice|
| ----:|:-----:|
| Non-Current Object Version | Discard non-current versions unless there is a need to be able to investigate the object’s history|
| Two Different Objects, Same Identifier and Timestamp |  If a consumer receives two objects that are different, but have the same identifier and modified timestamp, new objects should be created for both. |
| Object Content No Longer Valid | When the content of an object is no longer valid, it should be revoked.  |


#### 3.1.2 Updating Objects
If a producer/consumer determines that an object should be updated, there are 4 options:
1. Object creators can create a new version of the object if a material change is not being made
2. Producers can create a new object, with a new id, that contains all of the correct information plus any changes, introduing a `derived-from` relationship between the original and the new. Producers who are not object creators cannot revoke it .
3. Producers who are not the object creator can use the Opinion object to comment on the content. The `object-refs` property of the Opinion object should refer to the object being commented on
4. Producers who are not the object creator can  enrich the content of an object via the use of the Note object. Once again, the `object-refs` property of the Note object should refer to the object being enriched

| Situation| Best Practice|
| ----:|:-----:|
| Update Existing Object | The “derived-from” relationship, Opinion object, or Note object should be used to update existing objects.|

### 3.2 Anonymization
There are many situations where an object crreator may choose to be anonymous. However, consumers may not trust objects where the creator is not specified. A best practice is to create and anonymous identity, where the trust group can maintain the linkage between the anonymous creator and the actual creator.

| Situation| Best Practice|
| ----:|:-----:|
| Anonymous Identity | Create an anonymous Identity object rather than omitting the created_by_ref property.|

### 3.3 Handling Dangling References
OS-Threat does not support dangling references at all.

| Situation| Best Practice|
| ----:|:-----:|
| Dangling References | Unless a reference refers to an object from a common repository, producers should attempt to avoid dangling references.|
| Dangling References |**When a dangling reference is found, the producer of the content should be queried for the missing object.**|

### 3.4 Defining and Using Identities
In general, the identity should be described and carried with objects.

| Situation| Best Practice|
| ----:|:-----:|
| Identities and Contacts | Identity objects that are not anonymized should include contact information.|
| All SDO/SCO Contain Identity | **All SDOs/SROs created by an object creator should contain the identifier of the object creator's Identity object in the** **created_by_ref** **property.**|

### 3.5 Data Marking
Dont send any TLP Data Markings, only provide markings that restrict the use of SCO's when necessary.

| Situation| Best Practice|
| ----:|:-----:|
| Data Marking | There is never a need to share a TLP Data Marking object.|
| Data Marking | Ignore any TLP data marking object that is shared.|
| Data Marking | Only provide data markings restricting the use of SCOs when necessary.|


### 3.6 Bundles
Basic bundle stuff

| Situation| Best Practice|
| ----:|:-----:|
| Bundles | STIX Bundle objects should be treated as transitory objects rather than permanent objects.|
| Bundles | All STIX 2.0 objects should be upgraded to STIX 2.1 objects.|
| Bundles | Include Identity objects referred to by other objects in the bundle.|


## 4.  Best Practices for Common Types and Common Properties

### 4.1    External References
Consistent names should be used to identify external references

### 4.2 Hashes
By default SHA-256 should be used on object creation. Some additional hash types are rported by software, but not supported by the standard. OS-Threat will include extensions to support all hash types.

### 4.3 Deterministic Identifiers
OS-Threat will use the Stix2 library to generate new objects, and  hence support deterministic identifiers

### 4.4 Kill Chain Phases
It was decided that there would not be STIX objects for specifying kill chains and kill chain phases. In general, they have no extra information other than their names, and there are not that many different ones that are commonly referred to. Trust groups can define kill chains of their own if the generally known ones are not sufficient.

### 4.5 Timestamps
Timestamps should generally be defined with between 3 and 6  digits in the sub seconds

### 4.6 Labels
Labels are used to share details about a Stix object tht are not defined as terms in the standard. Care should be taken when choosing label names. Using a prefix to identify a producer or trust group might help avoid name collisions.  

Lastly, data marking is the appropriate object type in STIX to use when representing issues such as shareability, ownership, sensitivity, and other policies of the data.

### 4.7 Spec Version
The Spec version should be included on all objects

### 4.8 Confidence
Appendix A of the specificatin includes the confidence scales

### 4.9 Optional Common Properties
Stix objects should contain confidence scores and external references

| Situation| Best Practice|
| ----:|:-----:|
| External References | When possible, use consistent source names to identify external sources.|
| Hashes | SHA-256 should be used by content producers when generating a hash.|
| Deterministic Identifiers | Deterministic identifiers should be generated for SCOs using identifier contributing properties as defined in the specification to reduce the number of duplicate SCOs.|
| Deterministic Identifiers | Deterministic identifiers are not always appropriate given the use case and the SCO type.|
| Labels | Labels should only be used for content that connot be represented using other STIX properties|
| Spec Version | The "spec_version" proeprty should be provided on SCO's .|
| Confidence | STIX content should leverage a confidence scale that is selected from Appendix A of the STIX specification.|
| Common Properties | Each object should include a confidence score and external references to provide users of the information with valuable context.|

## 5 Best Practices for SDOs and SROs

### 5.1 Best Practices for Optional Properties
In general, the more properties on a STIX object, the more informative it will be

|Type | Best PRactice Properties |
|:----- | :--- |
|Campaign | `first_seen`, `objective` |
| Course of Action | `description` |
| Grouping | `description`, `name` |
| Identity|  `identity_class`, `sector` |
| Incident | `description` |
| Indicator | `indicator_type`, `kill_chain_phases` |
| Infrastructure |`description`, `infrastructure_type`, `first_seen`, `kill_chain_phases` |
| Intrusion Set | `first_seen`, `goals`, `primary_motivation` |
| Malware | `capabilities`, `malware_types`, `operating_system_refs`, `sample_refs` |
| Note | `authors` |
| Observed Data | `first_observed`|
| Opinion | `authors`, `explanation` |
| Sighting | `first_seen`, `last_seen`, `where_sighted_refs` |
| Threat Actor |`aliases`, `first_seen`, `goals`, `primary_motivation`, `threat_actor_type`|

### 5.2    Attack Patterns
OS-Threat includes the ATT&CK  content for Attack Patterns, so that they are only written once. Currently it does not incude the CAPEC objects.

### 5.3 Campaigns, Threat Actors, Groupings and Intrusion Sets
These STIX objects are used to share inferred cyber threat data. They are usually created as part of cyber analysis. Consider the following Rules.

Rules:
1. *Grouping:*
	1. If many objects have been found, without n overarching story, then the `grouping` object  asserts they are associated, without introducing explicit SRO's
	2. If one object has many of the same named relationship's to a set of target objects (a one to many relationship), then instead one named relationship to a `grouping` removes the need for many SRO's
2. *Campaign:*
	1. Using a `grouping` object may enable the start of a story development, which is captured as a `campaign` object
3. *Threat-Actor:*
	1. A `threat-actor` object is used to express who has been determined to be responsible for the malicious activity
	2. Sharing a `threat-actor` and its related objects is used to make others aware of the attack pattern
4. *Intrusion-Set:*
	1. An `intrusion-set` is a way to relate all of the adversarial behaviours and resources via a single object
	2. An `intrusion-set` is a vetted collection of cyber threat information for sharing

### 5.4 Incidents
1. Incidents 
	1. exist as a stub onject in Stix 21
2. Core Incident Extension - Stix Common Objects
	1. This extension should be used to give more robust incident reporting
	2. Sensitive incident details can be detailed in the master  `incident` SDO, and a new object can be authored with the filtered information, and related through a `derived-from` relationship object
	3. Incident response times are generally imprecise human values, and thereby systems that enable human entered values should restrict the fidelity (i.e. no millisecs or secs) `timestamp_fidelity`
3. External References:
	1. Most incident tracking systems will not have UUID's, and should be included in the external references fields
4. Course of Action
	1. Can be used to define the security controls that organisations put in place based on industry standards and regulations
	2. By recording the controls that failed during an incident it enables improvements to be made, using the relationships `for-prevention-of` or `for-mitigation-of` then adding a label indicating the success or failure
5. Attacker Activities
	1. Enables recording of the sequence, time span, outcome, goal, and attack pattern of attack activities along with the impacted infrastructure and technical observations made as part of this portion of the incident.
6. Defender Activities
	1. Recording key events enables a timeline to be shared between systems that are involved within the incident response process
	2. The defender sub-object includes the property `is_projection`. when set to true this indicates a future event and is often used to communicate estimated recovery dates
7. Impacts
	1. Zero's should be recorded for `availability_impact`, `confidentiality_impacts`, `integrity_impacts` and `physical_impacts` if there is no impact
	2. Otherwise values can be provided

### 5.5 Infrastructure
The `infrastructure` object is used to describe systems, software services, and any associated physical or virtual resources that are part of the offensive or defensive activity of an attack

Often such things can be described without the use of an `infrastructure` object. For instance, a malware instance could be used by a server at particular IP address. It might be tempting to connect the `malware` instance to the IP address via a `relationship` object of type `uses`. However, a best practice is to express this information through the use of an `infrastructure` object.

### 5.6 Malware
A  `malware` object can be used to represent both individual instances of malware as well as families of malware. To assist with graph analysis of STIX content, if your organization generates `malware` SDOs to represent families it is best to ensure that the UUIDs of these SDOs are tracked and updated instead of authoring new `malware` SDOs for the family each time a matching sample arrives.

### 5.7 Malware Analysis
Most anti-virus products assess if a file is believed to be malicious based on dynamic rules and heuristics. These methods cannot assert an application is safe only that the file does not appear to have malicious characteristics.

Malware Analysis pipelines are represented by chains of malware-analysis SDOs where each one inputs a value found in the **sample_ref** property and outputs a value found in the **analysis_sco_refs** property that can in turn be analyzed by other tools in the pipeline. By ensuring inputs and outputs are mapped consistently, useful tooling and analysis information can be easily determined.

### 5.8 Opinion and Notes
`opinion` objects are useful only to assess the correctness of information ***provided by others***.  An opinion object can never be used by the object creator, who can only version or revoke it.

An SCO represents facts, so relating it to an `opinion` object doesn't make sense. However, there can be use cases for a `note` object to be related to an SCO.

### 5.9 Observed Data
`observed-data` objects are defined with semantics to support the matching of STIX indicator pattenrs. Contained SCO's must always form a connected graph, with one root and all others reachable from that. It cannot be used for multiple unrelated objects.

### 5.10 Reports
When an extensive analysis is done, then analysts will usuy publish it in a document or `report` object.


### 5.11 Vulnerability
CVE is the standard registry for vulnerabilities and is managed by NIST and MITRE. Most vulnerability objects will refer to an already registered CVE via the **`external_references`** property. The CVE entry itself contains many links to additional information related to the vulnerability, so it is a best practice to not duplicate them as external references in a `vulnerability` object.


### 5.12 Relationships
Standard relationship names defined in the specification should be used when possible. However, other relationship names are allowed, but not currently supported in OS-Threat.

- `dervied-from` to be used if creating a new object from an old one, not for versioning
- `duplicate-of` ideally duplicate objects are merged into a single, new object
- `related-to` used if the semantics of the `relationship` object are not fully known


### 5.13 Sightings
The purpose of the `sighting` object is not to indicate that an SCO has been seen. That fact should be represented using an `observed-data` object. A Sighting object denotes the inference that some higher-level cyber threat object has been sighted.


|Situation | Best Practice |
|:---| :---|
|Optional Properties |Optional properties on SDOs and SROs should be populated to make them more informative.|
| Attack Patterns| STIX content that references ATT&CK or CAPEC should leverage the authoritative Attack Pattern objects.|
| Campaigns, Threat Actors, Groupings and Intrusion Sets| The selection of the appropriate SDO to use should be made carefully. |
| Incidents| Incident SDOs should include the core incident extension (extension-definition--ef765651-680c-498d-9894-99799f2fa126) to ensure robust incident reporting can be performed. |
| Incidents | Create derivative Incident SDOs to support sharing only public details while maintaining non-sharable data internally. |
| Incidents | Use external_references to correlate STIX Incident SDOs with internal systems. |
| Incidents |Record failed security controls using Courses of Action SDOs connected to the Incident using Relationships. |
| Incidents | Record observed data within the attacker_activities property of an Incident. |
| Inidents | Record defender_activities associated with incident response within an Incident. |
| Inidents | When recording attacker and defender activities set the relevant timestamp fidelity properties(s). |
| Inidents | Provide estimated recovery times for systems using the is_projection flag property of the defender_activities property.|
| Inidents | Record none for confidentiality_impacts integrity_impacts, and physical_impacts properties if there is no impact. Record 0 for the availability_impact property if there is no availability impact. |
| Infrastructure | The Infrastructure object should be used to describe systems, software services, and any associated physical or virtual resources that are part of the offensive or defensive activity of an attack. |
| Malware |Use consistent Malware SDOs to represent families|
| Malware | Create non-family Malware SDOs for samples that have relationships to their malware families instead of automatically updating the family’s SDO. |
| Malware Analysis | When recording anti-virus results the result_name property of the Malware Analysis object should record the tool’s specific name of the finding (if present) and in the result property the generic result of “malicious”, “suspicious”, or “unknown” as appropriate. Only tools that use known files lists should ever report “benign”. |
| Malware Analysis | Tools that perform static or dynamic analysis on malware to extract SCOs should record these results using analysis_sco_refs property. |
| Malware Analysis | Use Malware Analysis when Indicators cannot be shared. |
| Opinions and Notes | Opinions and Notes should not be used by the object creator. |
| Opinions and Notes | Opinions should not be used for SCOs |
| Opinions and Notes | The authors property on a Note object should be used to indicate the individual or application that created the Note. |
| Reports | Report objects should be used to share the details of the investigation of an attack. |
| Vulnerability | Avoid duplicate Vulnerability objects to refer to a CVE. |
| Vulnerability | Vulnerabilities without a CVE reference should be fully described in the description property including any external references that are available. |
| Relationships | Duplicate objects should be merged into a single new object using `duplicate_of`. |
| Sightings | SDOs that you observe should be represented with a Sightings object whereas SCOs that you observe should be represented in Observed Data. |
| Sightings | Although the object sighted should be an SDO, the related SCO should be included whenever possible. |
| Sightings | Changes to certain properties should not be viewed as a material change to the Sighting object. |
| Sightings | A Sighting with count=0 can be used to indicate a window of time when an SDO was not seen. |
| Sightings | Because sightings may enable others to act more quickly on cyber threat intelligence, a best practice is that organizations submit and produce Sightings as frequently as possible. |