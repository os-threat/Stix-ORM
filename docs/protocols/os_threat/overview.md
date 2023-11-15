# OS-Threat Custom Objects







### OS-Threat Domain Objects (SDO)



There are 4 OS-Threat Domain Objects, as shown in the table below





### OS-Threat Cyber Observable Objects (SCO)



There is 1 OS-Threat Cyber Observable Object, as shown in the table below





### OS-Threat Extension Objects (SUB)



There are 16 OS-Threat Extension Objects,  as shown in the table below






###  Domain Object Types

#### OS-Threat Stix Extensions 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Event](https://raw.githubusercontent.com/os-threat/images/main/img/rect-event.svg) | [Event](./sdo/Event.md) | Events are created by Sightings of suspicious or malicious activity on systems. Sightings are the footprint of malicious activity, whereas Events are the occurrence. Events integrate the start and end time, the number and type of changed objects, the goal and description to the Sightings. |
| ![Impact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact.svg) | [Impact](./sdo/Impact.md) | Incidents have Impacts that change over time. Events can cause or influence these Impacts which are in turn mitigated and potentially resolved by tasks performed as part of the incident response process.Change in Impacts over time is recorded in state-change sub-objects within Tasks or Event definitions |
| ![Task](https://raw.githubusercontent.com/os-threat/images/main/img/rect-task.svg) | [Task](./sdo/Task.md) | Tasks represent the work element needed to respond to, qualify and remediate Events and Impacts within an Incident |
| ![Sequence](https://raw.githubusercontent.com/os-threat/images/main/img/rect-step-single.svg) | [Sequence](./sdo/Sequence.md) | The Sequence SDO representes the sequencing of Events or Tasks, using the CACAO approach. Each Sequence object must be of a specific sequence_type (event or task) and step_type (start_step, single-step, parallel_step, end_step). Then the usage of the on_completion, on_succes/on_failure, or next_steps fields are the same as CACAO. Single-step Sequences then link to an event or task viz the sequenced_object field. |




###  Cyber Observable Object Types

#### OS-Threat Stix Extensions 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-anecdote.svg) | [Anecdote](./sco/Anecdote.md) | Anecdotes are reports provided by people that can relate to Events or Impacts. Anecdote SCO's record these details, connecting the identity of the reporter, the date of the report and the text provided. |




###  Relationship Object Types


###  Extension Object Types

#### OS-Threat Stix Extensions 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Impact-Availability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-availability.svg) | [Impact-Availability](./sub/Impact-Availability.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Availability Extension tracks the impact of availability in assets |
| ![Impact-Confidentiality](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-confidentiality.svg) | [Impact-Confidentiality](./sub/Impact-Confidentiality.md) | Every Impact MUST have an extension that has the same value of the impact_category. The confidentiality extension tracks the type of information and the type of loss involved as the impact.  |
| ![Impact-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-external.svg) | [Impact-External](./sub/Impact-External.md) | Every Impact MUST have an extension that has the same value of the impact_category. The External Extension tracks the impact on external assets. |
| ![Impact-Integrity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-integrity.svg) | [Impact-Integrity](./sub/Impact-Integrity.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Integrity Extension tracks the alteration in information assets. |
| ![Impact-Monetary](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-monetary.svg) | [Impact-Monetary](./sub/Impact-Monetary.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Monetary Extension tracks the monetary impact, for example ransom amounts. |
| ![Impact-Physical](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-physical.svg) | [Impact-Physical](./sub/Impact-Physical.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Physical Extension tracks the physical impact on assets |
| ![Impact-Traceability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-traceability.svg) | [Impact-Traceability](./sub/Impact-Traceability.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Traceability Extension tracks whether the traces left by the threat-actor, are sufficient to enable attribution. |
| ![Sighting-Alert](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-alert.svg) | [Sighting-Alert](./sub/Sighting-Alert.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Alert can be issued by a system or a user. Generally, when an Alert is issued, it is not known whether it is actually nefarious. Alerts are often used to initiailise an incident. Conceivably, once an Alert is qualified as a true positive, it could be joined to another Alert from another Incident.  |
| ![Sighting-Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-anecdote.svg) | [Sighting-Anecdote](./sub/Sighting-Anecdote.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Anecdote can be issued only by a person. Generally, when an Anecdote is issued, it is not known whether it is actually nefarious. Anecdotes are used to initiailise an incident. Conceivably, an Anecdote may also be issued that defines an Impact, rather than an Event Anecdotes are expected to have low confidence and result in the need to do tasks to increase the confidence. |
| ![Sighting-Context](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-context.svg) | [Sighting-Context](./sub/Sighting-Context.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Context data is based on querying of internal systems and has 100% confidence It can be of two types: Non-SCO: Historical or narrative data that would be contained in a Note, and is not an Event. The Note can attach to different objects, depending on the Inicdent type. SCO: For example a list of other user accounts that received the same email, queried from Exchange server, and is an Event. This example is shown to the right |
| ![Sighting-Exclusion](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-exclusion.svg) | [Sighting-Exclusion](./sub/Sighting-Exclusion.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Exclusion List is a source that provides a list of entities that have been shown by their processes (?) to be nefarious. Generally Exclusion lists are focused on specific approaches, such as phshing etc. There are often multiple sources covering the same approach, and it is to be expected that if an entity is found in multiple sources, then it has more confidence than if it is found in one out of many sources. A search on an Exclusion List can result in a sighting, but not an event, as it adds to the data available about. |
| ![Sighting-Enrichment](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-enrichment.svg) | [Sighting-Enrichment](./sub/Sighting-Enrichment.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). An Enrichment is an expansion in the evidence, by leveraging existing data and querying paid or free intel sources to return observables. The results of an Enrichment will generally be an SCO, although SDO’s can also be returned. Note observables may not be in the current SCO list. |
| ![Sighting-Hunt](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-hunt.svg) | [Sighting-Hunt](./sub/Sighting-Hunt.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). A Hunt is a targeted search using a hunting platform, such as Kestrel, or similar, started as a Task. A Hunt can result in: 1. Confirmation that an Alert has resulted in a negative Impact (e.g. user clicked on link, Outlook, which downloaded software and started a process), 2. Scope of Impact, which machines were impacted, 3. An Alert, since an unknown threat has been discovered. |
| ![Sighting-Framework](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-framework.svg) | [Sighting-Framework](./sub/Sighting-Framework.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Since SCO’s are ephemeral, the desire is to move up the Pyramid of Pain to more abstract characterisations, which are harder for attackers to evade. Frameworks, such as Mitre ATT&CK and DISARM are commonly used. Assignment of a Framework Component requires a judgement, or a correlation from a knowledge base, and thereby has subjectivity. |
| ![Sighting-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-external.svg) | [Sighting-External](./sub/Sighting-External.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Threat Reports are posted by researchers on free and paid services, such as MISP. This is one method of confirming that an unknown Indicator is actually malicious. However, reliability of a threat report is a concern, and confidence needs to be established for each individual provider in a channel such as MISP. |
| ![Identity-Contact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-identity-contact.svg) | [Identity-Contact](./sub/Identity-Contact.md) | The current STIX 2.1 Identity object only contains a single text field for contact information. This is insufficient to effectively move contact information for individuals between automated systems. This extension adds more granular tracking so that this can be effectively communicated between systems. |



