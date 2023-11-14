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
| ![Event](https://raw.githubusercontent.com/os-threat/images/main/img/rect-event.svg) | [Event](./docs/protocols/os_threat/sdo/Event.md) | Events are created by Sightings of suspicious or malicious activity on systems. Sightings are the footprint of malicious activity, whereas Events are the occurrence. Events integrate the start and end time, the number and type of changed objects, the goal and description to the Sightings. |
| ![Impact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact.svg) | [Impact](./docs/protocols/os_threat/sdo/Impact.md) | Incidents have Impacts that change over time. Events can cause or influence these Impacts which are in turn mitigated and potentially resolved by tasks performed as part of the incident response process.Change in Impacts over time is recorded in state-change sub-objects within Tasks or Event definitions |
| ![Task](https://raw.githubusercontent.com/os-threat/images/main/img/rect-task.svg) | [Task](./docs/protocols/os_threat/sdo/Task.md) | Tasks represent the work element needed to respond to, qualify and remediate Events and Impacts within an Incident |
| ![Sequence](https://raw.githubusercontent.com/os-threat/images/main/img/rect-step-single.svg) | [Sequence](./docs/protocols/os_threat/sdo/Sequence.md) | The Sequence SDO representes the sequencing of Events or Tasks, using the CACAO approach. Each Sequence object must be of a specific sequence_type (event or task) and step_type (start_step, single-step, parallel_step, end_step). Then the usage of the on_completion, on_succes/on_failure, or next_steps fields are the same as CACAO. Single-step Sequences then link to an event or task viz the sequenced_object field. |




###  Cyber Observable Object Types

#### OS-Threat Stix Extensions 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-anecdote.svg) | [Anecdote](./docs/protocols/os_threat/sco/Anecdote.md) | Anecdotes are reports provided by people that can relate to Events or Impacts. Anecdote SCO's record these details, connecting the identity of the reporter, the date of the report and the text provided. |




###  Relationship Object Types


###  Extension Object Types

#### OS-Threat Stix Extensions 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Impact-Availability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-availability.svg) | [Impact-Availability](./docs/protocols/os_threat/sub/Impact-Availability.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Availability Extension tracks the impact of availability in assets |
| ![Impact-Confidentiality](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-confidentiality.svg) | [Impact-Confidentiality](./docs/protocols/os_threat/sub/Impact-Confidentiality.md) | Every Impact MUST have an extension that has the same value of the impact_category. The confidentiality extension tracks the type of information and the type of loss involved as the impact.  |
| ![Impact-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-external.svg) | [Impact-External](./docs/protocols/os_threat/sub/Impact-External.md) | Every Impact MUST have an extension that has the same value of the impact_category. The External Extension tracks the impact on external assets. |
| ![Impact-Integrity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-integrity.svg) | [Impact-Integrity](./docs/protocols/os_threat/sub/Impact-Integrity.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Integrity Extension tracks the alteration in information assets. |
| ![Impact-Monetary](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-monetary.svg) | [Impact-Monetary](./docs/protocols/os_threat/sub/Impact-Monetary.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Monetary Extension tracks the monetary impact, for example ransom amounts. |
| ![Impact-Physical](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-physical.svg) | [Impact-Physical](./docs/protocols/os_threat/sub/Impact-Physical.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Physical Extension tracks the physical impact on assets |
| ![Impact-Traceability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-traceability.svg) | [Impact-Traceability](./docs/protocols/os_threat/sub/Impact-Traceability.md) | Every Impact MUST have an extension that has the same value of the impact_category. The Traceability Extension tracks whether the traces left by the threat-actor, are sufficient to enable attribution. |
| ![Sighting-Alert](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-alert.svg) | [Sighting-Alert](./docs/protocols/os_threat/sub/Sighting-Alert.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-anecdote.svg) | [Sighting-Anecdote](./docs/protocols/os_threat/sub/Sighting-Anecdote.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Context](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-context.svg) | [Sighting-Context](./docs/protocols/os_threat/sub/Sighting-Context.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Exclusion](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-exclusion.svg) | [Sighting-Exclusion](./docs/protocols/os_threat/sub/Sighting-Exclusion.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Enrichment](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-enrichment.svg) | [Sighting-Enrichment](./docs/protocols/os_threat/sub/Sighting-Enrichment.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Hunt](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-hunt.svg) | [Sighting-Hunt](./docs/protocols/os_threat/sub/Sighting-Hunt.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-Framework](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-framework.svg) | [Sighting-Framework](./docs/protocols/os_threat/sub/Sighting-Framework.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Sighting-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-external.svg) | [Sighting-External](./docs/protocols/os_threat/sub/Sighting-External.md) | The Sighting object is used for connecting Observed Data objects to SDO’s, such as Indicators, Malware and Threat Actors, based on Locations. Observations and Sightings have different evidentiary weightings based on their type (what they are) and provenance (how they were derived). Weightings cannot be established as provenance data is not collected for each observation, and confidence cannot be established. At present, Observations and Sightings cannot be added together as evidence, as they are different in nature. Sighting Extensions are used to collect the provenance for each type of data source. |
| ![Identity-Contact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-identity-contact.svg) | [Identity-Contact](./docs/protocols/os_threat/sub/Identity-Contact.md) | The current STIX 2.1 Identity object only contains a single text field for contact information. This is insufficient to effectively move contact information for individuals between automated systems. This extension adds more granular tracking so that this can be effectively communicated between systems. |



