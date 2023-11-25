# MITRE ATT&CK Protocol



### ATT&CK Domain Objects (SDO)



There are 13 ATT&CK Domain Objects, as shown in the table below



### ATT&CK Relationship Objects



There is 1 &ACK Relationship Object,as shown in the table below








###  Domain Object Types

#### MITRE ATT&CK 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Sub-Technique](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-subtechnique.svg) | [Sub-Technique](./sdo/Sub-Technique.md) | A sub-technique in ATT&CK is represented as an attack-pattern and follows the same format as techniques. They differ in that they have a boolean field (x_mitre_is_subtechnique) marking them as sub-techniques, and a relationship of the type subtechnique-of where the source_ref is the sub-technique and the target_ref is the parent technique. A sub-technique can only have 1 parent technique, but techniques can have multiple sub-techniques. |
| ![Technique](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-technique.svg) | [Technique](./sdo/Technique.md) | A Technique in ATT&CK is defined as an attack-pattern object.Techniques map into tactics by use of their kill_chain_phases property. Where the kill_chain_name is mitre-attack, mitre-mobile-attack, or mitre-ics-attack (for enterprise, mobile, and ics domains respectively), the phase_name corresponds to the x_mitre_shortname property of an x-mitre-tactic object. |
| ![Tactic](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-tactic.svg) | [Tactic](./sdo/Tactic.md) | A Tactic in ATT&CK is defined by an x-mitre-tactic object. As a custom STIX type they follow only the generic STIX Domain Object pattern. |
| ![Campaign](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-campaign.svg) | [Campaign](./sdo/Campaign.md) | A Campaign in ATT&CK is defined as a campaign object. |
| ![Collection](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-collection.svg) | [Collection](./sdo/Collection.md) | A collection is a set of related ATT&CK objects; collections may be used to represent specific releases of a dataset such as "Enterprise ATT&CK v7.2", or any other set of objects one may want to share with someone else. |
| ![Data-Component](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-data-component.svg) | [Data-Component](./sdo/Data-Component.md) | A Data Component in ATT&CK is represented as an x-mitre-data-component object. As a custom STIX type they follow only the generic STIX Domain Object pattern. |
| ![Data-Source](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-data-source.svg) | [Data-Source](./sdo/Data-Source.md) | A Data Source in ATT&CK is defined by an x-mitre-data-source object. As a custom STIX type they follow only the generic STIX Domain Object pattern. |
| ![Group](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-group.svg) | [Group](./sdo/Group.md) | A Group in ATT&CK is defined as an intrusion-set object. ATT&CK Groups do not depart from the STIX intrusion-set spec. |
| ![Identity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-identity.svg) | [Identity](./sdo/Identity.md) | Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector). The Mitre ATT&CK Identity is generally used to represent Mitre themselves, and contains additional properties not in the standard Identity. |
| ![Matrix](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-matrix.svg) | [Matrix](./sdo/Matrix.md) | The overall layout of the ATT&CK Matrices is stored in x-mitre-matrix objects. As a custom STIX type they follow only the generic STIX Domain Object pattern. |
| ![Mitigation](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-mitigation.svg) | [Mitigation](./sdo/Mitigation.md) | A Mitigation in ATT&CK is defined as a course-of-action object. ATT&CK Mitigations do not depart from the STIX course-of-action spec. |
| ![Software-Malware](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-software.svg) | [Software-Malware](./sdo/Software-Malware.md) | Software in ATT&CK is the union of two distinct STIX types: malware and tool. |
| ![Software-Tool](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-software.svg) | [Software-Tool](./sdo/Software-Tool.md) | Software in ATT&CK is the union of two distinct STIX types: malware and tool. |




###  Cyber Observable Object Types


###  Relationship Object Types

#### MITRE ATT&CK 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Procedure](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-procedure.svg) | [Procedure](./sro/Procedure.md) | ATT&CK does not represent procedures under their own STIX type. Instead, procedures are represented as relationships of type uses where the target_ref is a technique. This means that procedures can stem from usage by both groups (intrusion-sets) and software (malware or tools). The content of the procedure is described in the relationship description. |




###  Extension Object Types

