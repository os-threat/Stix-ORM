# Stix-ORM Overview



The Stix-ORM Library is an open-source Python Library built on top of the [OASIS Stix2 Python Library](https://stix2.readthedocs.io/en/latest/index.html) in order to make it simple to use TypeDB as a [DataStore](https://stix2.readthedocs.io/en/latest/guide/datastore.html), and extend it to suit additional protocols, such as Mitre ATT&CK, OASIS CACAO, OCA Kestrel, and custom objects (e.g. case management, feed management etc).



## What is the Stix-ORM?

The [OASIS Stix2 Python Library](https://stix2.readthedocs.io/en/latest/index.html) is designed to make it as easy as possible to produce and consume Stix 2.1 content. It is comprised of three layers:

1. Object Layer: Is where Python objects representing the Stix 2,1 data types (SDO, SCO and SRO), and sub-objects (external references, kill-chain phases, extensions etc.) are create and can be sereialised and deserialised to and from their JSON representation

2. Environment Layer: Components that make it easier to handle Stix 2.1 data as part of alarger applications, including DataSink's for storing data, DataSource's for retrieving data, and Object Factory's to create al of the common properties and markings

3. Workbench Layer: Python functions for use in an interctive environment (e.g. Jupyter Notebook) to enable comparison of objects, searching for objects and comparison of graphs.



The [OS-Threat Stix-ORM Library]() integrates with the OASIS Stix 2 Python Library to:

1. Provide a TypeDB DataSource and DataSink capability to store and retrieve Stix objects using simple python verbs, add, get, delete etc., including a simple reasoning system

2. Extend the Python Object, Parse, TypeDB DataSource and DataSink capabilities to additional cybersecurity protocols, such as MITRE ATT&CK, enabling validation of incoming objects, and the ability to create new correct objects

3. Enable custom objects, Stix extensions and new language protocols to be added relatively easily, so the library can be extended easily by users and researchers. 

4. Load common data assets, Stix - TLP-markings, common objects, MITRE ATT&CK, CVE's

5. Produce a platform for further developments and collaboration



The OS-Threat Stix-ORM library can be installed using pip, and is well documented.



An image of these concepts is shown below.

![](img/Library_overview.png)



## Stix ORM has an Apache 2 Client, and an AGPL3 Server

The OS-Threat Stix-ORM Library is split into two repos:

1. The object definitions and documents ("the client") as a github sub module under an Apache 2 license

2. The ORM (Object Role Modelling) code and associated libraries ("the server") under an AGPL3 license



This intentional splitting of the code base enables users to freely modify objects, or create their own objects and extensions, without any license restriction. Ideally, users make their own documentation for these customisations as well.



It is not exected that users will ever want to or need to customise the ORM code, although they are fully able to do so under the open source license. In short, this arrangement enables all users to make ad-hoc changes as required without cany concern about copy left licensing.



## What are the Benefits?

[TypeDB is without a doubt, the most powerful datastore for cybersecurity](typedb_benefits.md), because:

1. Semantic Hypergraph: Enables elegant, succinct representation of intricate cybersecurity objects and relationships

2. Fully Normalised Attributes: Data is only written once (e.g. Stix-ID, hash etc.), as attrbutes are normalised as a database guarantee

3. Unique Data Modelling: Unique modelling capabilities of attributes owning attributes (used in key-value store), and relations able to play roles in other relations

4. Class hierarchy on Entities, Relations and Attributes: Enables rich behavioural modelling of objects, sub-objects, properties, relations and linkages

5. When->Then Horn Logic rule system, enabling inference over large datasets dynamically triggered at query time, with an included example

6. Elegant query of complex objects through class hierarchy combined with rulesets



## Near-term Feature Roadmap

Very quickly we aim to add the following features to the system.

1. Add support for OASIS CACAO and OCA Kestrel protocols

2. Add support for Stix Patterns, and extend the method to all objects and properties

3. Add support for open vocabulary words to be selectively added

4. Add support for Stix extensions, and the ability to import Stix extensions

5. Add support for Detections, Mitigations and Tests connected to TTP's, and NIST Controls

6. Add import capability for all rulesets, tests and controls (e.g. Control Compass and Engenuity CTID)



The documentation system contains the following sections:

- [Using the Stix-ORM](install/configuration.md)

- [How the ORM Works](how_it_works/orm_oveview.md)

- [Protcols Supported](protocols/_orig.md)

- [Interacting with Stix-ORM](interactions/overview.md)



The current supported objects can be viewed here








###  Domain Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Attack-Pattern](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-pattern.svg) | [Attack-Pattern](./docs/stix21/sdo/Attack-Pattern.md)| ![Campaign](https://raw.githubusercontent.com/os-threat/images/main/img/rect-campaign.svg) | [Campaign](./docs/stix21/sdo/Campaign.md)| ![Course-of-Action](https://raw.githubusercontent.com/os-threat/images/main/img/rect-course-of-action.svg) | [Course-of-Action](./docs/stix21/sdo/Course-of-Action.md) |
| ![Grouping](https://raw.githubusercontent.com/os-threat/images/main/img/rect-grouping.svg) | [Grouping](./docs/stix21/sdo/Grouping.md)| ![Identity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-identity-individual.svg) | [Identity](./docs/stix21/sdo/Identity.md)| ![Incident](https://raw.githubusercontent.com/os-threat/images/main/img/rect-incident.svg) | [Incident](./docs/stix21/sdo/Incident.md) |
| ![Indicator](https://raw.githubusercontent.com/os-threat/images/main/img/rect-indicator.svg) | [Indicator](./docs/stix21/sdo/Indicator.md)| ![Infrastructure](https://raw.githubusercontent.com/os-threat/images/main/img/rect-infrastructure.svg) | [Infrastructure](./docs/stix21/sdo/Infrastructure.md)| ![Intrusion-Set](https://raw.githubusercontent.com/os-threat/images/main/img/rect-intrusion-set.svg) | [Intrusion-Set](./docs/stix21/sdo/Intrusion-Set.md) |
| ![Location](https://raw.githubusercontent.com/os-threat/images/main/img/rect-location.svg) | [Location](./docs/stix21/sdo/Location.md)| ![Malware](https://raw.githubusercontent.com/os-threat/images/main/img/rect-malware.svg) | [Malware](./docs/stix21/sdo/Malware.md)| ![Malware-Analysis](https://raw.githubusercontent.com/os-threat/images/main/img/rect-malware-analysis.svg) | [Malware-Analysis](./docs/stix21/sdo/Malware-Analysis.md) |
| ![Note](https://raw.githubusercontent.com/os-threat/images/main/img/rect-note.svg) | [Note](./docs/stix21/sdo/Note.md)| ![Observed-Data](https://raw.githubusercontent.com/os-threat/images/main/img/rect-observed-data.svg) | [Observed-Data](./docs/stix21/sdo/Observed-Data.md)| ![Opinion](https://raw.githubusercontent.com/os-threat/images/main/img/rect-opinion.svg) | [Opinion](./docs/stix21/sdo/Opinion.md) |
| ![Report](https://raw.githubusercontent.com/os-threat/images/main/img/rect-report.svg) | [Report](./docs/stix21/sdo/Report.md)| ![Threat-Actor](https://raw.githubusercontent.com/os-threat/images/main/img/rect-threat-actor.svg) | [Threat-Actor](./docs/stix21/sdo/Threat-Actor.md)| ![Tool](https://raw.githubusercontent.com/os-threat/images/main/img/rect-tool.svg) | [Tool](./docs/stix21/sdo/Tool.md) |
| ![Vulnerability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-vulnerability.svg) | [Vulnerability](./docs/stix21/sdo/Vulnerability.md)| ![]() | []()| ![]() | []() |



#### OS-Threat Stix Extensions 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Event](https://raw.githubusercontent.com/os-threat/images/main/img/rect-event.svg) | [Event](./docs/os_threat/sdo/Event.md)| ![Impact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact.svg) | [Impact](./docs/os_threat/sdo/Impact.md)| ![Task](https://raw.githubusercontent.com/os-threat/images/main/img/rect-task.svg) | [Task](./docs/os_threat/sdo/Task.md) |
| ![Sequence](https://raw.githubusercontent.com/os-threat/images/main/img/rect-step-single.svg) | [Sequence](./docs/os_threat/sdo/Sequence.md)| ![]() | []()| ![]() | []() |




###  Cyber Observable Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Artifact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-artifact.svg) | [Artifact](./docs/stix21/sco/Artifact.md)| ![Autonomous-System](https://raw.githubusercontent.com/os-threat/images/main/img/rect-autonomous-system.svg) | [Autonomous-System](./docs/stix21/sco/Autonomous-System.md)| ![Directory](https://raw.githubusercontent.com/os-threat/images/main/img/rect-directory.svg) | [Directory](./docs/stix21/sco/Directory.md) |
| ![Domain-Name](https://raw.githubusercontent.com/os-threat/images/main/img/rect-domain.svg) | [Domain-Name](./docs/stix21/sco/Domain-Name.md)| ![Email-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-addr.svg) | [Email-Address](./docs/stix21/sco/Email-Address.md)| ![Email-Message](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-message.svg) | [Email-Message](./docs/stix21/sco/Email-Message.md) |
| ![File-](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file.svg) | [File-](./docs/stix21/sco/File-.md)| ![IPv4-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-ipv4-addr.svg) | [IPv4-Address](./docs/stix21/sco/IPv4-Address.md)| ![IPv6-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-ipv6-addr.svg) | [IPv6-Address](./docs/stix21/sco/IPv6-Address.md) |
| ![MAC-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-mac-addr.svg) | [MAC-Address](./docs/stix21/sco/MAC-Address.md)| ![Mutex](https://raw.githubusercontent.com/os-threat/images/main/img/rect-mutex.svg) | [Mutex](./docs/stix21/sco/Mutex.md)| ![Network-Traffic](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic.svg) | [Network-Traffic](./docs/stix21/sco/Network-Traffic.md) |
| ![Process](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process](./docs/stix21/sco/Process.md)| ![Software](https://raw.githubusercontent.com/os-threat/images/main/img/rect-software.svg) | [Software](./docs/stix21/sco/Software.md)| ![URL](https://raw.githubusercontent.com/os-threat/images/main/img/rect-url.svg) | [URL](./docs/stix21/sco/URL.md) |
| ![User-Account](https://raw.githubusercontent.com/os-threat/images/main/img/rect-user-account.svg) | [User-Account](./docs/stix21/sco/User-Account.md)| ![Windows-Registry-Key](https://raw.githubusercontent.com/os-threat/images/main/img/rect-windows-registry-key.svg) | [Windows-Registry-Key](./docs/stix21/sco/Windows-Registry-Key.md)| ![Windows-Registry-Value](https://raw.githubusercontent.com/os-threat/images/main/img/rect-windows-registry-key.svg) | [Windows-Registry-Value](./docs/stix21/sco/Windows-Registry-Value.md) |
| ![X.509-Certificate](https://raw.githubusercontent.com/os-threat/images/main/img/rect-x509-certificate.svg) | [X.509-Certificate](./docs/stix21/sco/X.509-Certificate.md)| ![]() | []()| ![]() | []() |



#### OS-Threat Stix Extensions 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-anecdote.svg) | [Anecdote](./docs/os_threat/sco/Anecdote.md)| ![]() | []()| ![]() | []() |




###  Relationship Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Relationship](https://raw.githubusercontent.com/os-threat/images/main/img/rect-relationship.svg) | [Relationship](./docs/stix21/sro/Relationship.md)| ![Sighting](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting.svg) | [Sighting](./docs/stix21/sro/Sighting.md)| ![]() | []() |




###  Extension Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Email-MIME-Component](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-message-mime.svg) | [Email-MIME-Component](./docs/stix21/sub/Email-MIME-Component.md)| ![File-Archive](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-archive.svg) | [File-Archive](./docs/stix21/sub/File-Archive.md)| ![File-NTFS](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-ntfs.svg) | [File-NTFS](./docs/stix21/sub/File-NTFS.md) |
| ![File-PDF](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-pdf.svg) | [File-PDF](./docs/stix21/sub/File-PDF.md)| ![File-Raster-Image](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-img.svg) | [File-Raster-Image](./docs/stix21/sub/File-Raster-Image.md)| ![File-Windows-PE-Binary](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-bin.svg) | [File-Windows-PE-Binary](./docs/stix21/sub/File-Windows-PE-Binary.md) |
| ![Network-HTTP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-http.svg) | [Network-HTTP](./docs/stix21/sub/Network-HTTP.md)| ![Network-ICMP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-icmp.svg) | [Network-ICMP](./docs/stix21/sub/Network-ICMP.md)| ![Network-Socket](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-sock.svg) | [Network-Socket](./docs/stix21/sub/Network-Socket.md) |
| ![Network-TCP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-tcp.svg) | [Network-TCP](./docs/stix21/sub/Network-TCP.md)| ![Process-Windows-Process](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process-Windows-Process](./docs/stix21/sub/Process-Windows-Process.md)| ![Process-Windows-Service](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process-Windows-Service](./docs/stix21/sub/Process-Windows-Service.md) |
| ![User-UNIX-Account](https://raw.githubusercontent.com/os-threat/images/main/img/rect-user-account-unix.svg) | [User-UNIX-Account](./docs/stix21/sub/User-UNIX-Account.md)| ![X.509-Certificate-Extension](https://raw.githubusercontent.com/os-threat/images/main/img/rect-x509-certificate.svg) | [X.509-Certificate-Extension](./docs/stix21/sub/X.509-Certificate-Extension.md)| ![]() | []() |



#### OS-Threat Stix Extensions 

| Icon | Object Type | Icon | Object Type | Icon | Object Type  |
|:----------:|:-----------|:----------:|:-----------|:----------:|:----------- |
| ![Impact-Availability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-availability.svg) | [Impact-Availability](./docs/os_threat/sub/Impact-Availability.md)| ![Impact-Confidentiality](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-confidentiality.svg) | [Impact-Confidentiality](./docs/os_threat/sub/Impact-Confidentiality.md)| ![Impact-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-external.svg) | [Impact-External](./docs/os_threat/sub/Impact-External.md) |
| ![Impact-Integrity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-integrity.svg) | [Impact-Integrity](./docs/os_threat/sub/Impact-Integrity.md)| ![Impact-Monetary](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-monetary.svg) | [Impact-Monetary](./docs/os_threat/sub/Impact-Monetary.md)| ![Impact-Physical](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-physical.svg) | [Impact-Physical](./docs/os_threat/sub/Impact-Physical.md) |
| ![Impact-Traceability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-impact-traceability.svg) | [Impact-Traceability](./docs/os_threat/sub/Impact-Traceability.md)| ![Sighting-Alert](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-alert.svg) | [Sighting-Alert](./docs/os_threat/sub/Sighting-Alert.md)| ![Sighting-Anecdote](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-anecdote.svg) | [Sighting-Anecdote](./docs/os_threat/sub/Sighting-Anecdote.md) |
| ![Sighting-Context](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-context.svg) | [Sighting-Context](./docs/os_threat/sub/Sighting-Context.md)| ![Sighting-Exclusion](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-exclusion.svg) | [Sighting-Exclusion](./docs/os_threat/sub/Sighting-Exclusion.md)| ![Sighting-Enrichment](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-enrichment.svg) | [Sighting-Enrichment](./docs/os_threat/sub/Sighting-Enrichment.md) |
| ![Sighting-Hunt](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-hunt.svg) | [Sighting-Hunt](./docs/os_threat/sub/Sighting-Hunt.md)| ![Sighting-Framework](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-framework.svg) | [Sighting-Framework](./docs/os_threat/sub/Sighting-Framework.md)| ![Sighting-External](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting-external.svg) | [Sighting-External](./docs/os_threat/sub/Sighting-External.md) |
| ![Identity-Contact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-identity-contact.svg) | [Identity-Contact](./docs/os_threat/sub/Identity-Contact.md)| ![]() | []()| ![]() | []() |



