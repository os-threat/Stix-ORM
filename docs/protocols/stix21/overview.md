# Stix 2.1















### STIX DOmain Objects (SDO)



There are 19 STIX Domain Objects, as shown in the table below





### STIX Cyber Observable Objects (SCO)



There are 19 STIX Cyber Observable Objects, as shown in the table below





### STIX Relationship Objects (SRO)



There are 2 STIX Relationship Objects,  as shown in the table below





### STIX Extension Objects (SUB)



There are 14 STIX Extension Objects,  as shown in the table below












###  Domain Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Attack-Pattern](https://raw.githubusercontent.com/os-threat/images/main/img/rect-attack-pattern.svg) | [Attack-Pattern](./docs/protocols/stix21/sdo/Attack-Pattern.md) | Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed. An example of an attack pattern is "spear phishing": a common type of attack where an attacker sends a carefully crafted e-mail message to a party with the intent of getting them to click a link or open an attachment to deliver malware. Attack Patterns can also be more specific; spear phishing as practiced by a particular threat actor (e.g., they might generally say that the target won a contest) can also be an Attack Pattern. |
| ![Campaign](https://raw.githubusercontent.com/os-threat/images/main/img/rect-campaign.svg) | [Campaign](./docs/protocols/stix21/sdo/Campaign.md) | A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set. Campaigns are often attributed to an intrusion set and threat actors. The threat actors may reuse known infrastructure from the intrusion set or may set up new infrastructure specific for conducting that campaign. |
| ![Course-of-Action](https://raw.githubusercontent.com/os-threat/images/main/img/rect-course-of-action.svg) | [Course-of-Action](./docs/protocols/stix21/sdo/Course-of-Action.md) | Note: The Course of Action object in STIX 2.1 is a stub. It is included to support basic use cases (such as sharing prose courses of action) but does not support the ability to represent automated courses of action or contain properties to represent metadata about courses of action. Future STIX 2 releases will expand it to include these capabilities. A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action to mitigate a vulnerability could describe applying the patch that fixes it. |
| ![Grouping](https://raw.githubusercontent.com/os-threat/images/main/img/rect-grouping.svg) | [Grouping](./docs/protocols/stix21/sdo/Grouping.md) | A Grouping object explicitly asserts that the referenced STIX Objects have a shared context, unlike a STIX Bundle (which explicitly conveys no context). A Grouping object should not be confused with an intelligence product, which should be conveyed via a STIX Report. |
| ![Identity](https://raw.githubusercontent.com/os-threat/images/main/img/rect-identity-individual.svg) | [Identity](./docs/protocols/stix21/sdo/Identity.md) | Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector). |
| ![Incident](https://raw.githubusercontent.com/os-threat/images/main/img/rect-incident.svg) | [Incident](./docs/protocols/stix21/sdo/Incident.md) | Note: The Incident object in STIX 2.1 is a stub. It is included to support basic use cases but does not contain properties to represent metadata about incidents. Future STIX 2 releases will expand it to include these capabilities.  It is suggested that it is used as an extension point for an Incident object defined using the extension facility described in section 7.3. |
| ![Indicator](https://raw.githubusercontent.com/os-threat/images/main/img/rect-indicator.svg) | [Indicator](./docs/protocols/stix21/sdo/Indicator.md) | Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity. For example, an Indicator may be used to represent a set of malicious domains and use the STIX Patterning Language (see section 9) to specify these domains. The Indicator SDO contains a simple textual description, the Kill Chain Phases that it detects behavior in, a time window for when the Indicator is valid or useful, and a required pattern property to capture a structured detection pattern. Conforming STIX implementations MUST support the STIX Patterning Language as defined in section 9.  |
| ![Infrastructure](https://raw.githubusercontent.com/os-threat/images/main/img/rect-infrastructure.svg) | [Infrastructure](./docs/protocols/stix21/sdo/Infrastructure.md) | The Infrastructure SDO represents a type of TTP and describes any systems, software services and any associated physical or virtual resources intended to support some purpose (e.g., C2 servers used as part of an attack, device or server that are part of defense, database servers targeted by an attack, etc.). While elements of an attack can be represented by other SDOs or SCOs, the Infrastructure SDO represents a named group of related data that constitutes the infrastructure. |
| ![Intrusion-Set](https://raw.githubusercontent.com/os-threat/images/main/img/rect-intrusion-set.svg) | [Intrusion-Set](./docs/protocols/stix21/sdo/Intrusion-Set.md) | An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown Threat Actor. New activity can be attributed to an Intrusion Set even if the Threat Actors behind the attack are not known. Threat Actors can move from supporting one Intrusion Set to supporting another, or they may support multiple Intrusion Sets. Where a Campaign is a set of attacks over a period of time against a specific set of targets to achieve some objective, an Intrusion Set is the entire attack package and may be used over a very long period of time in multiple Campaigns to achieve potentially multiple purposes.  |
| ![Location](https://raw.githubusercontent.com/os-threat/images/main/img/rect-location.svg) | [Location](./docs/protocols/stix21/sdo/Location.md) | A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g. New York, US), latitude and longitude. Locations are primarily used to give context to other SDOs. For example, a Location could be used in a relationship to describe that the Bourgeois Swallow intrusion set originates from Eastern Europe. The Location SDO can be related to an Identity or Intrusion Set to indicate that the identity or intrusion set is located in that location. It can also be related from a malware or attack pattern to indicate that they target victims in that location. The Location object describes geographic areas, not governments, even in cases where that area might have a government. For example, a Location representing the United States describes the United States as a geographic area, not the federal government of the United States.  |
| ![Malware](https://raw.githubusercontent.com/os-threat/images/main/img/rect-malware.svg) | [Malware](./docs/protocols/stix21/sdo/Malware.md) | Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly. The intent is to compromise the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or otherwise annoy or disrupt the victim. The Malware SDO characterizes, identifies, and categorizes malware instances and families from data that may be derived from analysis. This SDO captures detailed information about how the malware works and what it does. This SDO captures contextual data relevant to sharing Malware data without requiring the full analysis provided by the Malware Analysis SDO. The Indicator SDO provides intelligence producers with the ability to define, using the STIX Pattern Grammar in a standard way to identify and detect behaviors associated with malicious activities. Although the Malware SDO provides vital intelligence on a specific instance or malware family, it does not provide a standard grammar that the Indicator SDO provides to identify those properties in security detection systems designed to process the STIX Pattern grammar. We strongly encourage the use of STIX Indicators for the detection of actual malware, due to its use of the STIX Patterning language and the clear semantics that it provides. |
| ![Malware-Analysis](https://raw.githubusercontent.com/os-threat/images/main/img/rect-malware-analysis.svg) | [Malware-Analysis](./docs/protocols/stix21/sdo/Malware-Analysis.md) | Malware Analysis captures the metadata and results of a particular static or dynamic analysis performed on a malware instance or family. One of result or analysis_sco_refs properties MUST be provided.  |
| ![Note](https://raw.githubusercontent.com/os-threat/images/main/img/rect-note.svg) | [Note](./docs/protocols/stix21/sdo/Note.md) | A Note is intended to convey informative text to provide further context and/or to provide additional analysis not contained in the STIX Objects, Marking Definition objects, or Language Content objects which the Note relates to. Notes can be created by anyone (not just the original object creator). For example, an analyst may add a Note to a Campaign object created by another organization indicating that they've seen posts related to that Campaign on a hacker forum.   |
| ![Observed-Data](https://raw.githubusercontent.com/os-threat/images/main/img/rect-observed-data.svg) | [Observed-Data](./docs/protocols/stix21/sdo/Observed-Data.md) | Observed Data conveys information about cyber security related entities such as files, systems, and networks using the STIX Cyber-observable Objects (SCOs). For example, Observed Data can capture information about an IP address, a network connection, a file, or a registry key. Observed Data is not an intelligence assertion, it is simply the raw information without any context for what it means. Observed Data can capture that a piece of information was seen one or more times. Meaning, it can capture both a single observation of a single entity (file, network connection) as well as the aggregation of multiple observations of an entity. When the number_observed property is 1 the Observed Data represents a single entity. When the number_observed property is greater than 1, the Observed Data represents several instances of an entity potentially collected over a period of time. If a time window is known, that can be captured using the first_observed and last_observed properties. When used to collect aggregate data, it is likely that some properties in the SCO (e.g., timestamp properties) will be omitted because they would differ for each of the individual observations. |
| ![Opinion](https://raw.githubusercontent.com/os-threat/images/main/img/rect-opinion.svg) | [Opinion](./docs/protocols/stix21/sdo/Opinion.md) | An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity. The primary property is the opinion property, which captures the level of agreement or disagreement using a fixed scale. That fixed scale also supports a numeric mapping to allow for consistent statistical operations across opinions. For example, an analyst from a consuming organization might say that they "strongly disagree" with a Campaign object and provide an explanation about why. In a more automated workflow, a SOC operator might give an Indicator "one star" in their TIP (expressing "strongly disagree") because it is considered to be a false positive within their environment. Opinions are subjective, and the specification does not address how best to interpret them. Sharing communities are encouraged to provide clear guidelines to their constituents regarding best practice for the use of Opinion objects within the community. |
| ![Report](https://raw.githubusercontent.com/os-threat/images/main/img/rect-report.svg) | [Report](./docs/protocols/stix21/sdo/Report.md) | Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details. They are used to group related threat intelligence together so that it can be published as a comprehensive cyber threat story. The Report SDO contains a list of references to STIX Objects (the CTI objects included in the report) along with a textual description and the name of the report.   |
| ![Threat-Actor](https://raw.githubusercontent.com/os-threat/images/main/img/rect-threat-actor.svg) | [Threat-Actor](./docs/protocols/stix21/sdo/Threat-Actor.md) | Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or be affiliated with various Intrusion Sets, groups, or organizations over time. Threat Actors leverage their resources, and possibly the resources of an Intrusion Set, to conduct attacks and run Campaigns against targets. |
| ![Tool](https://raw.githubusercontent.com/os-threat/images/main/img/rect-tool.svg) | [Tool](./docs/protocols/stix21/sdo/Tool.md) | Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during an attack. The Tool SDO characterizes the properties of these software tools and can be used as a basis for making an assertion about how a Threat Actor uses them during an attack. It contains properties to name and describe the tool, a list of Kill Chain Phases the tool can be used to carry out, and the version of the tool. |
| ![Vulnerability](https://raw.githubusercontent.com/os-threat/images/main/img/rect-vulnerability.svg) | [Vulnerability](./docs/protocols/stix21/sdo/Vulnerability.md) | A Vulnerability is a weakness or defect in the requirements, designs, or implementations of the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that can be directly exploited to negatively impact the confidentiality, integrity, or availability of that system. CVE is a list of information security vulnerabilities and exposures that provides common names for publicly known problems [CVE]. For example, if a piece of malware exploits CVE-2015-12345, a Malware object could be linked to a Vulnerability object that references CVE-2015-12345. |




###  Cyber Observable Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Artifact](https://raw.githubusercontent.com/os-threat/images/main/img/rect-artifact.svg) | [Artifact](./docs/protocols/stix21/sco/Artifact.md) | The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload. |
| ![Autonomous-System](https://raw.githubusercontent.com/os-threat/images/main/img/rect-autonomous-system.svg) | [Autonomous-System](./docs/protocols/stix21/sco/Autonomous-System.md) | This object represents the properties of an Autonomous System (AS). |
| ![Directory](https://raw.githubusercontent.com/os-threat/images/main/img/rect-directory.svg) | [Directory](./docs/protocols/stix21/sco/Directory.md) | The Directory object represents the properties common to a file system directory. |
| ![Domain-Name](https://raw.githubusercontent.com/os-threat/images/main/img/rect-domain.svg) | [Domain-Name](./docs/protocols/stix21/sco/Domain-Name.md) | The Domain Name object represents the properties of a network domain name. |
| ![Email-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-addr.svg) | [Email-Address](./docs/protocols/stix21/sco/Email-Address.md) | The Email Address object represents a single email address |
| ![Email-Message](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-message.svg) | [Email-Message](./docs/protocols/stix21/sco/Email-Message.md) | The Email Message object represents an instance of an email message, corresponding to the internet message format described in [RFC5322] and related RFCs. |
| ![File-](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file.svg) | [File-](./docs/protocols/stix21/sco/File-.md) | The File object represents the properties of a file. A File object MUST contain at least one of hashes or name. |
| ![IPv4-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-ipv4-addr.svg) | [IPv4-Address](./docs/protocols/stix21/sco/IPv4-Address.md) | The IPv4 Address object represents one or more IPv4 addresses expressed using CIDR notation. |
| ![IPv6-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-ipv6-addr.svg) | [IPv6-Address](./docs/protocols/stix21/sco/IPv6-Address.md) | The IPv6 Address object represents one or more IPv6 addresses expressed using CIDR notation. |
| ![MAC-Address](https://raw.githubusercontent.com/os-threat/images/main/img/rect-mac-addr.svg) | [MAC-Address](./docs/protocols/stix21/sco/MAC-Address.md) | The MAC Address object represents a single Media Access Control (MAC) address. |
| ![Mutex](https://raw.githubusercontent.com/os-threat/images/main/img/rect-mutex.svg) | [Mutex](./docs/protocols/stix21/sco/Mutex.md) | The Mutex object represents the properties of a mutual exclusion (mutex) object. |
| ![Network-Traffic](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic.svg) | [Network-Traffic](./docs/protocols/stix21/sco/Network-Traffic.md) | The Network Traffic object represents arbitrary network traffic that originates from a source and is addressed to a destination. The network traffic MAY or MAY NOT constitute a valid unicast, multicast, or broadcast network connection. This MAY also include traffic that is not established, such as a SYN flood. |
| ![Process](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process](./docs/protocols/stix21/sco/Process.md) | The Process object represents common properties of an instance of a computer program as executed on an operating system. A Process object MUST contain at least one property (other than type) from this object (or one of its extensions). |
| ![Software](https://raw.githubusercontent.com/os-threat/images/main/img/rect-software.svg) | [Software](./docs/protocols/stix21/sco/Software.md) | The Software object represents high-level properties associated with software, including software products. |
| ![URL](https://raw.githubusercontent.com/os-threat/images/main/img/rect-url.svg) | [URL](./docs/protocols/stix21/sco/URL.md) | The URL object represents the properties of a uniform resource locator (URL). |
| ![User-Account](https://raw.githubusercontent.com/os-threat/images/main/img/rect-user-account.svg) | [User-Account](./docs/protocols/stix21/sco/User-Account.md) | The User Account object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts. As all properties of this object are optional, at least one of the properties defined below MUST be included when using this object. |
| ![Windows-Registry-Key](https://raw.githubusercontent.com/os-threat/images/main/img/rect-windows-registry-key.svg) | [Windows-Registry-Key](./docs/protocols/stix21/sco/Windows-Registry-Key.md) | The Registry Key object represents the properties of a Windows registry key. As all properties of this object are optional, at least one of the properties defined below MUST be included when using this object. |
| ![Windows-Registry-Value](https://raw.githubusercontent.com/os-threat/images/main/img/rect-windows-registry-key.svg) | [Windows-Registry-Value](./docs/protocols/stix21/sco/Windows-Registry-Value.md) | The Windows Registry Value type captures the properties of a Windows Registry Key Value. As all properties of this type are optional, at least one of the properties defined below MUST be included when using this type. |
| ![X.509-Certificate](https://raw.githubusercontent.com/os-threat/images/main/img/rect-x509-certificate.svg) | [X.509-Certificate](./docs/protocols/stix21/sco/X.509-Certificate.md) | The X.509 Certificate object represents the properties of an X.509 certificate, as defined by ITU recommendation X.509 [X.509]. An X.509 Certificate object MUST contain at least one object specific property (other than type) from this object. |




###  Relationship Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Relationship](https://raw.githubusercontent.com/os-threat/images/main/img/rect-relationship.svg) | [Relationship](./docs/protocols/stix21/sro/Relationship.md) | The Relationship object is used to link together two SDOs or SCOs in order to describe how they are related to each other. If SDOs and SCOs are considered "nodes" or "vertices" in the graph, the Relationship Objects (SROs) represent "edges". STIX defines many relationship types to link together SDOs and SCOs. Relationship types defined in the specification SHOULD be used to ensure consistency. An example of a specification-defined relationship is that an indicator indicates a campaign. That relationship type is listed in the Relationships section of the Indicator SDO definition. |
| ![Sighting](https://raw.githubusercontent.com/os-threat/images/main/img/rect-sighting.svg) | [Sighting](./docs/protocols/stix21/sro/Sighting.md) | A Sighting denotes the belief that something in CTI (e.g., an indicator, malware, tool, threat actor, etc.) was seen. Sightings are used to track who and what are being targeted, how attacks are carried out, and to track trends in attack behavior. Sighting is distinct from Observed Data in that Sighting is an intelligence assertion ("I saw this threat actor") while Observed Data is simply information ("I saw this file"). When you combine them by including the linked Observed Data (observed_data_refs) from a Sighting, you can say "I saw this file, and that makes me think I saw this threat actor". |




###  Extension Object Types

#### OASIS Stix 2.1 

| Icon | Object Type | Description |
|:----------:|:-----------|:----------- |
| ![Email-MIME-Component](https://raw.githubusercontent.com/os-threat/images/main/img/rect-email-message-mime.svg) | [Email-MIME-Component](./docs/protocols/stix21/sub/Email-MIME-Component.md) | Specifies one component of a multi-part email body. |
| ![File-Archive](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-archive.svg) | [File-Archive](./docs/protocols/stix21/sub/File-Archive.md) | The Archive File extension specifies a default extension for capturing properties specific to archive files. The key for this extension when used in the extensions dictionary MUST be archive-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![File-NTFS](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-ntfs.svg) | [File-NTFS](./docs/protocols/stix21/sub/File-NTFS.md) | The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system. The key for this extension when used in the extensions dictionary MUST be ntfs-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![File-PDF](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-pdf.svg) | [File-PDF](./docs/protocols/stix21/sub/File-PDF.md) | The PDF file extension specifies a default extension for capturing properties specific to PDF files. The key for this extension when used in the extensions dictionary MUST be pdf-ext. Note that this predefined extension does not use the extension facility described in section 7.3.
 |
| ![File-Raster-Image](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-img.svg) | [File-Raster-Image](./docs/protocols/stix21/sub/File-Raster-Image.md) | The Raster Image file extension specifies a default extension for capturing properties specific to raster image files. The key for this extension when used in the extensions dictionary MUST be raster-image-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![File-Windows-PE-Binary](https://raw.githubusercontent.com/os-threat/images/main/img/rect-file-bin.svg) | [File-Windows-PE-Binary](./docs/protocols/stix21/sub/File-Windows-PE-Binary.md) | The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files. The key for this extension when used in the extensions dictionary MUST be windows-pebinary-ext. Note that this predefined extension does not use the extension facility described in section 7.3. An object using the Windows� PE Binary File Extension MUST contain at least one property other than the required pe_type property from this extension. |
| ![Network-HTTP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-http.svg) | [Network-HTTP](./docs/protocols/stix21/sub/Network-HTTP.md) | The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests. The key for this extension when used in the extensions dictionary MUST be http-request-ext. Note that this predefined extension does not use the extension facility described in section 7.3. The corresponding protocol value for this extension is http. |
| ![Network-ICMP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-icmp.svg) | [Network-ICMP](./docs/protocols/stix21/sub/Network-ICMP.md) | The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP. The key for this extension when used in the extensions dictionary MUST be icmp-ext. Note that this predefined extension does not use the extension facility described in section 7.3. The corresponding protocol value for this extension is icmp. |
| ![Network-Socket](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-sock.svg) | [Network-Socket](./docs/protocols/stix21/sub/Network-Socket.md) | The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets. The key for this extension when used in the extensions dictionary MUST be socket-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![Network-TCP](https://raw.githubusercontent.com/os-threat/images/main/img/rect-network-traffic-tcp.svg) | [Network-TCP](./docs/protocols/stix21/sub/Network-TCP.md) | The TCP extension specifies a default extension for capturing network traffic properties specific to TCP. The key for this extension when used in the extensions dictionary MUST be tcp-ext. Note that this predefined extension does not use the extension facility described in section 7.3. The corresponding protocol value for this extension is tcp. |
| ![Process-Windows-Process](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process-Windows-Process](./docs/protocols/stix21/sub/Process-Windows-Process.md) | The Windows Process extension specifies a default extension for capturing properties specific to Windows processes. The key for this extension when used in the extensions dictionary MUST be windows-process-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![Process-Windows-Service](https://raw.githubusercontent.com/os-threat/images/main/img/rect-process.svg) | [Process-Windows-Service](./docs/protocols/stix21/sub/Process-Windows-Service.md) | The Windows Service extension specifies a default extension for capturing properties specific to Windows services. The key for this extension when used in the extensions dictionary MUST be windows-service-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![User-UNIX-Account](https://raw.githubusercontent.com/os-threat/images/main/img/rect-user-account-unix.svg) | [User-UNIX-Account](./docs/protocols/stix21/sub/User-UNIX-Account.md) | The UNIX account extension specifies a default extension for capturing the additional information for an account on a UNIX system. The key for this extension when used in the extensions dictionary MUST be unix-account-ext. Note that this predefined extension does not use the extension facility described in section 7.3. |
| ![X.509-Certificate Extension](https://raw.githubusercontent.com/os-threat/images/main/img/rect-x509-certificate.svg) | [X.509-Certificate Extension](./docs/protocols/stix21/sub/X.509-Certificate Extension.md) | The X.509 v3 Extensions type captures properties associated with X.509 v3 extensions, which serve as a mechanism for specifying additional information such as alternative subject names. An object using the X.509 v3 Extensions type MUST contain at least one property from this type. |



