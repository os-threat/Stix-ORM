import json
import os
import datetime

#import dateutil.parser
#from dateutil.parser import *
from stixorm.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
from typedb.client import *
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.generate_docs import configure_overview_table_docs, object_tables
from stixorm.module.initialise import sort_layers, load_typeql_data
from stixorm.module.definitions.stix21 import (
    ObservedData, IPv4Address, EmailAddress, DomainName, EmailMessage, URL, UserAccount,
    Identity, Incident, Note, Sighting
)
from stixorm.module.definitions.os_threat import (
    StateChangeObject, EventCoreExt, Event, EntityCountObject, ImpactCoreExt,
    Availability, Confidentiality, External, Integrity, Monetary, Physical,
    Traceability, Impact, IncidentScoreObject, IncidentCoreExt, TaskCoreExt,
    Task, ObservedEvidence, ObservedAlert, ObservedContext, ObservedExclusion,
    ObservedEnrichment, ObservedHunt, SightingEvidence, SightingFramework,
    SightingExternal
)
from stixorm.module.orm.import_utilities import val_tql
#from stixorm.module.definitions.attack import attack_models
#from stixorm.module.definitions.property_definitions import get_definitions
import copy

import logging

from timeit import default_timer as timer

#from stix.module.typedb_lib.import_type_factory import AttackDomains, AttackVersions

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
#logger.addHandler(logging.StreamHandler())

########################################################################################################
#
#  TESTING THE INCIDENT Class Model - Jupyter style
#
########################################################################################################

bundle_list = []

#
# Step 0 - Setup Attack Data, so we dont have to create it from scratch
#

mitre_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--987eeee1-413a-44ac-96cc-0a8acdcc2f2c",
            "created": "2023-08-23T13:57:25.455083Z",
            "modified": "2023-08-23T13:57:25.455083Z",
            "name": "Contoso Customer ltd",
            "identity_class": "organization"
        }
mitre_marking = {
            "type": "marking-definition",
            "id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "created": "2017-06-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {
                "statement": "Copyright 2015-2023, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
            },
            "x_mitre_attack_spec_version": "2.1.0"
        }
TTP_spear_phishing = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "created": "2020-03-02T19:15:44.182Z",
            "modified": "2022-11-08T14:00:00.188Z",
            "name": "Spearphishing Link",
            "x_mitre_attack_spec_version": "2.1.0",
            "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.\n\nAll forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Additionally, adversaries may use seemingly benign links that abuse special characters to mimic legitimate websites (known as an \"IDN homograph attack\").(Citation: CISA IDN ST05-016)\n\nAdversaries may also utilize links to perform consent phishing, typically with OAuth 2.0 request URLs that when accepted by the user provide permissions/access for malicious applications, allowing adversaries to  [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s.(Citation: Trend Micro Pawn Storm OAuth 2017) These stolen access tokens allow the adversary to perform various actions on behalf of the user via API calls. (Citation: Microsoft OAuth 2.0 Consent Phishing 2021)",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1566/002",
                    "external_id": "T1566.002"
                },
                {
                    "source_name": "ACSC Email Spoofing",
                    "description": "Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.",
                    "url": "https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf"
                },
                {
                    "source_name": "CISA IDN ST05-016",
                    "description": "CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.",
                    "url": "https://us-cert.cisa.gov/ncas/tips/ST05-016"
                },
                {
                    "source_name": "Trend Micro Pawn Storm OAuth 2017",
                    "description": "Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.",
                    "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks"
                },
                {
                    "source_name": "Microsoft OAuth 2.0 Consent Phishing 2021",
                    "description": "Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.",
                    "url": "https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/"
                },
                {
                    "source_name": "Microsoft Anti Spoofing",
                    "description": "Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.",
                    "url": "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/163.html",
                    "external_id": "CAPEC-163"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_contributors": [
                "Philip Winther",
                "Shailesh Tiwary (Indian Army)",
                "Mark Wee",
                "Jeff Sakowicz, Microsoft Identity Developer Platform Services (IDPM Services)",
                "Saisha Agrawal, Microsoft Threat Intelligent Center (MSTIC)",
                "Kobi Haimovich, CardinalOps",
                "Menachem Goldstein"
            ],
            "x_mitre_data_sources": [
                "Application Log: Application Log Content",
                "Network Traffic: Network Traffic Flow",
                "Network Traffic: Network Traffic Content"
            ],
            "x_mitre_deprecated": False,
            "x_mitre_detection": "URL inspection within email (including expanding shortened links) can help detect links leading to known malicious sites as well as links redirecting to adversary infrastructure based by upon suspicious OAuth patterns with unusual TLDs.(Citation: Microsoft OAuth 2.0 Consent Phishing 2021). Detonation chambers can be used to detect these links and either automatically go to these sites to determine if they're potentially malicious, or wait and capture the content if a user visits the link.\n\nFiltering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)\n\nBecause this technique usually involves user interaction on the endpoint, many of the possible detections take place once [User Execution](https://attack.mitre.org/techniques/T1204) occurs.",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_is_subtechnique": True,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_platforms": [
                "Linux",
                "macOS",
                "Windows",
                "Office 365",
                "SaaS",
                "Google Workspace"
            ],
            "x_mitre_version": "2.3"
        }
TTP_lateral_movement = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--9db0cf3a-a3c9-4012-8268-123b9db6fd82",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "created": "2018-04-18T17:59:24.739Z",
            "modified": "2022-05-11T14:00:00.188Z",
            "name": "Exploitation of Remote Services",
            "x_mitre_attack_spec_version": "2.1.0",
            "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.\u00a0A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.\n\nAn adversary may need to determine if the remote system is in a vulnerable state, which may be done through [Network Service Discovery](https://attack.mitre.org/techniques/T1046) or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities,  or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.\n\nThere are several well-known vulnerabilities that exist in common services such as SMB (Citation: CIS Multiple SMB Vulnerabilities) and RDP (Citation: NVD CVE-2017-0176) as well as applications that may be used within internal networks such as MySQL (Citation: NVD CVE-2016-6662) and web server services.(Citation: NVD CVE-2014-7169)\n\nDepending on the permissions level of the vulnerable remote service an adversary may achieve [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) as a result of lateral movement exploitation as well.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "lateral-movement"
                }
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1210",
                    "external_id": "T1210"
                },
                {
                    "source_name": "CIS Multiple SMB Vulnerabilities",
                    "description": "CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.",
                    "url": "https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/"
                },
                {
                    "source_name": "NVD CVE-2017-0176",
                    "description": "National Vulnerability Database. (2017, June 22). CVE-2017-0176 Detail. Retrieved April 3, 2018.",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0176"
                },
                {
                    "source_name": "NVD CVE-2016-6662",
                    "description": "National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"
                },
                {
                    "source_name": "NVD CVE-2014-7169",
                    "description": "National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_contributors": [
                "ExtraHop"
            ],
            "x_mitre_data_sources": [
                "Application Log: Application Log Content",
                "Network Traffic: Network Traffic Content"
            ],
            "x_mitre_detection": "Detecting software exploitation may be difficult depending on the tools available. Software exploits may not always succeed or may cause the exploited process to become unstable or crash. Also look for behavior on the endpoint system that might indicate successful compromise, such as abnormal behavior of the processes. This could include suspicious files written to disk, evidence of [Process Injection](https://attack.mitre.org/techniques/T1055) for attempts to hide execution, evidence of [Discovery](https://attack.mitre.org/tactics/TA0007), or other unusual network traffic that may indicate additional tools transferred to the system.",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_is_subtechnique": False,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_permissions_required": [
                "User"
            ],
            "x_mitre_platforms": [
                "Linux",
                "Windows",
                "macOS"
            ],
            "x_mitre_system_requirements": [
                "Unpatched software or otherwise vulnerable target. Depending on the target and goal, the system and exploitable service may need to be remotely accessible from the internal network."
            ],
            "x_mitre_version": "1.1"
        }
#
#
# Step 1: A User reports a suspsicious email, so create an event and assign it to an incident
# email address = evil@northkorea.com
# email url = "https://www.northkorea.nk/we/are/mad/"
# email message = "we are coming for you"
# user address = naive@mycompany.com
# name = naive smith
# user account
#
email_addr1 = EmailAddress(value="evil@northkorea.com")
user_account1 = UserAccount(account_type="unix", account_login="nsmith", display_name="naive smith")
