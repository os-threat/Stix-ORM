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
    Identity, Incident, Note, Sighting, Indicator, Relationship
)
from stixorm.module.definitions.os_threat import (
    StateChangeObject, EventCoreExt, Event, EntityCountObject, ImpactCoreExt,
    Availability, Confidentiality, External, Integrity, Monetary, Physical,
    Traceability, Impact, IncidentScoreObject, IncidentCoreExt, TaskCoreExt,
    Task, SightingEvidence, Sequence, SequenceExt, ContactNumber, EmailContact,
    SocialMediaContact, IdentityContact, AnecdoteExt, Anecdote,
    SightingAnecdote, SightingAlert, SightingContext, SightingExclusion,
    SightingEnrichment, SightingHunt, SightingFramework, SightingExternal
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

def conv(stix_object):
    string_dict = stix_object.serialize()
    jdict = json.loads(string_dict)
    return jdict

########################################################################################################
#
#  TESTING THE INCIDENT Class Model - Jupyter style
#
########################################################################################################

#
# Step 0-A - Setup Common Variables
#
bundle_list = []
sequence_start_refs = []
sequence_refs = []
task_refs = []
event_refs = []
impact_refs = []
other_object_refs = []
sight_ext = SightingEvidence(extension_type="property-extension")
sight_ext_id = "extension-definition--0d76d6d9-16ca-43fd-bd41-4f800ba8fc43"
event_ext = EventCoreExt(extension_type="new-sdo")
event_ext_id = "extension-definition--4ca6de00-5b0d-45ef-a1dc-ea7279ea910e"
event_ext_dict = {event_ext_id: event_ext}
seq_ext = SequenceExt(extension_type="new-sdo")
seq_ext_id = 'extension-definition--be0c7c79-1961-43db-afde-637066a87a64'
seq_ext_dict = {seq_ext_id: seq_ext}
imp_ext = ImpactCoreExt(extension_type="new-sdo")
imp_ext_id = 'extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9'
anec_ext = AnecdoteExt(extension_type="new-sco")
anec_ext_id = 'extension-definition--23676abf-481e-4fee-ac8c-e3d0947287a4'
anec_ext_dict = {anec_ext_id:anec_ext}
task_ext = TaskCoreExt(extension_type="new-sdo")
task_ext_id = 'extension-definition--2074a052-8be4-4932-849e-f5e7798e0030'
task_ext_dict = {task_ext_id: task_ext}
ident_ext_id = 'extension-definition--66e2492a-bbd3-4be6-88f5-cc91a017a498'
inc_ext_id = 'extension-definition--2074a052-8be4-4932-849e-f5e7798e0030'
#
# Step 0-B - Description of Me, the Worker
#
me_user_account = UserAccount(account_type="unix", account_login="me", display_name="me jones")
me_email_addr = EmailAddress(value="me@mycompany.com", belongs_to_ref=me_user_account.id)

me_contact = ContactNumber(contact_number_type="work-phone", contact_number="0418-208-368")
me_email = EmailContact(digital_contact_type="work", email_address_ref=me_email_addr.id)
me_account = SocialMediaContact(digital_contact_type="work", user_account_ref=me_user_account.id)
me_ident_ext = IdentityContact(
    extension_type='property-extension', contact_numbers=[me_contact],
    email_addresses=[me_email], social_media_accounts=[me_account],
    first_name="Me", last_name="Jones", middle_name="Percival", prefix="Dr",
    team="All_Stars"
)
me = Identity(name="Me", identity_class="individual", extensions={ident_ext_id:me_ident_ext})
local_list0 = [conv(me_user_account), conv(me_email_addr), conv(me)]
bundle_list = bundle_list + local_list0
print("-----------------")
print(bundle_list)

#
# Step 0-C - Setup Attack Data, so we dont have to create it from scratch
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
############################################################################################
############################################################################################
# Step 1: A User reports a suspsicious email, so create an event and assign it to an incident
# email address = evil@northkorea.com
# email url = "https://www.northkorea.nk/we/are/mad/"
# email message = "we are coming for you"
# date = "2020-10-19T01:01:01.000Z"
# user address = naive@mycompany.com
# name = naive smith
# user account = nsmith
###########################################################################################
# 1.A Create SCO's and Observed-Data
###########################################################################################
#
# 1.A.1 Setup objects
email_addr1 = EmailAddress(value="evil@northkorea.com")
user_account2 = UserAccount(account_type="unix", account_login="nsmith", display_name="naive smith")
email_addr2 = EmailAddress(value="naive@mycompany.com", belongs_to_ref=user_account2.id)
email_message1 = EmailMessage(to_refs=email_addr2.id, from_ref=email_addr1.id, subject="we are coming for you",
                              is_multipart=False, date="2020-10-19T01:01:01.000Z")
url1 = URL(value="https://www.northkorea.nk/we/are/mad/")
rel1 = Relationship(relationship_type='derived-from', source_ref=email_message1.id, target_ref=url1.id)
obs_refs1 = [email_addr1.id, email_message1.id, url1.id, rel1.id]
observation1 = ObservedData(number_observed=1, object_refs=obs_refs1,
                            first_observed=email_message1.date,last_observed=email_message1.date)
#
# 1.A.2 Collect objects and id's in lists
local_list1 = [conv(email_addr1), conv(user_account2), conv(email_addr2), conv(email_message1), conv(url1), conv(rel1), conv(observation1)]
local_list_id1 = [email_addr1.id, user_account2.id, email_addr2.id, email_message1.id, url1.id, rel1.id, observation1.id]
other_object_refs = other_object_refs + local_list_id1
bundle_list = bundle_list + local_list1
##########################################################################################
# 1.B Create Indicator and Sighting
#
# 1.B.1 Setup Objects
pat1 = "[email-addr:value = '" + email_addr1.value + "' AND email:subject = '" + email_message1.subject + "']"
ind1 = Indicator(name="Suspicious Email", pattern_type="stix", pattern=pat1, indicator_types=["unknown"])

alert = SightingAlert(name="user-report", log="I have found a suspicious email")
sight_alert_ext = {
    sight_ext_id: sight_ext,
    "sighting-alert": alert
}
sighting1 = Sighting(observed_data_refs=observation1.id,
                     sighting_of_ref=ind1.id, extensions=sight_alert_ext)
#
# 1.B.2 Collect objects and ids in lists
local_list2 = [conv(ind1), conv(sighting1)]
local_list_id2 = [ind1.id, sighting1.id]
other_object_refs = other_object_refs + local_list_id2
bundle_list = bundle_list + local_list2
###########################################################################################
# 1.C Create Event, Sequence and Initialise Incident
###########################################################################################
#
# 1.C.1 Setup objects
event1 = Event(
    status="occured", description="user x found a suspicious email",
    event_types=["dissemination-phishing-emails"], name="suspiciouse email",
    sighting_refs=[sighting1], extensions=event_ext_dict
)
eseq1_1 = Sequence(
    step_type="single_step", sequenced_object=event1.id,
    sequence_type="event", extensions=seq_ext_dict
)
eseq1_0 = Sequence(
    step_type="start_step", on_completion=eseq1_1.id,
    sequence_type="event", extensions=seq_ext_dict
)
# incident_ext = IncidentCoreExt(
#     determination="suspected", extension_type="property-extension",
#     investigation_status="new", event_refs=[event1.id], incident_types=["dissemination-phishing-emails"])
#     other_object_refs=other_object_refs, sequence_start_refs=[eseq1_0.id],
#     sequence_refs=[eseq1_0.id, eseq1_1.id]
# )
# incident_ext1 = {"extension-definition--ef765651-680c-498d-9894-99799f2fa126": incident_ext}
# incident = Incident(type="incident", name="potential phishing", extensions=incident_ext1)
#
# 1.C.2 Collect objects and ids in lists
local_list3 = [conv(event1), conv(eseq1_1), conv(eseq1_0)]
bundle_list = bundle_list + local_list3
###########################################################################################
# 1.D Create Task to Discuss Impact with Event Reporter
###########################################################################################
#
# 1.D.1 Setup objects
task1 = Task(
    task_types=["investigation"], outcome="pending", name="Speak to User",
    description="Talk to user and determine what they say",
    owner=me.id, extensions={task_ext_id:task_ext}
)
task_refs.append(task1.id)
bundle_list.append(conv(task1))
#
# Step 1.D.2. Update  Incident with Task
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["task_refs"] = task_refs


############################################################################################
############################################################################################
# Step 2: We want to talk to the original user nd find out what the impact was
# user address = naive@mycompany.com
# name = naive smith
# user account = nsmith
# value = "I clicked on the link, and my laptop screen went wierd"
###########################################################################################
# 2.A Create SCO's and Observed-Data
###########################################################################################
#
# 2.A.1 Setup objects
# A. Reporter
reporter_contact = ContactNumber(contact_number_type="work-phone", contact_number="0499-999-109")
reporter_email = EmailContact(digital_contact_type="work", email_address_ref=email_addr2.id)
reporter_account = SocialMediaContact(digital_contact_type="work", user_account_ref=user_account2.id)
reporter_ident_ext = IdentityContact(
    extension_type='property-extension', contact_numbers=[reporter_contact],
    email_addresses=[reporter_email], social_media_accounts=[reporter_account],
    first_name="Naive", last_name="Smith", middle_name="Weakling", prefix="Mr",
    team="Users"
)
reporter = Identity(name="Naive", identity_class="individual", extensions={ident_ext_id:reporter_ident_ext})
# B. Anecdote
anecdote = Anecdote(
    value="I clicked on the link, and my laptop screen went weird",
    provided_by_ref=reporter.id, extensions=anec_ext_dict
)
# C. Observation
obs_refs2 = [anecdote.id]
observation2 = ObservedData(number_observed=1, object_refs=obs_refs2,
                            first_observed=anecdote.report_date,
                            last_observed=anecdote.report_date)
# D. Sighting
anec_sight_ext = SightingAnecdote(person_name="Naive Smith", person_context="employee",
                                  report_submission="interview")
sight_anec_ext = {
    sight_ext_id: sight_ext, "sighting-anecdote": anec_sight_ext
}
anec_sight = Sighting(observed_data_refs=observation2.id,
                      sighting_of_ref=reporter.id, extensions=sight_anec_ext)
# E. Availability Impact
numbers = EntityCountObject(computers_mobile=1)
availability = Availability(availability_impact=99)
avail_impact = Impact(
    impact_category="availability", criticality=99, description="Laptop is stuffed",
    impacted_entity_counts=numbers, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "availability":availability}
)
#
# Step 2.A.2 Collect Objects
#
impact_refs.append(avail_impact.id)
local_list4 = [conv(reporter), conv(anecdote), conv(observation2), conv(anec_sight), conv(avail_impact)]
local_list4_id = [reporter.id, anecdote.id, observation2.id, anec_sight.id]
bundle_list = bundle_list + local_list4
#
# Step 2.A.3. Update Task from Pending to Successful, and Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["task_refs"] = task_refs
    elif bun["type"] == "task" and bun["id"] == task1.id:
        bun["outcome"] = "successful"

############################################################################################
############################################################################################
# Step 3: We want to talk to the original user nd find out what the impact was
# user address = naive@mycompany.com
# name = naive smith
# user account = nsmith
# value = "I clicked on the link, and my laptop screen went wierd"
###########################################################################################
# 2.A Create SCO's and Observed-Data
###########################################################################################
#
# 2.A.1 Setup objects
# A. Reporter

#######################################################################################################
#######################################################################################################
# Print Bundle on console
#######################################################################################################
bun_len = len(bundle_list)
for inc, bun in enumerate(bundle_list):
    print(f"------------------------------ {inc+1} of {bun_len}--------------------------------------------")
    print(bun)

