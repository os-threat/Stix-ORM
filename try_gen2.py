import json
import os
import datetime

#import dateutil.parser
#from dateutil.parser import *
from stixorm.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
#from typedb.client import *
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.generate_docs import configure_overview_table_docs, object_tables
from stixorm.module.initialise import sort_layers, load_typeql_data
from stixorm.module.definitions.stix21 import (
    ObservedData, IPv4Address, EmailAddress, DomainName, EmailMessage, URL, UserAccount, File,
    Identity, Incident, Note, Sighting, Indicator, Relationship, Location, Software, Process, Bundle
)
from stixorm.module.definitions.os_threat import (
    StateChangeObject, EventCoreExt, Event, ImpactCoreExt,
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
# 0-A.1 List needed to collect objects
bundle_list = []
sequence_start_refs = []
sequence_refs = []
task_refs = []
event_refs = []
impact_refs = []
other_object_refs = []
#
# 0-A-2 Setup Extensions and Extension ID's that are common
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
# 0-B.1 My Email and User Account
me_user_account = UserAccount(account_type="unix", account_login="me", display_name="me jones")
me_email_addr = EmailAddress(value="me@mycompany.com", belongs_to_ref=me_user_account.id)
#
# 0-B.2 My Identity
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
#
# 0-B.3 Collect objects about me
local_list0 = [conv(me_user_account), conv(me_email_addr), conv(me)]
bundle_list = bundle_list + local_list0
bundle = Bundle(me)
bundle_dict = conv(bundle)

#
# Step 0-C - Setup Attack Data, so we dont have to create it from scratch
#

mitre_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "created": "2023-08-23T13:57:25.455083Z",
            "modified": "2023-08-23T13:57:25.455083Z",
            "name": "Mitre Ltd",
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
obs_refs1 = [email_addr1.id, email_message1.id, url1.id, rel1.id, email_addr2.id, user_account2.id]
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
event_refs.append(event1.id)
sequence_start_refs.append(eseq1_0.id)
sequence_refs=[eseq1_0.id, eseq1_1.id]
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
tseq1_1 = Sequence(
    step_type="single_step", sequenced_object=task1.id,
    sequence_type="task", extensions=seq_ext_dict
)
tseq1_0 = Sequence(
    step_type="start_step", on_completion=tseq1_1.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# 1.D.2 Collect objects
local_list3 = [conv(task1), conv(tseq1_0), conv(tseq1_1)]
task_refs.append(task1.id)
sequence_start_refs.append(tseq1_0.id)
sequence_refs.extend([tseq1_0.id, tseq1_1.id])
bundle_list = bundle_list + local_list3
#
# Step 1.D.3. Update  Incident with Task
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
    provided_by_ref=reporter.id) # , extensions=anec_ext_dict
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
numbers = {"computers-mobile": 1}
availability = Availability(availability_impact=99)
avail_impact = Impact(
    impact_category="availability", criticality=99, description="Laptop is stuffed",
    impacted_entity_counts=numbers, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "availability":availability}
)
#
# F. New Task to check the Exchange server for other suspicious emails
#
task2 = Task(
    task_types=["investigation"], outcome="pending", name="Query Exchange Server",
    description="Query Exchange to find out who else got the suspicious email",
    owner=me.id, extensions={task_ext_id:task_ext}
)
tseq1_2 = Sequence(
    step_type="single_step", sequenced_object=task2.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# Step 2.A.2 Collect Objects
#
task_refs.append(task2.id)
sequence_refs.append(tseq1_2.id)
impact_refs.append(avail_impact.id)
local_list4 = [conv(reporter), conv(anecdote), conv(observation2), conv(anec_sight),
               conv(avail_impact), conv(task2), conv(tseq1_2)]
local_list4_id = [reporter.id, anecdote.id, observation2.id, anec_sight.id]
bundle_list = bundle_list + local_list4
other_object_refs = other_object_refs + local_list4_id
#
# Step 2.A.3. Update Task from Pending to Successful, and add to Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["task_refs"] = task_refs
    elif bun["type"] == "task" and bun["id"] == task1.id:
        bun["outcome"] = "successful"
    elif bun["type"] == "sequence" and bun["id"] == tseq1_1.id:
        bun["on_completion"] = tseq1_2.id
############################################################################################
############################################################################################
# Step 3: We execute a Task to check out the Exchange Server and collect Context Evidence
# collect evidence
# email address = silly@mycompany.com, strange@mycompany.com, dumbo@mycompany.com
# user account = sthor, sman, dguy
# value = "I clicked on the link, and my laptop screen went wierd"
###########################################################################################
# 3.A Create SCO's and Observed-Data
###########################################################################################
#
# 3.A.1 Setup objects
# A. Email Addresses and User Accounts
user_account3 = UserAccount(account_type="unix", account_login="sthor", display_name="silly thor")
email_addr3 = EmailAddress(value="silly@mycompany.com", belongs_to_ref=user_account3.id)
user_account4 = UserAccount(account_type="unix", account_login="sguy", display_name="strange guy")
email_addr4 = EmailAddress(value="strange@mycompany.com", belongs_to_ref=user_account4.id)
user_account5 = UserAccount(account_type="unix", account_login="dguy", display_name="dumbo guy")
email_addr5 = EmailAddress(value="dumbo@mycompany.com", belongs_to_ref=user_account5.id)
# B. Duplicate-of SRO
sro3 = Relationship(relationship_type="duplicate-of", source_ref=email_addr2.id, target_ref=email_addr3)
sro4 = Relationship(relationship_type="duplicate-of", source_ref=email_addr2.id, target_ref=email_addr4)
sro5 = Relationship(relationship_type="duplicate-of", source_ref=email_addr2.id, target_ref=email_addr5)
# C. Setup observed-data
obs_refs2 = [email_addr1.id, email_message1.id, url1.id, rel1.id, email_addr3.id, user_account3.id,
             email_addr4.id, user_account4.id, email_addr5.id, user_account5,
             sro3.id, sro4.id, sro5.id]
observation3 = ObservedData(number_observed=1, object_refs=obs_refs2,
                            first_observed=email_message1.date,last_observed=email_message1.date)
#
# D. Setup Exchange Server Identity
exchange = Identity(name="Microsoft Exchange", description="Microsoft Exchange Server",
                    identity_class="system")
#
# E. Setup Sighting with Context Evidence
query = "query from:"+email_addr1.value+", subject:"+email_message1.subject
value = "["+email_addr3.value+", "+email_addr4.value+", "+email_addr5.value+"]"
context = SightingContext(name="Exchange", description=query, value=value)
sight_context_ext = {
    sight_ext_id: sight_ext,
    "sighting-context": context
}
sighting3 = Sighting(observed_data_refs=observation3.id,
                     sighting_of_ref=ind1.id, extensions=sight_context_ext)
#
# Step 3.A.2 New Task to check te Exclusion Lists in Step 4
#
task3 = Task(
    task_types=["investigation"], outcome="pending", name="Check Exclusion Lists",
    description="Check OS-Threat Exclusion List to see if email address is a known phisher",
    owner=me.id, extensions={task_ext_id:task_ext}
)
tseq1_3 = Sequence(
    step_type="single_step", sequenced_object=task3.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# Step 3.A.3 Collect Objects
#
local_list5 = [conv(user_account3), conv(email_addr3), conv(user_account4),
               conv(email_addr4), conv(user_account5), conv(email_addr5),
               conv(sro3), conv(sro4), conv(sro5), conv(observation3),
               conv(exchange), conv(sighting3), conv(task3), conv(tseq1_3)]
local_list5_id = [user_account3.id, user_account3.id, user_account4.id,
               email_addr4.id, user_account5.id, email_addr5.id, sighting3.id,
               sro3.id, sro3.id, sro5.id, observation3.id, exchange.id]
other_object_refs = other_object_refs + local_list5_id
sequence_refs.append(tseq1_3.id)
task_refs.append(task3.id)
bundle_list = bundle_list + local_list5
#
# Step 3.A.4. Update Task from Pending to Successful, and add objects and new task to Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["other_object_refs"] = other_object_refs
        inc_ext["task_refs"] = task_refs
    elif bun["type"] == "task" and bun["id"] == task2.id:
        bun["outcome"] = "successful"
    elif bun["type"] == "sequence" and bun["id"] == tseq1_2.id:
        bun["on_completion"] = tseq1_3.id
############################################################################################
############################################################################################
# Step 4: We execute a Task to check out the OS-Threat Exclusion List for the email
# we found
# domain = northkorea.com
# value = 197.133.142.27
###########################################################################################
# 4.A Create SCO's and Observed-Data
###########################################################################################
#
# 4.A.1 Setup objects
# A. IP Address and Domain Name
ip = IPv4Address(value="197.133.142.27")
domain = DomainName(value="northkorea.com", resolves_to_refs=[ip.id])
#
# B. Setup Observation
obs_refs4 = [ip.id, domain.id]
observation4 = ObservedData(number_observed=1, object_refs=obs_refs4,
                            first_observed=email_message1.date,last_observed=email_message1.date)
#
# C. Setup Indicator
pat2 = "[domain-name:value = '" + domain.value + "' AND ipv4-addr:value = '" + ip.value + "']"
ind2 = Indicator(name="Suspicious Email", pattern_type="stix", pattern=pat2, indicator_types=["malicious-activity"])
#
# D. Setup Sighting with Exclusion List Evidence
exclusion = SightingExclusion(source="www.phishdb.com", channel="Last 24 hours")
sight_exclusion_ext = {
    sight_ext_id: sight_ext,
    "sighting-exclusion": exclusion
}
sighting4 = Sighting(observed_data_refs=observation4.id,
                     sighting_of_ref=ind2.id, extensions=sight_exclusion_ext)
#
# E. New Task to check te Enrichments
#
task4 = Task(
    task_types=["investigation"], outcome="pending", name="Check Enrichments",
    description="Check known email, domain, IP address to see if we can get enrichments",
    owner=me.id, extensions={task_ext_id:task_ext}
)
tseq1_4 = Sequence(
    step_type="single_step", sequenced_object=task4.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# Step 4.A.3 Collect Objects
#
local_list6 = [conv(ip), conv(domain), conv(observation4), conv(ind2), conv(sighting4), conv(task4), conv(tseq1_4)]
local_list6_id = [ip.id, domain.id, observation4.id, ind2.id, sighting4.id]
other_object_refs = other_object_refs + local_list6_id
task_refs.append(task4.id)
sequence_refs.append(tseq1_4.id)
bundle_list = bundle_list + local_list6
#
# Step 4.A.4. Update Task from Pending to Successful, and add objects and new task to Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["other_object_refs"] = other_object_refs
        inc_ext["sequence_refs"] = sequence_refs
        inc_ext["task_refs"] = task_refs
    elif bun["type"] == "task" and bun["id"] == task3.id:
        bun["outcome"] = "successful"
    elif bun["type"] == "sequence" and bun["id"] == tseq1_3.id:
        bun["on_completion"] = tseq1_4.id

############################################################################################
############################################################################################
# Step 5: We execute a Task to check out the Enrichments
# we found a hosting record for the domain
# identity = Evil Incarnate Ltd
# location = 666 Infection St, Whyme, NK
# lat/long = 39.03385, 125.75432
###########################################################################################
# 5.A Create SCO's and Observed-Data
###########################################################################################
#
# 5.A.1 Setup objects
# A. Location
location = Location(name="Evil Incarnate Ltd", latitude=39.03385, longitude=125.75432,
                    street_address="666 Infection St", city="Whyme", country="PRK", region="south-eastern-asi")
# B. Identity
sender_identity = Identity(name="Evil Incarnate Ltd", description="Hosted phsihing domain",
                           identity_class="organization", contact_information="666 Infection St, Whyme, NK")
# C. STO -> located-at
sender_SRO = Relationship(relationship_type="located-at", source_ref=sender_identity.id, target_ref=location.id)
# D. Setup Sighting, connect the domain observation
enrichment = SightingEnrichment(name="maltego", url="maltego.com", paid=True,
                                value="Evil Incarnate Ltd, 666 Infection St, Whyme, NK, lat/long = 39.03385, 125.75432")
sight_enrichment_ext = {
    sight_ext_id: sight_ext,
    "sighting-enrichment": enrichment
}
sighting5 = Sighting(observed_data_refs=observation4.id, where_sighted_refs=[location.id],
                     sighting_of_ref=sender_identity.id, extensions=sight_enrichment_ext)
#
# E. New Task to setup the Hunt for Impact
#
task5 = Task(
    task_types=["investigation"], outcome="pending", name="Hunt the Actual Impact",
    description="Use Hunting to determine how many clicked the link, and what impact it caused",
    owner=me.id, extensions={task_ext_id:task_ext}
)
tseq1_5 = Sequence(
    step_type="single_step", sequenced_object=task5.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# Step 5.A.2 Collect Objects
#
local_list6 = [conv(location), conv(sender_identity), conv(sender_SRO), conv(sighting5), conv(task5), conv(tseq1_5)]
local_list6_id = [location.id, sender_identity.id, sender_SRO.id, sighting5.id]
other_object_refs = other_object_refs + local_list6_id
task_refs.append(task5.id)
sequence_refs.append(tseq1_5.id)
bundle_list = bundle_list + local_list6
#
# Step 5.A.3. Update Task from Pending to Successful, and add objects and new task to Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["other_object_refs"] = other_object_refs
        inc_ext["sequence_refs"] = sequence_refs
        inc_ext["task_refs"] = task_refs
    elif bun["type"] == "task" and bun["id"] == task4.id:
        bun["outcome"] = "successful"
    elif bun["type"] == "sequence" and bun["id"] == tseq1_4.id:
        bun["on_completion"] = tseq1_5.id

############################################################################################
############################################################################################
# Step 6: We execute a Task to hunt out the actual impacts
# We find the original user 2 and user4 both clicked on the link, downloaded
# some software which started a rm -r process
# name = evil.exe
###########################################################################################
# 6.A Create SCO's and Observed-Data
###########################################################################################
#
# 6.A.1 Setup objects
# A. Software
software = Software(name="evil.exe")
# B. File
hashes ={"SHA-256": "fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db"}
file = File(name="evil.exe", hashes=hashes)
# C. Process
process = Process(pid=1221, created_time="2023-01-20T14:11:25.55Z",
                  command_line="./gedit-bin --destroy-alll", image_ref=file.id)
# D. SRO "derived-from"
SRO_Evil = Relationship(relationship_type="derived-from", source_ref=software.id, target_ref=process.id)
#
# E. SRO related-to
SRO_click1 = Relationship(relationship_type="related-to", source_ref=email_addr2.id, target_ref=software.id)
SRO_click2 = Relationship(relationship_type="related-to", source_ref=email_addr4.id, target_ref=software.id)
#
# E. Setup Observation
obs_refs6 = [software.id, file.id, process.id, SRO_Evil.id, SRO_click1.id, SRO_click2.id,
             email_addr2.id, email_addr4.id, user_account2.id, user_account4.id]
observation6 = ObservedData(number_observed=1, object_refs=obs_refs6,
                            first_observed=email_message1.date,last_observed=email_message1.date)
#
# F. Sighting
hunt = SightingHunt(name="kestrel", playbook_id="playbook_1_1", rule="demo rule string")
sight_hunt_ext = {
    sight_ext_id: sight_ext,
    "sighting-hunt": hunt
}
sighting6 = Sighting(observed_data_refs=observation6.id, where_sighted_refs=[location.id],
                     sighting_of_ref=sender_identity.id, extensions=sight_hunt_ext)
#
# G. Setup Event and Sequence
event2 = Event(
    status="occured", description="2 users clicked on the email and destroyed their laptops",
    event_types=["dissemination-phishing-emails"], name="confirmed impact",
    sighting_refs=[sighting6], extensions=event_ext_dict
)
eseq1_2 = Sequence(
    step_type="single_step", sequenced_object=event2.id,
    sequence_type="event", extensions=seq_ext_dict
)
# H. Availability Impact
numbers2 = {"computers-mobile": 2}
availability2 = Availability(availability_impact=99)
avail_impact2 = Impact(
    impact_category="availability", criticality=99, description="Two Laptops are stuffed",
    impacted_entity_counts=numbers2, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "availability":availability2}
)
#
# I. New Task to setup the TTP
#
task6 = Task(
    task_types=["investigation"], outcome="pending", name="Add Phishing TTP",
    description="Use the Mitre ATT&CK Phishing TTP to confirm the technique",
    owner=me.id, extensions={task_ext_id:task_ext}
)
tseq1_6 = Sequence(
    step_type="single_step", sequenced_object=task6.id,
    sequence_type="task", extensions=seq_ext_dict
)
#
# Step 6.A.2 Collect Objects
#
local_list7 = [conv(software), conv(file), conv(process), conv(SRO_Evil), conv(SRO_click1), conv(SRO_click2),
               conv(observation6), conv(sighting6), conv(event2), conv(eseq1_2), conv(avail_impact2),
               conv(task6), conv(tseq1_6)]
local_list7_id = [software.id, file.id, process.id, SRO_Evil.id, SRO_click1.id, SRO_click2.id,
                  observation6.id, sighting6.id]
other_object_refs = other_object_refs + local_list7_id
task_refs.append(task5.id)
event_refs.append(event2.id)
impact_refs.append(avail_impact2.id)
sequence_refs.append(eseq1_2.id)
sequence_refs.append(tseq1_6.id)
bundle_list = bundle_list + local_list7
#
# Step 6.A.3. Update Task from Pending to Successful, and add objects and new task to Incident
#
for bun in bundle_list:
    if bun["type"] == "incident":
        ext = bun["extensions"]
        inc_ext = ext[inc_ext_id]
        inc_ext["other_object_refs"] = other_object_refs
        inc_ext["sequence_refs"] = sequence_refs
        inc_ext["task_refs"] = task_refs
        inc_ext["impact_refs"] = impact_refs
    elif bun["type"] == "task" and bun["id"] == task5.id:
        bun["outcome"] = "successful"
    elif bun["type"] == "sequence" and bun["id"] == tseq1_5.id:
        bun["on_completion"] = tseq1_6.id
    elif bun["type"] == "sequence" and bun["id"] == eseq1_1.id:
        bun["on_completion"] = eseq1_2.id


######################################################################################################
# Additional (Fake) Impact Examples for Documentation
######################################################################################################
numbers3 = {"computers-personal":2, "computers-server":3}
availability3 = Availability(availability_impact=99)
avail_impact3 = Impact(
    impact_category="availability", criticality=99, description="Two Laptops and 3 Servers are stuffed",
    impacted_entity_counts=numbers3, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "availability":availability3}
)

numbers4 = {"computers-personal":2}
confidentiality1 = Confidentiality(information_type="credentials-user", loss_type="exploited-loss", record_count=2, record_size=2000)
confid_impact = Impact(
    impact_category="confidentiality", criticality=99, description="Two Laptops had credentials stolen",
    impacted_entity_counts=numbers4, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "confidentiality":confidentiality1}
)

external_impact = External(impact_type="public-confidence")
extern_impact = Impact(
    impact_category="external", criticality=99, description="Public confidence has taken a hit",impacted_entity_counts=numbers4,
    recoverability="regular", extensions={imp_ext_id:imp_ext, "external":external_impact}
)
integrity_impact = Integrity(alteration="partial-modification", information_type="credentials-user",record_count=2, record_size=2000)
integ_impact = Impact(
    impact_category="integrity", criticality=99, description="The credentials were modified",
    impacted_entity_counts=numbers4, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "integrity":integrity_impact}
)
monetary_impact = Monetary(variety="ransom-demand", conversion_rate=1.538,conversion_time="2023-11-07T08:53:15.645995Z",
                            currency="USD", currency_actual="AUD", max_amount=100000, min_amount=10000)
money_impact = Impact(
    impact_category="monetary", criticality=99, description="The ransom demands were significant",
    impacted_entity_counts=numbers4, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "monetary":monetary_impact}
)
physical_impact = Physical(impact_type="damaged-nonfunctional", asset_type="computers-personal")
phys_impact = Impact(
    impact_category="physical", criticality=99, description="The rcomputers are not usable, but can be fixed",
    impacted_entity_counts=numbers4, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "physical":physical_impact}
)
traceability_impact = Traceability(traceability_impact="provable-accountability")
trace_impact = Impact(
    impact_category="traceability", criticality=99, description="We can reconstruct the attack from the data remaining",
    impacted_entity_counts=numbers4, recoverability="regular",
    extensions={imp_ext_id:imp_ext, "traceability":traceability_impact}
)
local_list8 = [
    conv(avail_impact3), conv(confid_impact), conv(confid_impact),
    conv(integ_impact), conv(money_impact), conv(phys_impact), conv(trace_impact)
]
bundle_list = bundle_list + local_list8
######################################################################################################
# Additional (Fake) Sighting Examples for Documentation
######################################################################################################

frame = SightingFramework(framework ="MITRE ATT&CK", version="14.1", domain="Enterprise",
                          comparison="exclusion list and hunt",
                          comparison_approach="The Exclusion List confirmed the email was previously sighted and the Hunt confirmed that processes had been started")
sight_frame_ext = {
    sight_ext_id: sight_ext,
    "sighting-framework": frame
}

sighting7 = Sighting(observed_data_refs=observation6.id, where_sighted_refs=[location.id],
                     sighting_of_ref=TTP_spear_phishing['id'], extensions=sight_frame_ext)

external = SightingExternal(source ="MISP", version="14.1", pattern=pat1, pattern_type="stix",
                          payload="Proven Malicious Phishing Source", valid_from="2023-09-07T08:53:15.645995Z",
                          valid_until="2023-11-07T08:53:15.645995Z")
sight_external_ext = {
    sight_ext_id: sight_ext,
    "sighting-external": external
}
sighting8 = Sighting(observed_data_refs=observation6.id, where_sighted_refs=[location.id],
                     sighting_of_ref=TTP_spear_phishing["id"], extensions=sight_external_ext)

local_list9 = [
    conv(sighting7), conv(sighting8), TTP_spear_phishing, mitre_identity, mitre_marking
]
bundle_list = bundle_list + local_list9

#######################################################################################################
#######################################################################################################
# Print Bundle on console
#######################################################################################################
bun_len = len(bundle_list)
seq_list = []
for inc, bun in enumerate(bundle_list):
    print(f"------------------------------ {inc+1} of {bun_len}--------------------------------------------")
    print(bun)

print("========================== task refs ====================================")
print(task_refs)
print("========================== event refs ====================================")
print(event_refs)
print("========================== impact refs ====================================")
print(impact_refs)
print("========================== other object refs ====================================")
print(other_object_refs)
#########################################################################################################
# Export bundle
#########################################################################################################
sorted_list = sorted(bundle_list, key=lambda i: i['id'])
bundle_dict["objects"] = sorted_list
pathfile="test/data/os-threat/test2/evidence.json"

with open(pathfile, 'w') as outfile:
    json.dump(bundle_dict, outfile, indent=6)