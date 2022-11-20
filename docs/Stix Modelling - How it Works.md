# Stix Modelling Overview - How Does it Work?

At high level, the Stix model transforms quite cleanly into a TypeQL model, and if one understands how the transforms work then it is easy to predict the TypeQL syntax. First one needs to consider the basic STIX model.

The STIX Model is based on six different types of objects, but the bulk of the system can be understood by examining just three:
1. 18 x STIX Domain Objects
2. 18 x STIX Cyber Observable Objects
3. 31 x STIX Relationship Objects

These two types of entities and one type of relation contain the bulk of the meaning expressed by Stix. By understanding the common features of these objects we cam quickly get an overview of how the whole model works. First, we examine the obects at high level.

There are two different types of similarities through the Stix standard:
1. Similarities based on object ierarchy, such as common properties
2. Similarities based on underlying data shape

The common properties that are widely used are  demonstrated in the image below.

<img src="../docs/images/stix-core.png?raw=true" width="600" />

## STIX Model Overview
The STIX model is based on more than 70 core objects (entities and relations), which can be considered as a flat core object with 7 optional sub objects.

<img src="../docs/images/Stix-Generic-Object.png?raw=true" width="400" />



### STIX DOmain Objects (SDO)
There are 18 STIX Domain Objects, as shown in the diagram below
```mermaid
  flowchart LR
    id0(Stix Domain Object - SDO)
    id1([Attack Patern])
    id2([Campaign])
    id3([Course of Action])
    id4([Grouping])
    id5([Identity])
    id6([Indicator])
    id7([Infrastructure])
    id8([Intrusion Set])
    id9([Location])
    id10([Malwaare])
    id11([Malware Analysis])
    id12([Note])
    id13([Observed Data])
    id14([Opinion])
    id15([Report])
    id16([Threat Actor])
    id17([Tool])
    id18([Vulnerability])
    id0-->id1
    id0-->id2
    id0-->id3
    id0-->id4
    id0-->id5
    id0-->id6
    id0-->id7
    id0-->id8
    id0-->id9
    id0-->id10
    id0-->id11
    id0-->id12
    id0-->id13
    id0-->id14
    id0-->id15
    id0-->id16
    id0-->id17
    id0-->id18
```

### STIX Cyber Observable Objects (SCO)
There are 18 STIX Cyber Observable Objects, as shown in the diagram below
```mermaid
  flowchart LR
    id0(Stix Cyber Observable Object - SCO)
    id1([Artifact])
    id2([Autonomous System])
    id3([Directory])
    id4([Domain Name])
    id5([Email Address])
    id6([Email Message])
    id7([File])
    id8([IPv4])
    id9([IPv6])
    id10([MAC Address])
    id11([Mutex])
    id12([Network Traffic])
    id13([Process])
    id14([Software])
    id15([URL])
    id16([User Account])
    id17([Windows Registry Key])
    id18([X509 Certificate])
    id0-->id1
    id0-->id2
    id0-->id3
    id0-->id4
    id0-->id5
    id0-->id6
    id0-->id7
    id0-->id8
    id0-->id9
    id0-->id10
    id0-->id11
    id0-->id12
    id0-->id13
    id0-->id14
    id0-->id15
    id0-->id16
    id0-->id17
    id0-->id18
```
### STIX Relationship Objects (SRO)
There are 30 STIX Relationship Objects, 31 if the Sighting Object is included, as shown in the diagram below

```mermaid
  flowchart LR
    id0(Stix Relationship Object - SRO)
      id1([delivers])
      id2([targets])
      id3([uses]) 
      id4([attributed-to]) 
      id5([compromises]) 
      id6([originates-from]) 	
      id7([investigates]) 
      id8([mitigates]) 
      id9([located-at]) 
      id10([indicates]) 
      id11([based-on]) 
      id12([communicates-with]) 
      id13([consist]) 
      id14([control]) 
      id15([have]) 
      id16([hosts]) 	
      id17([ownership]) 
      id18([authored-by]) 
      id19([resolve-to ])
      id20([beacon]) 
      id21([exfiltrate]) 	
      id22([download]) 
      id23([drop]) 
      id24([exploit]) 
      id25([variant]) 
      id26([characterise]) 
      id27([impersonate]) 
      id28([analysis]) 
      id29([av-analysis])
      id30([remediation]) 
      id31{{sighting}}
      id0-->id1
      id0-->id2
      id0-->id3
      id0-->id4
      id0-->id5
      id0-->id6
      id0-->id7
      id0-->id8
      id0-->id9
      id0-->id10
      id0-->id11
      id0-->id12
      id0-->id13
      id0-->id14
      id0-->id15
      id0-->id16
      id0-->id17
      id0-->id18
      id0-->id19
      id0-->id20
      id0-->id21
      id0-->id22
      id0-->id23
      id0-->id24
      id0-->id25
      id0-->id26
      id0-->id27
      id0-->id28
      id0-->id29
      id0-->id30
      id0-->id31
```
## The Generic Flat STIX Object
*Note: We establish a simple concept for a generic STIX object in order to demonstrate the key features of how Stix objkects work. There is no actual generic STIX object, it is simply a device used to talk through the common features of the core 66 objects.*

The generic flat stix object has some key features. It is an entity, or relation, that has:
- a "type" property, which is the name of the object type
- an "id" property, which is a unique key field that contains the type of the object and a UUID
- additional properties, which are a basic datatype: string, integer, double, boolean or datetime stamps

An example of a flat Stix object, with no sub-object shapes is shown below, an identity object.
```json
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--733c5838-34d9-4fbf-949c-62aba761184c",
            "created": "2016-08-23T18:05:49.307Z",
            "modified": "2016-08-23T18:05:49.307Z",
            "name": "Disco Team",
            "description": "Disco Team is the name of an organized threat actor crime-syndicate.",
            "identity_class": "organization",
            "contact_information": "disco-team@stealthemail.com"
        }
```
We can add an additional sub-type to the generic flat object, and this is where there is a string of basic datatypes. In this case, then the below threat-actor object with lists of strings is also a generic flat object.
```json
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
            "created": "2014-11-19T23:39:03.893Z",
            "modified": "2014-11-19T23:39:03.893Z",
            "name": "Disco Team Threat Actor Group",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "threat_actor_types": [
                "crime-syndicate"
            ],
            "aliases": [
                "Equipo del Discoteca"
            ],
            "roles": [
                "agent"
            ],
            "goals": [
                "Steal Credit Card Information"
            ],
            "sophistication": "expert",
            "resource_level": "organization",
            "primary_motivation": "personal-gain"
        }
```
In short, a generic flat object is any data object where it consists of an entity or relation, with perties comprised of basic datatypes or lists of basic datatypes.

## Hashes Sub Onject
Hashes are actually a Basic Sub Object (i.e. an entity and relation that acts )

```json
    {
        "type": "file",
        "id": "file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d",
        "spec_version": "2.1",
        "hashes": {
            "MD5": "1717b7fff97d37a1e1a0029d83492de1",
            "SHA-1": "c79a326f8411e9488bdc3779753e1e3489aaedea"
        },
        "size": 83968,
        "name": "resume.pdf"
    }
```


## Granular Markings Sub Object

## Embedded Relarion Sub Object

## List of Objects

## Extension

## Key-Value Store


## Basic Sub Object
