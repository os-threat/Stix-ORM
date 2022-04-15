# Rationale for Mapping Vaticle TypeDB to Stix 2.1



The key to deriving powerful TypeDB schemas is to focus on the local details, building intricacy at the local level produces less complexity at the overall level. This is critical when modelling a complicated system such as Stix 2.1. Numbers enclosed in brackets indicate the relevant section from the stix 2.1 specification (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)

## 1. Stix Common Data Types

Vaticle TypeDB supports basic data types, including long, double, string, boolean and datetime formats (https://docs.vaticle.com/docs/schema/concepts#attribute). The Stix 2.1 schema utilises these basic types but also uses datastructures including enums, lists, dicts and lists of dicts (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gv21fm9t1qgx).

In ordcer to fully represent the stix data, some TypeQL structures will be setup to model the Stix su-data-objects, namely external-reference, hashes, and kill-chain-phases. Once this is done, then the mapping of stix common data types to TypeDB data types/structures will be as in the table below.

| Stix Data Type| Stix 2.1 Section | TypeDB Type | Description|
| :--- | :---: | :--- | :--- |
| binary | (2.1) | string| A sequence of bytes. |
| boolean | (2.2) | boolean| A value of true or false.|
| dictionary| (2.3)| structure | A TypeQL structure will contain this (see below) |
| enum | (2.4) | string| A value from a STIX Enumeration.|
| external-reference| (2.5)| structure | A TypeQL structure will contain this (see below).|
| float | (2.6)| double | An IEEE 754 double-precision number|
| hashes | (2.7) |structure | A TypeQL structure will contain this.|
| hex | (2.8) | string | An array of octets as hexadecimal.|
| identifier | (2.9) | string | An identifier (ID) is for STIX Objects.|
| integer | (2.10) | long | A whole number |
| kill-chain-phase | (2.11) | structure | A TypeQL structure will contain this (see below).|
| list | (2.11) | list | A sequence of values |
| open-vocab | (2.13) | string | A value from aStix open vocabulary (enum)|
| string | (2.14) | string | A series of Unicode characters|
| timestamp| (2.15) | datetime | A date and time value |



### 1.1. Mapping Stix Basic Data Types to a Vaticle TypeDB Attribute

Mapping a basic data type in json to typedb is simple. A key/value pair is mapped to a named attribute value. So there is a conceptual dimension reduction, instead of two pieces of information, a key-name and a basic type of value, only one is required, a named basic tyhpe of attribute, with its value. Certain key-names are reserved words in typeql (https://docs.vaticle.com/docs/schema/overview#reserved-keywords), and thereby cannot be used.

As an example,  "id", "value" and "type" are reserved words, so the fragment of a stix object shown below

```json
{
  "type": "ipv4-addr",
  "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
  "value": "198.51.100.3"
}
```

Converting this to Vaticle TypeDB would assign three values to string-type attributes:
```
    stix_type =  "ipv4-addr",
    stix_id = "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
    stix_value = "198.51.100.3"
```
In short, mapping basic Stix data types to Vaticle TypeDB attributes collapses two pieces of data, a key and a value, into a single piece of data, a named attribute with a value.


### 1.2 Mapping Stix Enums and Vocab to Vaticle TypeDB Attributes

Vaticle TypeDB does not yet support enums, although this is anticipated for the future. TypeDB has the advantage of guaranteeing that any unqiue attribute value is only stored once. So TypeDB ensures that any attribute value is only entered once, which is very useful when one is considering a limited vocabulary.

If these limited sets of words are emplaced in the database first, then a user could match any of the text values, before inserting an object using this value. However, without direct enum support, the system cannot the values to only those values initially loaded.

In short, enums and vocab in the stix json will be represented by named attributes with string values, but the values cannot be restricted by the database, currently only the GRPC client can control what values are loaded.


### 1.3 Stix External Reference Modelled by Vaticle TypeDB Entity plus Relation

The External Reference is a Stix sub-data-object (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx) used to describe pointers to information represented outside of Stix. It is presented as a list of External_References, holding one or more individual pointer descriptions.

An example is shown below.

```json
{
  ...
  "external_references": [
    {
      "source_name": "veris",
      "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
      "url": "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/
data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
      "hashes": {
      "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
      }
    }
  ],
  ...
}
```
An External References list is modelled in TypeQL by an Entity-Relation combination. The Entity describes the External Reference record, and the relation links it to the objects doing the referencing

```
external-reference sub stix-meta-object,
	# In addition to source-name, at least one of description, url or external-id must be present§
	# Required
	owns source-name, 

	# Optional
	owns description,
	owns url, 
	owns external-id,
	plays hashes:owner,
	plays external-references:referenced;

external-references sub relation, 
	relates referenced,
	relates referencing;
  ```

Thereby, the relationship between the properties of Stix External Reference, and its mapping to TypeQL are as follows.

 Stix 2.1 Property| Schema Object | Schema Name | Required  Optional |
| :--- | :----: | :---: | :----: |
| source_name | external-reference | source-name | Required |
| description | external-reference | description | Optional |
| hashes  | external-reference | hashes:owner | Optional |
| external_id  | external-reference | external-id | Optional |
 

### 1.4 Stix Hashes Modelled by Vaticle TypeDB Relations

The Stix Hashes sub-data-object (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_odoabbtwuxyd) represents one or more cryptographic hashes. An example is shown below

```json
{
  "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
  "MD5": "e4d909c290d0fb1ca068ffaddf22cbd0"
}
````

The Stix hashes can be connected with a number of Stix obhjects, including external-reference, file, ntfs-ext, artifact, windows-pebinary-ext, windows-pe-optional-header-type, windows-pe-scetion and X509-certificate.

The Vaticle hash implmentation creates a basic entity record, and then uses sub-classing to reflect the various types. The Hash entity is then related as contained to the owner through the Hashes relation.

```
hash sub entity, 
	owns hash-value, 
	plays hashes:contained; 

	md5 sub hash;
	sha-1 sub hash; 
	sha-256 sub hash;
	sha-512 sub hash; 
	sha3-256 sub hash; 
	sha3-512 sub hash;
	ssdeep sub hash; 
	tlsh sub hash; 


hashes sub relation,
	relates contained,
	relates owner;
```



### 1.5 Stix Kill-Chain-Phase Modelled by Vaticle TypeDB Relations

The kill-chain-phase represents a phase in a kill chain, which describes the various phases an attacker may undertake in order to achieve their objectives (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h). An example is hsown below

```
{
  ...
  "kill_chain_phases": [
    {
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "reconnaissance"
    }
  ],
  ...
}
```
In TypeQL, this structure is based on a simple Six Meta Object, and then related to the object by the kill-chain-usage relation, as shown below.

```
kill-chain-phase sub stix-meta-object,
	owns kill-chain-name, 
	owns phase-name,
	plays kill-chain-usage:kill-chain-using,

	# inferred role player
	plays kill-chain:participating-kill-chain-phase;

kill-chain-usage sub stix-core-relationship,
	relates kill-chain-used as target,
	relates kill-chain-using as source;
```




## 2. STIX Common Properties (3.2)

Stix objects use a common set of properties. Not all objects use the complete set of properties, and Stix objects also have properties specific to their objects type. However, the common properties are the  backbone of the Stix schema, and with the results of Section 1 as archetypes, it is straightforward to define the mapping of Stix Common Properties (3.2) to TypeDB.

Note: Words in property names MUST be separated with an underscore (_), while words in type names and string enumerations MUST be separated with a hyphen (-). Dictionary key and hash algorithm names MAY have underscores (_) or hyphens (-).


| Stix Common Property| Stix Type | TypeDB Type | Description|
| :--- | :---: | :--- | :--- |
| type | string | string| The type property identifies the type of STIX Object.  |
| spec_version | string | string| The version of the STIX specification used to represent this object.|
| id| identifier| string | The id property uniquely identifies this object. |
| created_by_ref | identifier | relation | Specifies the id property of the identity object that created this object|
| created| timestamp| datetime|A non-STIX identifier or reference to other related external content.|
| modified | timestamp| datetime | Represents the time that this particular version of the object was last modified.|
| revoked | boolean | boolean | Revoked objects are no longer considered valid by the object creator.| 
| labels | list of type string | list of type string | The labels property specifies a set of terms used to describe this object. |
| confidence | integer | integer | The confidence property identifies the correctness of the data, range of 0-100.|
| lang | string | string | The lang property identifies the language of the text content in this object. |
| external_references | list of type external-reference |  TypeQL Structure | Provides one or more URLs, descriptions, or IDs. |
| object_marking_refs | list of type identifier |  TypeQL Structure | A list of id properties of marking-definition objects that apply to this object. |
| granular_markings | list of type granular-marking | TypeQL Structure| Specifies a list of granular markings applied to this object.|
| defanged | boolean | boolean | Defines whether or not the data contained within the object has been defanged.|
| extensions| dictionary |  TypeQL Structure | Specifies any extensions of the object, as a dictionary. |

All of the Stix Common Properties in the table above can be easily defined based on the basic properties in Section 1. There are four common properties that need a TypeQL structure to contain them, and these are outlined below.

### 2.1 Mapping the Stix created_by_ref embedded relation to a TypeQL relation

The Stix created_by_ref field marks an embedded relation, where the value if the id field of the Identity object the object was made by. In typedb, this field is transformed into the created-by relation, as shown below.

```
	created-by sub stix-core-relationship, 
		relates created as target,
		relates creator as source;
  ```


### 2.2 Mapping the Stix external_references structure to a TypeQL relation
see discussion in Section 2.5 above

### 2.3 Mapping the Stix object_marking_refs and granular_markings structures to a TypeQL relation

Points to discuss/expand:
- TLP markings are inserted into the database on init, so they are always matched
- markings must always be inserted second, after the identity records and before all other records
- object marking works exclusively against the object
- granular markings work directly against the object property, but are also linked to the object

```

marking-definition sub stix-meta-object,
	owns name, 
	owns spec-version,
	plays creation:created,
	plays data-marking:marking;

	statement-marking sub marking-definition, 
		owns statement; 

	tlp-marking sub marking-definition;
		tlp-white sub tlp-marking;
		tlp-green sub tlp-marking;
		tlp-amber sub tlp-marking;
		tlp-red sub tlp-marking;


data-marking sub relation, 
	relates marking,
	relates marked;

	object-marking sub data-marking; 

	granular-marking sub data-marking,
		relates object;
```



### 2.4 Usage of the Stix Common Properties



<p class=MsoNormal><span lang=EN style='font-size:11.0pt;line-height:115%'>&nbsp;</span></p>

<table class=a4 border=1 cellspacing=0 cellpadding=0 width=641
 style='border-collapse:collapse;border:none'>
 <tr style='height:20.0pt'>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:20.0pt'>
  <p class=MsoNormal><b><span lang=EN style='color:white'>&nbsp;</span></b></p>
  </td>
  <td width=180 colspan=3 valign=top style='width:135.0pt;border:solid black 1.0pt;
  border-left:none;background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt;
  height:20.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>STIX Core Objects</span></b></p>
  </td>
  <td width=235 colspan=3 valign=top style='width:176.25pt;border:solid black 1.0pt;
  border-left:none;background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt;
  height:20.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>STIX Meta Objects</span></b></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border:solid black 1.0pt;
  border-left:none;background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt;
  height:20.0pt'>
  <p class=MsoNormal style='line-height:normal'><b><span lang=EN
  style='color:white'>&nbsp;</span></b></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='color:white'>Property Name</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>SDOs</span></b></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>SROs</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>SCOs</span></b></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>Extension</span></b></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>Language</span></b></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>Markings</span></b></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal align=center style='text-align:center'><b><span lang=EN
  style='color:white'>Bundle</span></b></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>type</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>spec_version</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>id</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>created_by_ref</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>created</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>modified</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#F4CCCC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Required</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>revoked</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr style='height:19.0pt'>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;background:white;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas;color:black'>labels</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt;height:19.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>confidence</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas;background:
  white'>lang</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;background:white;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas;color:black'>external_references</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>object_marking_refs</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>granular_markings</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>defanged</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
 <tr>
  <td width=129 valign=top style='width:96.75pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><b><span lang=EN style='font-family:Consolas'>extensions</span></b></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=62 valign=top style='width:46.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=59 valign=top style='width:44.25pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=80 valign=top style='width:60.0pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
  <td width=81 valign=top style='width:60.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=74 valign=top style='width:55.5pt;border-top:none;border-left:none;
  border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;background:
  #FFF2CC;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>Optional</span></p>
  </td>
  <td width=97 valign=top style='width:72.75pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt'>
  <p class=MsoNormal><span lang=EN style='font-size:8.0pt;line-height:115%;
  color:black'>N/A</span></p>
  </td>
 </tr>
</table>

# 3. Stix Properties/Embedded Relationships that are Mapped to TypeQL Relations

## 3.1 operating_system_refs Malware Object

## 3.2 sample_refs Malware Object

## 3.3 host_vm_ref Malware Analaysis Object

## 3.4 operating_system_ref Malware Analaysis Object

## 3.5 installed_software_refs Malware Analaysis Object

## 3.6 analysis_sco_refs Malware Analaysis Object

## 3.7 sample_ref Malware Analaysis Object




```
sample sub relation, 
	relates associated-to, 
	relates sco-sample;

	malware-sample sub sample;
	malware-analysis-sample sub sample;

execution sub relation,
	relates hosts-vm,
	relates operating-system, 
	relates executed-malware;

os-hosts sub relation,
	relates installed-software,
	relates os-system;

directory-reference sub relation,
	relates child-directory, 
	relates parent-directory,
	relates file-in-directory;

belong sub relation,
	relates belonged,
	relates belonging-to;

	ipv-autonomous-system-belong sub belong;
	user-email-belong sub belong;

email-sending sub relation, 
	relates from-email,
	relates sender-email,
	relates to-email,
	relates cc-email,
	relates bcc-email, 
	relates sent-email;

raw-email-reference sub relation, 
	relates email,
	relates binary;

body-raw-reference sub relation,
	relates containing-mime,
	relates non-textual-mime-part;

body-multipart sub relation, 
	relates contained-in,
	relates mime-part;

file-contain sub relation, 
	relates contained-coo,
	relates contained-file,
	relates containing-file;

content-file-containing sub relation, 
	relates containing-file,
	relates contained-content;

ntfs-alt-contain sub relation,
	relates containing-ntfs-ext,
	relates contained-alt-data-stream;

optional-header sub relation, 
	relates pebinary,
	relates optional-headers;

metadata-specification sub relation, 
	relates pe-file-section,
	relates pebinary;

network-traffic-source sub relation, 
	relates traffic,
	relates source, 
	relates payload, 
	owns src-port,
	owns src-byte-count,
	owns src-packets;

network-traffic-destination sub relation, 
	relates traffic,
	relates destination,
	relates payload,
	owns dst-port, 
	owns dst-byte-count,
	owns dst-packets; 

network-traffic-encapsulate sub relation,
	relates encapsulating,
	relates encapsulated;

message-body-data-reference sub relation,
	relates contained-data,
	relates message-body;

connection-opening sub relation,
	relates opened-connection,
	relates opened-by;

user-created-by sub relation,
	relates windows-registry-key-created,
	relates process-created,
	relates creating;

image-process sub relation,	
	relates executed-image,
	relates executing-process;

process-hierarchy sub relation,
	relates parent,
	relates child;

dll-loading-process sub relation, 
	relates loaded-dll,
	relates loading-process;

windows-registry-key-value sub relation,
	relates key,
	relates value;
  ```


The Stix Domain Objects are outlined in section 4.