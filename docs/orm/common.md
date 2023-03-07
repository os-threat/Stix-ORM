# 1. Stix Common Data Types

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