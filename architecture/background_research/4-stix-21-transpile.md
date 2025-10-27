# STIX 2.1 Component Architecture Analysis

**Phase 0 Research Focus**: Understanding how STIX 2.1 objects are constructed from fundamental property types, what the typedb respresentation of these types looks like, and how this impacts TypeQL statement generation in STIX-ORM.

## Executive Summary

STIX 2.1 Python classes are built from **a series of fundamental property types** organized into **5 categories of JSON data structures**, we **need 5 different types of TypeQL structures to represent them**. Understanding how this component architecture is leveraged for transpiling is critical for STIX-ORM because:

This information underpins the transpiling process. This document should not be changed, only extended with additional insights.

## Every Stix Object or Subobject is Based on a Series of Parent Classes

All STIX 2.1 object and subobject classes are built from a series of parent classes that define their core behavior and property types. The main parent classes include:

- `_STIXBase21`: Base class for all STIX 2.1 objects and subobjects
- `_DomainObject`: Parent class for domain objects (e.g., Identity, AttackPattern)
- `_RelationshipObject`: Parent class for relationship objects (e.g., Relationship, Sighting)
- `_Observable`: Parent class for observable objects (e.g., File, NetworkTraffic)
- `_Extension`: Parent class for extension objects (e.g., custom extensions)

## Every Stix Python Object and subobject is Built from a combination of Common Property Types and Object Parent Classes

All property names must use underscore not dashes to space words. Every STIX 2.1 Python class is comprised of a unique combination of these underlying property types. They can be broken down into **5 Categories of TypeQL Representations** as follows:

### Category 1-A: True Simple Properties (7 Types)

| Simple Property | Representation | Template |
|---|---|---|
| StringProperty(Property) | Simple string, may expand to markdown | String |
| IntegerProperty(Property) | Simple integer | Integer |
| FloatProperty(Property) | Simple float | Double |
| BooleanProperty(Property) | Simple boolean | Boolean |
| TimestampProperty(Property) | Simple Timestamp | Timestamp |
| BinaryProperty(Property) | Simple binary | Base64String |
| HexProperty(Property) | Simple hex | HexString |

### Category 1-B: Pretend Simple Properties (5 Types)

These properties aren't simple in reality, but are modelled as simple strings for simplification purposes. Vocab and enum are treated as strings in this iteration. Patterns are also treated as strings for this analysis.

| Simple Property | Representation | Template |
|---|---|---|
| EnumProperty(StringProperty) | Select from List of Allowable Values | Enum (Select, 4 lines) |
| OpenVocabProperty(StringProperty) | Select from List of Words and Definitions | Vocab (Select, 4 lines, API Backend) |
| PatternProperty(StringProperty) | Viable Pattern Format | Pattern (Input) |
| IDProperty(Property) | Valid id, known string and valid UUID, treated as string | ID |
| SelectorProperty(Property) | Enables selection of properties, treated as string | Selector |

### Category 1-C: List of Simple Properties - (1 Type) **Property Name ends with 's'**

| Simple Property | Representation | Template |
|---|---|---|
| ListProperty(StringProperty(Property)) | Array of True Simple Property classes | List |

### Category 2: Key Value Stores (2 Types)

| Composite Property | Representation | Template |
|---|---|---|
| DictionaryProperty(Property) | String keys, any simple value | Dictionary (Input) |
| HashesProperty(DictionaryProperty) | Enter Allowable Keys, with hash value | Hash (Input) |

### Category 3: Extensions and Subobjects (3 Types)

| Composite Property | Representation | Template |
|---|---|---|
| ExtensionsProperty(DictionaryProperty) | Single key, Extension class value (_Extension class) | Extension |
| OSThreatExtensionsProperty(DictionaryProperty) | Enhanced cross-dialect extensions | Enhanced Extension |
| EmbeddedObjectProperty(Property) | Embedded sub object (_StixBase class) | Embedded |

### Category 4-A: Reference Properties (3 Types) - **Property Name ends with _ref**

| Reference Property | Representation | Template |
|---|---|---|
| ObjectReferenceProperty(StringProperty) | Reference to a valid object | Object_Ref |
| ReferenceProperty(Property) | Reference to a Stix-only valid object | Reference |
| OSThreatReference(Property) | Reference to an all-objects valid object | OSThreatReference |


### Category 4-B: List of References Properties (2 Types) - **Property Name ends with _refs**

| List of References Property | Representation | Template |
|---|---|---|
| ListProperty(ReferenceProperty(Property)) | Reference to a Stix-only valid object | Reference |
| ListProperty(OSThreatReference(Property)) | Reference to an all-objects valid object | OSThreatReference |

### Category 5: List of Subobjects (3 Types)

| List of Subobjects | StixORM Representation | Template |
|---|---|---|
| ListProperty(KillChainPhase()) | Reference to a sub-object | KillChainPhase |
| ListProperty(ExternalReference()) | Reference to a sub-object | ExternalReference |
| ListProperty(GranularMarking()) | Reference to a sub-object | GranularMarking |
| ListProperty(EmbeddedObjectProperty(type=?)) | Reference to a sub-object | EmbeddedObject |

### Data Missing from the Python Classes

The Python class definitions do not inlcude the specifications about what roles each object can play in various type of Stix relationship objects

## TypeQL Modelling of Stix

### Parent Python Class and TypeQL Type Names for Objects and Subobjects


 `_DomainObject`: `stix-domain-object` Parent class for domain objects (e.g., Identity, AttackPattern)
 `_RelationshipObject`: `stix-core-relationship` Parent class for relationship objects (e.g., Relationship, Sighting)
 `_Observable`: `stix-cyber-observable-object` Parent class for observable objects (e.g., File, NetworkTraffic)
 `_Extension`: `SCO-extension` Parent class for extension objects (e.g., custom extensions)
 `_STIXBase21`: `stix-sub-object` Base class for all STIX 2.1 objects and subobjects

### Parent TypeQL types for Relations used to Build composite Properties

All non-SRO relations used to model composite properties in TypeQL, are based on the same parent TypeQL type, with its own unique roles for source and target. Every use case of a relation is then sub-classed from this parent type, with specialised relation name and role names.:

```typeql

embedded sub relation,
	relates pointed-to, # the object being pointed to
	relates owner; # the current object

```

### Mapping the 5 Key Categories of STIX Class Properties

Importantly, typeql names may be different from stix property names, for a variety of reasons including naming conventions, to avoid collisions and the need for disambiguation.
The 5 categories of STIX properties can be modelled with 5 specific TypeQL constructs as follows:

1. **Simple Properties**: Map to TypeQL attributes, which can be owned by entities or relations. Lists of simple properties map to the same attributes, but with multiple values (polymorphic). For example
    ```typeql
    define    
      stix-attribute-string sub attribute, value string, abstract,
        plays data-marking:marked;
        name sub stix-attribute-string;

      identity sub stix-domain-object,
	      owns name;
    ```
2. **Key Value Properties**: Map to a subobject entity with a key and value that plays a role in an embedded relation that links that pointed to key and value entity to the owner entity. For example, the EXIF tags property in an image File object maps to:

```typeql
define
	
	EXIF-value sub stix-attribute-string;
	EXIF-key sub stix-sub-object,
    owns dict-key,
		owns EXIF-value,
		plays EXIF-tags:info;
			
  EXIF-tags sub embedded,
    relates image as owner,
    relates info as pointed-to;
```

3. **Extension and Sub ObjectProperties**: Map to subobject entities that play a role in a relation based on the embedded relation class defined above. For example, the Windows PE binary extension property in a File object maps to:

```typeql
define
	windows-pebinary-ext sub SCO-extension, 	
		owns pe-type,
		owns imphash,
		owns machine-hex,
		owns number-of-sections,
		owns time-date-stamp,
		owns pointer-to-symbol-table-hex,
		owns number-of-symbols,
		owns size-of-optional-header,
		owns characteristics-hex,
		plays hashes:hash-owner,
		plays optional-headers:pebinary,
		plays sections:pebinary,
		plays windows-pebinary-extension:pebinary;

		windows-pebinary-extension sub extensions,
			relates file as sco,
			relates pebinary as extension;

```

4. **Embedded Reference Properties**: Map to a specialised relation with two roles absed on the embedded parent relation type defined above. For example, the created_by_ref property in an Identity object maps to:

```typeql
define
	created-by sub embedded, 
		relates created as owner,
		relates creator as pointed-to;

```

5. **List of Objects Properties**: Represent array of subobjects, map to an entity based on stix-sub-object parent type, that plays a role in a specialised relation based on the embedded parent relation type defined above. For example, the external-references property in a Stix Domain Object maps to:

```typeql
define
  external-reference sub stix-sub-object,
    owns source-name, 
    # Optional
    owns description,
    owns url-link, 
    owns external-id, 
    plays hashes:hash-owner,
    plays external-references:referencing;  

	external-references sub embedded, 
		relates referenced as owner,
		relates referencing as pointed-to;


## Real-World Example: Identity Object Architecture

The Identity object demonstrates how multiple property types combine to create complex STIX objects with custom extensions.

### Core Identity Class (STIX 2.1 Standard)

The base Identity object uses **12 different property types**:

```python
class Identity(_DomainObject):
    """STIX 2.1 Identity object with comprehensive property type usage"""
    
    _type = 'identity'
    _properties = OrderedDict([
        # Simple Properties
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('contact_information', StringProperty()),
        ('lang', StringProperty()),
        
        # Reference Properties  
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        
        # Timestamp Properties
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        
        # Boolean Properties
        ('revoked', BooleanProperty(default=lambda: False)),
        
        # Integer Properties
        ('confidence', IntegerProperty()),
        
        # Collection Properties
        ('roles', ListProperty(StringProperty)),
        ('labels', ListProperty(StringProperty)),
        ('sectors', ListProperty(OpenVocabProperty(INDUSTRY_SECTOR))),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
        
        # Vocabulary Properties
        ('identity_class', OpenVocabProperty(IDENTITY_CLASS)),
        
        # Extension Properties
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])
```

### Custom Extension Classes (OS-Threat)

Custom extensions demonstrate how the same 28 property types create entirely new functionality:

```python
class ContactNumber(_STIXBase21):
    """Sub-object using simple properties only"""
    _type = 'contact-number'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('contact_number_type', StringProperty(required=True)),
        ('contact_number', StringProperty(required=True)),
    ])

class EmailContact(_STIXBase21):
    """Sub-object combining simple and reference properties"""
    _type = 'email-contact'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('digital_contact_type', StringProperty(required=True)),
        ('email_address_ref', ReferenceProperty(valid_types='email-addr', required=True)),
    ])

class SocialMediaContact(_STIXBase21):
    """Sub-object with different reference type"""
    _type = 'social-media-contact'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('digital_contact_type', StringProperty(required=True)),
        ('user_account_ref', ReferenceProperty(valid_types='user-account', required=True)),
    ])

class IdentityContact(_Extension):
    """Extension using embedded object properties and lists"""
    _type = 'extension-definition--66e2492a-bbd3-4be6-88f5-cc91a017a498'
    _properties = OrderedDict([
        ('extension_type', StringProperty(required=True, fixed='property-extension')),
        
        # Embedded Object Lists - Critical for TypeQL variable generation
        ('contact_numbers', ListProperty(EmbeddedObjectProperty(type=ContactNumber))),
        ('email_addresses', ListProperty(EmbeddedObjectProperty(type=EmailContact))),
        ('social_media_accounts', ListProperty(EmbeddedObjectProperty(type=SocialMediaContact))),
        
        # Simple String Properties
        ('first_name', StringProperty()),
        ('last_name', StringProperty()),
        ('middle_name', StringProperty()),
        ('prefix', StringProperty()),
        ('suffix', StringProperty()),
        ('team', StringProperty()),
    ])
```



## Example JSON Output from the Identity Object with Extension

The resulting JSON demonstrates how the 28 property types translate to actual data structures:

```json
{
  "type": "identity",
  "id": "identity--4e0dd272-7d68-4c8d-b6bc-0cb9d4b8e924",
  "created": "2022-05-06T01:01:01.000Z",
  "modified": "2022-12-16T01:01:01.000Z",
  "spec_version": "2.1",
  "name": "Paolo",
  "description": "The main point of contact for the incident.",
  "identity_class": "individual",
  "roles": [
    "security-point-of-contact"
  ],
  "contact_information": "Ring him as he is unreliable on Slack",
  "extensions": {
    "extension-definition--66e2492a-bbd3-4be6-88f5-cc91a017a498": {
      "extension_type": "property-extension",
      "team": "responders",
      "first_name": "Paolo",
      "middle_name": "",
      "last_name": "Di Prodi",
      "contact_numbers": [
        {
          "contact_number": "123-456-7890",
          "contact_number_type": "work-phone"
        }
      ],
      "email_addresses": [
        {
          "email_address_ref": "email-addr--06029cc1-105d-5495-9fc5-3d252dd7af76",
          "digital_contact_type": "work"
        },
        {
          "email_address_ref": "email-addr--78b946aa-91ab-5ce8-829b-4d078a8ecc00",
          "digital_contact_type": "organizational"
        }
      ],
      "social_media_accounts": [
        {
          "user_account_ref": "user-account--7aa68be3-1d4d-5b0f-8c26-8410085e5741",
          "digital_contact_type": "career",
          "description": "Paolo's LinkedIn contact details"
        }
      ]
    }
  }
}
```

### TypeQL for the Example JSON Output from the Identity Object with Extension


The above JSON then converts into the following TypeQL match and insert statements using the 5 categories of modelling approach described above.

```typeql

match  
 $email-address-ref-email-addr0 isa email-addr, has stix-id "email-addr--06029cc1-105d-5495-9fc5-3d252dd7af76";
 $email-address-ref-email-addr1 isa email-addr, has stix-id "email-addr--78b946aa-91ab-5ce8-829b-4d078a8ecc00";
 $user-account-ref-user-account0 isa user-account, has stix-id "user-account--7aa68be3-1d4d-5b0f-8c26-8410085e5741";
 
insert 
$identity isa identity,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified,
 has name $name,
 has description $description,
 has stix-role $roles0,
 has identity-class $identity-class,
 has contact-information $contact-information;

 $stix-type "identity";
 $spec-version "2.1";
 $stix-id "identity--4e0dd272-7d68-4c8d-b6bc-0cb9d4b8e924";
 $created 2022-05-06T01:01:01.0;
 $modified 2022-12-16T01:01:01.0;
 $name "Paolo";
 $description "The main point of contact for the incident.";
 $roles0 "security-point-of-contact";
 $identity-class "individual";
 $contact-information "Ring him as he is unreliable on Slack";

 $identity-contact isa identity-contact,
 has extension-type $extension-type,
 has first-name $first-name,
 has last-name $last-name,
 has middle-name $middle-name,
 has team $team;

 $extension-type "property-extension";
 $first-name "Paolo";
 $last-name "Di Prodi";
 $middle-name "";
 $team "responders";

 $identity-ext0 (identity-base:$identity, identity-spec:$identity-contact) isa identity-ext;


$contact-number-sub0 isa contact-number-sub,
 has contact-number "work-phone",
 has contact-number-type "123-456-7890";

 $identity-number (identity:$identity-contact, number-object:$contact-number-sub0) isa identity-number;

$email-contact-sub0 isa email-contact-sub,
 has digital-contact-type "work";
$email-contact-sub1 isa email-contact-sub,
 has digital-contact-type "organizational";

 $identity-email (identity:$identity-contact, email-object:$email-contact-sub0, email-object:$email-contact-sub1) isa identity-email;

 $email-ref0 (origin:$email-contact-sub0, email:$email-address-ref-email-addr0) isa email-ref;

 $email-ref1 (origin:$email-contact-sub1, email:$email-address-ref-email-addr1) isa email-ref;

$social-media-sub0 isa social-media-sub,
 has description "Paolo's LinkeIn contact details",
 has digital-contact-type "career";

 $identity-account (identity:$identity-contact, account-object:$social-media-sub0) isa identity-account;

 $user-account-ref0 (origin:$social-media-sub0, account:$user-account-ref-user-account0) isa user-account-ref;
 ```