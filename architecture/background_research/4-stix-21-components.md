# STIX 2.1 Component Architecture Analysis

**Phase 0 Research Focus**: Understanding how STIX 2.1 objects are constructed from fundamental property types

## Executive Summary

STIX 2.1 objects are built from **28 fundamental property types** organized into **5 categories**. Understanding this component architecture is critical for STIX-ORM because:

1. **Dynamic Reference Detection** - Reference properties follow predictable patterns
2. **TypeQL Mapping** - Each property type requires specific TypeQL translation
3. **Extension Handling** - Custom extensions use the same fundamental building blocks

## The 28 Property Types: Complete Architecture

Every STIX 2.1 Python class is comprised of a unique combination of these underlying property types in two main categories:

- **Simple Properties**: Basic data types (string, integer, boolean, etc.)
- **Composite Properties**: Complex structures (lists, dictionaries, object references, extensions)

### Category 1: Simple Properties (7 Types)

| Simple Property | Representation | Template |
|---|---|---|
| StringProperty(Property) | Simple string, may expand to markdown | String |
| IntegerProperty(Property) | Simple integer | Integer |
| FloatProperty(Property) | Simple float | Double |
| BooleanProperty(Property) | Simple boolean | Boolean |
| TimestampProperty(Property) | Simple Timestamp | Timestamp |
| BinaryProperty(Property) | Simple binary | Base64String |
| HexProperty(Property) | Simple hex | HexString |

### Category 2: Collection Properties (3 Types)

| Collection Property | Representation | Template |
|---|---|---|
| DictionaryProperty(Property) | String keys, any simple value | Dictionary (Input) |
| ExtensionsProperty(DictionaryProperty) | Single key, Extension class value | Extension |
| ListProperty(Property) | Collection of Property or Container classes | List |

### Category 3: External Data Properties (4 Types)

| External Data Property | Representation | Template |
|---|---|---|
| EnumProperty(StringProperty) | Select from List of Allowable Values | Enum (Select, 4 lines) |
| OpenVocabProperty(StringProperty) | Select from List of Words and Definitions | Vocab (Select, 4 lines, API Backend) |
| HashesProperty(DictionaryProperty) | Enter Allowable Keys, with hash value | Hash (Input) |
| PatternProperty(StringProperty) | Viable Pattern Format | Pattern (Input) |

### Category 4: Reference Properties (6 Types) - **Critical for STIX-ORM**

| Reference Property | Representation | Template |
|---|---|---|
| EmbeddedObjectProperty(Property) | Embedded sub object (_StixBase class) | Embedded |
| IDProperty(Property) | Valid id, known string and valid UUID | ID |
| ObjectReferenceProperty(StringProperty) | Reference to a valid object | Object_Ref |
| ReferenceProperty(Property) | Reference to a Stix-only valid object | Reference |
| SelectorProperty(Property) | Enables selection of properties | Selector |
| ThreatReference(Property) | Reference to an all-objects valid object | ThreatReference |

### Category 5: Common Subobjects (3 Types)

| Common Subobjects | StixORM Representation | Template |
|---|---|---|
| KillChainPhase() | Reference to a sub-object | KillChainPhase |
| ExternalReference() | Reference to a sub-object | ExternalReference |
| GranularMarking() | Reference to a sub-object | GranularMarking |

## Critical Insights for STIX-ORM Development

### Reference Property Analysis
The **Reference Properties** are most critical for understanding STIX-ORM's challenges:

1. **ObjectReferenceProperty**: Standard `_ref` fields (e.g., `created_by_ref`)
2. **ReferenceProperty**: STIX-specific object references  
3. **ThreatReference**: All-objects valid references (includes custom extensions)
4. **EmbeddedObjectProperty**: Sub-objects within main objects

### Dynamic Detection Implications
- **Pattern Recognition**: `_ref` and `_refs` suffixes indicate reference fields
- **Value Validation**: References must match STIX ID format: `{type}--{uuid}`
- **Extension Support**: Custom extensions use same property types

### TypeQL Mapping Requirements
Each property type requires specific TypeQL translation:
- **Simple Properties** → Attributes
- **Reference Properties** → Relations with unique variables
- **List Properties** → Multiple attribute instances or relation targets
- **Extension Properties** → Special handling for custom schemas

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
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
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

### Key Architectural Insights

1. **Compositional Design**: Complex objects built from simple, reusable components
2. **Reference Patterns**: Multiple reference types (`email_address_ref`, `user_account_ref`) - each needs unique TypeQL variables
3. **Extension Mechanism**: Custom functionality using same fundamental property types
4. **Nested Structure**: Sub-objects within extensions within main objects 

## Complete JSON Output Analysis

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

### Critical Reference Fields Identified

This example contains **multiple reference fields** that STIX-ORM must handle:

1. **Standard References**:
   - `id` - Self-identification
   - `created_by_ref` - (not shown, but would reference Identity)

2. **Extension References**:
   - `email_address_ref` - References `email-addr` objects (appears twice)
   - `user_account_ref` - References `user-account` object

3. **TypeQL Variable Collision Risk**:
   - Multiple `email_address_ref` fields → Need unique variables
   - Different reference types to same object type → Need relation-aware naming

## Phase 0 Learning Objectives Achieved

✅ **Component Architecture**: Understanding of 28 property types across 5 categories  
✅ **Reference Patterns**: Recognition of `_ref` patterns and STIX ID format validation  
✅ **Extension Mechanisms**: How custom functionality uses same building blocks  
✅ **TypeQL Mapping Requirements**: Each property type needs specific translation approach  
✅ **Variable Collision Understanding**: Multiple references require unique variable generation

This analysis provides the foundational knowledge needed to understand STIX-ORM's:
- **Dynamic Reference Detection** algorithms
- **TypeQL Variable Collision Prevention** strategies  
- **Conditional Enrichment** system requirements

