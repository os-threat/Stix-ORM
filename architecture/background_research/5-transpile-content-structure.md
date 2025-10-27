# Stix to TypeQL Transpiling Model

## Assumptions About the Process

1. **Different Names for Stix and TypeQL Properties**: Stix property names are set, and follow conventions such as  using underscores, ending with "_ref" for references, "_refs" for list of references, ending with "s" for list properties. The corresponding TypeQL variable name may be different because it uses hyphens instead of underscores, has to avoid reserved TypeQL keywords, and sometimes needs to add words to overlapping names/properties with different definitions between different Stix dialects
2. **Collapse the 28 Stix Components into 8 Categories**: The 28 Stix components that every Stix object is comprised of can be collapsed into  8 categories based on the shape of the data:
   a. Simple Properties (string, integer, boolean, timestamp, float, etc)
   b. List Properties (the property names that are lists)
   c. Embedded Reference Properties (single foreign key reference to another Stix object), and  List of References Properties (list of references to other Stix objects)
   d. Subobject and Extension Properties (sub-objects with their own properties)
   e. List of Subobjects (list of sub-objects with their own properties)
   f. Key-Value Dictionary Properties (dictionary of key-value pairs)
   g. SRO Relationship Properties (relationship objects with roles and references to other Stix objects)
   h. Entity Names ( a name registry for the different types of names for objects and subobjects)
3. **Fixed TypeQL Structure per Category**: Each of the 8 categories has a specific TypeQL structure that is used to represent it in TypeQL. For example, simple properties are represented as attributes, list properties as multiple attributes, embedded references as relations with roles, subobjects as entities connected by a relation, etc.

## Modelling the 8 Stix Categories in TypeQL

### Simple Properties Transpiled to TypeQL


### List Properties Transpiled to TypeQL

### Embedded Reference Properties Transpiled to TypeQL

### Subobject and Extension Properties Transpiled to TypeQL

### List of Subobjects Transpiled to TypeQL

### Key-Value Dictionary Properties Transpiled to TypeQL

### SRO Relationship Properties Transpiled to TypeQL

### Entity Names Transpiled to TypeQL for Objects and Subobjects




## StixORM Content Layout for the 8 Categories

### StixORM Content for Simple Properties

### StixORM Content for Subobject and Extension Properties

### StixORM Content for List of Subobjects

### StixORM Content for Key-Value Dictionary Properties

### StixORM Content for SRO Relationship Properties

### StixORM Content for Entity Names


## Identity Example Converting Stix to TypeQL

Given the above, as an example consider the IDentity class, with the data example presented in the stix-21-components.md file.

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
