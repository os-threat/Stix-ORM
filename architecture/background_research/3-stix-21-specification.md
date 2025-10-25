# STIX 2.1 Specification - Core Concepts

## Phase 0 Research Focus: Object Types, Relationships, Reference Patterns

### 1. STIX Overview

**Core Mission**: Language and serialization format for exchanging cyber threat intelligence (CTI)

**Graph-Based Model**: STIX represents connected nodes (objects) and edges (relationships)
- **Nodes**: STIX Domain Objects (SDOs) and STIX Cyber-observable Objects (SCOs)
- **Edges**: STIX Relationship Objects (SROs) and embedded relationships

### 2. STIX Object Architecture

#### STIX Domain Objects (SDOs) - 19 Types
1. **Attack Pattern** - Adversarial tactics and techniques
2. **Campaign** - Set of attacks over time against specific targets
3. **Course of Action** - Response/mitigation actions
4. **Grouping** - Explicit assertion of shared context
5. **Identity** - Individuals, organizations, groups
6. **Incident** - Security events (stub object in 2.1)
7. **Indicator** - Detection patterns using STIX Pattern Language
8. **Infrastructure** - Systems, software, resources supporting operations
9. **Intrusion Set** - Grouped adversarial behaviors from single organization
10. **Location** - Geographic or logical locations
11. **Malware** - Malicious code instances and families
12. **Malware Analysis** - Analysis results of malware samples
13. **Note** - Annotations and additional context
14. **Observed Data** - Raw cyber data observations
15. **Opinion** - Assessment or evaluation of STIX objects
16. **Report** - Collections of threat intelligence
17. **Threat Actor** - Individuals/groups conducting attacks
18. **Tool** - Legitimate software used by threat actors
19. **Vulnerability** - Weaknesses in systems/software

#### STIX Cyber-observable Objects (SCOs) - 18 Types
1. **Artifact** - Binary or file data
2. **Autonomous System** - Internet routing information
3. **Directory** - File system directories
4. **Domain Name** - Network domain names
5. **Email Address** - Email address information
6. **Email Message** - Email message content
7. **File** - File system objects
8. **IPv4 Address** - IPv4 network addresses
9. **IPv6 Address** - IPv6 network addresses
10. **MAC Address** - Media Access Control addresses
11. **Mutex** - Mutual exclusion objects
12. **Network Traffic** - Network communication data
13. **Process** - Computer process information
14. **Software** - Software package information
15. **URL** - Uniform Resource Locators
16. **User Account** - User account information
17. **Windows Registry Key** - Windows registry data
18. **X.509 Certificate** - Digital certificate information

### 3. Relationship Patterns

#### Embedded Relationships (ID References)
- **Purpose**: Inherent linkages within objects
- **Format**: Property containing ID of another STIX object
- **Example**: `created_by_ref` → Links to Identity object
- **Key Pattern**: Property names ending in `_ref` (single) or `_refs` (multiple)

#### External Relationships (SROs)
- **Generic Relationship Object**: Flexible relationship_type property
- **Sighting Object**: Special case for "seeing" objects with additional properties

#### Common Relationship Types
- `indicates` - Indicator → Malware/Campaign/Threat Actor
- `uses` - Campaign/Threat Actor → Attack Pattern/Tool/Malware
- `targets` - Attack Pattern → Identity/Location/Vulnerability
- `mitigates` - Course of Action → Attack Pattern/Malware/Vulnerability
- `attributed-to` - Campaign/Intrusion Set → Threat Actor
- `based-on` - Indicator → Observed Data
- `related-to` - Generic relationship for any objects

### 4. Reference Field Identification Patterns

#### Standard Reference Patterns
1. **Single References**: Properties ending in `_ref`
   - `created_by_ref` - References Identity object
   - `sample_ref` - References File/Artifact object
   - `source_ref` - References source object in relationships

2. **Multiple References**: Properties ending in `_refs`
   - `object_refs` - References to multiple STIX objects
   - `object_marking_refs` - References to Marking Definition objects
   - `sample_refs` - References to multiple File/Artifact objects

3. **Relationship References**
   - `source_ref` - Source object in relationship
   - `target_ref` - Target object in relationship
   - `sighting_of_ref` - Object being sighted

#### STIX ID Format Pattern
```regex
^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$
```
- **Structure**: `{object-type}--{UUID}`
- **Example**: `malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b`
- **UUID Types**: UUIDv4 for SDOs/SROs, UUIDv5 for SCOs

### 5. Common Properties Across Objects

#### Required Properties (Most Objects)
- `type` - Object type identifier
- `spec_version` - STIX version (must be "2.1")
- `id` - Unique identifier
- `created` - Creation timestamp
- `modified` - Last modification timestamp

#### Optional Properties
- `created_by_ref` - Reference to Identity object
- `revoked` - Boolean indicating if object is revoked
- `labels` - User-defined categorization
- `confidence` - Assessment confidence level
- `lang` - Language code
- `external_references` - Non-STIX references
- `object_marking_refs` - Data marking references
- `granular_markings` - Granular data markings
- `extensions` - Object extensions

### 6. Key Implementation Considerations

#### Object Versioning
- **Version Identification**: Combination of `id` + `modified` timestamp
- **Version Rules**: Only object creator can create new versions
- **Latest Version**: Most recent `modified` timestamp

#### ID References Resolution
- **Process**: Match reference value to exact `id` property
- **Multiple Versions**: Use latest version (most recent `modified`)
- **Unresolved References**: Specification doesn't define handling

#### Extension Mechanisms
- **Property Extensions**: Add properties to existing objects
- **New Object Types**: Define entirely new STIX objects
- **Toplevel Extensions**: Add properties at object root level

### 7. Custom Field Patterns in Real-World Data

#### MITRE ATT&CK Extensions
- `x_mitre_*` properties for ATT&CK-specific data
- Custom relationship types for technique relationships
- Extended kill chain phases

#### STIX Extensions
- `behavioral_refs` - References to behavior objects
- `on_completion` - Reference to sequence object (collision-prone)
- `sequence` - Reference to sequence object (collision-prone)
- `external_id` - Alternative identifiers

#### Dynamic Detection Strategy
1. **Method 1**: Check property name patterns (`_ref`, `_refs`)
2. **Method 2**: Validate value against STIX ID regex
3. **Method 3**: Resolve reference to confirm valid STIX object

### 8. Critical Success Factors for STIX-ORM

#### Reference Field Detection
- **Must Handle**: Standard patterns + custom extensions
- **Cannot Hardcode**: Field lists break with new extensions
- **Dynamic Approach**: Pattern matching + value validation

#### TypeQL Variable Generation
- **Challenge**: Multiple references to same object type
- **Solution**: Relation-aware variable naming
- **Pattern**: `f"{property.replace('_', '-')}-{object_type}{sequence}"`

#### Dependency Management
- **Requirement**: Insert referenced objects before referencing objects
- **Approach**: Topological sorting of object dependencies
- **Edge Cases**: Circular references and self-references

---

## Phase 0 Knowledge Checkpoints

- [ ] **STIX Object Structure**: Understanding of 19 SDOs + 18 SCOs + relationship patterns
- [ ] **Reference Patterns**: Recognition of `_ref`/`_refs` patterns + STIX ID format
- [ ] **Dynamic Detection**: Methods for identifying reference fields in custom extensions
- [ ] **Relationship Types**: Common relationship patterns and their semantics
- [ ] **Extension Mechanisms**: How STIX allows customization while maintaining compatibility

This foundation knowledge enables understanding of conditional enrichment systems, TypeQL variable collision prevention, and dynamic reference detection patterns implemented in STIX-ORM.