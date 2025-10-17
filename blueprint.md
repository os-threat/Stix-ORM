# STIX-ORM Architectural Blueprint
## Cybersecurity Intelligence Hypergraph Transformation System

### Table of Contents
1. System Overview
2. Architecture Diagrams
3. Core Components
4. Transformation Pipeline
5. Example: Malware Object Transformation
6. Implementation Patterns
7. Schema Synchronization
8. Deployment Architecture

## System Overview

STIX-ORM is a sophisticated cybersecurity intelligence transformation system that bridges seven distinct STIX dialects with TypeDB's hypergraph database technology. The system transforms flat JSON threat intelligence data into rich graph relationships through synchronized Python classes, TypeQL schemas, and mapping configurations.

**Core Innovation:** Universal transformation patterns that work consistently across all cybersecurity frameworks while maintaining semantic fidelity and enabling complex graph queries.

## Architecture Diagrams

### System Context
```
┌─────────────────────────────────────────────────────────────────┐
│                    STIX-ORM Ecosystem                          │
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐          │
│  │    STIX     │   │   Python    │   │   TypeQL    │          │
│  │    JSON     │──▶│   Classes   │──▶│   Schema    │          │
│  │             │   │             │   │             │          │
│  └─────────────┘   └─────────────┘   └─────────────┘          │
│                                                                 │
│  Seven Dialects:                                               │
│  • Core STIX 2.1        • Attack Flow                         │
│  • MITRE ATT&CK         • MITRE ATLAS                         │
│  • OCA Extensions       • MBC Extensions                       │
│  • OS-Threat Extensions                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                  STIX-ORM Core Components                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ Class Registry  │    │ Mapping Engine  │                   │
│  │                 │    │                 │                   │
│  │ • Type Detection│    │ • 6-Type System │                   │
│  │ • Dynamic Import│◄──▶│ • Config-Driven │                   │
│  │ • Instantiation │    │ • Cross-Dialect │                   │
│  └─────────────────┘    └─────────────────┘                   │
│           │                        │                          │
│           ▼                        ▼                          │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ Schema Manager  │    │ TypeDB Sink    │                   │
│  │                 │    │                 │                   │
│  │ • Multi-Dialect │    │ • Transaction   │                   │
│  │ • Validation    │◄──▶│   Assembly      │                   │
│  │ • Synchronization│    │ • Batch Process │                   │
│  └─────────────────┘    └─────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow Architecture
```
STIX JSON → Dialect Detection → Class Instantiation → Property Extraction
    │              │                    │                     │
    ▼              ▼                    ▼                     ▼
Input Bundle   Framework ID    Python Object Model    _inner() Method
    │              │                    │                     │
    ▼              ▼                    ▼                     ▼
Validation     ATT&CK/OCA/etc.    Domain Classes       Property Categories
                                                             │
                                                             ▼
                                              ┌─────────────────────┐
                                              │ Six-Type Mapping    │
                                              │                     │
                                              │ 1. Key-Value Store  │
                                              │ 2. List of Objects  │
                                              │ 3. Extensions       │
                                              │ 4. Single Reference │
                                              │ 5. Multiple Refs    │
                                              │ 6. SRO Roles        │
                                              └─────────────────────┘
                                                         │
                                                         ▼
                                              ┌─────────────────────┐
                                              │ TypeQL Generation   │
                                              │                     │
                                              │ • Match Statements  │
                                              │ • Insert Statements │
                                              │ • Relation Creation │
                                              └─────────────────────┘
                                                         │
                                                         ▼
                                              ┌─────────────────────┐
                                              │ TypeDB Storage      │
                                              │                     │
                                              │ • Hypergraph Model  │
                                              │ • Query Engine      │
                                              │ • Inference Rules   │
                                              └─────────────────────┘
```

## Core Components

### 1. Universal Class Registry
**Objective:** Dynamic resolution of STIX types to Python classes across all dialects.

**Implementation:**
```python
def resolve_stix_class(stix_object: Dict[str, Any]) -> Type[_STIXBase21]:
    """
    Resolve STIX object type to appropriate Python class.
    
    Args:
        stix_object: Raw STIX JSON object
        
    Returns:
        Python class for object instantiation
    """
    obj_type = stix_object.get('type')
    dialect = detect_dialect(stix_object)
    
    # Load dialect-specific class registry
    registry = load_class_registry(dialect)
    
    if obj_type not in registry:
        raise ValueError(f"Unknown STIX type: {obj_type}")
    
    class_config = registry[obj_type]
    module_path = f"stixorm.module.definitions.{dialect}.classes"
    
    # Dynamic import and instantiation
    module = importlib.import_module(module_path)
    stix_class = getattr(module, class_config['python_class'])
    
    return stix_class
```

### 2. Six-Type Mapping Engine
**Objective:** Transform complex JSON structures into hypergraph relationships.

The system categorizes all STIX composite properties into six universal patterns:

1. **Key-Value Store**: Custom properties → Multiple entities
2. **List of Objects**: Arrays → Multiple relations  
3. **Extensions**: STIX extensions → Sub-entities
4. **Single Reference**: `_ref` fields → Binary relation
5. **Multiple References**: `_refs` fields → Multiple binary relations
6. **SRO Roles**: Relationship objects → Specialized relations

### 3. Binary Relationship Foundation
**Objective:** Standardize all TypeDB relationships using consistent binary patterns.

**Schema Pattern:**
```typeql
# Universal foundation for all relationships
embedded sub relation,
    relates owner,      # Source of relationship
    relates pointed-to; # Target of relationship

# All specific relations inherit this pattern
created-by sub embedded,
    relates created as owner,
    relates creator as pointed-to;

kill-chain-usage sub embedded,
    relates kill-chain-used as owner,
    relates kill-chain-using as pointed-to;
```

## Transformation Pipeline

### Nine-Phase Processing Pipeline

```
Phase 1: Bundle Parsing & Validation
┌─────────────────────────────────────┐
│ • Extract STIX objects from bundle │
│ • Validate JSON structure          │
│ • Check STIX specification         │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 2: Dialect Detection & Classification  
┌─────────────────────────────────────┐
│ • Analyze type prefixes            │
│ • Check property signatures        │
│ • Route to appropriate processor   │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 3: Dependency Analysis & Ordering
┌─────────────────────────────────────┐
│ • Extract reference relationships  │
│ • Build dependency graph           │
│ • Topological sort for order       │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 4: Python Class Instantiation
┌─────────────────────────────────────┐
│ • Registry lookup for class type   │
│ • Dynamic module import             │
│ • Object instantiation with data   │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 5: Property Extraction via _inner()
┌─────────────────────────────────────┐
│ • Load mapping configurations      │
│ • Categorize simple vs composite   │
│ • Apply naming conventions         │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 6: Six-Type Hypergraph Mapping
┌─────────────────────────────────────┐
│ • Dispatch by mapping type         │
│ • Generate TypeQL fragments        │
│ • Handle cross-dialect references  │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 7: TypeQL Statement Assembly
┌─────────────────────────────────────┐
│ • Combine match/insert statements  │
│ • Optimize query structure         │
│ • Validate relationship constraints│
└─────────────────────────────────────┘
                  │
                  ▼
Phase 8: Transaction Batching
┌─────────────────────────────────────┐
│ • Group operations for performance │
│ • Respect transaction size limits  │
│ • Handle dependency ordering       │
└─────────────────────────────────────┘
                  │
                  ▼
Phase 9: TypeDB Execution
┌─────────────────────────────────────┐
│ • Execute database transactions    │
│ • Handle errors and rollbacks      │
│ • Validate final state            │
└─────────────────────────────────────┘
```

## Example: Malware Object Transformation

Let's trace a complete transformation using a MITRE ATT&CK malware object:

### Input STIX JSON
```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--162d917e-766f-4611-b5d6-652791454fca",
  "created": "2017-05-12T16:16:33.000Z",
  "modified": "2021-04-26T15:16:33.000Z",
  "name": "Poison Ivy",
  "description": "Poison Ivy is a popular remote access tool...",
  "malware_types": ["remote-access-trojan"],
  "is_family": true,
  "aliases": ["Darkmoon"],
  "x_mitre_version": "1.2",
  "x_mitre_platforms": ["Windows"],
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ],
  "external_references": [
    {
      "source_name": "FireEye Poison Ivy",
      "description": "Detailed analysis of Poison Ivy",
      "url": "https://example.com/analysis"
    }
  ],
  "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
}
```

### Python Class Processing
```python
class SoftwareMalware(_DomainObject):
    """MITRE ATT&CK Malware class with TypeQL synchronization."""
    
    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('malware_types', ListProperty(OpenVocabProperty(MALWARE_TYPE))),
        ('is_family', BooleanProperty(required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),  # Composite
        ('external_references', ListProperty(ExternalReference)),  # Composite
        ('created_by_ref', ReferenceProperty(valid_types='identity')),  # Composite
        # ... additional properties
    ])
    
    def _inner(self) -> Dict[str, Any]:
        """Extract properties for TypeQL conversion."""
        # Load ATT&CK-specific mappings
        data_mappings = load_mapping_config('attack/mappings/data/malware.json')
        sub_object_mappings = load_mapping_config('attack/mappings/sub_objects/malware.json')
        
        simple_properties = {}
        composite_properties = {}
        
        # Process each property
        for prop_name, value in self.__dict__.items():
            if prop_name in data_mappings:
                # Simple property: direct mapping
                typeql_name = data_mappings[prop_name]
                simple_properties[typeql_name] = value
            elif prop_name in sub_object_mappings:
                # Composite property: hypergraph mapping required
                composite_properties[prop_name] = {
                    'value': value,
                    'mapping': sub_object_mappings[prop_name]
                }
        
        return {
            'simple': simple_properties,
            'composite': composite_properties
        }
```

### Mapping Configurations

**Simple Properties** (`attack/mappings/data/malware.json`):
```json
{
  "name": "name",
  "description": "description", 
  "malware_types": "malware-types",
  "is_family": "is-family",
  "aliases": "aliases",
  "x_mitre_version": "x-mitre-version",
  "x_mitre_platforms": "x-mitre-platforms"
}
```

**Composite Properties** (`attack/mappings/sub_objects/malware.json`):
```json
{
  "kill_chain_phases": {
    "mapping_type": "list_of_objects",
    "typeql_relation": "kill-chain-usage",
    "source_role": "kill-chain-used",
    "target_role": "kill-chain-using",
    "target_object": "kill-chain-phase"
  },
  "external_references": {
    "mapping_type": "list_of_objects", 
    "typeql_relation": "external-references",
    "source_role": "referenced",
    "target_role": "referencing",
    "target_object": "external-reference"
  },
  "created_by_ref": {
    "mapping_type": "embedded_relation_single",
    "typeql_relation": "created-by",
    "source_role": "created",
    "target_role": "creator"
  }
}
```

### TypeQL Schema Synchronization
```typeql
# Synchronized TypeQL schema for malware entity
define
    malware sub stix-domain-object,
        owns name,
        owns description,
        owns malware-types,
        owns is-family,
        owns aliases,
        owns x-mitre-version,
        owns x-mitre-platforms,
        
        # Relationship participation
        plays kill-chain-usage:kill-chain-used,
        plays external-references:referenced,
        plays created-by:created;

# Binary relationship definitions
kill-chain-usage sub embedded,
    relates kill-chain-used as owner,
    relates kill-chain-using as pointed-to;

external-references sub embedded,
    relates referenced as owner,
    relates referencing as pointed-to;

created-by sub embedded,
    relates created as owner,
    relates creator as pointed-to;
```

### Generated TypeQL Output
```typeql
# Insert malware entity with simple properties
insert $malware isa malware,
    has stix-id "malware--162d917e-766f-4611-b5d6-652791454fca",
    has name "Poison Ivy",
    has description "Poison Ivy is a popular remote access tool...",
    has malware-types "remote-access-trojan",
    has is-family true,
    has aliases "Darkmoon",
    has x-mitre-version "1.2",
    has x-mitre-platforms "Windows";

# Insert kill chain phase object and relationship
insert $kcp isa kill-chain-phase,
    has kill-chain-name "mitre-attack",
    has phase-name "command-and-control";
    
insert $rel1 (kill-chain-used: $malware, kill-chain-using: $kcp) isa kill-chain-usage;

# Insert external reference object and relationship  
insert $extref isa external-reference,
    has source-name "FireEye Poison Ivy",
    has description "Detailed analysis of Poison Ivy",
    has url "https://example.com/analysis";
    
insert $rel2 (referenced: $malware, referencing: $extref) isa external-references;

# Insert created-by relationship
match $identity isa identity, has stix-id "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5";
insert $rel3 (created: $malware, creator: $identity) isa created-by;
```

### Hypergraph Visualization
```
    ┌─────────────────┐
    │ Poison Ivy      │
    │ (malware)       │
    └─────────────────┘
           │ │ │
           │ │ └── created-by ──────────► ┌─────────────┐
           │ │                            │ Identity    │
           │ │                            │ (MITRE)     │
           │ └─── external-references ──► └─────────────┘
           │                              ┌─────────────┐
           │                              │ External    │
           │                              │ Reference   │
           └──── kill-chain-usage ──────► └─────────────┘
                                          ┌─────────────┐
                                          │ Kill Chain  │
                                          │ Phase       │
                                          └─────────────┘
```

## Implementation Patterns

### 1. Configuration-Driven Architecture
All mapping logic is externalized to JSON configuration files, enabling:
- Easy extension to new STIX dialects
- Modification without code changes  
- Validation and testing of mappings
- Consistent patterns across frameworks

### 2. Universal Naming Conventions
- **STIX JSON**: `snake_case` (e.g., `kill_chain_phases`)
- **Python Classes**: `snake_case` (e.g., `kill_chain_phases`)  
- **TypeQL Schema**: `kebab-case` (e.g., `kill-chain-phases`)

### 3. Error Handling Strategy
```python
def safe_transform(stix_object: Dict[str, Any]) -> Optional[List[str]]:
    """
    Safely transform STIX object with comprehensive error handling.
    
    Args:
        stix_object: Raw STIX JSON object
        
    Returns:
        List of TypeQL statements or None if transformation fails
    """
    try:
        # Attempt transformation
        python_object = instantiate_stix_class(stix_object)
        properties = python_object._inner()
        typeql_statements = generate_typeql(properties)
        return typeql_statements
        
    except ValidationError as e:
        logger.error(f"STIX validation failed: {e}")
        return None
        
    except MappingError as e:
        logger.error(f"Mapping configuration error: {e}")
        return None
        
    except Exception as e:
        logger.error(f"Unexpected transformation error: {e}")
        return None
```

## Schema Synchronization

### Validation Framework
```python
def validate_python_typeql_sync(dialect: str) -> List[str]:
    """
    Validate synchronization between Python classes and TypeQL schemas.
    
    Args:
        dialect: STIX dialect to validate
        
    Returns:
        List of synchronization issues found
    """
    issues = []
    
    # Load components
    python_classes = load_python_classes(dialect)
    typeql_entities = load_typeql_schema(dialect)
    
    for class_name, class_def in python_classes.items():
        typeql_name = convert_class_to_entity_name(class_name)
        
        if typeql_name not in typeql_entities:
            issues.append(f"Missing TypeQL entity for {class_name}")
            continue
            
        # Validate property synchronization
        python_props = extract_properties(class_def)
        typeql_props = typeql_entities[typeql_name]['attributes']
        
        for py_prop in python_props:
            tql_prop = convert_property_name(py_prop)
            if tql_prop not in typeql_props:
                issues.append(f"Property {py_prop} not found in TypeQL")
    
    return issues
```

## Deployment Architecture

### Production Environment
```
┌─────────────────────────────────────────────────────────────────┐
│                Production Deployment Stack                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ Load Balancer   │    │ STIX-ORM API    │                   │
│  │                 │    │                 │                   │
│  │ • Route Requests│───▶│ • Endpoint Mgmt │                   │
│  │ • Health Checks │    │ • Input Valid.  │                   │
│  │ • SSL Termination│    │ • Batch Process │                   │
│  └─────────────────┘    └─────────────────┘                   │
│                                   │                            │
│                                   ▼                            │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ TypeDB Cluster  │    │ Processing      │                   │
│  │                 │    │ Workers         │                   │
│  │ • Core Database │◄───│                 │                   │
│  │ • Schema Mgmt   │    │ • Parallel Proc │                   │
│  │ • Query Engine  │    │ • Error Handling│                   │
│  └─────────────────┘    └─────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Performance Optimization
- **Batch Processing**: 500-1000 objects per transaction
- **Parallel Processing**: Multiple dialect workers
- **Query Optimization**: Indexed attributes and relations
- **Memory Management**: Garbage collection tuning
- **Monitoring**: Performance metrics and error tracking

---

This blueprint provides a comprehensive architectural foundation for understanding and implementing the STIX-ORM cybersecurity intelligence transformation system, demonstrating how flat JSON threat intelligence data becomes rich hypergraph relationships through systematic Python-TypeQL synchronization patterns.