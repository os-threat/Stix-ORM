---
description: 'Master index for all STIX-ORM implementation knowledge'
applyTo: '**/*'
---

# MASTER INDEX - STIX-ORM Implementation Knowledge

## 🚨 INSTRUCTION OPTIMIZATION
**READ FIRST**: → PRIMARY.instructions.md (size-efficient instruction writing)

## 🔥 CRITICAL PATTERNS (Always in Context)

### TypeQL Variable Collision Prevention
- **Pattern**: `relation_prefix = prop.replace('_', '-'); var = f"{relation_prefix}-{prop_type}{i}"`
- **Examples**: `on_completion` → `on-completion-sequence0`, `created_by_ref` → `created-by-identity1`
- **Anti-pattern**: Generic naming like `sequence0`, `sequence1` (causes DB failures)
- **Full Details**: → typeql-integration.instructions.md

### Conditional Enrichment System
- **Signature**: `clean_stix_list(objects, clean_sco_fields=False, enrich_from_external_sources=False)`
- **Default**: Air-gapped mode (no external calls)
- **Enabled**: Fetches from 5 MITRE/MBC sources
- **Full Details**: → enhancement-summary.instructions.md

### Dynamic Reference Detection
- **Method 1**: Standard patterns (`_ref`, `_refs`)
- **Method 2**: Universal STIX ID regex `^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$`
- **Purpose**: Handle custom fields like `on_completion`, `behavior_refs`
- **Anti-pattern**: Hardcoded field lists
- **Full Details**: → python-patterns.instructions.md

### Error Handling Standard
- **Pattern**: `try: result = process(deepcopy(input)) except: return input, failure_report`
- **Rule**: Always preserve original input on failure
- **Report**: Include missing_ids_list for debugging
- **Full Details**: → python-patterns.instructions.md

## 📋 IMPLEMENTATION DOMAINS

### Pipeline Operations (7-Step Process)
1. **Deduplication** → cleaning-pipeline.instructions.md#operation-1
2. **Expansion** (conditional) → cleaning-pipeline.instructions.md#operation-2-3
3. **SCO Cleaning** (conditional) → cleaning-pipeline.instructions.md#operation-4
4. **Circular Resolution** → dependency-sorting.instructions.md
5. **Dependency Sort** → dependency-sorting.instructions.md
6. **Report Generation** → cleaning-pipeline.instructions.md#operation-7

### TypeDB Integration
- **Variable Generation** → typeql-integration.instructions.md
- **Insert Ordering** → dependency-sorting.instructions.md
- **Schema Mapping** → python-patterns.instructions.md#mapping

### Testing Requirements
- **Collision Tests** → testing-patterns.instructions.md#collision-prevention
- **Conditional Paths** → testing-patterns.instructions.md#conditional-testing
- **Performance** → testing-patterns.instructions.md#performance

## 🎯 QUICK REFERENCE LOOKUP

### Function Signatures
```python
# Core Functions
clean_stix_list(stix_list, clean_sco_fields=False, enrich_from_external_sources=False)
embedded_relation(prop, prop_type, prop_value, i, local_optional_objects, inc_add="")
dependency_sort(stix_objects)

# Detection Functions  
is_reference_field(field_name, field_value)
extract_stix_id_pattern(value)
normalize_property_name(prop_name)
```

### Common Anti-Patterns to Avoid
- ❌ `REFERENCE_FIELDS = ['created_by_ref', 'object_refs']` # Breaks extensions
- ❌ `variable = f"{obj_type}{i}"` # Causes collisions
- ❌ `for obj in objects: obj['modified'] = True` # Mutates input
- ❌ `except: return None` # Silent failures

### File Navigation Map
```
CRITICAL CORE:
├── MASTER-INDEX.instructions.md (this file)
├── enhancement-summary.instructions.md (major implementations)
├── typeql-integration.instructions.md (collision prevention)
└── python-patterns.instructions.md (dynamic detection)

IMPLEMENTATION:
├── cleaning-pipeline.instructions.md (7-operation pipeline)
├── dependency-sorting.instructions.md (topological ordering)
└── python.instructions.md (code standards)

PROCESS:
├── task-implementation.instructions.md (development workflow)
└── README.md (file descriptions)
```

## 🔍 CONTEXT TRIGGERS

When working on:
- **TypeQL generation** → Load: typeql-integration.instructions.md
- **STIX cleaning** → Load: cleaning-pipeline.instructions.md, enhancement-summary.instructions.md
- **Reference detection** → Load: python-patterns.instructions.md
- **Database operations** → Load: dependency-sorting.instructions.md
- **Testing** → Load: testing-patterns.instructions.md
- **New features** → Load: ALL core files

## 📊 KNOWLEDGE LAYERS

### Layer 1: Always Available (This Index)
- Critical patterns with examples
- Anti-patterns to avoid
- Function signatures
- File navigation

### Layer 2: Context-Triggered (Domain Files)
- Detailed implementations
- Comprehensive examples
- Edge case handling
- Performance considerations

### Layer 3: Reference Materials (Supporting Docs)
- Architecture documentation
- Full API references
- Historical context
- Design decisions