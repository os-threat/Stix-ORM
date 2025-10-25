---
description: 'TypeQL integration patterns and variable collision prevention'
applyTo: '**/*'
---

# TypeQL Integration Instructions

## 🚨 OPTIMIZATION NOTE
**Instruction Writing**: Follow size-efficient patterns → PRIMARY.instructions.md

## 🔥 CRITICAL PATTERN: Variable Collision Prevention

### Core Problem
Multiple same-type references generate identical TypeQL variables → database insertion failures

### Solution: Relation-Aware Variable Generation
```python
# ✅ CRITICAL IMPLEMENTATION
def embedded_relation(prop, prop_type, prop_value, i, local_optional_objects, inc_add=""):
    relation_prefix = prop.replace('_', '-')
    variable_name = f"{relation_prefix}-{prop_type}{i}{inc_add}"
    return variable_name

# Examples:
# on_completion + sequence → "on-completion-sequence0"
# sequence + sequence → "sequence-sequence1"  
# created_by_ref + identity → "created-by-identity0"
```

### Before vs. After
```python
# ❌ PROBLEMATIC (Generic naming)
incident = {
    'on_completion': 'sequence--target-1',    # → "sequence0"  
    'sequence': 'sequence--target-2',         # → "sequence1" 
    'another_seq_ref': 'sequence--target-3'   # → "sequence2"
}
# Result: Variable collisions, database insertion failures

# ✅ FIXED (Relation-aware naming)
# on_completion → "on-completion-sequence0"
# sequence → "sequence-sequence1"
# another_seq_ref → "another-seq-sequence2"
# Result: All variables unique, safe database insertion
```
```

### Rule 2: Consistent Normalization
Always apply consistent normalization rules to property names:

```python
def normalize_property_name(prop_name: str) -> str:
    """Normalize property names for consistent variable generation"""
    return prop_name.replace('_', '-').lower()

# Ensures consistent output regardless of input format:
# "on_completion" -> "on-completion"
# "created_by_ref" -> "created-by-ref" 
# "object_refs" -> "object-refs"
```

### Rule 3: Collision Testing
Always test variable uniqueness in complex scenarios:

```python
def test_variable_collision_prevention():
    """Test TypeQL variable uniqueness with complex object relationships"""
    
    # Create object with multiple same-type references
    complex_object = {
        'type': 'incident',
        'id': 'incident--test-123',
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2', 
        'other_sequence_ref': 'sequence--target-3',
        'created_by_ref': 'identity--analyst-1'
    }
    
    # Generate variables for each relation
    generated_variables = []
    for i, (prop, value) in enumerate(complex_object.items()):
        if prop in ['on_completion', 'sequence', 'other_sequence_ref']:
            var = embedded_relation(prop, 'sequence', value, i)
            generated_variables.append(var)
        elif prop == 'created_by_ref':
            var = embedded_relation(prop, 'identity', value, i)  
            generated_variables.append(var)
    
    # Verify all variables are unique
    assert len(generated_variables) == len(set(generated_variables))
    
    # Expected unique variables:
    # ["on-completion-sequence0", "sequence-sequence1", "other-sequence-sequence2", "created-by-identity3"]
```

## Implementation Patterns

### Pattern 1: Database-Safe Object Processing
Ensure objects are processed in dependency order with collision-free variables:

## Essential Implementation Rules

### Rule 1: Always Use Relation-Aware Variables
- **Pattern**: `relation_prefix = prop.replace('_', '-'); var = f"{relation_prefix}-{type}{i}"`
- **Purpose**: Prevents TypeQL variable naming collisions  
- **Critical**: Database insertion failures without this pattern

### Rule 2: Consistent Normalization
```python
def normalize_property_name(prop_name: str) -> str:
    return prop_name.replace('_', '-').lower()
```

### Rule 3: Collision Testing
Always test variable uniqueness in complex scenarios:
```python
def test_variable_collision_prevention():
    complex_object = {
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2', 
        'other_sequence_ref': 'sequence--target-3',
        'created_by_ref': 'identity--analyst-1'
    }
    
    generated_variables = []
    for i, (prop, value) in enumerate(complex_object.items()):
        if is_reference_field(prop, value):
            var = embedded_relation(prop, get_object_type(value), i)
            generated_variables.append(var)
    
    # CRITICAL: Verify all variables are unique
    assert len(generated_variables) == len(set(generated_variables))
```

## Implementation Patterns

### Pattern 1: Database-Safe Processing
```python
def safe_typeql_insertion(sorted_objects):
    for obj in sorted_objects:
        typeql_statements = []
        for prop, value in obj.items():
            if is_reference_field(prop, value):
                variable = embedded_relation(prop, get_object_type(value), 0)
                typeql_statements.append(f"${variable} isa {get_object_type(value)};")
        database.execute(' '.join(typeql_statements))
```

### Pattern 2: Debug Variable Generation
```python
def debug_variable_generation(obj, debug=False):
    variables = {}
    for prop, value in obj.items():
        if is_reference_field(prop):
            variable = embedded_relation(prop, get_object_type(value), 0)
            variables[prop] = variable
            if debug:
                print(f"DEBUG VAR: {prop} -> {variable} (for {value})")
    return variables
```

## Integration with Dependency Sorting

### Combined Processing Pipeline
```python
def integrated_processing_pipeline(stix_objects):
    # Phase 1: Sort objects by dependencies
    sorted_objects, sorting_report = dependency_sort(stix_objects)
    
    # Phase 2: Generate collision-free TypeQL for each object
    typeql_queries = []
    for obj in sorted_objects:
        query = generate_typeql_insert(obj)  # Uses embedded_relation() internally
        typeql_queries.append(query)
    
    # Phase 3: Execute in dependency order with unique variables
    for query in typeql_queries:
        database.execute(query)  # Safe execution
    
    return sorted_objects, typeql_queries
```
def integrated_processing_pipeline(stix_objects: List[Dict[str, Any]]):
    """Combined dependency sorting + collision-free TypeQL generation"""
    
    # Phase 1: Sort objects by dependencies
    sorted_objects, sorting_report = dependency_sort(stix_objects)
    
    # Phase 2: Generate collision-free TypeQL for each object
    typeql_queries = []
    for obj in sorted_objects:
        # Use relation-aware variable generation
        query = generate_typeql_insert(obj)  # Uses embedded_relation() internally
        typeql_queries.append(query)
    
    # Phase 3: Execute in dependency order with unique variables
    for query in typeql_queries:
        database.execute(query)  # Safe execution - no collisions or constraint violations
    
    return sorted_objects, typeql_queries
## Performance Considerations

### Efficient Variable Generation
```python
# Pre-compile patterns for performance
STIX_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$')
PROPERTY_NAME_CACHE = {}

def cached_normalize_property(prop_name: str) -> str:
    if prop_name not in PROPERTY_NAME_CACHE:
        PROPERTY_NAME_CACHE[prop_name] = prop_name.replace('_', '-').lower()
    return PROPERTY_NAME_CACHE[prop_name]
```

## Testing Requirements

### Critical Integration Testing
```python
def test_complete_integration():
    test_objects = load_complex_stix_test_data()
    sorted_objects, report = clean_stix_list(test_objects)
    typeql_queries = [generate_typeql_insert(obj) for obj in sorted_objects]
    
    # CRITICAL: Verify no variable collisions
    all_variables = extract_variables_from_queries(typeql_queries)
    assert len(all_variables) == len(set(all_variables)), "Variable collision detected"
```

## Migration Guidelines

### Upgrading Existing Code
1. **Identify collision points**: Find objects with multiple same-type references
2. **Test current behavior**: Document existing variable generation patterns  
3. **Update gradually**: Implement relation-aware naming incrementally
4. **Validate thoroughly**: Test with complex real-world data

```python
# Migration helper function
def detect_potential_collisions(objects):
    collision_candidates = []
    for obj in objects:
        type_counts = {}
        for prop, value in obj.items():
            if is_reference_field(prop):
                obj_type = get_object_type(value)
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
        
        # Objects with multiple references to same type are collision candidates
        for obj_type, count in type_counts.items():
            if count > 1:
                collision_candidates.append(obj['id'])
                break
    return collision_candidates
```

### Rule 9: Upgrading Existing Code
When upgrading systems that use generic variable naming:

1. **Identify collision points**: Find objects with multiple same-type references
2. **Test current behavior**: Document existing variable generation patterns  
3. **Update gradually**: Implement relation-aware naming incrementally
4. **Validate thoroughly**: Test with complex real-world data
5. **Monitor production**: Watch for insertion errors or constraint violations

```python
# Migration helper function
def detect_potential_collisions(objects: List[Dict]) -> List[str]:
    """Detect objects that may have variable naming collisions"""
    
    collision_candidates = []
    
    for obj in objects:
        type_counts = {}
        for prop, value in obj.items():
            if is_reference_field(prop):
                obj_type = get_object_type(value)
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
        
        # Objects with multiple references to same type are collision candidates
        for obj_type, count in type_counts.items():
            if count > 1:
                collision_candidates.append(obj['id'])
                break
    
    return collision_candidates
```