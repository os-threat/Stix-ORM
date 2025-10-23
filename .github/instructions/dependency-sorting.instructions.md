# Dependency Sorting Implementation Rules

## Overview
Rules for implementing dependency-based topological sorting in STIX object processing pipelines, ensuring objects are ordered so dependencies appear before dependents.

## Core Principles

### 1. Dynamic Reference Detection
- **NO hardcoded field lists**: Never use static lists of reference field names
- **Dual detection strategy**: Use both standard field patterns AND universal STIX ID pattern matching
- **Future-proof design**: System must adapt automatically to new STIX specifications and extensions

```python
# ✅ CORRECT: Dynamic detection
def _extract_references_from_object(obj_data):
    references = set()
    
    # Method 1: Standard reference fields
    for key, value in obj_data.items():
        if key.endswith('_ref') or key.endswith('_refs'):
            # Extract references from standard fields
    
    # Method 2: Universal STIX ID pattern matching
    _extract_from_data(obj_data, references, obj_data.get('id'))
    return references

# ❌ WRONG: Hardcoded field lists
HARDCODED_FIELDS = ['created_by_ref', 'object_refs', 'on_completion']  # Never do this
```

### 2. Two-Phase Dependency Processing
Always separate dependency detection from sorting to maintain clear separation of concerns:

```python
# Phase 1: Pre-compute dependencies
object_dependencies = []
for obj in objects:
    dependencies = _extract_references_from_object(obj)
    object_dependencies.append({
        'object': obj,
        'dependencies': dependencies,
        'id': obj['id']
    })

# Phase 2: Sort using computed dependencies
sorted_objects = _topological_sort_with_dependencies(object_dependencies)
```

### 3. Preserve Original Data Format
- Accept raw dictionaries as input
- Convert to internal format only when necessary for processing
- Always return data in the same format as input
- Avoid unnecessary object conversions

## Implementation Rules

### Rule 1: STIX ID Pattern Validation
```python
def _is_valid_stix_id(potential_id: str) -> bool:
    """Validate STIX ID format: type--uuid"""
    if not isinstance(potential_id, str) or '--' not in potential_id:
        return False
    
    parts = potential_id.split('--')
    if len(parts) != 2:
        return False
    
    type_part, uuid_part = parts
    # Validate type part (letters, numbers, hyphens)
    if not re.match(r'^[a-zA-Z0-9\-]+$', type_part):
        return False
    
    # Validate UUID part (hexadecimal with hyphens)
    if not re.match(r'^[0-9a-fA-F\-]+$', uuid_part):
        return False
    
    return True
```

### Rule 2: Recursive Reference Extraction
Always traverse nested structures completely:

```python
def _extract_from_data(data, references: set, self_id: str):
    """Recursively extract STIX IDs from any data structure"""
    if isinstance(data, str):
        if _is_valid_stix_id(data) and data != self_id:
            references.add(data)
    elif isinstance(data, list):
        for item in data:
            _extract_from_data(item, references, self_id)
    elif isinstance(data, dict):
        for value in data.values():
            _extract_from_data(value, references, self_id)
```

### Rule 3: Topological Sort with Debugging
Implement Kahn's algorithm with comprehensive debugging for troubleshooting:

```python
def _topological_sort_with_dependencies(object_dependencies: List[Dict]) -> List[Dict]:
    """Sort objects using pre-computed dependencies with debugging"""
    
    # Build dependency graph
    in_degree = defaultdict(int)
    adj_list = defaultdict(list)
    
    # Debug output for complex cases
    print(f"DEBUG TOPO: Starting with {len(object_dependencies)} objects")
    
    # Initialize and build graph
    for item in object_dependencies:
        obj_id = item['id']
        dependencies = item['dependencies']
        
        for dep_id in dependencies:
            if dep_id in all_ids:
                adj_list[dep_id].append(obj_id)
                in_degree[obj_id] += 1
    
    # Kahn's algorithm with progress tracking
    queue = [obj_id for obj_id in all_ids if in_degree[obj_id] == 0]
    sorted_objects = []
    
    while queue:
        current_id = queue.pop(0)
        sorted_objects.append(obj_dict[current_id])
        
        for dependent_id in adj_list[current_id]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)
    
    return sorted_objects
```

### Rule 4: Error Handling and Reporting
Always provide comprehensive error reporting:

```python
# Calculate unresolved references
all_ids = {obj['id'] for obj in objects}
unresolved_refs = []
for item in object_dependencies:
    for dep_id in item['dependencies']:
        if dep_id not in all_ids:
            unresolved_refs.append(dep_id)

# Include in report
report = SortingReport(
    sorting_successful=success,
    sorted_list_of_stix_ids=sorted_ids,
    diagram_of_sorted_dependencies=diagram,
    unresolved_references=list(set(unresolved_refs))  # Remove duplicates
)
```

## Integration Rules

### Rule 5: Pipeline Integration
When integrating with cleaning pipelines:

```python
def clean_stix_list(stix_list: List[Dict[str, Any]], clean_sco_fields: bool = False):
    """Accept dictionaries, process with StixObjects internally, return dictionaries"""
    
    # Convert to StixObjects for internal processing
    stix_objects = [StixObject(**obj_dict) for obj_dict in stix_list]
    
    # Process through pipeline (operations 1-6)
    working_objects = process_pipeline(stix_objects)
    
    # Convert back to dictionaries for return
    result_dicts = [obj.model_dump() for obj in working_objects]
    return result_dicts, report
```

### Rule 6: Compatibility with Existing Systems
Maintain backward compatibility while adding new functionality:

```python
def _topological_sort(objects: List[StixObject]) -> Tuple[List[str], List[str], bool]:
    """Legacy function - converts to new format internally"""
    # Convert to new dependency format
    object_dependencies = []
    for obj in objects:
        references = _extract_references_from_object(obj.model_dump())
        object_dependencies.append({
            'object': obj,
            'dependencies': references,
            'id': obj.id
        })
    
    # Use new sorting function
    sorted_deps = _topological_sort_with_dependencies(object_dependencies)
    
    # Return in legacy format
    sorted_ids = [item['id'] for item in sorted_deps]
    return sorted_ids, unresolved_refs, success
```

## Testing Rules

### Rule 7: Comprehensive Test Coverage
Always test with real-world examples:

```python
def test_dependency_sorting():
    """Test with actual STIX objects containing custom reference fields"""
    
    # Load real data with known dependency relationships
    sequence_objects = load_os_threat_sequences()
    
    # Verify dependency detection
    for seq in sequence_objects:
        if 'on_completion' in seq:
            deps = _extract_references_from_object(seq)
            assert seq['on_completion'] in deps
    
    # Verify sorting order
    sorted_objects, report = clean_stix_list(sequence_objects)
    
    # Check that targets come before dependents
    target_positions = get_positions(sorted_objects, target_ids)
    dependent_positions = get_positions(sorted_objects, dependent_ids)
    assert max(target_positions) < min(dependent_positions)
```

### Rule 8: Debug Output Standards
Provide consistent debugging information:

```python
# Debug dependency detection
if obj_id in DEBUG_OBJECTS:
    print(f"DEBUG OP6: {obj_id[:20]}... pre-computed dependencies: {dependencies}")

# Debug graph construction  
if obj_id in DEBUG_OBJECTS or dep_id in DEBUG_OBJECTS:
    print(f"DEBUG GRAPH: {obj_id[:20]}... depends on {dep_id[:20]}...")

# Debug sorting progress
print(f"DEBUG TOPO: Starting queue (in_degree=0): {[id[:20]+'...' for id in queue]}")
```

## Anti-Patterns to Avoid

### ❌ Never Do These:
1. **Hardcode field names**: `if field in ['created_by_ref', 'on_completion']`
2. **Skip pattern validation**: Assuming strings are STIX IDs without validation
3. **Ignore self-references**: Including object's own ID in its dependencies
4. **Convert unnecessarily**: Converting between dict/object formats multiple times
5. **Hide dependency info**: Not including dependency data in reports
6. **Skip error handling**: Not handling circular dependencies or missing references

### ✅ Always Do These:
1. **Use pattern matching**: Scan all strings for STIX ID patterns
2. **Validate STIX IDs**: Check format before treating as dependency
3. **Exclude self-references**: `if potential_id != self_id`
4. **Preserve data formats**: Input format = output format
5. **Report dependencies**: Include in sorting reports for debugging
6. **Handle edge cases**: Circular dependencies, missing objects, malformed data

## Performance Considerations

### Rule 9: Efficiency Guidelines
- Cache STIX ID validation results when processing large datasets
- Use sets for dependency storage to avoid duplicates
- Implement early termination in recursive traversal when possible
- Pre-filter objects by type when working with specific object relationships

### Rule 10: Scalability Requirements  
- Algorithm must handle 1000+ objects efficiently
- Memory usage should scale linearly with object count
- Debugging output should be optional for production use
- Support incremental processing for very large datasets

## Documentation Requirements

Always document:
- **Purpose**: Why dependency sorting is needed
- **Algorithm**: Which topological sort variant is used
- **Edge Cases**: How circular dependencies are handled
- **Performance**: Expected time/space complexity
- **Examples**: Real-world use cases with sample data
- **Integration**: How to use with existing pipelines