# STIX Cleaning Pipeline Rules

## Overview
Rules for implementing and maintaining the STIX object cleaning pipeline with dependency-based ordering.

## Pipeline Architecture Rules

### Rule 1: 7-Operation Pipeline Structure
Always maintain this exact operation sequence:

```python
def clean_stix_list(stix_list: List[Dict[str, Any]], clean_sco_fields: bool = False):
    """7-operation cleaning pipeline"""
    
    # Operation 1: Object Deduplication
    working_objects, dedup_report = _operation_1_object_deduplication(working_objects)
    
    # Operation 2: Expansion Round 1  
    working_objects, expansion_report = _operation_2_expansion_round_1(working_objects)
    
    # Operation 3: Expansion Round 2
    working_objects, expansion_report = _operation_3_expansion_round_2(working_objects, expansion_report)
    
    # Pruning Step: Remove unreferenced objects
    working_objects, _ = _prune_unreferenced_objects(working_objects, original_objects)
    
    # Operation 4: SCO Field Cleaning (conditional)
    working_objects, sco_report = _operation_4_sco_cleaning(working_objects, clean_sco_fields)
    
    # Operation 5: Circular Reference Resolution
    working_objects, circular_report = _operation_5_circular_reference_resolution(working_objects)
    
    # Operation 6: Dependency Sorting
    working_objects, sorting_report = _operation_6_dependency_sorting(working_objects)
    
    # Operation 7: Comprehensive Reporting
    list_report = _operation_7_comprehensive_reporting(...)
```

### Rule 2: Input/Output Format Consistency
- **Input**: Always accept `List[Dict[str, Any]]` (raw STIX dictionaries)
- **Internal**: Convert to `List[StixObject]` for processing
- **Output**: Always return `List[Dict[str, Any]]` (converted back to dictionaries)

```python
# ✅ CORRECT: Format conversion pattern
def clean_stix_list(stix_list: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Report]:
    # Convert input dictionaries to StixObjects
    stix_objects = [StixObject(**obj_dict) for obj_dict in stix_list]
    
    # Process with StixObjects internally
    working_objects = process_operations(stix_objects)
    
    # Convert back to dictionaries for return
    result_dicts = [obj.model_dump() for obj in working_objects]
    return result_dicts, report
```

### Rule 3: Error Handling Strategy
Always provide graceful degradation and comprehensive error reporting:

```python
try:
    # Process through pipeline
    result_objects, success_report = process_pipeline(working_objects)
    return result_objects, success_report
    
except Exception as e:
    # Create failure report with partial results
    failure_report = CleanStixListFailureReport(
        report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
        total_number_of_objects_processed=original_count,
        clean_operation_outcome=False,
        return_message=f"Failed to process STIX objects: {str(e)}",
        detailed_operation_reports=create_partial_reports(...)
    )
    
    # Return original input on failure
    return stix_list, failure_report
```

## Operation-Specific Rules

### Rule 4: Operation 1 - Deduplication
- Use object ID as deduplication key
- Preserve order of first occurrence
- Track duplicate IDs for reporting

```python
def _operation_1_object_deduplication(objects: List[StixObject]) -> Tuple[List[StixObject], DeduplicationReport]:
    unique_objects = {}
    duplicate_ids = []
    
    for obj in objects:
        if obj.id in unique_objects:
            duplicate_ids.append(obj.id)
        else:
            unique_objects[obj.id] = obj
    
    return list(unique_objects.values()), DeduplicationReport(...)
```

### Rule 5: Operations 2-3 - Expansion Rounds
- Extract all references from existing objects
- Fetch missing objects from external sources
- Run two rounds to catch cascading dependencies
- Prune unreferenced objects added during expansion

### Rule 6: Operation 4 - SCO Field Cleaning
- Only run when `clean_sco_fields=True`
- Remove `created` and `modified` fields from STIX Cyber Observable objects
- Track which objects were modified

### Rule 7: Operation 5 - Circular Reference Resolution
- Identify circular dependency patterns
- Break cycles using predefined resolution strategies
- Document which fields were removed

### Rule 8: Operation 6 - Dependency Sorting
**CRITICAL**: This is where our new dependency sorting implementation applies.

```python
def _operation_6_dependency_sorting(objects: List[StixObject]) -> Tuple[List[StixObject], SortingReport]:
    """Use two-phase dependency sorting approach"""
    
    # Phase 1: Pre-compute dependencies
    object_dependencies = []
    for obj in objects:
        obj_dict = obj.model_dump()
        dependencies = _extract_references_from_object(obj_dict)
        object_dependencies.append({
            'object': obj,
            'dependencies': dependencies,
            'id': obj.id
        })
    
    # Phase 2: Sort using computed dependencies
    sorted_deps = _topological_sort_with_dependencies(object_dependencies)
    sorted_objects = [item['object'] for item in sorted_deps]
    
    return sorted_objects, create_sorting_report(...)
```

## Reference Detection Rules

### Rule 9: Dual Detection Strategy
Always use both methods for maximum coverage:

```python
def _extract_references_from_object(obj_data: Dict[str, Any]) -> Set[str]:
    references = set()
    self_id = obj_data.get('id')
    
    # Method 1: Standard reference fields (_ref, _refs)
    for key, value in obj_data.items():
        if key.endswith('_ref'):
            if isinstance(value, str) and _is_valid_stix_id(value) and value != self_id:
                references.add(value)
        elif key.endswith('_refs'):
            if isinstance(value, list):
                for ref in value:
                    if isinstance(ref, str) and _is_valid_stix_id(ref) and ref != self_id:
                        references.add(ref)
    
    # Method 2: Universal STIX ID pattern matching
    _extract_from_data(obj_data, references, self_id)
    
    return references
```

### Rule 10: STIX ID Validation
Always validate before treating strings as STIX IDs:

```python
def _is_valid_stix_id(potential_id: str) -> bool:
    """Validate STIX ID format: type--uuid"""
    if not isinstance(potential_id, str) or '--' not in potential_id:
        return False
    
    parts = potential_id.split('--')
    if len(parts) != 2:
        return False
    
    type_part, uuid_part = parts
    
    # Validate type part
    if not re.match(r'^[a-zA-Z0-9\-]+$', type_part):
        return False
    
    # Validate UUID part  
    if not re.match(r'^[0-9a-fA-F\-]+$', uuid_part):
        return False
    
    return True
```

## Timing and Performance Rules

### Rule 11: Operation Timing
Track timing for each operation with microsecond precision:

```python
# Before each operation
op_start = datetime.now()

# Process operation
result, report = _operation_N_name(working_objects)

# After each operation  
op_end = datetime.now()
operation_timings.append(OperationTiming(
    operation_name="Operation Name",
    start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
    end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
    duration_seconds=(op_end - op_start).total_seconds()
))
```

### Rule 12: Memory Management
- Use `deepcopy()` to avoid modifying original input
- Clean up large intermediate objects when possible
- Use generators for processing large datasets

## Reporting Rules

### Rule 13: Success Report Structure
```python
success_report = CleanStixListSuccessReport(
    report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
    total_number_of_objects_processed=len(working_objects),
    clean_operation_outcome=True,
    return_message=f"Successfully processed {len(working_objects)} STIX objects (started with {original_count})",
    detailed_operation_reports=list_report
)
```

### Rule 14: Failure Report Structure  
```python
failure_report = CleanStixListFailureReport(
    report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
    total_number_of_objects_processed=original_count,
    clean_operation_outcome=False,
    return_message=f"Failed to process STIX objects: {str(e)}",
    detailed_operation_reports=partial_list_report
)
```

### Rule 15: Detailed Operation Reports
Always include comprehensive details for each operation:

```python
list_report = ListReport(
    deduplication_report=deduplication_report,
    expansion_report=expansion_report,
    cleaning_sco_report=sco_report,
    circular_reference_report=circular_report,
    sorting_report=sorting_report,  # ← This includes dependency information
    operation_timings=operation_timings,
    total_processing_time_seconds=total_time
)
```

## Integration Rules

### Rule 16: External Data Sources
- Always define external source paths in constants
- Handle missing external files gracefully  
- Cache external objects to avoid repeated loading
- Support multiple data source formats (bundles, lists, single objects)

### Rule 17: File vs Memory Processing
- Use `clean_stix_list()` for in-memory processing
- Use `clean_stix_directory()` for batch file processing
- Maintain consistent interfaces between both approaches

## Testing Rules  

### Rule 18: Test Coverage Requirements
Every operation must have:
- Unit tests with known inputs/outputs
- Integration tests with real STIX data
- Error condition tests
- Performance benchmarks

### Rule 19: Dependency Sorting Test Requirements
```python
def test_dependency_sorting():
    # Test with objects containing custom reference fields
    sequences = load_test_sequences_with_on_completion()
    
    # Verify detection works
    for seq in sequences:
        deps = _extract_references_from_object(seq)
        if 'on_completion' in seq:
            assert seq['on_completion'] in deps
    
    # Verify ordering works
    cleaned_objects, report = clean_stix_list(sequences)
    assert_correct_dependency_order(cleaned_objects, report)
```

## Maintenance Rules

### Rule 20: Backwards Compatibility
- Never change public function signatures without deprecation
- Maintain legacy function wrappers when refactoring
- Version all report structures
- Document breaking changes in upgrade guides

### Rule 21: Documentation Requirements  
Every function must document:
- Purpose and responsibilities
- Input/output formats and types
- Error conditions and handling
- Performance characteristics
- Examples with real data

### Rule 22: Debug Output Standards
- Use consistent prefixes: `DEBUG OP6:`, `DEBUG TOPO:`, `DEBUG GRAPH:`
- Include object ID prefixes for readability: `sequence--5ced78bf-a...`
- Make debug output optional for production use
- Provide progress indicators for long operations

## Anti-Patterns

### ❌ Never Do:
1. **Modify input objects**: Always work on copies
2. **Skip error handling**: Every operation can fail
3. **Hardcode field names**: Use dynamic detection
4. **Ignore timing**: Performance regression detection is critical
5. **Return different formats**: Input format must match output format
6. **Skip validation**: Always validate STIX IDs and object structures

### ✅ Always Do:
1. **Deep copy inputs**: Protect original data
2. **Catch all exceptions**: Provide graceful degradation  
3. **Use pattern matching**: Future-proof reference detection
4. **Track timing**: Monitor performance over time
5. **Maintain format consistency**: Predictable interfaces
6. **Validate everything**: Robust error detection