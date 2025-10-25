# Python Implementation Patterns for STIX Processing

## Overview
Specific Python coding patterns and practices established during the STIX-ORM dependency sorting implementation.

## Data Structure Patterns

### Pattern 1: Dependency Object Structure
Always use this structure for passing objects with their dependencies:

```python
object_dependencies = [
    {
        'object': stix_object,        # The actual STIX object (StixObject instance)
        'dependencies': set_of_ids,   # Set of STIX IDs this object depends on
        'id': 'stix_id_string'       # Object's ID for quick lookup
    }
    # ... more objects
]
```

### Pattern 2: Type Annotations
Always use comprehensive type hints:

```python
from typing import Dict, List, Set, Tuple, Any, Union
from stixorm.module.parsing.clean_list_or_bundle import StixObject

def _extract_references_from_object(obj_data: Dict[str, Any]) -> Set[str]:
    """Extract STIX ID references from object data."""
    pass

def _topological_sort_with_dependencies(
    object_dependencies: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Sort objects using pre-computed dependencies."""
    pass
```

### Pattern 3: Pydantic Model Usage
Use Pydantic models for structured data with validation:

```python
from pydantic import BaseModel, ConfigDict
from typing import List, Literal

class StixObject(BaseModel):
    """Base STIX Object model allowing extra fields"""
    model_config = ConfigDict(extra='allow')
    id: str
    type: str

class SortingReport(BaseModel):
    """Report for dependency sorting operations"""
    sorting_successful: bool
    sorted_list_of_stix_ids: List[str]
    diagram_of_sorted_dependencies: str
    unresolved_references: List[str]
```

## Algorithm Implementation Patterns

### Pattern 4: Two-Phase Processing
Separate computation from application for clarity:

```python
def process_with_dependencies(objects: List[StixObject]) -> List[StixObject]:
    """Two-phase processing pattern"""
    
    # Phase 1: Compute dependencies for all objects
    object_dependencies = []
    for obj in objects:
        dependencies = compute_dependencies(obj)
        object_dependencies.append({
            'object': obj,
            'dependencies': dependencies,
            'id': obj.id
        })
    
    # Phase 2: Apply processing using computed dependencies
    processed_deps = apply_processing(object_dependencies)
    
    # Extract results
    return [item['object'] for item in processed_deps]
```

### Pattern 5: Kahn's Algorithm Implementation
Standard pattern for topological sorting:

```python
from collections import defaultdict

def _topological_sort_with_dependencies(object_dependencies: List[Dict]) -> List[Dict]:
    """Kahn's algorithm with dependency objects"""
    
    # Initialize data structures
    in_degree = defaultdict(int)
    adj_list = defaultdict(list)
    obj_dict = {item['id']: item for item in object_dependencies}
    all_ids = set(obj_dict.keys())
    
    # Build graph
    for item in object_dependencies:
        obj_id = item['id']
        for dep_id in item['dependencies']:
            if dep_id in all_ids:
                adj_list[dep_id].append(obj_id)
                in_degree[obj_id] += 1
    
    # Process with queue
    queue = [obj_id for obj_id in all_ids if in_degree[obj_id] == 0]
    result = []
    
    while queue:
        current_id = queue.pop(0)
        result.append(obj_dict[current_id])
        
        for dependent_id in adj_list[current_id]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)
    
    return result
```

## Error Handling Patterns

### Pattern 6: Graceful Degradation
Always provide fallback behavior:

```python
def robust_processing(objects: List[Dict]) -> Tuple[List[Dict], bool]:
    """Process with graceful degradation"""
    try:
        # Attempt primary processing
        result = primary_processing(objects)
        return result, True
        
    except SpecificError as e:
        logger.warning(f"Primary processing failed: {e}")
        # Fall back to simpler approach
        result = fallback_processing(objects)
        return result, False
        
    except Exception as e:
        logger.error(f"All processing failed: {e}")
        # Return original input unchanged
        return objects, False
```

### Pattern 7: Exception Context
Provide detailed error context:

```python
def process_stix_objects(objects: List[Dict]) -> Tuple[List[Dict], Report]:
    """Process with comprehensive error reporting"""
    start_time = datetime.now()
    original_count = len(objects)
    
    try:
        # Processing logic here
        result = process_objects(objects)
        
        success_report = SuccessReport(
            total_objects=len(result),
            processing_time=datetime.now() - start_time,
            outcome=True
        )
        return result, success_report
        
    except Exception as e:
        failure_report = FailureReport(
            total_objects=original_count,
            processing_time=datetime.now() - start_time,
            outcome=False,
            error_message=str(e),
            error_type=type(e).__name__
        )
        return objects, failure_report  # Return original input
```

## Data Validation Patterns

### Pattern 8: Input Validation
Always validate inputs at function boundaries:

```python
def _extract_references_from_object(obj_data: Any) -> Set[str]:
    """Extract references with input validation"""
    if not isinstance(obj_data, dict):
        raise ValueError(f"Expected dict, got {type(obj_data)}")
    
    if 'id' not in obj_data:
        raise ValueError("Object missing required 'id' field")
    
    if not isinstance(obj_data['id'], str):
        raise ValueError("Object 'id' must be string")
    
    # Processing logic here
    pass
```

### Pattern 9: STIX ID Validation
Use regex patterns for format validation:

```python
import re

def _is_valid_stix_id(potential_id: str) -> bool:
    """Validate STIX ID format with regex"""
    if not isinstance(potential_id, str):
        return False
    
    # STIX ID format: type--uuid
    pattern = r'^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$'
    
    if not re.match(pattern, potential_id):
        return False
    
    # Additional validation
    parts = potential_id.split('--')
    if len(parts) != 2:
        return False
    
    type_part, uuid_part = parts
    return len(type_part) > 0 and len(uuid_part) > 0
```

## Recursive Processing Patterns

### Pattern 10: Safe Recursive Traversal
Handle nested data structures safely:

```python
def _extract_from_data(data: Any, references: Set[str], self_id: str, depth: int = 0) -> None:
    """Recursively extract STIX IDs with depth limiting"""
    
    # Prevent infinite recursion
    if depth > 50:
        return
    
    if isinstance(data, str):
        if _is_valid_stix_id(data) and data != self_id:
            references.add(data)
            
    elif isinstance(data, list):
        for item in data:
            _extract_from_data(item, references, self_id, depth + 1)
            
    elif isinstance(data, dict):
        for value in data.values():
            _extract_from_data(value, references, self_id, depth + 1)
    
    # Ignore other types (int, float, bool, None, etc.)
```

## Debug and Logging Patterns

### Pattern 11: Structured Debug Output
Use consistent debug formatting:

```python
def debug_operation(operation_name: str, obj_id: str, details: Any) -> None:
    """Standard debug output format"""
    short_id = obj_id[:20] + '...' if len(obj_id) > 20 else obj_id
    print(f"DEBUG {operation_name}: {short_id} {details}")

# Usage examples:
debug_operation("OP6", obj.id, f"dependencies: {dependencies}")
debug_operation("TOPO", obj_id, f"added to queue (in_degree=0)")
debug_operation("GRAPH", obj_id, f"depends on {dep_id[:20]}...")
```

### Pattern 12: Performance Timing
Track operation timing consistently:

```python
from datetime import datetime
from typing import NamedTuple

class OperationTiming(NamedTuple):
    operation_name: str
    start_time: str
    end_time: str
    duration_seconds: float

def time_operation(operation_name: str):
    """Context manager for timing operations"""
    from contextlib import contextmanager
    
    @contextmanager
    def timer():
        start = datetime.now()
        try:
            yield start
        finally:
            end = datetime.now()
            duration = (end - start).total_seconds()
            print(f"{operation_name} took {duration:.3f} seconds")
    
    return timer()

# Usage:
with time_operation("Dependency Sorting"):
    result = sort_dependencies(objects)
```

## Memory Management Patterns

### Pattern 13: Deep Copy for Safety
Always protect original data:

```python
from copy import deepcopy

def safe_processing(input_objects: List[Dict]) -> List[Dict]:
    """Process without modifying original data"""
    
    # Create deep copy to avoid side effects
    working_objects = deepcopy(input_objects)
    
    # Process the copy
    result = process(working_objects)
    
    return result
```

### Pattern 14: Generator for Large Datasets
Use generators for memory efficiency:

```python
def process_large_dataset(objects: List[Dict]) -> Iterator[Dict]:
    """Process objects one at a time for memory efficiency"""
    for obj in objects:
        processed = process_single_object(obj)
        yield processed

# Usage:
results = list(process_large_dataset(large_object_list))
```

## Integration Patterns

### Pattern 15: Format Conversion Wrapper
Handle format conversion at boundaries:

```python
def dict_to_stix_wrapper(func):
    """Decorator to handle dict <-> StixObject conversion"""
    def wrapper(objects: List[Dict], *args, **kwargs):
        # Convert input dicts to StixObjects
        stix_objects = [StixObject(**obj) for obj in objects]
        
        # Call original function
        result_objects, report = func(stix_objects, *args, **kwargs)
        
        # Convert back to dicts
        result_dicts = [obj.model_dump() for obj in result_objects]
        
        return result_dicts, report
    
    return wrapper

@dict_to_stix_wrapper
def clean_with_stix_objects(objects: List[StixObject]) -> Tuple[List[StixObject], Report]:
    """Function that works with StixObjects internally"""
    pass
```

### Pattern 16: Report Aggregation
Combine multiple operation reports:

```python
def create_comprehensive_report(*operation_reports) -> ComprehensiveReport:
    """Aggregate multiple operation reports"""
    total_time = sum(r.duration for r in operation_reports if hasattr(r, 'duration'))
    
    return ComprehensiveReport(
        operation_reports=list(operation_reports),
        total_processing_time=total_time,
        overall_success=all(r.success for r in operation_reports if hasattr(r, 'success'))
    )
```

## Testing Patterns

### Pattern 17: Test Data Factories
Create reusable test data generators:

```python
def create_test_sequence(seq_id: str, depends_on: str = None) -> Dict[str, Any]:
    """Factory for test sequence objects"""
    seq = {
        'type': 'sequence',
        'id': seq_id,
        'step_type': 'start_step' if depends_on else 'single_step'
    }
    
    if depends_on:
        seq['on_completion'] = depends_on
    
    return seq

# Usage in tests:
target_seq = create_test_sequence('sequence--target-1')
dependent_seq = create_test_sequence('sequence--dependent-1', depends_on='sequence--target-1')
```

### Pattern 18: Assertion Helpers
Create domain-specific assertions:

```python
def assert_dependency_order(objects: List[Dict], target_ids: List[str], dependent_ids: List[str]):
    """Assert that targets appear before dependents"""
    obj_ids = [obj['id'] for obj in objects]
    
    target_positions = [obj_ids.index(tid) for tid in target_ids if tid in obj_ids]
    dependent_positions = [obj_ids.index(did) for did in dependent_ids if did in obj_ids]
    
    if target_positions and dependent_positions:
        max_target = max(target_positions)
        min_dependent = min(dependent_positions)
        assert max_target < min_dependent, f"Dependency order violated: max target pos {max_target} >= min dependent pos {min_dependent}"

# Usage:
assert_dependency_order(sorted_objects, target_seq_ids, dependent_seq_ids)
```

## Conditional Operation Patterns

### Pattern 19: Conditional Processing with Early Return
Handle conditional operations with proper failure reporting:

```python
def conditional_enrichment_operation(
    objects: List[StixObject], 
    enrich_from_external_sources: bool = False
) -> Tuple[List[StixObject], Union[SuccessReport, FailureReport]]:
    """Conditional enrichment with missing dependency detection"""
    
    if enrich_from_external_sources:
        # Perform full enrichment
        return _perform_enrichment(objects)
    else:
        # Check for missing dependencies without enrichment
        missing_deps = _detect_missing_dependencies(objects)
        
        if missing_deps:
            # Return failure report with missing dependency list
            failure_report = FailureReport(
                missing_ids_list=missing_deps,
                return_message=f"Missing dependencies: {missing_deps}"
            )
            return objects, failure_report
        else:
            # No missing dependencies, continue processing
            success_report = SuccessReport(
                return_message="No missing dependencies detected"
            )
            return objects, success_report
```

### Pattern 20: Boolean Parameter Validation
Always validate boolean parameters and provide clear defaults:

```python
def enhanced_clean_function(
    stix_list: List[Dict[str, Any]], 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> Tuple[List[Dict[str, Any]], Report]:
    """Enhanced cleaning with explicit boolean parameters"""
    
    # Validate parameters
    if not isinstance(clean_sco_fields, bool):
        raise TypeError("clean_sco_fields must be a boolean")
    if not isinstance(enrich_from_external_sources, bool):
        raise TypeError("enrich_from_external_sources must be a boolean")
    
    # Document behavior in comments
    # clean_sco_fields=False: Skip SCO field cleaning (default)
    # enrich_from_external_sources=False: Check dependencies only, no enrichment (default)
    
    return _process_with_conditions(stix_list, clean_sco_fields, enrich_from_external_sources)
```

## TypeQL Variable Generation Patterns

### Pattern 21: Collision-Free Variable Naming
Generate unique TypeQL variables using relation-aware prefixes:

```python
def generate_typeql_variable(
    relation_property: str, 
    object_type: str, 
    sequence_number: int, 
    additional_suffix: str = ""
) -> str:
    """Generate collision-free TypeQL variable names"""
    
    # Normalize relation property name
    relation_prefix = relation_property.replace('_', '-')
    
    # Combine with object type and sequence
    variable_name = f"{relation_prefix}-{object_type}{sequence_number}{additional_suffix}"
    
    return variable_name

# Examples:
# generate_typeql_variable("on_completion", "sequence", 0) -> "on-completion-sequence0"
# generate_typeql_variable("created_by_ref", "identity", 1) -> "created-by-identity1"
# generate_typeql_variable("sequence", "sequence", 2) -> "sequence-sequence2"
```

### Pattern 22: Variable Collision Testing
Test for TypeQL variable uniqueness in complex scenarios:

```python
def test_typeql_variable_uniqueness():
    """Test that TypeQL variables are unique across relations"""
    
    # Create incident with multiple sequence references
    incident_data = {
        'type': 'incident',
        'id': 'incident--test-123',
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2',
        'other_sequence_ref': 'sequence--target-3'
    }
    
    # Generate variables for each relation
    variables = []
    for i, (prop, value) in enumerate(incident_data.items()):
        if prop.endswith('_ref') or 'sequence' in prop:
            var = generate_typeql_variable(prop, 'sequence', i)
            variables.append(var)
    
    # Assert all variables are unique
    assert len(variables) == len(set(variables)), f"Variable collision detected: {variables}"
    
    # Expected output:
    # ["on-completion-sequence0", "sequence-sequence1", "other-sequence-sequence2"]
```

## Integration Pattern Updates

### Pattern 23: Enhanced Error Context
Provide comprehensive error context for debugging:

```python
def enhanced_error_handling(operation_name: str, input_data: Any):
    """Enhanced error context for debugging"""
    
    try:
        result = process_operation(input_data)
        return result, None
        
    except Exception as e:
        error_context = {
            'operation': operation_name,
            'input_type': type(input_data).__name__,
            'input_count': len(input_data) if hasattr(input_data, '__len__') else 'N/A',
            'error_type': type(e).__name__,
            'error_message': str(e),
            'stack_trace': traceback.format_exc()
        }
        
        logger.error(f"Operation {operation_name} failed", extra=error_context)
        return input_data, error_context  # Return original input on failure
```