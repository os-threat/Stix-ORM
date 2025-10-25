# STIX-ORM Coding Standards

## Python Code Standards

### General Python Conventions

- **PEP 8 Compliance**: All code must follow PEP 8 styling guidelines
- **Type Hints**: Use comprehensive type annotations for all functions and methods
- **Docstrings**: Google-style docstrings for all public functions, classes, and methods
- **Variable Naming**: Use descriptive names with snake_case for variables and functions
- **Class Naming**: Use PascalCase for class names
- **Constants**: Use UPPER_SNAKE_CASE for module-level constants

### STIX-ORM Specific Patterns

#### 1. Property Normalization

Always normalize property names consistently:

```python
def normalize_property_name(prop_name: str) -> str:
    """Normalize property names for consistent variable generation"""
    return prop_name.replace('_', '-').lower()

# Examples:
# "on_completion" -> "on-completion"
# "created_by_ref" -> "created-by-ref" 
# "object_refs" -> "object-refs"
```

#### 2. TypeQL Variable Generation

**CRITICAL**: Always use relation-aware variable generation to prevent database collisions:

```python
def embedded_relation(prop, prop_type, prop_value, i, local_optional_objects, inc_add=""):
    """
    Generate collision-free TypeQL variables for embedded relations.
    
    Variable Naming Pattern:
        {relation_property}-{object_type}{sequence_number}{additional_suffix}
    
    Examples:
        on_completion + sequence + 0 -> "on-completion-sequence0"
        created_by_ref + identity + 1 -> "created-by-identity1" 
        object_refs + malware + 2 -> "object-refs-malware2"
    """
    relation_prefix = prop.replace('_', '-')
    variable_name = f"{relation_prefix}-{prop_type}{i}{inc_add}"
    return variable_name
```

#### 3. Conditional Function Design

All major processing functions must include explicit boolean parameters:

```python
def clean_stix_list(
    stix_list: List[Dict[str, Any]], 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> Tuple[List[Dict[str, Any]], Union[SuccessReport, FailureReport]]:
    """
    Clean STIX objects with optional external enrichment and SCO field cleaning.
    
    Args:
        stix_list: List of STIX objects to process
        clean_sco_fields: Whether to remove forbidden SCO fields
        enrich_from_external_sources: Whether to fetch missing dependencies from external sources
        
    Returns:
        Tuple of (cleaned_objects, report) where report indicates success/failure
    """
```

#### 4. Dynamic Reference Detection

Never hardcode STIX reference fields. Use pattern-based detection:

```python
def is_reference_field(field_name: str, field_value: Any) -> bool:
    """
    Detect STIX reference fields using dual-method approach.
    
    Method 1: Standard reference field patterns (_ref, _refs)
    Method 2: Universal STIX ID pattern matching
    """
    # Standard reference field patterns
    if field_name.endswith('_ref') or field_name.endswith('_refs'):
        return True
    
    # Universal STIX ID pattern matching
    if isinstance(field_value, str):
        return bool(STIX_ID_PATTERN.match(field_value))
    elif isinstance(field_value, list):
        return all(isinstance(item, str) and STIX_ID_PATTERN.match(item) for item in field_value)
    
    return False
```

#### 5. Error Handling Patterns

Always preserve original input on failure and provide detailed error context:

```python
def process_stix_objects(objects: List[Dict]) -> Tuple[List[Dict], ProcessingReport]:
    """Standard error handling pattern for STIX processing functions"""
    try:
        # Attempt processing
        processed_objects = perform_processing(objects)
        return processed_objects, create_success_report()
        
    except Exception as e:
        # On failure, return original input with detailed error report
        error_report = create_failure_report(
            error_message=str(e),
            original_input_preserved=True,
            context_details=get_error_context()
        )
        return objects, error_report  # Original input preserved
```

## Code Organization

### Module Structure

```
stixorm/
├── __init__.py                 # Package initialization
├── module/                     # Core functionality modules
│   ├── parsing/               # STIX parsing and cleaning
│   ├── orm/                   # TypeQL and database integration
│   └── definitions/           # STIX object definitions
└── unit/                      # Unit tests and test utilities
```

### File Naming Conventions

- **Module files**: Use snake_case (e.g., `clean_list_or_bundle.py`)
- **Test files**: Prefix with `test_` (e.g., `test_conditional_enrichment.py`)
- **Configuration files**: Use descriptive names (e.g., `pyproject.toml`)
- **Documentation files**: Use kebab-case (e.g., `implementation-guide.md`)

### Import Organization

Follow this import order:

```python
# 1. Standard library imports
import re
from typing import List, Dict, Any, Tuple, Union
from copy import deepcopy

# 2. Third-party imports
from pydantic import BaseModel
import requests

# 3. Local application imports
from stixorm.module.definitions.stix21 import StixDomainObject
from stixorm.module.parsing.dependency_sort import dependency_sort
```

## Function Design Patterns

### 1. Pure Functions

Prefer pure functions that don't modify input parameters:

```python
# ✅ CORRECT: Pure function with immutable input
def clean_stix_objects(objects: List[Dict]) -> List[Dict]:
    """Returns new list without modifying input"""
    return [clean_object(deepcopy(obj)) for obj in objects]

# ❌ INCORRECT: Mutating input parameters  
def clean_stix_objects_mutating(objects: List[Dict]) -> List[Dict]:
    """Modifies input list in place - avoid this pattern"""
    for obj in objects:
        obj['cleaned'] = True  # Mutates input
    return objects
```

### 2. Defensive Programming

Always validate inputs and handle edge cases:

```python
def process_stix_bundle(bundle: Dict[str, Any]) -> ProcessingResult:
    """Defensive programming example with comprehensive validation"""
    
    # Input validation
    if not isinstance(bundle, dict):
        raise ValueError(f"Expected dict, got {type(bundle)}")
    
    if 'objects' not in bundle:
        return ProcessingResult(success=False, message="No objects found in bundle")
    
    objects = bundle['objects']
    if not isinstance(objects, list):
        raise ValueError(f"Expected list of objects, got {type(objects)}")
    
    # Edge case: empty list
    if not objects:
        return ProcessingResult(success=True, message="Empty bundle processed", objects=[])
    
    # Main processing with error handling
    try:
        processed = perform_processing(objects)
        return ProcessingResult(success=True, objects=processed)
    except Exception as e:
        return ProcessingResult(success=False, message=f"Processing failed: {e}")
```

### 3. Configuration Over Hard-coding

Use configuration parameters instead of hard-coded values:

```python
# ✅ CORRECT: Configurable behavior
class STIXProcessor:
    def __init__(self, 
                 external_sources_enabled: bool = False,
                 max_retry_attempts: int = 3,
                 timeout_seconds: int = 30):
        self.external_sources_enabled = external_sources_enabled
        self.max_retry_attempts = max_retry_attempts
        self.timeout_seconds = timeout_seconds

# ❌ INCORRECT: Hard-coded values
class STIXProcessorBad:
    def fetch_external_data(self):
        # Hard-coded timeout and retry logic
        response = requests.get(url, timeout=30)  # Should be configurable
        for i in range(3):  # Should be configurable
            # retry logic
```

## Testing Standards

### Test Function Naming

Use descriptive test names that explain the scenario:

```python
def test_clean_stix_list_with_missing_dependencies_returns_failure_report():
    """Test that missing dependencies trigger appropriate failure reporting"""
    
def test_typeql_variable_generation_prevents_collisions_with_multiple_sequence_refs():
    """Test collision prevention with complex incident objects"""
    
def test_conditional_enrichment_disabled_skips_external_source_operations():
    """Test that enrichment=False skips operations 2-3 in pipeline"""
```

### Test Data Organization

Organize test data systematically:

```python
# Test data constants
BASIC_STIX_OBJECT = {
    'type': 'malware',
    'id': 'malware--test-123',
    'name': 'Test Malware'
}

COMPLEX_INCIDENT_WITH_SEQUENCES = {
    'type': 'incident',
    'id': 'incident--test-456',
    'on_completion': 'sequence--target-1',
    'sequence': 'sequence--target-2',
    'other_sequence_ref': 'sequence--target-3'
}

# Test scenarios
class TestScenarios:
    @staticmethod
    def create_missing_dependency_scenario():
        """Create test data with intentionally missing dependencies"""
        return [BASIC_STIX_OBJECT]  # References missing objects
```

## Performance Guidelines

### 1. Efficient Pattern Matching

Pre-compile regex patterns for performance:

```python
# Module-level constants for performance
STIX_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$')
PROPERTY_NAME_CACHE = {}

def is_stix_id(potential_id: str) -> bool:
    """Fast STIX ID validation using pre-compiled regex"""
    return bool(STIX_ID_PATTERN.match(potential_id))
```

### 2. Memory Management

Use generators for large datasets:

```python
def process_large_stix_dataset(file_path: str) -> Iterator[ProcessingResult]:
    """Process large datasets without loading everything into memory"""
    with open(file_path, 'r') as file:
        for line in file:
            stix_object = json.loads(line)
            yield process_single_object(stix_object)
```

### 3. Caching Strategies

Implement intelligent caching for repeated operations:

```python
@functools.lru_cache(maxsize=1000)
def normalize_property_name_cached(prop_name: str) -> str:
    """Cache normalized property names for performance"""
    return prop_name.replace('_', '-').lower()
```

## Documentation Standards

### Docstring Format

Use Google-style docstrings with comprehensive examples:

```python
def clean_stix_list(
    stix_list: List[Dict[str, Any]], 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> Tuple[List[Dict[str, Any]], Union[SuccessReport, FailureReport]]:
    """
    Clean and validate STIX objects with optional enrichment and SCO field cleaning.
    
    This function implements a 7-operation cleaning pipeline with conditional
    execution based on the provided boolean parameters. When external enrichment
    is disabled, the function performs missing dependency detection for debugging.
    
    Args:
        stix_list: List of STIX objects to process. Objects should be valid 
            STIX 2.1 format dictionaries.
        clean_sco_fields: Whether to remove forbidden SCO fields that violate
            STIX specification. Defaults to False.
        enrich_from_external_sources: Whether to fetch missing dependencies
            from external MITRE/MBC sources. Defaults to False for air-gapped
            operation.
            
    Returns:
        Tuple containing:
            - List of cleaned STIX objects (original objects preserved on failure)
            - ProcessingReport indicating success/failure with detailed context
            
    Raises:
        ValueError: If stix_list is not a list or contains invalid objects
        TypeError: If boolean parameters are not bool type
        
    Examples:
        Basic cleaning without external calls:
        >>> objects = [{'type': 'malware', 'id': 'malware--123', 'name': 'test'}]
        >>> cleaned, report = clean_stix_list(objects)
        >>> assert report.clean_operation_outcome is True
        
        Full processing with all options:
        >>> cleaned, report = clean_stix_list(
        ...     objects,
        ...     clean_sco_fields=True,
        ...     enrich_from_external_sources=True
        ... )
        
        Handling missing dependencies:
        >>> incomplete_objects = [{'type': 'relationship', 'source_ref': 'missing--123'}]
        >>> cleaned, report = clean_stix_list(incomplete_objects)
        >>> assert report.clean_operation_outcome is False
        >>> assert 'missing--123' in report.detailed_operation_reports.missing_ids_list
    """
```

### Comment Standards

Use comments to explain complex logic and anti-patterns:

```python
def embedded_relation(prop, prop_type, prop_value, i, local_optional_objects, inc_add=""):
    """Generate collision-free TypeQL variables for embedded relations."""
    
    # CRITICAL: Use relation-aware prefixes to prevent variable collisions
    # This solves the problem where multiple relations to the same object type
    # would generate identical variable names (e.g., "sequence0", "sequence1")
    # causing database insertion failures
    relation_prefix = prop.replace('_', '-')
    
    # Combine relation + object type + sequence for guaranteed uniqueness
    # Examples: "on-completion-sequence0", "created-by-identity1"
    variable_name = f"{relation_prefix}-{prop_type}{i}{inc_add}"
    
    return variable_name
```

## Anti-Patterns to Avoid

### ❌ **Hard-coded Field Lists**

```python
# AVOID: Hard-coded reference fields
REFERENCE_FIELDS = ['created_by_ref', 'object_refs', 'source_ref', 'target_ref']

# This breaks with custom STIX extensions like os-threat
```

### ❌ **Generic Variable Names**

```python
# AVOID: Generic TypeQL variable generation
variable_name = f"{prop_type}{i}"  # Causes collisions

# USE: Relation-aware variable generation
variable_name = f"{relation_prefix}-{prop_type}{i}"  # Prevents collisions
```

### ❌ **Silent Failures**

```python
# AVOID: Silent failure without reporting
try:
    result = risky_operation()
except Exception:
    return None  # User doesn't know what went wrong

# USE: Comprehensive error reporting
try:
    result = risky_operation()
except Exception as e:
    return create_failure_report(error=e, context=get_context())
```

### ❌ **Input Mutation**

```python
# AVOID: Modifying input parameters
def process_objects(objects):
    for obj in objects:
        obj['processed'] = True  # Mutates input
    return objects

# USE: Pure functions with immutable inputs
def process_objects(objects):
    return [process_object(deepcopy(obj)) for obj in objects]
```

## Code Review Checklist

### Pre-Commit Validation

- [ ] All functions have comprehensive type hints
- [ ] All public functions have Google-style docstrings
- [ ] TypeQL variable generation uses relation-aware prefixes
- [ ] No hard-coded STIX field lists (use dynamic detection)
- [ ] Error handling preserves original input on failure
- [ ] Boolean parameters have sensible defaults (False for optional operations)
- [ ] Tests cover all conditional execution paths
- [ ] Documentation updated for any API changes

### Performance Review

- [ ] No unnecessary deep copying in hot paths
- [ ] Regex patterns pre-compiled at module level
- [ ] Large datasets processed with generators/iterators
- [ ] Caching implemented for repeated operations
- [ ] Memory usage scales linearly with input size

### Security Review

- [ ] Input validation for all public functions
- [ ] No SQL injection vectors in TypeQL generation
- [ ] External API calls include proper timeout and retry logic
- [ ] Sensitive data not logged or exposed in error messages
- [ ] All user inputs sanitized appropriately

---

**Following these coding standards ensures maintainable, performant, and reliable STIX-ORM code that integrates seamlessly with the existing architecture and prevents common pitfalls.**