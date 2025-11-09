---
description: 'Python coding conventions and guidelines'
applyTo: '**/*.py'
---

# Python Coding Conventions

## Python Instructions

- Write clear and concise comments for each function.
- Ensure functions have descriptive names and include type hints.
- Provide docstrings following PEP 257 conventions.
- Use the `typing` module for type annotations (e.g., `List[str]`, `Dict[str, int]`).
- Break down complex functions into smaller, more manageable functions.
- Always use explicit boolean parameters with clear defaults (e.g., `clean_sco_fields: bool = False`).
- Implement conditional operations with proper early returns and failure reporting.

## General Instructions

- Always prioritize readability and clarity.
- For algorithm-related code, include explanations of the approach used.
- Write code with good maintainability practices, including comments on why certain design decisions were made.
- Handle edge cases and write clear exception handling.
- For libraries or external dependencies, mention their usage and purpose in comments.
- Use consistent naming conventions and follow language-specific best practices.
- Write concise, efficient, and idiomatic code that is also easily understandable.

## Code Style and Formatting

- Follow the **PEP 8** style guide for Python.
- Maintain proper indentation (use 4 spaces for each level of indentation).
- Ensure lines do not exceed 79 characters.
- Place function and class docstrings immediately after the `def` or `class` keyword.
- Use blank lines to separate functions, classes, and code blocks where appropriate.

## Edge Cases and Testing

- Always include test cases for critical paths of the application.
- Account for common edge cases like empty inputs, invalid data types, and large datasets.
- Include comments for edge cases and the expected behavior in those cases.
- Write unit tests for functions and document them with docstrings explaining the test cases.
- Test conditional operations with both enabled and disabled states.
- Validate TypeQL variable uniqueness in complex scenarios with multiple relations.

## STIX-ORM Specific Patterns

### Conditional Operations
- Use explicit boolean parameters for optional operations (default: False).
- Implement missing dependency detection when enrichment is disabled.
- Return failure reports with specific missing dependency lists for debugging.

### TypeQL Integration  
- Generate collision-free variable names using relation-aware prefixes.
- Use format: `{relation_property.replace('_', '-')}-{object_type}{sequence_number}`.
- Test variable uniqueness across complex object relationships.

### Error Handling
- Always return original input on failure to prevent data loss.
- Include comprehensive error context for debugging complex pipelines.
- Implement graceful degradation with fallback processing when possible.

## Example of Proper Documentation

```python
def clean_stix_list(
    stix_list: List[Dict[str, Any]], 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> Tuple[List[Dict[str, Any]], Union[SuccessReport, FailureReport]]:
    """
    Clean STIX objects through 7-operation pipeline with conditional enrichment.
    
    Args:
        stix_list: Raw STIX object dictionaries requiring cleaning
        clean_sco_fields: Whether to remove forbidden fields from SCO objects (default: False)
        enrich_from_external_sources: Whether to fetch missing objects from external sources (default: False)
    
    Returns:
        Tuple containing:
        - List[Dict]: Processed and dependency-ordered STIX object dictionaries  
        - Report: Success/failure report with detailed operation metrics
        
    Raises:
        TypeError: If boolean parameters are not actually boolean
        ValueError: If input data format is invalid
        
    Example:
        >>> cleaned_objects, report = clean_stix_list(stix_objects, enrich_from_external_sources=True)
        >>> if report.clean_operation_outcome:
        ...     print(f"Success: {report.total_number_of_objects_processed} objects processed")
    """
    # Implementation following established patterns...
