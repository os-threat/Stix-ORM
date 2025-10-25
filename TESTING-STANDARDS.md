# STIX-ORM Testing Standards

## Testing Philosophy

STIX-ORM follows a comprehensive testing approach that validates not just individual functions, but the entire data transformation pipeline from raw STIX JSON through to TypeDB insertion. Our testing strategy emphasizes real-world scenarios, edge case coverage, and validation of critical anti-patterns.

## Testing Architecture

### Test Organization

```
test/
├── unit/                       # Unit tests for individual functions
│   ├── test_clean_stix.py     # STIX cleaning pipeline tests
│   ├── test_typeql_generation.py # TypeQL variable generation tests
│   └── test_dependency_sort.py   # Dependency sorting tests
├── integration/                # Integration tests for full pipelines
│   ├── test_stix_to_typedb.py # End-to-end transformation tests
│   └── test_conditional_pipeline.py # Conditional operation tests
├── performance/                # Performance and load tests
│   ├── test_large_datasets.py # Memory and speed validation
│   └── test_concurrency.py    # Concurrent processing tests
└── fixtures/                   # Test data and mock objects
    ├── stix_objects.py        # Standard test objects
    ├── complex_scenarios.py   # Edge case test data
    └── malformed_data.py      # Invalid input test cases
```

## Critical Test Requirements

### 1. TypeQL Variable Collision Prevention

**CRITICAL**: Every test involving TypeQL generation must validate variable uniqueness:

```python
def test_typeql_variable_collision_prevention():
    """Test that TypeQL variable generation prevents all collisions"""
    
    # Create object with multiple same-type references
    complex_incident = {
        'type': 'incident',
        'id': 'incident--test-123',
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2', 
        'other_sequence_ref': 'sequence--target-3',
        'created_by_ref': 'identity--analyst-1'
    }
    
    # Generate TypeQL variables
    generated_variables = []
    for i, (prop, value) in enumerate(complex_incident.items()):
        if is_reference_field(prop, value):
            obj_type = extract_object_type(value)
            var = embedded_relation(prop, obj_type, value, i)
            generated_variables.append(var)
    
    # CRITICAL VALIDATION: All variables must be unique
    assert len(generated_variables) == len(set(generated_variables)), \
        f"Variable collision detected: {generated_variables}"
    
    # Expected unique variables:
    # ["on-completion-sequence0", "sequence-sequence1", "other-sequence-sequence2", "created-by-identity3"]
    expected_prefixes = ["on-completion", "sequence", "other-sequence", "created-by"]
    for i, var in enumerate(generated_variables):
        assert var.startswith(expected_prefixes[i]), f"Incorrect prefix for {var}"
```

### 2. Conditional Enrichment Testing

**MANDATORY**: Test all conditional operation paths:

```python
class TestConditionalEnrichment:
    """Comprehensive testing of conditional enrichment functionality"""
    
    def test_enrichment_disabled_skips_external_operations(self):
        """Test that enrichment=False skips operations 2-3"""
        stix_objects = create_test_objects_with_missing_deps()
        
        cleaned, report = clean_stix_list(
            stix_objects, 
            enrich_from_external_sources=False
        )
        
        # Should identify missing dependencies without fetching
        assert report.clean_operation_outcome is False
        assert len(report.detailed_operation_reports.missing_ids_list) > 0
        assert "external sources skipped" in report.return_message.lower()
    
    def test_enrichment_enabled_fetches_external_dependencies(self):
        """Test that enrichment=True triggers external source operations"""
        stix_objects = create_test_objects_with_missing_deps()
        
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value.json.return_value = create_mock_mitre_response()
            
            cleaned, report = clean_stix_list(
                stix_objects,
                enrich_from_external_sources=True
            )
        
        # Should attempt external fetching
        assert mock_get.called
        assert report.clean_operation_outcome is True
        assert len(cleaned) > len(stix_objects)  # New objects added
    
    def test_sco_field_cleaning_conditional(self):
        """Test that SCO field cleaning is properly conditional"""
        sco_object = create_sco_with_forbidden_fields()
        
        # Without SCO cleaning
        cleaned, _ = clean_stix_list([sco_object], clean_sco_fields=False)
        assert 'forbidden_field' in cleaned[0]
        
        # With SCO cleaning
        cleaned, _ = clean_stix_list([sco_object], clean_sco_fields=True)
        assert 'forbidden_field' not in cleaned[0]
```

### 3. Dynamic Reference Detection Validation

**ESSENTIAL**: Validate dynamic detection works with custom extensions:

```python
def test_dynamic_reference_detection_with_custom_fields():
    """Test that dynamic detection works with os-threat and MBC custom fields"""
    
    custom_object = {
        'type': 'incident',
        'id': 'incident--custom-123',
        # Standard STIX references
        'created_by_ref': 'identity--analyst-1',
        'object_refs': ['malware--sample-1', 'indicator--ioc-1'],
        # Custom os-threat fields
        'on_completion': 'sequence--target-1',
        'sequenced_object': 'event--action-1',
        # Custom MBC fields  
        'behavior_refs': ['malware-behavior--mbc-1', 'malware-behavior--mbc-2']
    }
    
    detected_refs = extract_all_references(custom_object)
    
    # Should detect all reference fields regardless of naming
    expected_refs = {
        'created_by_ref': 'identity--analyst-1',
        'object_refs': ['malware--sample-1', 'indicator--ioc-1'],
        'on_completion': 'sequence--target-1', 
        'sequenced_object': 'event--action-1',
        'behavior_refs': ['malware-behavior--mbc-1', 'malware-behavior--mbc-2']
    }
    
    for field, expected_value in expected_refs.items():
        assert field in detected_refs
        assert detected_refs[field] == expected_value
```

## Test Data Management

### Standard Test Objects

Create reusable test objects for common scenarios:

```python
class STIXTestFixtures:
    """Standard test objects for consistent testing"""
    
    @staticmethod
    def create_basic_malware():
        return {
            'type': 'malware',
            'id': 'malware--test-basic-123',
            'name': 'Test Malware',
            'malware_types': ['trojan']
        }
    
    @staticmethod
    def create_complex_incident_with_sequences():
        """Incident with multiple sequence references for collision testing"""
        return {
            'type': 'incident',
            'id': 'incident--collision-test-456',
            'name': 'Collision Test Incident',
            'on_completion': 'sequence--target-1',
            'sequence': 'sequence--target-2',
            'another_sequence_ref': 'sequence--target-3',
            'created_by_ref': 'identity--analyst-1'
        }
    
    @staticmethod
    def create_missing_dependency_scenario():
        """Objects with intentionally missing dependencies"""
        return [
            {
                'type': 'relationship',
                'id': 'relationship--missing-deps-789',
                'relationship_type': 'uses',
                'source_ref': 'malware--missing-source',  # Missing
                'target_ref': 'attack-pattern--missing-target'  # Missing
            }
        ]
    
    @staticmethod
    def create_circular_reference_scenario():
        """Objects with circular dependencies for sorting tests"""
        return [
            {
                'type': 'malware',
                'id': 'malware--circular-a',
                'name': 'Circular A',
                'derived_from': 'malware--circular-b'
            },
            {
                'type': 'malware', 
                'id': 'malware--circular-b',
                'name': 'Circular B',
                'derived_from': 'malware--circular-a'
            }
        ]
```

### Error Scenario Testing

Create specific test cases for all error conditions:

```python
class TestErrorScenarios:
    """Test all error conditions and edge cases"""
    
    def test_invalid_input_types(self):
        """Test handling of invalid input types"""
        invalid_inputs = [
            None,
            "not a list",
            123,
            {'not': 'a list'},
            [None, "invalid", 123]  # Mixed invalid types in list
        ]
        
        for invalid_input in invalid_inputs:
            with pytest.raises((ValueError, TypeError)):
                clean_stix_list(invalid_input)
    
    def test_malformed_stix_objects(self):
        """Test handling of malformed STIX objects"""
        malformed_objects = [
            {},  # Empty object
            {'type': 'malware'},  # Missing required ID
            {'id': 'malware--123'},  # Missing required type
            {'type': 'invalid-type', 'id': 'invalid--123'},  # Invalid type
            {'type': 'malware', 'id': 'invalid-id-format'}  # Invalid ID format
        ]
        
        for malformed_obj in malformed_objects:
            cleaned, report = clean_stix_list([malformed_obj])
            # Should preserve original input on failure
            assert cleaned == [malformed_obj]
            assert report.clean_operation_outcome is False
    
    def test_network_failure_graceful_degradation(self):
        """Test graceful handling when external sources are unavailable"""
        objects_with_missing_deps = create_test_objects_with_missing_deps()
        
        with mock.patch('requests.get', side_effect=requests.ConnectionError()):
            cleaned, report = clean_stix_list(
                objects_with_missing_deps,
                enrich_from_external_sources=True
            )
        
        # Should gracefully degrade to local processing
        assert cleaned == objects_with_missing_deps  # Original preserved
        assert report.clean_operation_outcome is False
        assert "network error" in report.return_message.lower()
```

## Performance Testing

### Load Testing Requirements

**MANDATORY**: Test with realistic dataset sizes:

```python
class TestPerformance:
    """Performance validation for large datasets"""
    
    def test_processing_speed_large_dataset(self):
        """Test processing speed with 1000+ objects"""
        large_dataset = [
            STIXTestFixtures.create_basic_malware() 
            for i in range(1000)
        ]
        
        start_time = time.time()
        cleaned, report = clean_stix_list(large_dataset)
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        # Should process 1000 objects in under 10 seconds
        assert processing_time < 10.0, f"Processing took {processing_time:.2f}s"
        assert report.clean_operation_outcome is True
        assert len(cleaned) == 1000
    
    def test_memory_usage_scaling(self):
        """Test that memory usage scales linearly with input size"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Test with small dataset
        small_dataset = [STIXTestFixtures.create_basic_malware() for i in range(100)]
        initial_memory = process.memory_info().rss
        
        clean_stix_list(small_dataset)
        small_memory = process.memory_info().rss
        
        # Test with larger dataset
        large_dataset = [STIXTestFixtures.create_basic_malware() for i in range(1000)]
        clean_stix_list(large_dataset)
        large_memory = process.memory_info().rss
        
        # Memory should scale roughly linearly (allow 50% variance)
        expected_large_memory = initial_memory + (small_memory - initial_memory) * 10
        assert large_memory < expected_large_memory * 1.5
    
    def test_typeql_generation_performance(self):
        """Test TypeQL variable generation performance"""
        complex_objects = [
            STIXTestFixtures.create_complex_incident_with_sequences()
            for i in range(100)
        ]
        
        start_time = time.time()
        
        for obj in complex_objects:
            variables = []
            for i, (prop, value) in enumerate(obj.items()):
                if is_reference_field(prop, value):
                    obj_type = extract_object_type(value)
                    var = embedded_relation(prop, obj_type, value, i)
                    variables.append(var)
        
        end_time = time.time()
        
        # Should generate variables for 100 complex objects in under 1 second
        assert end_time - start_time < 1.0
```

## Integration Testing

### End-to-End Pipeline Testing

**CRITICAL**: Test complete pipeline from STIX to TypeDB:

```python
class TestIntegrationPipeline:
    """End-to-end integration testing"""
    
    def test_complete_stix_to_typedb_pipeline(self):
        """Test complete transformation: STIX JSON -> TypeDB insertion"""
        
        # Step 1: Clean STIX objects
        raw_objects = load_test_stix_bundle()
        cleaned, clean_report = clean_stix_list(
            raw_objects,
            clean_sco_fields=True,
            enrich_from_external_sources=False
        )
        assert clean_report.clean_operation_outcome is True
        
        # Step 2: Generate TypeQL statements
        typeql_statements = []
        for obj in cleaned:
            statement = generate_typeql_insert(obj)
            typeql_statements.append(statement)
        
        # Step 3: Validate TypeQL statements
        for statement in typeql_statements:
            assert validate_typeql_syntax(statement) is True
        
        # Step 4: Check for variable collisions across all statements
        all_variables = extract_variables_from_statements(typeql_statements)
        assert len(all_variables) == len(set(all_variables)), "Variable collision detected"
        
        # Step 5: Test database insertion (if test database available)
        if test_database_available():
            for statement in typeql_statements:
                result = test_database.execute(statement)
                assert result.success, f"Database insertion failed: {statement}"
    
    def test_conditional_pipeline_paths(self):
        """Test all conditional execution paths through the pipeline"""
        
        test_objects = STIXTestFixtures.create_missing_dependency_scenario()
        
        # Path 1: No enrichment, no SCO cleaning
        cleaned1, report1 = clean_stix_list(test_objects)
        assert report1.clean_operation_outcome is False  # Missing dependencies
        
        # Path 2: No enrichment, with SCO cleaning
        cleaned2, report2 = clean_stix_list(test_objects, clean_sco_fields=True)
        assert report2.clean_operation_outcome is False  # Still missing dependencies
        
        # Path 3: With enrichment, no SCO cleaning
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value.json.return_value = create_mock_dependencies()
            cleaned3, report3 = clean_stix_list(test_objects, enrich_from_external_sources=True)
            assert report3.clean_operation_outcome is True  # Dependencies resolved
        
        # Path 4: Full processing with all options
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value.json.return_value = create_mock_dependencies()
            cleaned4, report4 = clean_stix_list(
                test_objects,
                clean_sco_fields=True,
                enrich_from_external_sources=True
            )
            assert report4.clean_operation_outcome is True
```

## Test Execution Standards

### Pytest Configuration

Standard pytest configuration in `pytest.ini`:

```ini
[tool:pytest]
testpaths = test
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --verbose
    --strict-markers
    --disable-warnings
    --cov=stixorm
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=90
markers =
    unit: Unit tests for individual functions
    integration: Integration tests for full pipelines
    performance: Performance and load tests
    slow: Tests that take longer than 1 second
```

### Test Execution Commands

```bash
# Run all tests
pytest

# Run only unit tests
pytest -m unit

# Run with coverage report
pytest --cov=stixorm --cov-report=html

# Run performance tests (exclude from CI)
pytest -m performance

# Run tests with detailed output
pytest -v -s

# Run specific test file
pytest test/test_clean_stix.py

# Run specific test function
pytest test/test_clean_stix.py::test_typeql_variable_collision_prevention
```

### Continuous Integration Testing

**MANDATORY**: All tests must pass in CI environment:

```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, "3.10", "3.11"]
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v3
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install poetry
          poetry install
      - name: Run unit tests
        run: poetry run pytest -m "unit and not slow"
      - name: Run integration tests
        run: poetry run pytest -m integration
      - name: Check coverage
        run: poetry run pytest --cov=stixorm --cov-fail-under=90
```

## Test Quality Assurance

### Test Review Checklist

Before merging any code, ensure:

- [ ] All critical test requirements are met
- [ ] TypeQL variable collision prevention is validated
- [ ] All conditional operation paths are tested
- [ ] Dynamic reference detection is validated with custom fields
- [ ] Error scenarios and edge cases are covered
- [ ] Performance requirements are met
- [ ] Integration tests pass end-to-end
- [ ] Test coverage is above 90%
- [ ] Tests are properly documented with clear descriptions
- [ ] Test data is organized and reusable

### Code Coverage Requirements

**MINIMUM**: 90% code coverage across all modules

**CRITICAL MODULES**: 95%+ coverage required for:
- `clean_list_or_bundle.py` - Core cleaning pipeline
- `import_utilities.py` - TypeQL variable generation
- `dependency_sort.py` - Dependency ordering

### Testing Anti-Patterns to Avoid

**❌ DO NOT**:
- Test implementation details instead of behavior
- Use real external API calls in unit tests
- Skip testing error conditions and edge cases
- Create tests that depend on specific execution order
- Mock too much (lose confidence in integration)
- Write tests that pass randomly (flaky tests)

**✅ DO**:
- Test observable behavior and outputs
- Mock external dependencies appropriately
- Test all error paths and edge cases
- Write independent, isolated tests
- Balance unit tests with integration tests
- Write deterministic, repeatable tests

## Documentation and Reporting

### Test Documentation

Document complex test scenarios:

```python
def test_complex_dependency_resolution_with_circular_refs():
    """
    Test dependency resolution with circular references.
    
    This test validates that the dependency sorting algorithm can handle
    circular references gracefully by breaking cycles and processing
    objects in a safe order that prevents constraint violations.
    
    Scenario:
        - Malware A derives from Malware B
        - Malware B derives from Malware A (circular dependency)
        - System should detect cycle and process both objects
    
    Expected Behavior:
        - Circular reference detected and reported
        - Both objects processed without dependency errors
        - Final order ensures database constraints are met
    """
```

### Test Result Reporting

Generate comprehensive test reports:

```python
# conftest.py
def pytest_html_report_title(report):
    report.title = "STIX-ORM Test Suite Report"

def pytest_html_results_summary(prefix, summary, postfix):
    prefix.extend([
        "<h2>STIX-ORM Testing Standards Compliance</h2>",
        "<p>This report validates compliance with STIX-ORM testing standards.</p>"
    ])
```

---

**These testing standards ensure that STIX-ORM maintains the highest quality and reliability standards while preventing regressions in critical functionality like TypeQL variable collision prevention and conditional enrichment operations.**