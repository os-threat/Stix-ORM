# STIX-ORM Quick Reference

## 🚀 Quick Start

```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

# Basic processing (recommended for most use cases)
cleaned_objects, report = clean_stix_list(raw_stix_objects)

# Full processing with all options
cleaned_objects, report = clean_stix_list(
    raw_stix_objects,
    clean_sco_fields=True,           # Remove forbidden SCO fields
    enrich_from_external_sources=True # Fetch missing dependencies
)
```

## 📋 Core Functions

### STIX Object Processing

| Function | Purpose | Parameters |
|----------|---------|------------|
| `clean_stix_list()` | Clean and validate STIX objects | `stix_list`, `clean_sco_fields=False`, `enrich_from_external_sources=False` |
| `clean_stix_directory()` | Process STIX files in directory | `directory_path`, `clean_sco_fields=False`, `enrich_from_external_sources=False` |
| `dependency_sort()` | Sort objects by dependencies | `stix_objects` |

### TypeQL Generation

| Function | Purpose | Key Features |
|----------|---------|-------------|
| `embedded_relation()` | Generate collision-free variables | Relation-aware prefixes |
| `generate_typeql_insert()` | Create TypeQL insert statements | Safe variable naming |
| `extract_all_references()` | Find all STIX references | Dynamic field detection |

## 🔧 Configuration Options

### Processing Modes

| Mode | `clean_sco_fields` | `enrich_from_external_sources` | Use Case |
|------|-------------------|-------------------------------|----------|
| **Basic** | `False` | `False` | Most common, air-gapped environments |
| **SCO Compliant** | `True` | `False` | STIX standard compliance |
| **Enriched** | `False` | `True` | Missing dependency resolution |
| **Full** | `True` | `True` | Complete processing with all features |

### External Sources

When `enrich_from_external_sources=True`, system fetches from:

- MITRE ATT&CK Enterprise
- MITRE ATT&CK Mobile
- MITRE ATT&CK ICS
- MITRE ATLAS
- Malware Behavior Catalog (MBC)

## 🏗️ Architecture Overview

### 7-Operation Cleaning Pipeline

1. **Object Deduplication** - Remove duplicate STIX objects
2. **Expansion (Conditional)** - Fetch missing dependencies from external sources
3. **Validation (Conditional)** - Validate expanded objects
4. **SCO Field Cleaning (Conditional)** - Remove forbidden SCO fields
5. **Circular Reference Resolution** - Handle circular dependencies
6. **Dependency Sorting** - Order objects for safe database insertion
7. **Report Generation** - Create comprehensive processing reports

### TypeQL Variable Generation

```python
# CRITICAL: Always use relation-aware prefixes
relation_prefix = prop.replace('_', '-')
variable_name = f"{relation_prefix}-{prop_type}{i}{inc_add}"

# Examples:
# "on_completion" + "sequence" + 0 -> "on-completion-sequence0"
# "created_by_ref" + "identity" + 1 -> "created-by-identity1"
```

## 🔍 Dynamic Reference Detection

### Supported Reference Patterns

| Pattern | Example | Detection Method |
|---------|---------|------------------|
| Standard `_ref` | `created_by_ref` | Field name pattern |
| Standard `_refs` | `object_refs` | Field name pattern |
| Custom fields | `on_completion`, `sequenced_object` | STIX ID pattern matching |
| Extension fields | `behavior_refs` | Universal STIX ID regex |

### STIX ID Pattern

```python
STIX_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$')
```

## 📊 Report Structure

### Success Report

```python
class CleanStixListSuccessReport:
    clean_operation_outcome: True
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]
```

### Failure Report

```python
class CleanStixListFailureReport:
    clean_operation_outcome: False
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]
    # Contains missing_ids_list for debugging
```

## 🚨 Critical Anti-Patterns

### ❌ NEVER Do These

```python
# ❌ Hard-coded reference fields
REFERENCE_FIELDS = ['created_by_ref', 'object_refs']  # Breaks with extensions

# ❌ Generic variable names
variable = f"{obj_type}{i}"  # Causes TypeQL collisions

# ❌ Mutate input parameters
def process(objects):
    for obj in objects:
        obj['modified'] = True  # Modifies original input

# ❌ Silent failures
try:
    result = risky_operation()
except:
    return None  # User doesn't know what failed
```

### ✅ Always Do These

```python
# ✅ Dynamic reference detection
if field.endswith('_ref') or is_stix_id(value):
    # Handle as reference

# ✅ Relation-aware variables
relation_prefix = prop.replace('_', '-')
variable = f"{relation_prefix}-{obj_type}{i}"

# ✅ Preserve original input on failure
try:
    result = process(deepcopy(input))
except Exception as e:
    return input, failure_report(e)

# ✅ Comprehensive error reporting
return processed_data, success_report(details)
```

## 🧪 Testing Quick Reference

### Essential Test Categories

| Category | Purpose | Example |
|----------|---------|---------|
| **Collision Prevention** | Validate TypeQL variable uniqueness | Multiple sequence references |
| **Conditional Operations** | Test all pipeline paths | All 4 parameter combinations |
| **Dynamic Detection** | Custom field recognition | os-threat, MBC extensions |
| **Error Handling** | Edge cases and failures | Missing dependencies, network errors |

### Test Execution

```bash
# Run all tests
pytest

# Unit tests only
pytest -m unit

# With coverage
pytest --cov=stixorm --cov-report=html

# Specific test
pytest test/test_clean_stix.py::test_collision_prevention
```

## 📚 Documentation Navigation

### Core Documentation

| File | Purpose | When to Use |
|------|---------|-------------|
| `PROJECT-OVERVIEW.md` | High-level project introduction | Understanding project scope |
| `blueprint.md` | Detailed architecture design | Implementation planning |
| `docs/implementation-guide.md` | Comprehensive technical guide | Detailed implementation |
| `CODING-STANDARDS.md` | Code quality guidelines | Development work |
| `TESTING-STANDARDS.md` | Testing requirements | Writing tests |

### Instruction Files

| File | Purpose | Critical Content |
|------|---------|------------------|
| `enhancement-summary.instructions.md` | Major improvements overview | Conditional enrichment, collision prevention |
| `typeql-integration.instructions.md` | TypeQL patterns | Variable collision solutions |
| `python-patterns.instructions.md` | Implementation patterns | Dynamic detection, error handling |
| `python.instructions.md` | Python conventions | Code style and standards |

## 🔧 Common Use Cases

### 1. Basic STIX Validation

```python
# Validate and clean STIX objects without external calls
objects = load_stix_data()
cleaned, report = clean_stix_list(objects)

if report.clean_operation_outcome:
    print(f"Successfully processed {len(cleaned)} objects")
else:
    print(f"Processing failed: {report.return_message}")
```

### 2. Missing Dependency Detection

```python
# Check for missing dependencies without fetching
objects = load_incomplete_stix_data()
cleaned, report = clean_stix_list(objects, enrich_from_external_sources=False)

if not report.clean_operation_outcome:
    missing_ids = report.detailed_operation_reports.missing_ids_list
    print(f"Missing dependencies: {missing_ids}")
```

### 3. Full Processing with Enrichment

```python
# Complete processing with external source enrichment
objects = load_stix_data()
cleaned, report = clean_stix_list(
    objects,
    clean_sco_fields=True,
    enrich_from_external_sources=True
)

print(f"Original: {len(objects)}, Cleaned: {len(cleaned)}")
```

### 4. TypeDB Integration

```python
# Process for TypeDB insertion
cleaned, report = clean_stix_list(objects)

if report.clean_operation_outcome:
    # Generate TypeQL statements
    typeql_statements = [generate_typeql_insert(obj) for obj in cleaned]
    
    # Execute in dependency order (guaranteed by cleaning)
    for statement in typeql_statements:
        database.execute(statement)
```

## 🔍 Debugging Guide

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| **Variable Collisions** | TypeDB insertion failures | Use `embedded_relation()` with relation prefixes |
| **Missing Dependencies** | Constraint violations | Enable external enrichment or fix input data |
| **Circular References** | Infinite loops in processing | Use dependency sorting to break cycles |
| **Custom Field Detection** | Missing references | Verify STIX ID pattern matching is working |

### Debug Output

```python
# Enable debug mode for detailed reporting
cleaned, report = clean_stix_list(objects, debug=True)

# Check detailed operation reports
for operation_report in report.detailed_operation_reports:
    print(f"Operation: {operation_report.operation_name}")
    print(f"Success: {operation_report.success}")
    if hasattr(operation_report, 'missing_ids_list'):
        print(f"Missing IDs: {operation_report.missing_ids_list}")
```

## 💡 Performance Tips

### Optimization Strategies

| Strategy | Implementation | Performance Gain |
|----------|----------------|------------------|
| **Conditional Processing** | Use appropriate boolean flags | Skip unnecessary operations |
| **Pre-compiled Patterns** | Module-level regex compilation | Faster pattern matching |
| **Efficient Copying** | Strategic use of `deepcopy()` | Reduce memory overhead |
| **Batch Processing** | Process files in chunks | Better memory management |

### Memory Management

```python
# Process large datasets efficiently
def process_large_dataset(file_paths):
    for file_path in file_paths:
        objects = load_stix_file(file_path)
        cleaned, report = clean_stix_list(objects)
        yield cleaned, report  # Generator for memory efficiency
```

## 🛠️ Development Workflow

### 1. Setup Development Environment

```bash
# Clone repository
git clone https://github.com/your-org/stix-orm.git
cd stix-orm

# Install dependencies
pip install poetry
poetry install

# Run tests
poetry run pytest
```

### 2. Making Changes

1. Read relevant instruction files in `.github/instructions/`
2. Follow patterns in `CODING-STANDARDS.md`
3. Write tests according to `TESTING-STANDARDS.md`
4. Update documentation as needed

### 3. Validation Checklist

- [ ] All tests pass: `pytest`
- [ ] Code follows standards: Check `CODING-STANDARDS.md`
- [ ] TypeQL variables use relation-aware prefixes
- [ ] Functions preserve original input on failure
- [ ] Documentation updated for API changes

## 📞 Support and Resources

### Getting Help

1. **Documentation**: Start with `PROJECT-OVERVIEW.md`
2. **Implementation Details**: See `docs/implementation-guide.md`
3. **Code Examples**: Check `examples/` directory
4. **Issue Reporting**: Use GitHub issues with detailed context

### Community Resources

- **GitHub Repository**: Source code and discussions
- **Documentation Site**: Comprehensive guides and API reference
- **Example Projects**: Real-world implementation samples

---

**This quick reference provides immediate access to essential STIX-ORM functionality. For detailed information, consult the comprehensive documentation files listed above.**