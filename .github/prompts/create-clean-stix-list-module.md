# STIX Bundle and List Cleaning Module - Refined Task Specification

**You are a maestro at building clever Python code, integrated with Pydantic data classes.**

## Mission Statement

Create a comprehensive STIX cleaning module with the following deliverables:

- **Python Module**: `clean_list_or_bundle.py`
- **Documentation**: `clean_list_or_bundle.md`
- **Target Location**: `stixorm/stixorm/module/parsing/` directory

## Core Architecture

### Primary Functions (2 Required)

1. **`clean_stix_list()`** - Process STIX objects directly from memory
2. **`clean_stix_directory()`** - Process STIX files from filesystem with organization

### Processing Pipeline (6 Sequential Operations)

Both functions must execute the same 6-step cleaning pipeline on every STIX object collection:

**Step 1-2: Object Expansion** (Two-round expansion for transitive dependencies)
**Step 3: SCO Field Cleaning** (Remove forbidden fields from STIX Cyber Observables)
**Step 4: Circular Reference Resolution** (Break dependency cycles)
**Step 5: Dependency Sorting** (Topological ordering)
**Step 6: Comprehensive Reporting** (Detailed operation tracking)

### File Organization Strategy (Directory Processing)

```text
target_directory/
├── original/           # Archive source files here (CREATE IF MISSING)
├── reports/           # Save operation reports here (CREATE IF MISSING)
├── cleaned_file1.json # Save updated bundles here (ROOT DIRECTORY)
└── cleaned_file2.json
```

## 1. Required Function Signatures

```python
def clean_stix_list(stix_list: List[StixObject], clean_sco_fields: bool = False) -> Tuple[List[StixObject], Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Clean STIX objects in memory through 6-operation pipeline.
    
    Args:
        stix_list (List[StixObject]): Raw STIX objects requiring cleaning
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
    
    Returns:
        Tuple containing:
        - List[StixObject]: Processed and sorted STIX objects
        - Report: Success/failure report with detailed operation metrics
    """

def clean_stix_directory(directory_path: str, clean_sco_fields: bool = False) -> List[Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Process all JSON files in directory through cleaning pipeline with file organization.
    
    Args:
        directory_path (str): Target directory containing STIX JSON files
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
    
    Returns:
        List[Report]: Collection of processing reports (one per input file)
    
    File Organization:
        - Originals moved to: {directory_path}/original/
        - Reports saved to: {directory_path}/reports/
        - Cleaned bundles saved to: {directory_path}/ (root)
    """
```

## 2. Six Operations Specification (Apply to Every STIX List)

### Operation 1: Object Expansion (Round 1)

**Objective**: Expand STIX objects by fetching missing referenced objects from external sources.

**Algorithm**:

1. Extract all unique STIX IDs referenced by existing objects
2. Compare referenced IDs to defined object IDs
3. Identify missing object definitions
4. Sequentially check external sources for missing objects
5. Add found objects to the collection

**External Sources** (check in this order):

1. MITRE ATT&CK Enterprise: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json`
2. MITRE ATT&CK Mobile: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json`
3. MITRE ATT&CK ICS: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json`
4. MITRE Atlas: `https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/refs/heads/main/dist/stix-atlas.json`
5. Malware MBC: `https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/refs/heads/main/mbc/mbc.json`

**Output**: Expanded object list + ExpansionReport

### Operation 2: Object Expansion (Round 2)

**Objective**: Handle transitive dependencies introduced by newly added objects.

**Algorithm**: Repeat Operation 1 logic on the expanded dataset from Operation 1.

**Rationale**: New objects may reference additional objects not yet in the collection.

**Output**: Fully expanded object list + Updated ExpansionReport

### Operation 3: SCO Field Cleaning (Conditional)

**Objective**: Remove forbidden fields from STIX Cyber Observable (SCO) objects.

**Execution Control**: Only runs when `clean_sco_fields=True` parameter is set (default: False)

**SCO Detection Method**:

```python
from stixorm.module.parsing.content.parse import get_group_from_type
is_sco = get_group_from_type(stix_type) == "sco"
```

**Fields to Remove from SCOs**:

- `created` (forbidden in STIX spec for SCOs)
- `modified` (forbidden in STIX spec for SCOs)
- Any other non-specification fields

**Output**: 
- When `clean_sco_fields=True`: Cleaned object list + CleaningSCOReport
- When `clean_sco_fields=False`: Unchanged object list + Empty CleaningSCOReport

### Operation 4: Circular Reference Resolution

**Objective**: Detect and break circular reference chains to enable dependency sorting.

**Circular Reference Types**:

1. **Self-Reference**: Object references its own ID
2. **Bidirectional**: A→B and B→A patterns

**Resolution Strategy** (Priority Order):

1. **Self-Reference**: Delete the referencing field
2. **Identity ↔ Marking Definition**: Remove `object_marking_refs` from Identity if the marking definition object referenced has "created_by_ref" pointing back to the Identity

**Output**: Acyclic object list + CircularReferenceReport

### Operation 5: Dependency Sorting

**Objective**: Topologically sort objects so referenced objects appear before referencing objects.

**Algorithm**: Kahn's algorithm for topological sorting

**Process**:

1. Build dependency graph from object references
2. Perform topological sort
3. If cycles detected, report unresolved references
4. If sorting fails, retry expansion (fallback to Operation 1-2)

**Output**: Dependency-sorted object list + SortingReport

### Operation 6: Comprehensive Reporting

**Objective**: Aggregate all operation results into final success/failure report.

**Process**:

1. Collect reports from Operations 1-5
2. Determine overall success/failure status
3. Generate timestamp and summary statistics
4. Package into appropriate report type

**Output**: CleanStixListSuccessReport or CleanStixListFailureReport

## 3. Pydantic Model Specifications

### 3.1 Core STIX Models

```python
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Union, Optional
from typing_extensions import Literal

class StixObject(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    type: str

class StixBundle(BaseModel):
    type: str = "bundle"
    id: str
    objects: List[StixObject]
```

### 3.2 Operation Report Models

```python
class ExpansionReport(BaseModel):
    number_of_objects_defined: int
    number_of_objects_referenced: int
    missing_ids_list: List[str]
    sources_of_expansion: List[Dict[str, List[str]]]  # [{"source_name": str, "found_list": List[str]}]

class CleaningSCOReport(BaseModel):
    number_of_scos_cleaned: int
    list_of_stix_ids_where_created_field_was_removed: List[str]
    list_of_stix_ids_where_modified_field_was_removed: List[str]
    list_of_stix_ids_where_other_fields_were_removed: List[Dict[str, List[str]]]  # [{"stix_id": str, "removed_fields": List[str]}]

class DeletedFieldAndValue(BaseModel):
    field_name: str
    deleted_value: Union[str, List[str], Dict]

class CircularReferenceReport(BaseModel):
    number_of_circular_references_found: int
    list_of_circular_reference_paths: List[List[str]]  # Each inner list represents a circular path
    deleted_fields_and_values: List[Dict[str, List[DeletedFieldAndValue]]]  # [{"stix_id": str, "deleted_fields": List[DeletedFieldAndValue]}]

class SortingReport(BaseModel):
    sorting_successful: bool
    sorted_list_of_stix_ids: List[str]
    diagram_of_sorted_dependencies: str  # String representation of dependency graph
    unresolved_references: List[str]

class SingleFileReport(BaseModel):
    original_file_name: str
    original_file_path: str
    updated_file_name: str
    updated_file_path: str
    report_file_name: str
    report_file_path: str

class FileReport(BaseModel):
    number_of_files_processed: int
    list_of_processed_changes_per_file: List[SingleFileReport]

class OperationsReport(BaseModel):
    expansion_report: ExpansionReport
    cleaning_sco_report: CleaningSCOReport
    circular_reference_report: CircularReferenceReport
    sorting_report: SortingReport
    file_report: Optional[FileReport] = None

class CleanStixListSuccessReport(BaseModel):
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[True]
    return_message: str
    detailed_operation_reports: OperationsReport

class CleanStixListFailureReport(BaseModel):
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[False]
    return_message: str
    detailed_operation_reports: OperationsReport
```

## 4. File Organization Rules (Directory Processing Only)

### 4.1 Input Processing

- Process all `.json` files in the target directory
- Support both STIX bundles and STIX lists
- Handle nested JSON structures appropriately

### 4.2 Output Organization

**Original Files**: Move to `{directory_path}/original/`
**Report Files**: Save to `{directory_path}/reports/` as `{filename}_report.json`
**Cleaned Files**: Save to `{directory_path}/` as STIX bundles

### 4.3 Bundle Template for Output

```json
{
  "type": "bundle",
  "id": "bundle--<uuid4>",
  "objects": [/* cleaned and sorted objects */]
}
```

### 4.4 Directory Creation Rules

- Create `original/` subdirectory if it doesn't exist
- Create `reports/` subdirectory if it doesn't exist
- Handle file naming conflicts with incremental suffixes

## 5. Error Handling Strategy

### 5.1 Network Resilience

- **External Source Failures**: Continue processing, log warnings in ExpansionReport
- **Timeout Handling**: 30-second timeout per external source request
- **Partial Expansion**: Process available data, document missing objects

### 5.2 Data Integrity Protection

- **Deep Copy**: Never modify original input data
- **Validation**: Validate STIX object structure at each operation
- **Rollback**: Maintain capability to trace all modifications

### 5.3 File Operation Safety

- **Atomic Operations**: Move originals only after successful processing
- **Directory Permissions**: Handle read/write permission errors gracefully
- **Disk Space**: Verify sufficient space before file operations

## 6. Implementation Requirements

### 6.1 Pydantic V2 Compliance

- Use `ConfigDict(extra='allow')` for flexible object handling
- Use `model_dump()` method for serialization
- Follow Pydantic V2 best practices throughout

### 6.2 External Dependencies

- HTTP client for external source fetching (requests library recommended)
- JSON handling for STIX object processing
- UUID generation for bundle IDs
- Path manipulation utilities

### 6.3 Performance Considerations

- **Memory Management**: Process large datasets efficiently
- **Caching**: Cache external source data during processing session
- **Batch Processing**: Minimize network round-trips where possible

## 7. Documentation Requirements

Create comprehensive `clean_list_or_bundle.md` documentation including:

- **Function Reference**: Complete signatures and parameters
- **Workflow Diagrams**: Visual representation of 6-operation pipeline
- **Usage Examples**: Code examples for both functions
- **Model Reference**: Complete Pydantic model documentation
- **Error Handling**: Common error patterns and solutions
- **Performance Notes**: Memory and network considerations
- **Integration Examples**: How to use with existing STIX workflows

## 8. Validation Requirements

The implementation must handle these test scenarios:

- **Empty Lists**: Graceful handling of empty STIX collections
- **Invalid Objects**: Proper error reporting for malformed STIX objects
- **Network Failures**: Resilient operation when external sources unavailable
- **Large Datasets**: Efficient processing of 1000+ object collections
- **Complex Dependencies**: Proper sorting of deeply nested object references
- **File System Edge Cases**: Permission errors, disk space, concurrent access

## Key Refinements from Original

1. **Clearer Operation Sequencing**: Numbered operations with explicit input/output flows
2. **Explicit Algorithms**: Specified Kahn's algorithm for sorting, detection strategies for circular references
3. **Comprehensive Error Handling**: Network resilience, data integrity protection, file operation safety
4. **Performance Guidelines**: Memory management, caching strategies, batch processing
5. **Structured Documentation**: Clear organization of requirements and specifications
6. **Validation Framework**: Specific test scenarios for robust implementation

All originally specified conditions are preserved while providing significantly clearer execution guidance and implementation structure.