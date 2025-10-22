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

### Processing Pipeline (7 Sequential Operations)

Both functions must execute the same 7-step cleaning pipeline on every STIX object collection:

**Step 1: Object Deduplication** (Remove duplicate objects by STIX ID)
**Step 2-3: Object Expansion** (Two-round expansion for transitive dependencies)
**Step 4: SCO Field Cleaning** (Remove forbidden fields from STIX Cyber Observables)
**Step 5: Circular Reference Resolution** (Break dependency cycles)
**Step 6: Dependency Sorting** (Topological ordering)
**Step 7: Comprehensive Reporting** (Detailed operation tracking)

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

## 2. Seven Operations Specification (Apply to Every STIX List)

### Operation 1: Object Deduplication

**Objective**: Remove duplicate STIX objects that share the same ID to prevent database constraint violations.

**Algorithm**:

1. Create a dictionary keyed by STIX ID
2. Iterate through all objects and keep only the first occurrence of each ID
3. Return deduplicated object list maintaining original order where possible

**Rationale**: When processing multiple STIX files, common objects (like identity and marking-definition objects) often appear in multiple files, causing unique key constraint violations during database insertion.

**Output**: Deduplicated object list + DeduplicationReport

### Operation 2: Object Expansion (Round 1)

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

### Operation 3: Object Expansion (Round 2)

**Objective**: Handle transitive dependencies introduced by newly added objects.

**Algorithm**: Repeat Operation 2 logic on the expanded dataset from Operation 2.

**Rationale**: New objects may reference additional objects not yet in the collection.

**Output**: Fully expanded object list + Updated ExpansionReport

### Operation 4: SCO Field Cleaning (Conditional)

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

### Operation 5: Circular Reference Resolution

**Objective**: Detect and break circular reference chains to enable dependency sorting.

**Circular Reference Types**:

1. **Self-Reference**: Object references its own ID
2. **Bidirectional**: A→B and B→A patterns

**Resolution Strategy** (Priority Order):

1. **Self-Reference**: Delete the referencing field
2. **Identity ↔ Marking Definition**: Remove `object_marking_refs` from Identity if the marking definition object referenced has "created_by_ref" pointing back to the Identity
3. **Malware Behavior ↔ Malware Method**: Remove the `behavior_ref` field from the malware method if the malware behavior object it points to references back to the malware method in the `detect_ref` or `examplify_ref` fields

**Output**: Acyclic object list + CircularReferenceReport

### Operation 6: Dependency Sorting

**Objective**: Topologically sort objects so referenced objects appear before referencing objects.

**Algorithm**: Kahn's algorithm for topological sorting

**Process**:

1. Build dependency graph from object references
2. Perform topological sort
3. If cycles detected, report unresolved references
4. If sorting fails, retry expansion (fallback to Operation 1-2)

**Output**: Dependency-sorted object list + SortingReport

### Operation 7: Comprehensive Reporting

**Objective**: Aggregate all operation results into final success/failure report.

**Process**:

1. Collect reports from Operations 1-6
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
class DeduplicationReport(BaseModel):
    number_of_objects_before_deduplication: int
    number_of_objects_after_deduplication: int
    number_of_duplicates_removed: int
    list_of_duplicate_stix_ids: List[str]

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

class DeletedFieldAndValues(BaseModel):
    stix_id: str # of the object where the field is deleted
    field_name: str # field name deleted
    deleted_value: Union[str, List[str]] # Stix_id or list of Stix_id's referenced by the deleted field

class OperationTiming(BaseModel):
    operation_name: str
    start_time: str  # Format: "%Y-%m-%d %H:%M:%S.%f"
    end_time: str    # Format: "%Y-%m-%d %H:%M:%S.%f"
    duration_seconds: float

class CircularReferenceReport(BaseModel):
    number_of_circular_references_found: int
    list_of_circular_reference_paths: List[List[str]]  # Each inner list represents a circular path
    deleted_fields_and_values: List[DeletedFieldAndValues]  # [{"stix_id": str, "deleted_fields": List[DeletedFieldAndValue]}]

class SortingReport(BaseModel):
    sorting_successful: bool
    sorted_list_of_stix_ids: List[str]
    diagram_of_sorted_dependencies: str  # String representation of dependency graph
    unresolved_references: List[str]

class ListReport(BaseModel):
    deduplication_report: DeduplicationReport
    expansion_report: ExpansionReport
    cleaning_sco_report: CleaningSCOReport
    circular_reference_report: CircularReferenceReport
    sorting_report: SortingReport
    operation_timings: List[OperationTiming]  # Time measurements for each of the 7 operations
    total_processing_time_seconds: float  # Sum of all operation durations

class FileReport(BaseModel):
    directory_path: str
    original_file_name: str
    original_file_path: str
    updated_file_name: str
    updated_file_path: str
    report_file_name: str
    report_file_path: str
    operations_report: ListReport
    total_processing_time_seconds: float


class CleanStixListSuccessReport(BaseModel):
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[True]
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]

class CleanStixListFailureReport(BaseModel):
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[False]
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]
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
- **Operation Timing Requirements**:
  - Measure precise timing for each of the 7 operations per STIX list processed
  - Use OperationTiming class with microsecond precision timestamps
  - Calculate total_processing_time_seconds as sum of individual operation durations
  - For directory processing, FileReport timing covers file I/O + ListReport timing for list operations

## 7. Documentation Requirements

Create comprehensive `clean_list_or_bundle.md` documentation including:

- **Function Reference**: Complete signatures and parameters
- **Workflow Diagrams**: Visual representation of 7-operation pipeline
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
