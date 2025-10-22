# STIX Bundle and List Cleaning Module Documentation

## Overview

The `clean_list_or_bundle.py` module provides comprehensive cleaning operations for STIX object collections through a 7-operation pipeline. It supports both in-memory processing and file-based directory processing with detailed timing and reporting capabilities.

## Key Features

- **7-Operation Pipeline**: Object deduplication, expansion (2 rounds), SCO cleaning, circular reference resolution, dependency sorting, and comprehensive reporting
- **External Source Integration**: Automatically fetches missing objects from 5 MITRE/MBC data sources
- **Timing Measurement**: Precise operation timing with microsecond accuracy
- **Streamlined Reporting**: Nested report structure (ListReport → FileReport → Success/Failure Reports)
- **File Organization**: Automatic directory structure management for batch processing
- **Circular Reference Resolution**: Handles Identity↔Marking Definition and Malware Behavior↔Malware Method patterns

## Function Reference

### clean_stix_list()

```python
def clean_stix_list(
    stix_list: List[StixObject], 
    clean_sco_fields: bool = False
) -> Tuple[List[StixObject], Union[CleanStixListSuccessReport, CleanStixListFailureReport]]
```

**Purpose**: Process STIX objects in memory through the complete 7-operation cleaning pipeline.

**Parameters**:
- `stix_list`: List of STIX objects to process
- `clean_sco_fields`: Whether to remove forbidden fields from STIX Cyber Observable objects (default: False)

**Returns**:
- `Tuple[List[StixObject], Report]`: Cleaned objects and detailed processing report

**Usage Example**:
```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list
from stixorm.module.parsing.clean_list_or_bundle import StixObject

# Load your STIX objects
stix_objects = [StixObject(**obj_data) for obj_data in raw_data]

# Clean the objects
cleaned_objects, report = clean_stix_list(stix_objects, clean_sco_fields=True)

# Check results
if report.clean_operation_outcome:
    print(f"Success! Processed {report.total_number_of_objects_processed} objects")
    print(f"Total time: {report.detailed_operation_reports.total_processing_time_seconds}s")
else:
    print(f"Failed: {report.return_message}")
```

### clean_stix_directory()

```python
def clean_stix_directory(
    directory_path: str, 
    clean_sco_fields: bool = False
) -> List[Union[CleanStixListSuccessReport, CleanStixListFailureReport]]
```

**Purpose**: Process all JSON files in a directory through the cleaning pipeline with automatic file organization.

**Parameters**:
- `directory_path`: Path to directory containing STIX JSON files
- `clean_sco_fields`: Whether to remove forbidden fields from SCO objects (default: False)

**Returns**:
- `List[Report]`: List of processing reports (one per input file)

**File Organization**:
```
target_directory/
├── original/           # Moved source files
├── reports/           # Processing reports
├── cleaned_file1.json # Cleaned STIX bundles
└── cleaned_file2.json
```

**Usage Example**:
```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_directory

# Process all JSON files in directory
reports = clean_stix_directory("/path/to/stix/files", clean_sco_fields=True)

# Review results
for report in reports:
    if report.clean_operation_outcome:
        file_info = report.detailed_operation_reports
        print(f"✓ {file_info.original_file_name} → {file_info.updated_file_name}")
        print(f"  Time: {file_info.total_processing_time_seconds}s")
    else:
        print(f"✗ Failed: {report.return_message}")
```

## Processing Pipeline

### Operation 1: Object Deduplication

**Objective**: Remove duplicate STIX objects that share the same ID to prevent database constraint violations.

**Process**:
1. Create dictionary keyed by STIX ID
2. Keep only first occurrence of each ID
3. Maintain original order where possible
4. Track duplicate IDs for reporting

**Rationale**: Multiple STIX files often contain identical common objects (identity, marking-definition), causing unique key constraint violations during database operations.

### Operation 2-3: Object Expansion (Two Rounds)

**Objective**: Fetch missing referenced objects from external MITRE/MBC sources.

**External Sources** (checked in order):
1. MITRE ATT&CK Enterprise
2. MITRE ATT&CK Mobile  
3. MITRE ATT&CK ICS
4. MITRE Atlas
5. Malware MBC

**Process**:
1. Extract all STIX ID references from existing objects
2. Identify missing object definitions
3. Query external sources for missing objects
4. Perform second round to handle transitive dependencies
5. Prune unreferenced objects added during expansion

### Operation 4: SCO Field Cleaning

**Objective**: Remove forbidden fields from STIX Cyber Observable objects.

**Execution**: Only when `clean_sco_fields=True`

**Fields Removed**:
- `created` (forbidden in STIX spec for SCOs)
- `modified` (forbidden in STIX spec for SCOs)

**SCO Detection**: Uses `get_group_from_type()` to identify SCO objects.

### Operation 5: Circular Reference Resolution

**Objective**: Break circular dependency chains to enable topological sorting.

**Resolution Strategies** (priority order):

1. **Self-Reference**: Remove fields that reference the object's own ID
2. **Identity ↔ Marking Definition**: Remove `object_marking_refs` from Identity objects
3. **Malware Behavior ↔ Malware Method**: Remove `behavior_ref` from malware method objects
4. **Generic Bidirectional**: Remove `created_by_ref` from second object in cycle

### Operation 6: Dependency Sorting

**Objective**: Topologically sort objects so dependencies appear before dependents using dynamic reference detection.

**Algorithm**: Kahn's algorithm for directed acyclic graphs with intelligent reference extraction

**Reference Detection Strategy**:
1. **Dynamic Field Detection**: Automatically identifies all fields ending with `_ref` or `_refs`
2. **Pattern-Based Scanning**: Searches all string values for valid STIX ID patterns (`type--uuid`)
3. **Recursive Traversal**: Processes nested objects and arrays at any depth
4. **Future-Proof Design**: Works with any STIX extensions, custom objects, or new reference types

**Process**:
1. Dynamically extract all STIX ID references from objects using dual detection methods
2. Build dependency graph with detected references  
3. Perform topological sort using Kahn's algorithm
4. Handle any remaining cycles as unresolved references

**Key Advantages**:
- **No Static Lists**: Eliminates fragile hardcoded reference field lists
- **Extension Compatible**: Automatically handles os_threat, MBC, and custom STIX extensions  
- **Comprehensive Coverage**: Finds references regardless of field naming conventions
- **Maintainability**: Self-adapting to new STIX specifications and extensions

### Operation 7: Comprehensive Reporting

**Objective**: Aggregate timing and results from all operations.

**Generates**:

- Individual operation timing measurements
- Total processing time calculations
- Success/failure determination
- Detailed operation reports

## Report Structure

### ListReport (Core Operations)

Contains the core processing results for a single STIX list:

```python
class ListReport(BaseModel):
    deduplication_report: DeduplicationReport
    expansion_report: ExpansionReport
    cleaning_sco_report: CleaningSCOReport
    circular_reference_report: CircularReferenceReport
    sorting_report: SortingReport
    operation_timings: List[OperationTiming]
    total_processing_time_seconds: float
```

### FileReport (Directory Processing)

Extends ListReport with file-specific information:

```python
class FileReport(BaseModel):
    directory_path: str
    original_file_name: str
    original_file_path: str
    updated_file_name: str
    updated_file_path: str
    report_file_name: str
    report_file_path: str
    operations_report: ListReport  # Nested ListReport
    total_processing_time_seconds: float  # Includes file I/O time
```

### Success/Failure Reports

Top-level reports that can contain either ListReport or FileReport:

```python
class CleanStixListSuccessReport(BaseModel):
    report_date_time: str
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[True]
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]
```

## Timing Measurements

### Operation Timing

Each operation is precisely timed with microsecond accuracy:

```python
class OperationTiming(BaseModel):
    operation_name: str
    start_time: str  # Format: "%Y-%m-%d %H:%M:%S.%f"
    end_time: str    # Format: "%Y-%m-%d %H:%M:%S.%f"
    duration_seconds: float
```

### Timing Levels

- **Per-List**: Individual operation timings within ListReport
- **Per-File**: File I/O + embedded ListReport timings within FileReport
- **Total Processing**: Sum of all operation durations

## Error Handling

### Network Resilience

- **30-second timeout** per external source request
- **Continue on failure**: Process available data even if sources are unreachable
- **Partial expansion**: Document missing objects in ExpansionReport

### Data Integrity

- **Deep copy protection**: Never modify original input data
- **Validation**: STIX object structure validation at each operation
- **Rollback capability**: Maintain traceability for all modifications

### File Operations

- **Atomic operations**: Move originals only after successful processing
- **Directory permissions**: Graceful handling of read/write errors
- **Disk space validation**: Verify sufficient space before operations

## Integration Examples

### Basic Integration

```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list, StixObject

def process_stix_data(raw_objects: List[Dict]) -> List[Dict]:
    """Simple integration example"""
    # Convert to StixObject instances
    stix_objects = [StixObject(**obj) for obj in raw_objects]
    
    # Clean the objects
    cleaned, report = clean_stix_list(stix_objects, clean_sco_fields=True)
    
    if report.clean_operation_outcome:
        return [obj.model_dump() for obj in cleaned]
    else:
        raise RuntimeError(f"Cleaning failed: {report.return_message}")
```

### Advanced Integration with Timing Analysis

```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

def analyze_processing_performance(stix_objects: List[StixObject]) -> Dict:
    """Analyze processing performance"""
    cleaned, report = clean_stix_list(stix_objects, clean_sco_fields=True)
    
    if report.clean_operation_outcome:
        list_report = report.detailed_operation_reports
        
        # Analyze timing breakdown
        timing_analysis = {}
        for timing in list_report.operation_timings:
            timing_analysis[timing.operation_name] = {
                'duration': timing.duration_seconds,
                'percentage': (timing.duration_seconds / list_report.total_processing_time_seconds) * 100
            }
        
        return {
            'success': True,
            'total_time': list_report.total_processing_time_seconds,
            'object_count': report.total_number_of_objects_processed,
            'timing_breakdown': timing_analysis,
            'expansion_added': len(list_report.expansion_report.sources_of_expansion)
        }
    else:
        return {'success': False, 'error': report.return_message}
```

### Batch Processing Integration

```python
from pathlib import Path
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_directory

def batch_process_stix_feeds(base_directory: str) -> Dict:
    """Process multiple STIX feed directories"""
    results = {}
    base_path = Path(base_directory)
    
    for feed_dir in base_path.iterdir():
        if feed_dir.is_dir():
            print(f"Processing {feed_dir.name}...")
            
            reports = clean_stix_directory(str(feed_dir), clean_sco_fields=True)
            
            # Aggregate results
            total_files = len(reports)
            successful = sum(1 for r in reports if r.clean_operation_outcome)
            total_objects = sum(r.total_number_of_objects_processed for r in reports)
            total_time = sum(
                r.detailed_operation_reports.total_processing_time_seconds 
                for r in reports if r.clean_operation_outcome
            )
            
            results[feed_dir.name] = {
                'files_processed': total_files,
                'successful_files': successful,
                'total_objects': total_objects,
                'total_time_seconds': total_time,
                'success_rate': (successful / total_files) * 100 if total_files > 0 else 0
            }
    
    return results
```

## Performance Notes

### Memory Management

- **Large datasets**: Efficient processing of 1000+ object collections
- **Deep copy operations**: Memory-safe but consider memory usage for very large datasets
- **Streaming potential**: Consider implementing streaming for extremely large files

### Network Optimization

- **Caching**: External source data is cached during processing session
- **Batch requests**: Minimize round-trips where possible
- **Timeout handling**: 30-second timeouts prevent hanging operations

### Processing Efficiency

- **Topological sorting**: O(V + E) complexity for dependency resolution
- **Reference extraction**: Optimized for common STIX reference patterns
- **Pruning algorithm**: Efficient removal of unreferenced expansion objects

## Common Usage Patterns

### Development and Testing

```python
# Quick validation of STIX data
cleaned, report = clean_stix_list(test_objects)
assert report.clean_operation_outcome
assert len(cleaned) >= len(test_objects)  # May expand with external refs
```

### Production Pipeline

```python
# Robust production processing
try:
    reports = clean_stix_directory(input_dir, clean_sco_fields=True)
    
    # Log processing results
    for report in reports:
        if report.clean_operation_outcome:
            logger.info(f"Processed {report.total_number_of_objects_processed} objects "
                       f"in {report.detailed_operation_reports.total_processing_time_seconds:.2f}s")
        else:
            logger.error(f"Processing failed: {report.return_message}")
            
except Exception as e:
    logger.error(f"Directory processing failed: {e}")
```

### Analysis and Monitoring

```python
# Performance monitoring
def monitor_processing_performance(stix_data):
    _, report = clean_stix_list(stix_data)
    
    if report.clean_operation_outcome:
        list_report = report.detailed_operation_reports
        
        # Check for performance issues
        if list_report.total_processing_time_seconds > 30:
            logger.warning("Slow processing detected")
            
        # Check expansion effectiveness
        expansion = list_report.expansion_report
        if len(expansion.missing_ids_list) > 0:
            logger.info(f"Unable to resolve {len(expansion.missing_ids_list)} references")
```

## Troubleshooting

### Common Issues

1. **Network timeouts**: External sources may be temporarily unavailable
   - **Solution**: Processing continues with available data
   - **Check**: `expansion_report.missing_ids_list` for unresolved references

2. **Large memory usage**: Very large STIX collections
   - **Solution**: Consider processing in smaller batches
   - **Monitor**: System memory usage during processing

3. **Circular reference complexity**: Complex dependency cycles
   - **Check**: `circular_reference_report.list_of_circular_reference_paths`
   - **Solution**: Review STIX data structure for unnecessary cycles

4. **File permission errors**: Directory processing issues
   - **Solution**: Ensure write permissions for target directory
   - **Check**: Directory exists and is writable before processing

### Debugging Tips

- Enable detailed logging to track operation progress
- Check timing reports to identify performance bottlenecks
- Review expansion reports to understand external dependency resolution
- Use circular reference reports to identify data quality issues

## Version Compatibility

- **Python**: 3.8+
- **Pydantic**: V2 (uses ConfigDict and model_dump())
- **STIX**: 2.1 specification compliance
- **External Sources**: Current MITRE/MBC endpoints as of implementation date

This documentation provides comprehensive guidance for using the STIX cleaning module effectively in various integration scenarios.