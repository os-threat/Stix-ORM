#!/usr/bin/env python3
"""
STIX Object Analysis Script

This script analyzes STIX JSON files to:
1. Process both bundle and list formats
2. Extract defined objects and referenced STIX IDs
3. Generate reports showing defined vs referenced objects
4. Create a summary table of all analyzed files
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any
import argparse

class StixAnalyzer:
    """Analyzes STIX JSON files for object definitions and references."""
    
    def __init__(self):
        self.defined_objects = set()
        self.referenced_ids = set()
        self.file_reports = []
        self.external_objects = {}  # Cache for external object definitions
        
        # External data source paths
        self.data_sources = [
            "test/data/mitre/latest/enterprise-attack-17.1.json",
            "test/data/mitre/latest/mobile-attack-17.1.json",
            "test/data/mbc/framework/mbc.json"
        ]
        
        # STIX 2.1 SCO (Stix Cyberobservable Object) types that should NOT have created/modified fields
        self.SCO_TYPES = {
            'artifact', 'autonomous-system', 'directory', 'domain-name', 'email-addr', 
            'email-message', 'file', 'ipv4-addr', 'ipv6-addr', 'mac-addr', 'mutex', 
            'network-traffic', 'process', 'software', 'url', 'user-account', 
            'windows-registry-key', 'x509-certificate'
        }
    
    def extract_stix_ids_from_value(self, value: Any) -> Set[str]:
        """Recursively extract STIX IDs from any JSON value."""
        stix_ids = set()
        
        if isinstance(value, str):
            # Check if string looks like a STIX ID
            if self.is_stix_id(value):
                stix_ids.add(value)
        elif isinstance(value, list):
            for item in value:
                stix_ids.update(self.extract_stix_ids_from_value(item))
        elif isinstance(value, dict):
            for key, val in value.items():
                stix_ids.update(self.extract_stix_ids_from_value(val))
        
        return stix_ids
    
    def is_stix_id(self, text: str) -> bool:
        """Check if a string looks like a STIX ID."""
        # STIX IDs follow the pattern: type--uuid
        if not isinstance(text, str):
            return False
        
        parts = text.split('--')
        if len(parts) != 2:
            return False
        
        # Check if first part is a valid STIX type
        valid_types = {
            'attack-pattern', 'campaign', 'course-of-action', 'group', 'identity',
            'indicator', 'infrastructure', 'intrusion-set', 'location', 'malware',
            'malware-analysis', 'note', 'observed-data', 'opinion', 'report',
            'threat-actor', 'tool', 'vulnerability', 'x-mitre-collection',
            'x-mitre-data-component', 'x-mitre-data-source', 'x-mitre-matrix',
            'x-mitre-tactic', 'artifact', 'autonomous-system', 'directory',
            'domain-name', 'email-addr', 'email-message', 'file', 'ipv4-addr',
            'ipv6-addr', 'mac-addr', 'mutex', 'network-traffic', 'process',
            'software', 'url', 'user-account', 'windows-registry-key',
            'x509-certificate', 'marking-definition', 'language-content',
            'relationship', 'sighting', 'bundle', 'extension-definition',
            'attack-flow', 'attack-action', 'attack-asset'
        }
        
        return parts[0] in valid_types
    
    def process_objects_list(self, objects: List[Dict]) -> Tuple[Set[str], Set[str]]:
        """Process a list of STIX objects to extract defined objects and references."""
        defined_objects = set()
        referenced_ids = set()
        
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            
            # Extract the ID of the defined object
            if 'id' in obj:
                defined_objects.add(obj['id'])
            
            # Extract all STIX IDs referenced in this object
            obj_references = self.extract_stix_ids_from_value(obj)
            referenced_ids.update(obj_references)
        
        return defined_objects, referenced_ids
    
    def load_external_data_sources(self):
        """Load objects from external data sources."""
        print("Loading external data sources...")
        
        for source_path in self.data_sources:
            source_file = Path(source_path)
            if not source_file.exists():
                print(f"  Warning: {source_path} not found, skipping")
                continue
            
            try:
                with open(source_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Extract objects from the data source
                objects_to_process = []
                if isinstance(data, dict) and data.get('type') == 'bundle' and 'objects' in data:
                    objects_to_process = data['objects']
                elif isinstance(data, list):
                    objects_to_process = data
                elif isinstance(data, dict) and 'id' in data:
                    objects_to_process = [data]
                
                # Index objects by ID
                for obj in objects_to_process:
                    if isinstance(obj, dict) and 'id' in obj:
                        self.external_objects[obj['id']] = obj
                
                print(f"  Loaded {len(objects_to_process)} objects from {source_file.name}")
                
            except Exception as e:
                print(f"  Error loading {source_path}: {e}")
        
        print(f"  Total external objects cached: {len(self.external_objects)}")
    
    def find_missing_object(self, missing_id: str) -> Dict[str, Any]:
        """Find a missing object in external data sources."""
        return self.external_objects.get(missing_id)
    
    def add_missing_objects_to_file(self, file_path: Path, missing_ids: List[str]) -> int:
        """Add missing objects to a file from external data sources."""
        if not missing_ids:
            return 0
        
        print(f"  Adding missing objects to {file_path.name}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"    Error loading file: {e}")
            return 0
        
        objects_to_add = []
        added_count = 0
        
        for missing_id in missing_ids:
            # Find the object in external data sources
            missing_object = self.find_missing_object(missing_id)
            if missing_object:
                objects_to_add.append(missing_object)
                added_count += 1
                print(f"    + Found and adding {missing_object.get('type', 'unknown')} object: {missing_id}")
            else:
                print(f"    - Could not find object: {missing_id}")
        
        if objects_to_add:
            # Add objects to the file
            if isinstance(data, dict) and data.get('type') == 'bundle':
                if 'objects' in data:
                    data['objects'].extend(objects_to_add)
                else:
                    data['objects'] = objects_to_add
            elif isinstance(data, list):
                data.extend(objects_to_add)
            else:
                # Single object - convert to bundle
                original_obj = data
                data = {
                    'type': 'bundle',
                    'id': f"bundle--{missing_id.split('--')[-1][:8]}-auto-generated",
                    'spec_version': '2.1',
                    'objects': [original_obj] + objects_to_add
                }
            
            # Write back to file
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"    ✓ Added {added_count} missing objects to {file_path.name}")
            except Exception as e:
                print(f"    Error writing file: {e}")
                return 0
        
        return added_count
    
    def reorder_objects_in_file(self, file_path: Path):
        """Reorder objects so they are defined before they are referenced."""
        print(f"  Reordering objects in {file_path.name}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"    Error loading file: {e}")
            return
        
        # Get the objects list
        objects = []
        if isinstance(data, dict) and data.get('type') == 'bundle' and 'objects' in data:
            objects = data['objects']
        elif isinstance(data, list):
            objects = data
        else:
            # Single object
            objects = [data]
        
        if len(objects) <= 1:
            return  # Nothing to reorder
        
        # Build dependency graph
        object_ids = {}
        dependencies = {}  # object_id -> set of objects it references
        
        for obj in objects:
            if isinstance(obj, dict) and 'id' in obj:
                obj_id = obj['id']
                object_ids[obj_id] = obj
                dependencies[obj_id] = set()
                
                # Find all STIX IDs this object references
                referenced_ids = self.extract_stix_ids_from_value(obj)
                for ref_id in referenced_ids:
                    if ref_id in object_ids:  # Only internal references
                        dependencies[obj_id].add(ref_id)
        
        # Topological sort to order objects
        ordered_objects = []
        visited = set()
        temp_visited = set()
        
        def visit(obj_id):
            if obj_id in temp_visited:
                return  # Circular dependency - ignore for now
            if obj_id in visited:
                return
            
            temp_visited.add(obj_id)
            
            # Visit dependencies first
            for dep_id in dependencies[obj_id]:
                if dep_id in object_ids:
                    visit(dep_id)
            
            temp_visited.remove(obj_id)
            visited.add(obj_id)
            ordered_objects.append(object_ids[obj_id])
        
        # Visit all objects
        for obj_id in object_ids:
            if obj_id not in visited:
                visit(obj_id)
        
        # Update the data structure
        if isinstance(data, dict) and data.get('type') == 'bundle':
            data['objects'] = ordered_objects
        elif isinstance(data, list):
            data[:] = ordered_objects
        else:
            # Single object - shouldn't happen after reordering
            pass
        
        # Write back to file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"    ✓ Reordered {len(ordered_objects)} objects in {file_path.name}")
        except Exception as e:
            print(f"    Error writing file: {e}")
    
    def add_all_missing_objects_iteratively(self, file_path: Path) -> int:
        """Iteratively add missing objects until no more can be found."""
        total_added = 0
        iteration = 0
        max_iterations = 5  # Prevent infinite loops
        
        while iteration < max_iterations:
            iteration += 1
            print(f"    Iteration {iteration}: Checking for missing objects...")
            
            # Analyze the current state of the file
            report = self.analyze_file(file_path)
            if report['error']:
                break
            
            if report['missing_count'] == 0:
                print(f"    ✓ No missing objects found in iteration {iteration}")
                break
            
            print(f"    Found {report['missing_count']} missing objects in iteration {iteration}")
            added_this_iteration = self.add_missing_objects_to_file(file_path, report['missing_ids'])
            total_added += added_this_iteration
            
            if added_this_iteration == 0:
                print(f"    No new objects could be added in iteration {iteration}")
                break
        
        return total_added
    
    def clean_sco_objects(self, objects: List[Dict]) -> int:
        """Remove 'created' and 'modified' fields from SCO objects."""
        sco_objects_cleaned = 0
        
        for obj in objects:
            if isinstance(obj, dict) and obj.get('type') in self.SCO_TYPES:
                cleaned = False
                if 'created' in obj:
                    del obj['created']
                    cleaned = True
                if 'modified' in obj:
                    del obj['modified']
                    cleaned = True
                if cleaned:
                    sco_objects_cleaned += 1
        
        return sco_objects_cleaned
    
    def group_objects_by_type(self, objects: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Group objects into SDOs and SCOs."""
        sdos = []  # Stix Domain Objects
        scos = []  # Stix Cyberobservable Objects
        
        for obj in objects:
            if isinstance(obj, dict) and 'type' in obj:
                obj_type = obj['type']
                if obj_type in self.SCO_TYPES:
                    scos.append(obj)
                else:
                    sdos.append(obj)
            else:
                # If no type, assume it's an SDO
                sdos.append(obj)
        
        return sdos, scos
    
    def reorder_objects_with_grouping(self, file_path: Path) -> Tuple[int, int]:
        """Reorder objects with SDO/SCO grouping and clean SCO fields."""
        print(f"  Reordering and grouping objects in {file_path.name}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"    Error loading file: {e}")
            return 0, 0
        
        # Get the objects list
        objects = []
        if isinstance(data, dict) and data.get('type') == 'bundle' and 'objects' in data:
            objects = data['objects']
        elif isinstance(data, list):
            objects = data
        else:
            # Single object
            objects = [data]
        
        if len(objects) <= 1:
            return 0, 0  # Nothing to reorder
        
        # Group objects into SDOs and SCOs
        sdos, scos = self.group_objects_by_type(objects)
        
        # Clean SCO objects (remove created/modified fields)
        sco_objects_cleaned = self.clean_sco_objects(scos)
        
        # Build dependency graph for SDOs only
        sdo_ids = {}
        dependencies = {}  # object_id -> set of objects it references
        
        for obj in sdos:
            if isinstance(obj, dict) and 'id' in obj:
                obj_id = obj['id']
                sdo_ids[obj_id] = obj
                dependencies[obj_id] = set()
                
                # Find all STIX IDs this object references
                referenced_ids = self.extract_stix_ids_from_value(obj)
                for ref_id in referenced_ids:
                    if ref_id in sdo_ids:  # Only internal SDO references
                        dependencies[obj_id].add(ref_id)
        
        # Topological sort to order SDOs
        ordered_sdos = []
        visited = set()
        temp_visited = set()
        
        def visit(obj_id):
            if obj_id in temp_visited:
                return  # Circular dependency - ignore for now
            if obj_id in visited:
                return
            
            temp_visited.add(obj_id)
            
            # Visit dependencies first
            for dep_id in dependencies[obj_id]:
                if dep_id in sdo_ids:
                    visit(dep_id)
            
            temp_visited.remove(obj_id)
            visited.add(obj_id)
            ordered_sdos.append(sdo_ids[obj_id])
        
        # Visit all SDOs
        for obj_id in sdo_ids:
            if obj_id not in visited:
                visit(obj_id)
        
        # Combine ordered SDOs first, then SCOs
        ordered_objects = ordered_sdos + scos
        
        # Update the data structure
        if isinstance(data, dict) and data.get('type') == 'bundle':
            data['objects'] = ordered_objects
        elif isinstance(data, list):
            data[:] = ordered_objects
        else:
            # Single object - shouldn't happen after reordering
            pass
        
        # Write back to file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"    ✓ Reordered {len(ordered_objects)} objects ({len(ordered_sdos)} SDOs, {len(scos)} SCOs) in {file_path.name}")
            if sco_objects_cleaned > 0:
                print(f"    ✓ Cleaned {sco_objects_cleaned} SCO objects (removed created/modified fields)")
        except Exception as e:
            print(f"    Error writing file: {e}")
            return 0, 0
        
        return len(ordered_sdos), sco_objects_cleaned
    
    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a single STIX JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            return {
                'file': file_path.name,
                'error': f"Failed to load file: {e}",
                'defined_count': 0,
                'referenced_count': 0,
                'missing_count': 0,
                'missing_ids': []
            }
        
        defined_objects = set()
        referenced_ids = set()
        
        if isinstance(data, dict):
            # Handle bundle format
            if data.get('type') == 'bundle' and 'objects' in data:
                defined_objects, referenced_ids = self.process_objects_list(data['objects'])
            else:
                # Single object
                if 'id' in data:
                    defined_objects.add(data['id'])
                referenced_ids = self.extract_stix_ids_from_value(data)
        
        elif isinstance(data, list):
            # Handle list format
            defined_objects, referenced_ids = self.process_objects_list(data)
        
        else:
            return {
                'file': file_path.name,
                'error': "Unsupported JSON format",
                'defined_count': 0,
                'referenced_count': 0,
                'missing_count': 0,
                'missing_ids': []
            }
        
        # Find missing references
        missing_ids = referenced_ids - defined_objects
        
        return {
            'file': file_path.name,
            'error': None,
            'defined_count': len(defined_objects),
            'referenced_count': len(referenced_ids),
            'missing_count': len(missing_ids),
            'missing_ids': sorted(list(missing_ids)),
            'defined_objects': defined_objects,
            'referenced_ids': referenced_ids,
            'sco_objects_cleaned': 0  # Will be updated during processing
        }
    
    def analyze_directory(self, directory_path: Path, recursive: bool = False, auto_fix: bool = False) -> List[Dict[str, Any]]:
        """Analyze all JSON files in a directory."""
        reports = []
        
        if not directory_path.exists():
            print(f"Error: Directory {directory_path} does not exist")
            return reports
        
        # Find JSON files
        if recursive:
            json_files = list(directory_path.rglob("*.json"))
        else:
            json_files = list(directory_path.glob("*.json"))
        
        if not json_files:
            print(f"No JSON files found in {directory_path}")
            return reports
        
        print(f"Analyzing {len(json_files)} JSON files...")
        
        # Load external data sources if auto-fix is enabled
        if auto_fix:
            self.load_external_data_sources()
        
        for json_file in sorted(json_files):
            print(f"Processing: {json_file.name}")
            report = self.analyze_file(json_file)
            reports.append(report)
            
            # Auto-fix missing objects if enabled
            if auto_fix and not report['error']:
                # Iteratively add all missing objects
                total_added = self.add_all_missing_objects_iteratively(json_file)
                if total_added > 0:
                    print(f"  Total objects added: {total_added}")
                
                # Reorder objects with SDO/SCO grouping and clean SCO fields
                sdo_count, sco_objects_cleaned = self.reorder_objects_with_grouping(json_file)
                
                # Re-analyze the file to get updated counts
                updated_report = self.analyze_file(json_file)
                # Update the report with new data including SCO cleaning count
                updated_report['sco_objects_cleaned'] = sco_objects_cleaned
                reports[-1] = updated_report
        
        return reports
    
    def print_individual_reports(self, reports: List[Dict[str, Any]]):
        """Print detailed reports for each file."""
        print("\n" + "="*80)
        print("DETAILED FILE REPORTS")
        print("="*80)
        
        for report in reports:
            print(f"\nFile: {report['file']}")
            print("-" * 50)
            
            if report['error']:
                print(f"ERROR: {report['error']}")
                continue
            
            print(f"Objects defined: {report['defined_count']}")
            print(f"STIX IDs referenced: {report['referenced_count']}")
            print(f"Missing references: {report['missing_count']}")
            
            if report['missing_ids']:
                print(f"\nMissing STIX IDs:")
                for missing_id in report['missing_ids']:
                    print(f"  - {missing_id}")
            else:
                print("\n✓ All referenced objects are defined in this file")
    
    def print_summary_table(self, reports: List[Dict[str, Any]]):
        """Print a summary table of all reports."""
        print("\n" + "="*140)
        print("SUMMARY TABLE")
        print("="*140)
        
        # Table header
        print(f"{'File Name':<50} {'Defined':<8} {'Referenced':<11} {'Missing':<8} {'SCOs Cleaned':<15} {'Status':<15}")
        print("-" * 140)
        
        # Table rows
        total_defined = 0
        total_referenced = 0
        total_missing = 0
        total_sco_cleaned = 0
        files_with_errors = 0
        
        for report in reports:
            file_name = report['file'][:47] + "..." if len(report['file']) > 50 else report['file']
            
            if report['error']:
                status = "ERROR"
                files_with_errors += 1
                print(f"{file_name:<50} {'N/A':<8} {'N/A':<11} {'N/A':<8} {'N/A':<15} {status:<15}")
            else:
                defined = report['defined_count']
                referenced = report['referenced_count']
                missing = report['missing_count']
                sco_cleaned = report.get('sco_objects_cleaned', 0)
                
                total_defined += defined
                total_referenced += referenced
                total_missing += missing
                total_sco_cleaned += sco_cleaned
                
                if missing == 0:
                    status = "COMPLETE"
                else:
                    status = f"INCOMPLETE ({missing})"
                
                print(f"{file_name:<50} {defined:<8} {referenced:<11} {missing:<8} {sco_cleaned:<15} {status:<15}")
        
        # Summary totals
        print("-" * 140)
        print(f"{'TOTALS':<50} {total_defined:<8} {total_referenced:<11} {total_missing:<8} {total_sco_cleaned:<15}")
        
        if files_with_errors > 0:
            print(f"\nFiles with errors: {files_with_errors}")
        
        successful_files = len([r for r in reports if not r['error']])
        complete_files = len([r for r in reports if not r['error'] and r['missing_count'] == 0])
        
        print(f"Files analyzed: {len(reports)}")
        print(f"Files processed successfully: {successful_files}")
        print(f"Files with complete object definitions: {complete_files}")
        print(f"Files with missing object definitions: {successful_files - complete_files}")
        print(f"Total SCO objects cleaned (created/modified fields removed): {total_sco_cleaned}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Analyze STIX JSON files for object definitions and references')
    parser.add_argument('path', help='Path to JSON file or directory containing JSON files')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='Recursively search subdirectories (when path is a directory)')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed reports for each file')
    parser.add_argument('--auto-fix', action='store_true',
                       help='Automatically add missing objects from external data sources')
    
    args = parser.parse_args()
    
    analyzer = StixAnalyzer()
    path = Path(args.path)
    
    if path.is_file():
        # Analyze single file
        print(f"Analyzing single file: {path.name}")
        reports = [analyzer.analyze_file(path)]
    elif path.is_dir():
        # Analyze directory
        print(f"Analyzing directory: {path}")
        reports = analyzer.analyze_directory(path, args.recursive, args.auto_fix)
    else:
        print(f"Error: Path {path} does not exist")
        sys.exit(1)
    
    if not reports:
        print("No reports generated")
        sys.exit(1)
    
    # Print reports
    if args.detailed:
        analyzer.print_individual_reports(reports)
    
    analyzer.print_summary_table(reports)

if __name__ == "__main__":
    main()
