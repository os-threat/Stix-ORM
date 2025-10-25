#!/usr/bin/env python3
"""
Analysis script to examine incident object dependencies in block_output.json
"""
import json
from pathlib import Path
from typing import Dict, List, Set

def analyze_incident_dependencies():
    """Analyze the incident object and its dependencies in block_output.json"""
    
    # Load the data
    project_root = Path(__file__).parent
    test_file = project_root / "test/data/os-threat/examples/block_output.json"
    
    with open(test_file, 'r') as f:
        objects = json.load(f)
    
    print("=== INCIDENT DEPENDENCY ANALYSIS ===\n")
    
    # Find the incident object
    incident = None
    incident_position = -1
    for i, obj in enumerate(objects):
        if obj.get('type') == 'incident':
            incident = obj
            incident_position = i
            break
    
    if not incident:
        print("❌ No incident object found!")
        return
    
    print(f"📍 Incident found at position {incident_position + 1} of {len(objects)} objects")
    print(f"🆔 Incident ID: {incident['id']}")
    print()
    
    # Extract all referenced IDs from incident
    referenced_ids = set()
    extensions = incident.get('extensions', {})
    
    for ext_key, ext_data in extensions.items():
        if isinstance(ext_data, dict):
            for field, value in ext_data.items():
                if field.endswith('_refs') or field.endswith('_ref'):
                    if isinstance(value, list):
                        referenced_ids.update(value)
                    elif isinstance(value, str):
                        referenced_ids.add(value)
    
    print(f"📋 Total referenced IDs: {len(referenced_ids)}")
    print()
    
    # Build a map of all objects in the file
    object_map = {}
    object_positions = {}
    
    for i, obj in enumerate(objects):
        obj_id = obj.get('id')
        if obj_id:
            object_map[obj_id] = obj
            object_positions[obj_id] = i + 1  # 1-based position
    
    print(f"📊 Total objects in file: {len(object_map)}")
    print()
    
    # Analysis 1: Are all referenced objects defined?
    print("=== QUESTION 1: Are all referenced objects defined in the list? ===")
    missing_objects = []
    defined_objects = []
    
    for ref_id in referenced_ids:
        if ref_id in object_map:
            defined_objects.append(ref_id)
        else:
            missing_objects.append(ref_id)
    
    if missing_objects:
        print(f"❌ {len(missing_objects)} missing objects:")
        for missing_id in missing_objects:
            print(f"   - {missing_id}")
    else:
        print(f"✅ All {len(referenced_ids)} referenced objects are defined in the list")
    
    print()
    
    # Analysis 2: Are all dependencies defined before the incident?
    print("=== QUESTION 2: Are all dependencies defined before the incident? ===")
    dependencies_after_incident = []
    dependencies_before_incident = []
    
    for ref_id in defined_objects:
        ref_position = object_positions[ref_id]
        if ref_position > incident_position:
            dependencies_after_incident.append((ref_id, ref_position))
        else:
            dependencies_before_incident.append((ref_id, ref_position))
    
    if dependencies_after_incident:
        print(f"❌ {len(dependencies_after_incident)} dependencies appear AFTER the incident:")
        for dep_id, pos in sorted(dependencies_after_incident, key=lambda x: x[1]):
            print(f"   - Position {pos}: {dep_id}")
    else:
        print(f"✅ All {len(dependencies_before_incident)} dependencies appear before the incident")
    
    print()
    
    # Analysis 3: Detailed dependency breakdown by type
    print("=== QUESTION 3: Dependency breakdown by reference type ===")
    
    reference_types = {}
    for ext_key, ext_data in extensions.items():
        if isinstance(ext_data, dict):
            for field, value in ext_data.items():
                if field.endswith('_refs') or field.endswith('_ref'):
                    if isinstance(value, list):
                        reference_types[field] = value
                    elif isinstance(value, str):
                        reference_types[field] = [value]
    
    for ref_type, ref_list in reference_types.items():
        print(f"\n📌 {ref_type} ({len(ref_list)} objects):")
        for ref_id in ref_list:
            if ref_id in object_map:
                pos = object_positions[ref_id]
                obj_type = object_map[ref_id].get('type', 'unknown')
                status = "✅" if pos <= incident_position else "❌"
                print(f"   {status} Position {pos}: {obj_type} {ref_id}")
            else:
                print(f"   ❌ MISSING: {ref_id}")
    
    print()
    
    # Analysis 4: Check for potential TypeQL issues
    print("=== QUESTION 4: Potential TypeQL/Database Issues ===")
    
    issues_found = []
    
    # Check for extremely long reference lists (TypeQL query size limits)
    for ref_type, ref_list in reference_types.items():
        if len(ref_list) > 10:
            issues_found.append(f"Large reference list: {ref_type} has {len(ref_list)} objects")
    
    # Check for complex nested structures
    total_refs = sum(len(refs) for refs in reference_types.values())
    if total_refs > 20:
        issues_found.append(f"High complexity: Total of {total_refs} object references")
    
    # Check extension structure complexity
    if len(extensions) > 1:
        issues_found.append(f"Multiple extensions: {len(extensions)} extension blocks")
    
    if issues_found:
        print("⚠️  Potential issues detected:")
        for issue in issues_found:
            print(f"   - {issue}")
        print("\n💡 These could cause TypeQL query complexity issues or database constraints")
    else:
        print("✅ No obvious structural issues detected")
    
    print()
    
    # Summary
    print("=== SUMMARY ===")
    print(f"🔍 Incident references {len(referenced_ids)} objects across {len(reference_types)} reference types")
    print(f"📍 Incident appears at position {incident_position + 1} of {len(objects)}")
    
    if missing_objects:
        print(f"❌ {len(missing_objects)} missing object definitions")
    if dependencies_after_incident:
        print(f"❌ {len(dependencies_after_incident)} dependencies appear after incident")
    if issues_found:
        print(f"⚠️  {len(issues_found)} potential complexity issues")
        
    if not missing_objects and not dependencies_after_incident and not issues_found:
        print("✅ All dependency requirements satisfied - failure likely due to TypeQL syntax or database constraints")
    else:
        print("🔧 Dependency ordering or missing object issues detected")

if __name__ == "__main__":
    analyze_incident_dependencies()