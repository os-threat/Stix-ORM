#!/usr/bin/env python3
"""
Minimal test to verify topological sorting for sequence dependencies
"""

import sys
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

def test_sequence_ordering():
    """Test topological sorting specifically for sequence dependencies"""
    
    # Load the test data
    test_file = project_root / "test/data/os-threat/examples/block_output.json"
    with open(test_file, 'r') as f:
        raw_objects = json.load(f)
    
    # Use raw objects directly for now
    print(f"Loaded {len(raw_objects)} raw objects")
    
    # Filter to just sequence objects for focused testing  
    sequence_objects = [obj for obj in raw_objects if obj.get('type') == 'sequence']
    print(f"Found {len(sequence_objects)} sequence objects:")
    
    for seq in sequence_objects:
        deps = seq.get('on_completion') or seq.get('sequenced_object')
        print(f"  {seq['id']}: {seq.get('step_type', 'unknown')} -> {deps}")
    
    # Convert to StixObject instances
    stix_objects = []
    for seq in sequence_objects:
        stix_obj = StixObject(**seq)
        stix_objects.append(stix_obj)
    
    # Test topological sort on StixObject instances
    print(f"\nRunning topological sort on {len(stix_objects)} sequences...")
    sorted_ids, unresolved_refs, success = _topological_sort(stix_objects)
    
    print(f"Sort result: success={success}, unresolved_count={len(unresolved_refs)}")
    print(f"Sorted order:")
    for i, seq_id in enumerate(sorted_ids):
        print(f"  {i}: {seq_id}")
    
    if unresolved_refs:
        print(f"Unresolved references: {unresolved_refs}")
    
    # Check if the problematic sequences are in correct order
    problem_seqs = [
        "sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e",
        "sequence--fb97db29-be35-4f8d-b483-c2899750838d"
    ]
    target_seqs = [
        "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8", 
        "sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef"
    ]
    
    print(f"\nChecking dependency order:")
    for target in target_seqs:
        if target in sorted_ids:
            target_pos = sorted_ids.index(target)
            print(f"  {target}: position {target_pos}")
            
    for problem in problem_seqs:
        if problem in sorted_ids:
            problem_pos = sorted_ids.index(problem)
            print(f"  {problem}: position {problem_pos}")

if __name__ == "__main__":
    test_sequence_ordering()