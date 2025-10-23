#!/usr/bin/env python3
"""
Test dependency sorting with the updated cleaning pipeline
"""

import sys
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

def test_sequence_dependency_sorting():
    """Test dependency sorting through the full cleaning pipeline"""
    
    # Load the test data
    test_file = project_root / "test/data/os-threat/examples/block_output.json"
    with open(test_file, 'r') as f:
        raw_objects = json.load(f)
    
    print(f"Loaded {len(raw_objects)} raw objects")
    
    # Filter to just sequence objects for focused testing  
    sequence_objects = [obj for obj in raw_objects if obj.get('type') == 'sequence']
    print(f"Found {len(sequence_objects)} sequence objects:")
    
    for seq in sequence_objects:
        deps = seq.get('on_completion') or seq.get('sequenced_object')
        print(f"  {seq['id']}: {seq.get('step_type', 'unknown')} -> {deps}")
    
    # Test cleaning pipeline with dependency sorting
    print(f"\nRunning full cleaning pipeline on {len(sequence_objects)} sequences...")
    try:
        print("Calling clean_stix_list...")
        cleaned_objects, report = clean_stix_list(sequence_objects, clean_sco_fields=False)
        print("clean_stix_list returned successfully")
        
        print("Cleaning pipeline completed!")
        print(f"Success: {report.clean_operation_outcome}")
        print(f"Report type: {type(report)}")
        
        if hasattr(report, 'return_message'):
            print(f"Return message: {report.return_message}")
        
        print(f"Returned objects count: {len(cleaned_objects)}")
        
        if hasattr(report, 'detailed_operation_reports') and hasattr(report.detailed_operation_reports, 'sorting_report'):
            sorting = report.detailed_operation_reports.sorting_report
            print(f"Sorting successful: {sorting.sorting_successful}")
            print("Final order:")
            for i, obj_id in enumerate(sorting.sorted_list_of_stix_ids):
                print(f"  {i}: {obj_id}")
            
            # Check if the problematic sequences are in correct order
            problem_seqs = [
                "sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e",
                "sequence--fb97db29-be35-4f8d-b483-c2899750838d"
            ]
            target_seqs = [
                "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8", 
                "sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef"
            ]
            
            sorted_ids = sorting.sorted_list_of_stix_ids
            print("\nDependency order analysis:")
            for target in target_seqs:
                if target in sorted_ids:
                    target_pos = sorted_ids.index(target)
                    print(f"  Target {target}: position {target_pos}")
                    
            for problem in problem_seqs:
                if problem in sorted_ids:
                    problem_pos = sorted_ids.index(problem)
                    print(f"  Dependent {problem}: position {problem_pos}")
                    
            # Check if targets come before dependents
            target_positions = [sorted_ids.index(t) for t in target_seqs if t in sorted_ids]
            problem_positions = [sorted_ids.index(p) for p in problem_seqs if p in sorted_ids]
            
            if target_positions and problem_positions:
                max_target_pos = max(target_positions)
                min_problem_pos = min(problem_positions)
                
                if max_target_pos < min_problem_pos:
                    print("\n✅ SUCCESS: All target sequences appear before dependent sequences!")
                else:
                    print(f"\n❌ FAILURE: Dependency order is incorrect. Max target position: {max_target_pos}, Min dependent position: {min_problem_pos}")
            
        else:
            print("No sorting report available")
            
    except Exception as e:
        print(f"Cleaning pipeline failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_sequence_dependency_sorting()