#!/usr/bin/env python3
"""
Test script for conditional enrichment functionality
"""

import json
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

def test_conditional_enrichment():
    """Test the conditional enrichment functionality"""
    
    # Create test data with a reference to a missing object
    test_objects = [
        {
            "id": "indicator--test-123",
            "type": "indicator",
            "created": "2023-01-01T00:00:00.000Z",
            "modified": "2023-01-01T00:00:00.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "labels": ["malicious-activity"],
            "created_by_ref": "identity--missing-identity-123"  # This will be missing
        },
        {
            "id": "malware--test-456", 
            "type": "malware",
            "created": "2023-01-01T00:00:00.000Z",
            "modified": "2023-01-01T00:00:00.000Z",
            "name": "TestMalware",
            "labels": ["trojan"],
            "object_refs": ["indicator--test-123"]  # This exists
        }
    ]
    
    print("🧪 Testing conditional enrichment functionality")
    print(f"Input: {len(test_objects)} objects")
    print("Expected missing dependency: identity--missing-identity-123")
    print()
    
    # Test 1: Enrichment disabled (default) - should fail with missing dependencies
    print("📋 Test 1: Enrichment disabled (should fail with missing dependencies)")
    cleaned_objects, report = clean_stix_list(test_objects, enrich_from_external_sources=False)
    
    print(f"✅ Result: {'SUCCESS' if not report.clean_operation_outcome else 'UNEXPECTED SUCCESS'}")
    print(f"📊 Objects processed: {report.total_number_of_objects_processed}")
    print(f"💬 Message: {report.return_message}")
    
    if hasattr(report.detailed_operation_reports, 'expansion_report'):
        missing_ids = report.detailed_operation_reports.expansion_report.missing_ids_list
        print(f"🔍 Missing IDs found: {missing_ids}")
        
    print()
    
    # Test 2: Enrichment enabled - should try to fetch from external sources  
    print("📋 Test 2: Enrichment enabled (will try external sources)")
    cleaned_objects, report = clean_stix_list(test_objects, enrich_from_external_sources=True)
    
    print(f"✅ Result: {'SUCCESS' if report.clean_operation_outcome else 'FAILED'}")
    print(f"📊 Objects processed: {report.total_number_of_objects_processed}")
    print(f"📊 Objects after cleaning: {len(cleaned_objects)}")
    print(f"💬 Message: {report.return_message if hasattr(report, 'return_message') else 'Success'}")
    
    if hasattr(report.detailed_operation_reports, 'expansion_report'):
        missing_ids = report.detailed_operation_reports.expansion_report.missing_ids_list
        if missing_ids:
            print(f"🔍 Still missing IDs: {missing_ids}")
        else:
            print("🎉 All dependencies resolved!")
            
    print()
    
    # Test 3: Basic mode (both disabled) - should succeed with what we have
    print("📋 Test 3: Basic mode (both enrichment and SCO cleaning disabled)")
    cleaned_objects, report = clean_stix_list(test_objects)
    
    print(f"✅ Result: {'SUCCESS' if not report.clean_operation_outcome else 'UNEXPECTED SUCCESS'}")
    print(f"📊 Objects processed: {report.total_number_of_objects_processed}")
    print(f"💬 Message: {report.return_message}")
    print()


if __name__ == "__main__":
    test_conditional_enrichment()