#!/usr/bin/env python3
"""
Test Incident Problem - Debug TypeQL generation for the incident object
This script isolates the incident object processing to identify where
variable name collisions are occurring in the TypeQL generation.
"""

import json
import logging
from typing import Dict
from stixorm.module.authorise import import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.orm.import_objects import raw_stix2_to_typeql

# Configure logging for detailed debugging
logging.basicConfig(
    level=logging.DEBUG, 
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Setup import type for os-threat data
import_type = import_type_factory.get_all_imports()

def dict_to_typeql(stix_dict, import_type):
    """Convert a STIX dict into TypeQL statements with detailed debugging.
    
    This is the same function from try_refactor.py but with enhanced logging
    to track the TypeQL generation process.
    
    Args:
        stix_dict: Dictionary containing STIX object data
        import_type: Import type configuration
        
    Returns:
        Dictionary containing TypeQL components
    """
    print(f"\n{'='*60}")
    print(f"PROCESSING STIX OBJECT: {stix_dict.get('type', 'unknown')} - {stix_dict.get('id', 'unknown')}")
    print(f"{'='*60}")
    
    # Parse STIX dict into Python object
    logger.debug("📥 STEP 1: Parsing STIX dictionary into Python object...")
    stix_obj = parse(stix_dict, False, import_type)
    logger.debug(f"✅ Parsed object type: {type(stix_obj)} -> {stix_obj}")
    
    # Convert to TypeQL
    logger.debug("🔄 STEP 2: Converting to TypeQL statements...")
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, import_type)
    
    # Package results
    dep_obj["dep_match"] = dep_match
    dep_obj["dep_insert"] = dep_insert  
    dep_obj["indep_ql"] = indep_ql
    dep_obj["core_ql"] = core_ql
    
    # Detailed logging of results
    print(f"\n📋 TYPEQL GENERATION RESULTS:")
    print(f"{'─'*40}")
    print(f"🔗 dep_match length: {len(dep_match)} characters")
    print(f"📝 dep_insert length: {len(dep_insert)} characters") 
    print(f"🏗️ indep_ql length: {len(indep_ql)} characters")
    print(f"⚙️ core_ql length: {len(core_ql)} characters")
    
    # Check for potential variable name issues
    analyze_variable_usage(dep_match, dep_insert, stix_dict.get('id', 'unknown'))
    
    logger.debug(f'\n📤 FINAL TYPEQL COMPONENTS:')
    logger.debug(f'dep_match: {dep_obj["dep_match"]}')
    logger.debug(f'dep_insert: {dep_obj["dep_insert"]}') 
    logger.debug(f'indep_ql: {dep_obj["indep_ql"]}')
    logger.debug(f'core_ql: {dep_obj["core_ql"]}')
    
    return dep_obj

def analyze_variable_usage(dep_match: str, dep_insert: str, object_id: str):
    """Analyze TypeQL for variable naming patterns and potential conflicts.
    
    Args:
        dep_match: The dependency match clause
        dep_insert: The dependency insert clause  
        object_id: The STIX object ID being processed
    """
    print(f"\n🔍 VARIABLE ANALYSIS FOR {object_id}:")
    print(f"{'─'*50}")
    
    # Extract variable patterns from match clause
    import re
    
    # Find all variable declarations (e.g., $sequence00, $task10)
    var_pattern = r'\$(\w+\d*)\s+isa\s+(\w+),\s+has\s+stix-id\s+"([^"]+)"'
    matches = re.findall(var_pattern, dep_match)
    
    if matches:
        print(f"📍 Variable declarations found in dep_match:")
        variable_map = {}
        
        for var_name, type_name, stix_id in matches:
            full_var = f"${var_name}"
            print(f"   {full_var:15} -> {type_name:12} -> {stix_id}")
            
            # Track variable reuse
            if full_var in variable_map:
                print(f"   ⚠️  WARNING: {full_var} already used for {variable_map[full_var]}")
                print(f"   ⚠️  NOW ALSO: {full_var} used for {stix_id}")
                print(f"   🚨 COLLISION DETECTED! Same variable for different objects!")
            else:
                variable_map[full_var] = stix_id
        
        # Check for type-based variable patterns
        print(f"\n📊 Variable usage summary:")
        type_counts = {}
        for var_name, type_name, stix_id in matches:
            if type_name not in type_counts:
                type_counts[type_name] = 0
            type_counts[type_name] += 1
            
        for obj_type, count in type_counts.items():
            print(f"   {obj_type:15}: {count} variables")
            if count > 1:
                print(f"   ⚠️  Multiple variables for {obj_type} - potential for conflicts")
    else:
        print("📍 No variable declarations found in dep_match")
    
    # Check insert statements for variable usage
    if dep_insert:
        insert_vars = re.findall(r'\$(\w+\d*)', dep_insert)
        unique_insert_vars = set(insert_vars)
        print(f"\n📝 Variables used in dep_insert: {len(unique_insert_vars)} unique")
        if len(insert_vars) != len(unique_insert_vars):
            print(f"   ⚠️  Variable reuse detected in insert: {len(insert_vars)} total vs {len(unique_insert_vars)} unique")

def test_incident_typeql_generation():
    """Test TypeQL generation for the incident object from testing.json."""
    
    print("🚀 INCIDENT TYPEQL GENERATION TEST")
    print("="*60)
    
    # Load the incident test file
    test_file = "testing.json"
    
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
            
        print(f"📂 Loaded test file: {test_file}")
        
        # Handle both single object and list formats
        if isinstance(test_data, list):
            if len(test_data) == 1:
                stix_dict = test_data[0]
                print(f"📋 Processing single object from list")
            else:
                print(f"⚠️  Multiple objects in file ({len(test_data)}), using first object")
                stix_dict = test_data[0]
        elif isinstance(test_data, dict):
            if test_data.get("type") == "bundle":
                objects = test_data.get("objects", [])
                if objects:
                    stix_dict = objects[0]  # Use first object from bundle
                    print(f"📦 Processing first object from bundle")
                else:
                    print("❌ Empty bundle!")
                    return
            else:
                stix_dict = test_data
                print(f"📄 Processing single object")
        else:
            print(f"❌ Unexpected data format: {type(test_data)}")
            return
        
        # Verify it's an incident object
        if stix_dict.get("type") != "incident":
            print(f"⚠️  Expected incident object, got: {stix_dict.get('type', 'unknown')}")
            print("Continuing anyway for testing...")
        
        print(f"🎯 Target object: {stix_dict.get('type', 'unknown')} - {stix_dict.get('id', 'unknown')}")
        
        # Generate TypeQL and analyze
        dep_obj = dict_to_typeql(stix_dict, import_type)
        
        # Display full TypeQL for manual inspection
        print(f"\n🔧 COMPLETE TYPEQL OUTPUT:")
        print(f"{'='*60}")
        
        dep_match = dep_obj.get("dep_match", "")
        dep_insert = dep_obj.get("dep_insert", "")
        indep_ql = dep_obj.get("indep_ql", "")
        core_ql = dep_obj.get("core_ql", "")
        
        # Build complete query
        prestring = ""
        if dep_match != "":
            prestring = "match " + dep_match
        complete_query = prestring + " insert " + indep_ql + dep_insert
        
        print("📄 COMPLETE TYPEQL QUERY:")
        print("─" * 40)
        print(complete_query)
        print("─" * 40)
        
        # Final analysis
        print(f"\n📊 FINAL ANALYSIS:")
        print(f"{'='*40}")
        print(f"✅ TypeQL generation completed")
        print(f"📏 Total query length: {len(complete_query)} characters")
        print(f"🔗 Match clause: {'Present' if dep_match else 'Empty'}")
        print(f"📝 Insert clause: {'Present' if (indep_ql or dep_insert) else 'Empty'}")
        
        if "sequence00" in complete_query:
            print(f"⚠️  Found 'sequence00' in query - potential collision risk")
        if "sequence10" in complete_query:  
            print(f"⚠️  Found 'sequence10' in query - potential collision risk")
            
        # Count variable occurrences
        import re
        all_vars = re.findall(r'\$\w+\d*', complete_query)
        unique_vars = set(all_vars)
        
        print(f"📊 Variable usage: {len(all_vars)} total, {len(unique_vars)} unique")
        if len(all_vars) != len(unique_vars):
            print(f"🚨 VARIABLE REUSE DETECTED!")
            
            # Find which variables are reused
            from collections import Counter
            var_counts = Counter(all_vars)
            reused = {var: count for var, count in var_counts.items() if count > 1}
            
            print(f"🔍 Reused variables:")
            for var, count in reused.items():
                print(f"   {var}: used {count} times")
        else:
            print(f"✅ No variable reuse - all variables unique")
        
    except FileNotFoundError:
        print(f"❌ Test file not found: {test_file}")
        print("💡 Make sure to create testing.json with the incident object")
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logger.exception("Full error details:")

if __name__ == "__main__":
    test_incident_typeql_generation()