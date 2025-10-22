#!/usr/bin/env python3
"""
Script to regenerate all relationship UUIDs in MBC test data with proper UUID4 values.
This ensures all UUIDs are valid and consistent across all files.
"""

import os
import re
import uuid
import json
from pathlib import Path

def generate_uuid4():
    """Generate a proper UUID4 string."""
    return str(uuid.uuid4())

def find_all_relationship_uuids(base_dir):
    """Find all unique relationship UUIDs in the test data."""
    uuids = set()
    pattern = r'"relationship--([a-f0-9-]{36})"'
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        matches = re.findall(pattern, content)
                        for match in matches:
                            uuids.add(f"relationship--{match}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    return sorted(list(uuids))

def create_uuid_mapping(old_uuids):
    """Create mapping from old UUIDs to new UUID4s."""
    mapping = {}
    for old_uuid in old_uuids:
        new_uuid = f"relationship--{generate_uuid4()}"
        mapping[old_uuid] = new_uuid
        print(f"Mapping: {old_uuid} -> {new_uuid}")
    return mapping

def replace_uuids_in_file(file_path, uuid_mapping):
    """Replace UUIDs in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace each UUID
        for old_uuid, new_uuid in uuid_mapping.items():
            content = content.replace(old_uuid, new_uuid)
        
        # Only write if content changed
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated: {file_path}")
            return True
        else:
            print(f"No changes needed: {file_path}")
            return False
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to regenerate all relationship UUIDs."""
    base_dir = "test/data/mbc/examples"
    
    if not os.path.exists(base_dir):
        print(f"Directory {base_dir} not found!")
        return
    
    print("Finding all relationship UUIDs...")
    old_uuids = find_all_relationship_uuids(base_dir)
    
    print(f"\nFound {len(old_uuids)} unique relationship UUIDs:")
    for uuid in old_uuids:
        print(f"  {uuid}")
    
    print(f"\nGenerating new UUID4 mappings...")
    uuid_mapping = create_uuid_mapping(old_uuids)
    
    print(f"\nUpdating files...")
    files_updated = 0
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                if replace_uuids_in_file(file_path, uuid_mapping):
                    files_updated += 1
    
    print(f"\nCompleted! Updated {files_updated} files with new relationship UUIDs.")
    
    # Verify the changes by trying to parse JSON files
    print("\nVerifying JSON syntax...")
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                except json.JSONDecodeError as e:
                    print(f"JSON syntax error in {file_path}: {e}")
                except Exception as e:
                    print(f"Error validating {file_path}: {e}")
    
    print("JSON validation complete!")

if __name__ == "__main__":
    main()