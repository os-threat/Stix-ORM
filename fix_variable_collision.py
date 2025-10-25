#!/usr/bin/env python3
"""
TypeQL Variable Collision Fix

This script fixes the variable naming collision issue in the STIX-ORM import_utilities.py
where multiple relations referencing the same type (e.g., sequence) get identical variable names.

The issue: $sequence00 is used for different sequences in different relations, causing conflicts.
The fix: Include the relation name in the variable to make them unique.

Example:
Before: $sequence00, $sequence00 (collision!)
After:  $sequence_start_refs00, $sequence_refs00 (unique!)
"""

import re
import shutil
from pathlib import Path

def main():
    """Fix variable collision in import_utilities.py"""
    
    # File paths
    original_file = Path("stixorm/module/orm/import_utilities.py")
    backup_file = Path("stixorm/module/orm/import_utilities.py.backup")
    
    print("🔧 FIXING TYPEQL VARIABLE COLLISION")
    print("=" * 50)
    
    # Create backup
    print(f"📋 Creating backup: {backup_file}")
    shutil.copy2(original_file, backup_file)
    
    # Read the file
    print(f"📖 Reading file: {original_file}")
    with open(original_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # The collision happens in the embedded_relation function around line 548
    # Current problematic code:
    # prop_var = '$' + prop_type + str(i) + inc_add
    
    # We need to modify this function to accept and use the relation name
    print("🔍 Locating embedded_relation function...")
    
    # Find the embedded_relation function signature
    func_pattern = r'(def embedded_relation\([^)]+\):)'
    match = re.search(func_pattern, content)
    if not match:
        print("❌ Could not find embedded_relation function!")
        return False
    
    print("✅ Found embedded_relation function")
    
    # Find the problematic line where variables are created
    # Look for: prop_var = '$' + prop_type + str(i) + inc_add
    var_pattern = r"(\s+)(prop_var = '\$' \+ prop_type \+ str\(i\) \+ inc_add)"
    
    # Replace with relation-aware variable naming
    new_var_line = r'\1prop_var = "$" + prop.replace("_", "-") + "-" + prop_type + str(i) + inc_add'
    
    print("🔄 Applying variable naming fix...")
    
    # Apply the fix
    updated_content = re.sub(var_pattern, new_var_line, content)
    
    # Also need to update the single value case
    single_var_pattern = r"(\s+)(prop_var = '\$' \+ prop_type \+ inc_add)"
    single_new_var_line = r'\1prop_var = "$" + prop.replace("_", "-") + "-" + prop_type + inc_add'
    updated_content = re.sub(single_var_pattern, single_new_var_line, updated_content)
    
    if updated_content == content:
        print("❌ No changes made - pattern not found!")
        print("Let me try a different approach...")
        
        # Try finding the exact lines from our debug trace
        lines = content.split('\n')
        modified = False
        
        for i, line in enumerate(lines):
            # Look for the variable creation lines
            if 'prop_var = \'$\' + prop_type + str(i) + inc_add' in line:
                # Replace with relation-aware naming
                lines[i] = line.replace(
                    'prop_var = \'$\' + prop_type + str(i) + inc_add',
                    'prop_var = \'$\' + prop.replace("_", "-") + "-" + prop_type + str(i) + inc_add'
                )
                modified = True
                print(f"✅ Fixed line {i+1}: list case")
            
            elif 'prop_var = \'$\' + prop_type + inc_add' in line and 'prop_var_list.append' in lines[i+1] if i+1 < len(lines) else False:
                # Replace single value case
                lines[i] = line.replace(
                    'prop_var = \'$\' + prop_type + inc_add',
                    'prop_var = \'$\' + prop.replace("_", "-") + "-" + prop_type + inc_add'
                )
                modified = True
                print(f"✅ Fixed line {i+1}: single case")
        
        if modified:
            updated_content = '\n'.join(lines)
        else:
            print("❌ Could not find the exact variable creation lines!")
            return False
    
    # Write the fixed content
    print(f"💾 Writing fixed content to: {original_file}")
    with open(original_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print("✅ Variable collision fix applied successfully!")
    print("\n🎯 EXPECTED RESULT:")
    print("   Before: $sequence00, $sequence00 (collision!)")
    print("   After:  $sequence-start-refs-sequence00, $sequence-refs-sequence00 (unique!)")
    print(f"\n🔙 Backup saved as: {backup_file}")
    
    return True

if __name__ == "__main__":
    main()