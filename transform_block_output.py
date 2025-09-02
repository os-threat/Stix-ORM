#!/usr/bin/env python3
"""
Transform data from OS-Triage, assuming it is block_output.json to extract the 'original' property from each object.
"""

import json

def transform_block_output():
    """
    Read block_output.json and transform it to extract only the 'original' property
    from each object in the list. Overwrites the original file.
    """
    input_file = "test/data/os-threat/exercise/block_output.json"
    
    try:
        # Read the original file
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Transform the data to extract 'original' properties
        transformed_data = []
        for obj in data:
            if 'original' in obj:
                transformed_data.append(obj['original'])
            else:
                print(f"Warning: Object with id '{obj.get('id', 'unknown')}' has no 'original' property")
        
        # Overwrite the original file with transformed data
        with open(input_file, 'w', encoding='utf-8') as f:
            json.dump(transformed_data, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully transformed {len(data)} objects to {len(transformed_data)} original objects")
        print(f"File {input_file} has been updated in place")
        
        return transformed_data
        
    except FileNotFoundError:
        print(f"Error: Could not find file {input_file}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {input_file}: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    transform_block_output()
