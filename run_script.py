from stixorm.module.parsing.clean_list_or_bundle import clean_stix_directory

# Process all JSON files in directory
reports = clean_stix_directory("test/data/mbc/examples")

for report in reports:
    print(f"File processing: {report.clean_operation_outcome}")