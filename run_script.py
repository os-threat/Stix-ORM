#!/usr/bin/env python3
"""
STIX Cleaning Test Script

Tests the clean_stix_directory function on both MBC and Attack Flow example directories.
Provides detailed reporting on processing results, timing, and operations performed.
"""

import sys
from pathlib import Path
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_directory

def process_directory(directory_path: str, directory_name: str, enable_sco_cleaning: bool = False) -> None:
    """Process a directory and display detailed results"""
    print(f"\n{'='*60}")
    print(f"Processing {directory_name} Examples")
    print(f"Directory: {directory_path}")
    if enable_sco_cleaning:
        print("🧹 SCO Field Cleaning: ENABLED")
    else:
        print("🧹 SCO Field Cleaning: DISABLED")
    print(f"{'='*60}")
    
    try:
        # Process the directory with SCO cleaning setting
        reports = clean_stix_directory(directory_path, clean_sco_fields=enable_sco_cleaning)
        
        if not reports:
            print(f"❌ No JSON files found in {directory_path}")
            return
        
        # Summary statistics
        total_files = len(reports)
        successful_files = sum(1 for r in reports if r.clean_operation_outcome)
        failed_files = total_files - successful_files
        
        print(f"\n📊 Summary:")
        print(f"   Total files processed: {total_files}")
        print(f"   ✅ Successful: {successful_files}")
        print(f"   ❌ Failed: {failed_files}")
        print(f"   📈 Success rate: {(successful_files/total_files)*100:.1f}%")
        
        # Process each report
        for i, report in enumerate(reports, 1):
            print(f"\n📄 File {i}/{total_files}:")
            
            if report.clean_operation_outcome:
                # Success case - show detailed info
                file_report = report.detailed_operation_reports
                list_report = file_report.operations_report
                
                print(f"   ✅ {file_report.original_file_name}")
                print(f"   📁 Cleaned: {file_report.updated_file_name}")
                print(f"   📝 Report: {file_report.report_file_name}")
                print(f"   🔢 Objects processed: {report.total_number_of_objects_processed}")
                print(f"   ⏱️  Total time: {file_report.total_processing_time_seconds:.3f}s")
                
                # Show expansion results
                expansion = list_report.expansion_report
                if len(expansion.sources_of_expansion) > 0:
                    total_expanded = sum(len(source.found_list) for source in expansion.sources_of_expansion)
                    print(f"   🔍 Objects expanded: {total_expanded} from {len(expansion.sources_of_expansion)} sources")
                
                # Show circular references resolved
                circular = list_report.circular_reference_report
                if circular.number_of_circular_references_found > 0:
                    print(f"   🔄 Circular refs resolved: {circular.number_of_circular_references_found}")
                
                # Show SCO cleaning results
                sco = list_report.cleaning_sco_report
                if sco.number_of_scos_cleaned > 0:
                    print(f"   🧹 SCO objects cleaned: {sco.number_of_scos_cleaned}")
                
                # Show operation timing breakdown
                print(f"   ⏱️  Operation timing:")
                for timing in list_report.operation_timings:
                    if list_report.total_processing_time_seconds > 0:
                        percentage = (timing.duration_seconds / list_report.total_processing_time_seconds) * 100
                        print(f"      • {timing.operation_name}: {timing.duration_seconds:.3f}s ({percentage:.1f}%)")
                    else:
                        print(f"      • {timing.operation_name}: {timing.duration_seconds:.3f}s")
                
            else:
                # Failure case
                print(f"   ❌ Processing failed")
                print(f"   📝 Error: {report.return_message}")
                print(f"   🔢 Objects processed: {report.total_number_of_objects_processed}")
        
        # Overall timing analysis for successful files
        if successful_files > 0:
            successful_reports = [r for r in reports if r.clean_operation_outcome]
            total_objects = sum(r.total_number_of_objects_processed for r in successful_reports)
            total_time = sum(r.detailed_operation_reports.total_processing_time_seconds for r in successful_reports)
            avg_time_per_file = total_time / successful_files
            avg_objects_per_file = total_objects / successful_files
            
            print(f"\n📈 Performance Analysis:")
            print(f"   Total objects processed: {total_objects}")
            print(f"   Total processing time: {total_time:.3f}s")
            print(f"   Average time per file: {avg_time_per_file:.3f}s")
            print(f"   Average objects per file: {avg_objects_per_file:.1f}")
            print(f"   Processing rate: {total_objects/total_time:.1f} objects/second")
            
    except Exception as e:
        print(f"❌ Error processing {directory_path}: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main execution function"""
    print("🚀 STIX Cleaning Module Test")
    print("Testing both MBC and Attack Flow example directories")
    print("📋 Processing Configuration:")
    print("   • MBC (Malware Behavior Catalog): SCO cleaning DISABLED")
    print("   • Attack Flow: SCO cleaning ENABLED")
    
    # Test directories with SCO cleaning settings
    directories = [
        ("test/data/mbc/examples", "MBC (Malware Behavior Catalog)", False),  # NO SCO cleaning for MBC
        ("test/data/attack_flow/examples", "Attack Flow", True)  # SCO cleaning ONLY for Attack Flow
    ]
    
    # Process each directory
    for directory_path, directory_name, enable_sco in directories:
        if Path(directory_path).exists():
            process_directory(directory_path, directory_name, enable_sco)
        else:
            print(f"\n❌ Directory not found: {directory_path}")
    
    print(f"\n{'='*60}")
    print("✅ Test execution completed!")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()