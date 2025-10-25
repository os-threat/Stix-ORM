#!/usr/bin/env python3
"""
Extract and analyze the incident TypeQL statement from the test output
"""

def extract_incident_typeql():
    """Extract the incident TypeQL from the terminal output"""
    
    print("=== INCIDENT TYPEQL ANALYSIS ===\n")
    
    # The incident TypeQL from the test output (from the terminal log)
    incident_typeql = """
match  $sequence00 isa sequence, has stix-id "sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e";
 $sequence10 isa sequence, has stix-id "sequence--fb97db29-be35-4f8d-b483-c2899750838d";
 $sequence00 isa sequence, has stix-id "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8";
 $sequence10 isa sequence, has stix-id "sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef";
 $sequence20 isa sequence, has stix-id "sequence--10fe3d71-a3d1-4f83-ad54-9c290d7136e9";
 $task00 isa task, has stix-id "task--3f23faa4-e21e-4880-bd8a-c8d89aa453aa";
 $task10 isa task, has stix-id "task--01537439-3b2d-4afe-81a3-45b2dd35c655";
 $event00 isa event, has stix-id "event--e8f641e7-89ca-4776-a828-6838d8eccdca";
 $impact00 isa impact, has stix-id "impact--1b87fa10-78fd-4b3e-970e-dea91e9a7457";
 $email-addr00 isa email-addr, has stix-id "email-addr--eb38d07e-6ba8-56c1-b107-d4db4aacf212";
 $email-addr10 isa email-addr, has stix-id "email-addr--4722424c-7012-56b0-84d5-01d076fc547b";
 $user-account20 isa user-account, has stix-id "user-account--597ad4d4-35ba-585d-8f6d-134a75032f9b";
 $identity30 isa identity, has stix-id "identity--ce31dd38-f69b-45ba-9bcd-2a208bbf8017";
 $identity40 isa identity, has stix-id "identity--31f2aeea-dfe1-4fc9-98c9-38e590e3b55b";
 $url50 isa url, has stix-id "url--3279c7de-8f91-5c1a-99d9-d6546c6c41f7";
 $email-message60 isa email-message, has stix-id "email-message--6090e3d4-1fa8-5b36-9d2d-4a66d824995d";
 $observed-data70 isa observed-data, has stix-id "observed-data--5aa35ce5-7d95-4cbb-8ab4-f29b44de80ad";
 $indicator80 isa indicator, has stix-id "indicator--dd52359a-1dd5-43c3-8970-2cc8aa0e1544";
 $sighting90 isa sighting, has stix-id "sighting--06faabfe-490a-4516-a66e-1340aad78870";
 $identity100 isa identity, has stix-id "identity--3789a438-8d49-4f2a-bb1a-06d3575d2f33";
 $anecdote110 isa anecdote, has stix-id "anecdote--e1298bc0-818e-5cdb-9154-eac37c8e260f";
 $observed-data120 isa observed-data, has stix-id "observed-data--98f47f54-715a-4bdf-ac74-4d65f22bea8e";
 $sighting130 isa sighting, has stix-id "sighting--4fb5cd06-3c90-42d7-be38-abea7f752fba";
 insert $incident isa incident,
 has stix-type $stix-type,
 has spec-version $spec-version,
 has stix-id $stix-id,
 has created $created,
 has modified $modified,
 has name $name;

 $stix-type "incident";
 $spec-version "2.1";
 $stix-id "incident--145eb841-90db-4526-8407-b25fd2d705c1";
 $created 2025-07-27T06:01:14.656;
 $modified 2025-07-27T06:01:14.656;
 $name "potential phishing";

 $incident-ext isa incident-ext,
 has extension-type $extension-type,
 has investigation-status $investigation-status,
 has incident-types $incident_types0;

 $extension-type "property-extension";
 $investigation-status "new";
 $incident_types0 "dissemination-phishing-emails";

 $occurence-ext0 (occurence:$incident, incident-core:$incident-ext) isa occurence-ext;

 $sequence-start-refs0 (incident:$incident-ext, sequence-start:$sequence00, sequence-start:$sequence10) isa sequence-start-refs;

 $sequence-refs0 (incident:$incident-ext, the-steps:$sequence00, the-steps:$sequence10, the-steps:$sequence20) isa sequence-refs;

 $task-refs0 (incident:$incident-ext, the-task:$task00, the-task:$task10) isa task-refs;

 $event-refs0 (incident:$incident-ext, the-event:$event00) isa event-refs;

 $impact-refs0 (incident:$incident-ext, the-impact:$impact00) isa impact-refs;

 $other-obj-refs0 (object:$incident-ext, referred:$email-addr00, referred:$email-addr10, referred:$user-account20, referred:$identity30, referred:$identity40, referred:$url50, referred:$email-message60, referred:$observed-data70, referred:$indicator80, referred:$sighting90, referred:$identity100, referred:$anecdote110, referred:$observed-data120, referred:$sighting130) isa other-obj-refs;
"""
    
    print("🔍 ANALYSIS OF GENERATED INCIDENT TYPEQL:\n")
    
    # Extract the problems
    issues = []
    
    # Check 1: Variable name conflicts
    print("1️⃣ VARIABLE NAME CONFLICTS:")
    if "$sequence00" in incident_typeql and incident_typeql.count("$sequence00") > 1:
        print("❌ $sequence00 is used multiple times with different STIX IDs!")
        print("   - First: sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e")  
        print("   - Second: sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8")
        issues.append("Variable name collision: $sequence00")
    
    if "$sequence10" in incident_typeql and incident_typeql.count("$sequence10") > 1:
        print("❌ $sequence10 is used multiple times with different STIX IDs!")
        print("   - First: sequence--fb97db29-be35-4f8d-b483-c2899750838d")
        print("   - Second: sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef") 
        issues.append("Variable name collision: $sequence10")
    
    print()
    
    # Check 2: Relation role mismatches
    print("2️⃣ RELATION ROLE USAGE:")
    relation_checks = [
        ("sequence-start-refs", "sequence-start:$sequence00, sequence-start:$sequence10", "Should use unique sequence variables"),
        ("sequence-refs", "the-steps:$sequence00, the-steps:$sequence10, the-steps:$sequence20", "Uses conflicting sequence variables"),
        ("other-obj-refs", "(object:$incident-ext, referred:...", "Should be (incident:$incident-ext, referred:...)"),
    ]
    
    for relation, usage, issue in relation_checks:
        print(f"🔍 {relation}: {issue}")
        if relation == "other-obj-refs":
            print("❌ Schema expects: relates incident as owner, relates referred as pointed-to")
            print("❌ Generated uses: object:$incident-ext (should be incident:$incident-ext)")
            issues.append(f"Role mismatch in {relation}")
    
    print()
    
    # Check 3: Schema compliance
    print("3️⃣ SCHEMA COMPLIANCE ISSUES:")
    schema_issues = [
        "Variable naming conflicts prevent proper matching",
        "Incorrect role usage in other-obj-refs relation", 
        "Complex 23-way match statement may exceed TypeQL limits",
        "Multiple variables pointing to same objects create ambiguity"
    ]
    
    for i, issue in enumerate(schema_issues, 1):
        print(f"❌ {i}. {issue}")
        issues.append(issue)
    
    print()
    
    # Summary
    print("=== SUMMARY ===")
    print(f"🚨 Total issues found: {len(issues)}")
    print("\n🎯 ROOT CAUSE:")
    print("The TypeQL generation has multiple critical issues:")
    print("1. Variable name collisions ($sequence00 and $sequence10 reused)")
    print("2. Incorrect relation roles (object: vs incident:)")  
    print("3. Complex query structure exceeding practical limits")
    print("\n💡 RECOMMENDATION:")
    print("Fix the TypeQL generator to:")
    print("- Generate unique variable names for each object")
    print("- Use correct schema-defined relation roles")
    print("- Consider breaking complex incidents into smaller queries")

if __name__ == "__main__":
    extract_incident_typeql()