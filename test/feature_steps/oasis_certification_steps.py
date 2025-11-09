from pytest_bdd import given, then, when, scenario, parsers

from stixorm.module.typedb import TypeDBSink, logger
from stixorm.module.typedb_lib.factories.import_type_factory import ImportTypeFactory
from test.test_methods.oasis_certification import run_profile


@given(parsers.parse("a table with the following certifications\n{table}"))
def input_table(table):
    return table

@given("an empty database")
def empty_database(working_connection):
    import_type = ImportTypeFactory().get_default_import()
    sink_db = TypeDBSink(connection=working_connection, clear=True, import_type=import_type, strict_failure=True)
    base_ids = sink_db.get_stix_ids()
    assert len(base_ids) == 0
    return sink_db



@when("the certification profile is run")
def run_certification_profile(empty_database, profile_key, profile_value):
    logger.info(f'Checking profile {profile_key}')
    result = run_profile(empty_database, profile_key, profile_value)
    logger.info(result)
    return result

@then("the expected flags are asserted and report is generated")
def assert_flags_and_generate_report(run_certification_profile, tags, out_file, template):
    report = template
    for code in run_certification_profile.keys():
        if code in tags:
            logger.info(f'Asserting flag {code}')
            report = report.replace(code, run_certification_profile[code])
    with open(out_file, 'w') as file:
        file.write(report)