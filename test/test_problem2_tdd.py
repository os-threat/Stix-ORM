import pytest

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus


@pytest.mark.usefixtures("setup_teardown")
def test_missing_references_should_be_enriched(generate_connection):
    """
    TDD: Desired behaviour — loader enriches bundles that reference undeclared objects.
    Current behaviour — expected to FAIL: returns missing dependency instead of success.
    """
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)

    # Identity A references Identity B (not present in bundle)
    identity_a = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--aaaaaaa1-1111-4111-8111-aaaaaaaaaaa1",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Referencing Org",
        "identity_class": "organization",
        "created_by_ref": "identity--bbbbbbb2-2222-4222-8222-bbbbbbbbbbb2"  # missing in this bundle
    }

    results = typedb.add([identity_a])

    # Desired: the loader should enrich and succeed — this assertion will FAIL today.
    assert all(r.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB] for r in results), \
        f"Expected enrichment + success, but got statuses: {[r.status for r in results]}"


@pytest.mark.usefixtures("setup_teardown")
def test_attack_flow_sco_timestamps_should_be_sanitised(generate_connection):
    """
    TDD: Desired behaviour — SCO objects from Attack Flow with created/modified are sanitised and accepted.
    Current behaviour — expected to FAIL: parser/loader rejects/treats as error.
    """
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)

    # Minimal SCO (file) with forbidden created/modified (Attack Flow quirk)
    sco_file = {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--ccccccc3-3333-4333-8333-ccccccccccc3",
        "name": "payload.bin",
        # Forbidden on SCOs per STIX 2.1; Attack Flow data sometimes includes them
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z"
    }

    results = typedb.add([sco_file])

    # Desired: loader sanitises timestamps and succeeds — this assertion will FAIL today.
    assert all(r.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB] for r in results), \
        f"Expected sanitisation + success, but got statuses: {[r.status for r in results]}"


