import pytest

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus


def _resolver_for_identity(mid: str):
    # Return a minimal identity if requested ID matches, else None
    if mid.startswith("identity--"):
        return [{
            "type": "identity",
            "spec_version": "2.1",
            "id": mid,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Resolved Org",
            "identity_class": "organization"
        }]
    return None


@pytest.mark.usefixtures("setup_teardown")
def test_enrichment_resolver_fetches_identity(generate_connection):
    """
    TDD: Given a bundle referencing a missing identity, the resolver supplies it,
    and the load succeeds.
    """
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection,
                        clear=True,
                        import_type=import_type,
                        enrich_resolver=_resolver_for_identity,
                        sanitize_profile="attack_flow",
                        strict_failure=True)

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--d9e1a9f9-1111-4111-8111-aaaaaaaaaaa1",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Org",
        "identity_class": "organization",
        "created_by_ref": "identity--bbbbbbbb-2222-4222-8222-bbbbbbbbbbb2"
    }

    results = typedb.add([identity])

    assert all(r.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB] for r in results), \
        f"Expected success with resolver enrichment, got: {[r.status for r in results]}"


@pytest.mark.usefixtures("setup_teardown")
def test_attack_flow_sco_sanitisation_scoped(generate_connection):
    """
    TDD: When sanitize_profile=attack_flow, SCOs with created/modified are accepted.
    """
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection,
                        clear=True,
                        import_type=import_type,
                        sanitize_profile="attack_flow",
                        strict_failure=True)

    sco_file = {
        "type": "file",
        "spec_version": "2.1",
        "id": "file--99999999-3333-4333-8333-ccccccccccc3",
        "name": "payload.bin",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z"
    }

    results = typedb.add([sco_file])
    assert all(r.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB] for r in results), \
        f"Expected sanitisation + success, but got statuses: {[r.status for r in results]}"


