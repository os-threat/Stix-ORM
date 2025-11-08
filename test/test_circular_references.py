import pytest

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus


@pytest.mark.usefixtures("setup_teardown")
def test_identity_marking_circular_refs_generate_cyclical(generate_connection):
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)

    identity_id = "identity--11111111-1111-4111-8111-111111111111"
    marking_id = "marking-definition--22222222-2222-4222-8222-222222222222"
    ts = "2020-01-01T00:00:00.000Z"

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": ts,
        "modified": ts,
        "name": "Acme Corp",
        "identity_class": "organization",
        # Self-reference creates a self-loop
        "created_by_ref": identity_id,
        # Mutual reference to marking-definition
        "object_marking_refs": [marking_id],
    }

    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": ts,
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
        # Back-reference to identity completes the cycle
        "created_by_ref": identity_id,
    }

    # Attempt to add both objects; the planner should detect the cycle
    results = typedb.add([identity, marking])

    # Expect at least one cyclical dependency reported (both may be flagged)
    assert any(r.status == ResultStatus.CYCLICAL_DEPENDENCY for r in results), (
        f"Expected CYCLICAL_DEPENDENCY, got {[r.status for r in results]}"
    )


