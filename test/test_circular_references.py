import pytest

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus


@pytest.mark.usefixtures("setup_teardown")
def test_identity_marking_circular_refs_load_success(generate_connection):
    import_type = import_type_factory.get_default_import()
    typedb = TypeDBSink(connection=generate_connection, clear=True, import_type=import_type)

    identity_id = "identity--11111111-1111-4111-8111-111111111111"
    # Use canonical TLP:WHITE id/created to satisfy stix2 constraint checks
    marking_id = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ts = "2017-01-20T00:00:00.000Z"

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

    # Attempt to add both objects; the loader should handle the cycle with two-phase insert
    results = typedb.add([identity, marking])

    # Expect success or already-in-db statuses (no cyclical dependency reported)
    assert all(r.status in [ResultStatus.SUCCESS, ResultStatus.ALREADY_IN_DB] for r in results), \
        f"Expected success for cyclical refs two-phase load, got {[r.status for r in results]}"


