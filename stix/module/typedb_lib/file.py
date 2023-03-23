import json

from returns.io import impure_safe


@impure_safe
def write_to_file(file_name: str,
                  obj):
    json_object = json.loads(obj.serialize())
    with open(file_name, "w") as outfile:
        json.dump(json_object, outfile)