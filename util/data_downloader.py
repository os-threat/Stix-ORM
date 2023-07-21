import json
from pathlib import Path
from urllib.parse import urlparse

import requests


def attack_data():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

    response = requests.get(url)
    index_data = response.json()
    index_data_collections = index_data["collections"]
    mitre_versions = index_data_collections[0]["versions"]

    result = []
    for mitre_version in mitre_versions:
        url = mitre_version["url"]
        last_part = str(urlparse(url).path.split("/")[-1])
        response = requests.get(url)
        data = response.json()

        mitre_folder = Path(__file__).parents[1].joinpath("test").joinpath("data").joinpath("mitre")
        assert mitre_folder.exists()
        file_path = mitre_folder.joinpath(last_part)
        with open(file_path, "w") as json_file:
            json.dump(data, json_file)


    return result


if __name__ == '__main__':
    attack_data()