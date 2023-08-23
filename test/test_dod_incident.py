import json
import os
import datetime
import stix2


with open('./data/os-threat/incident/human_trigger.json','r') as file:
    bundle_json = json.load(file)

    missing = ['sighting--9af0cfab-2dfe-448d-a4e3-85ae0af3149c', 'sighting--f771469d-bd11-4e7a-b1f8-9a732b77db23', 'identity--2242662b-d581-4864-8696-fff719dc0500', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', 'report--f66c52bc-cb78-4657-894f-a4c2902b1c30', 'identity--987eeee1-413a-44ac-96cc-0a8acdcc2f2c', 'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168']
    print('Missing %d' % len(missing))

    found = 0
    for object in bundle_json['objects']:
        is_m = any([object['id']==m for m in missing])
        if is_m:
            print(object['id'])
            found += 1
        if 'created_by_ref' in object:
            is_m = any([object['created_by_ref'] == m for m in missing])
            if is_m:
                print(object['id'])
                found += 1
        if 'sighting_refs' in object:
            for ref in object['sighting_refs']:
                is_m = any([ref == m for m in missing])
                if is_m:
                    print(object['id'])
                    found += 1

    print('Total found %d' % found)