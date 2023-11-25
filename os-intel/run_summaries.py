import requests
import pandas as pd

root_url = "https://raw.githubusercontent.com/dod-cyber-crime-center/cti-stix-common-objects/incident_rework/extension-definition-specifications/incident-core/examples/"

def run(name):

    common_cols = ["created", "name", "description", "type", "labels", "status", "goal", "impact_category",
                      "variety", "priority", "outcome", "detection_methods", "incident_types","relationship_type"]
    r = requests.get(root_url + name)
    data = r.json()
    info = []
    if type(data) == list:
        for o in data:
            row = {}
            for s in common_cols:
                if o.get(s):
                    row[s] = o[s]

            if o.get("extensions"):
                for exkey in o['extensions'].keys():
                    exobj = o["extensions"][exkey]
                    for ex2key in exobj.keys():
                        if ex2key in ["determination","detection_methods","investigation_status"]:
                            row[ex2key]=exobj[ex2key]

            info.append(row)
    elif type(data) == dict:
        for o in data["objects"]:
            row = {}
            for s in common_cols:

                if o.get(s):
                    row[s] = o[s]

            if o.get("extensions"):
                for exkey in o['extensions'].keys():
                    exobj = o["extensions"][exkey]
                    for ex2key in exobj.keys():
                        if ex2key in ["determination","detection_methods","investigation_status"]:
                            row[ex2key]=exobj[ex2key]

            info.append(row)

    sum_df = pd.DataFrame(info)
    sum_df.set_index("created", inplace=True)

    sum_df.to_csv(name.replace(".json",".csv"))

examples = ["incident_asset_context.json",
            "incident_duplication.json",
            "incident_expo_1.json",
            "incident_expo_2.json",
            "incident_expo_3.json",
            "incident_expo_4.json",
            "incident_indicators.json",
            "incident_observables.json",
            "incident_pii_report.json",
            "incident_ransom.json",
            "incident_sample_activity.json",
            "incident_sample_infrastructure.json",
            "incident_with_child.json"]


for name in examples:
    print(name)
    run(name)