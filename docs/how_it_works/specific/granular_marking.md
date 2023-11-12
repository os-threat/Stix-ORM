# Granualar Marking



## Granular Markings Sub Object
The Granular MArkings sub object is actually just a list of objects, but it has its own category as it is a common property.

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--1ed8caa7-a708-4706-b651-f1186ede6ca1",
    "created_by_ref": "identity--b38dfe21-7477-40d1-aa90-5c8671ce51ca",
    "created": "2017-04-27T16:18:24.318Z",
    "modified": "2017-04-27T16:18:24.318Z",
    "name": "Fake email address",
    "description": "Known to be used by The Joker.",
    "indicator_types": [
        "malicious-activity",
        "attribution"
    ],
    "pattern": "[email-message:from_ref.value MATCHES '.+\\\\banking@g0thamnatl\\\\.com$']",
    "pattern_type": "stix",
    "valid_from": "2017-04-27T16:18:24.318Z",
    "granular_markings": [
        {
            "marking_ref": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "selectors": [
                "description"
            ]
        },
        {
            "marking_ref": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "selectors": [
                "indicator_types.[1]"
            ]
        },
        {
            "marking_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "selectors": [
                "indicator_types.[0]",
                "name",
                "pattern"
            ]
        }
    ]
}
```


```mermaid
  flowchart TD
    subgraph obj0 [Stix 2.1 Object]
        direction TB
        c1([Stix Object])
        a1[Attribute]
        a2[Atomic Value]
        a3[Attribute]
        a4[List of Values]
        a7[Marking Attribute]
        a8[Marking Value]
        a9[Marking Attribute]
        a10[Marking Value]
        c1-->a1
        c1-->a3 
        c1--granular markings-->ide2
        subgraph ide1 [Flat Object]
            direction LR
            a1-->a2
            a3-->a4
        end
        subgraph ide2 [List of Granular Markings]
        direction TB
            subgraph ide3 [Granular Marking]
                direction TB
                a7-->a8
            end
            subgraph ide4 [Granular Marking]
                direction TB
                a9-->a10
            end
        end
    end
```