### 1.3 Stix External Reference Modelled by Vaticle TypeDB Entity plus Relation

The External Reference is a Stix sub-data-object (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx) used to describe pointers to information represented outside of Stix. It is presented as a list of External_References, holding one or more individual pointer descriptions.

An example is shown below.

```json
{
  ...
  "external_references": [
    {
      "source_name": "veris",
      "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
      "url": "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/
data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
      "hashes": {
      "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
      }
    }
  ],
  ...
}
```
An External References list is modelled in TypeQL by an Entity-Relation combination. The Entity describes the External Reference record, and the relation links it to the objects doing the referencing

```
external-reference sub stix-meta-object,
	# In addition to source-name, at least one of description, url or external-id must be present§
	# Required
	owns source-name, 

	# Optional
	owns description,
	owns url, 
	owns external-id,
	plays hashes:owner,
	plays external-references:referenced;

external-references sub relation, 
	relates referenced,
	relates referencing;
  ```

Thereby, the relationship between the properties of Stix External Reference, and its mapping to TypeQL are as follows.

 Stix 2.1 Property| Schema Object | Schema Name | Required  Optional |
| :--- | :----: | :---: | :----: |
| source_name | external-reference | source-name | Required |
| description | external-reference | description | Optional |
| hashes  | external-reference | hashes:owner | Optional |
| external_id  | external-reference | external-id | Optional |




### 1.5 Stix Kill-Chain-Phase Modelled by Vaticle TypeDB Relations

The kill-chain-phase represents a phase in a kill chain, which describes the various phases an attacker may undertake in order to achieve their objectives (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h). An example is hsown below

```
{
  ...
  "kill_chain_phases": [
    {
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "reconnaissance"
    }
  ],
  ...
}
```
In TypeQL, this structure is based on a simple Six Meta Object, and then related to the object by the kill-chain-usage relation, as shown below.

```
kill-chain-phase sub stix-meta-object,
	owns kill-chain-name, 
	owns phase-name,
	plays kill-chain-usage:kill-chain-using,

	# inferred role player
	plays kill-chain:participating-kill-chain-phase;

kill-chain-usage sub stix-core-relationship,
	relates kill-chain-used as target,
	relates kill-chain-using as source;
```
