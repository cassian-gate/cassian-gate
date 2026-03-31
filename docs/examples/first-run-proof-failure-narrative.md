# First-Run Proof Failure Narrative

Problem category:

Incorrect firewall policy blocks an application port that should be reachable.

Why it matters:

This is a real production-relevant failure class. A service can be deployed correctly, hosts can be present, and the network can still fail the intended proof because policy blocks the required port.

Passing variant:

- `contrib/topologies/first-run-proof/passing/topology.yaml`

Failing variant:

- `contrib/topologies/first-run-proof/failing/topology.yaml`

What changes between them:

- the passing variant allows TCP/8443 through the firewall
- the failing variant allows TCP/2222 instead, while the proof still expects TCP/8443 to work

Exact commands:

    python src/netsim.py test contrib/topologies/first-run-proof/failing/topology.yaml
    python src/netsim.py test contrib/topologies/first-run-proof/passing/topology.yaml

Expected verdict difference:

- failing variant -> FAIL (validation)
- passing variant -> PASS

What the failing result shows:

- ai-netsim is not just approving deployment
- ai-netsim is catching a declared service-reachability failure through the normal authoritative gate path
- the failure is a validation failure, not a YAML error, unsupported feature, or boot/runtime failure

Authoritative artifacts produced by each run:

- `labs/clab-first-run-proof-failing/topology.resolved.yaml`
- `labs/clab-first-run-proof-failing/results.json`
- `labs/clab-first-run-proof-failing/results.summary.txt`
- `labs/clab-first-run-proof-passing/topology.resolved.yaml`
- `labs/clab-first-run-proof-passing/results.json`
- `labs/clab-first-run-proof-passing/results.summary.txt`

Authority boundary:

- `results.json` is the authoritative verdict artifact
- this narrative is explanatory only
- repo location and documentation do not determine verdicts

Bounded support framing:

- this narrative documents one bounded first-run proof family only
- it does not claim broad certification
- it does not claim protocol completeness
- it does not claim broad NOS support from a single example
