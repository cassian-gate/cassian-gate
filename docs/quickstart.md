# Quickstart (10 minutes)

## Prereqs
- Docker
- containerlab
- Python venv set up for Cassian Gate

## 1) Build demo images (one-time)
```bash
docker build -t cassian/frr-demo-bgp-r1:latest images/frr-demo-bgp-r1
docker build -t cassian/frr-demo-bgp-r2:latest images/frr-demo-bgp-r2
docker build -t cassian/frr-demo-static-r1:latest images/frr-demo-static-r1
docker build -t cassian/frr-demo-static-r2:latest images/frr-demo-static-r2
Note: the canonical CLI name is `cassian`, but the current source-tree examples below still invoke `./src/netsim.py` because that is the present repository entrypoint in this repo.

2) Run the simplest gate (connected + negative test)
./src/netsim.py up examples/01_connected_smoke.yaml --reconfigure
./src/netsim.py test ex01-connected-smoke

3) Run BGP advertisement proof (routing comes from the image)
./src/netsim.py up examples/02_bgp_advertise.yaml --reconfigure
./src/netsim.py test ex02-bgp-advertise

4) Run multi-hop ping proof (static routes come from the image)
./src/netsim.py up examples/03_static_multihop_ping.yaml --reconfigure
./src/netsim.py test ex03-static-multihop

Where to look

Artifacts are under:

labs/clab-<labname>/results.json

labs/clab-<labname>/results.summary.txt

Important boundary

Topology does NOT encode routing mechanics in v1.x.
Routing behavior must come from device configuration (images/config) and is proven via tests.


---

# 5) Verification steps

After implementing:
```bash
python -m py_compile src/netsim.py
./scripts/verify_phase1.sh
./src/netsim.py up examples/01_connected_smoke.yaml --reconfigure
./src/netsim.py test ex01-connected-smoke


Then run the BGP example if those tests exist in your engine:

./src/netsim.py up examples/02_bgp_advertise.yaml --reconfigure
./src/netsim.py test ex02-bgp-advertise
