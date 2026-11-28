"""contrib/netbox-seed/seed.py: seed a throwaway NetBox with one site for the importer.

Called by capture.py with an API client whose token lives only in memory. It writes no file and
prints no token. The site is built from what the importer admits (IR-28): platform `frr`, Linux
interface names, point-to-point IPv4 links, router IDs and static routes in device local context
data under the key `cassian` (IR-35), and BGP sessions from the `netbox-bgp` plugin (IR-4).

Site `site-a` (ruling 46-S3-R3):
- imported: leaf1 and leaf2, each cabled to spine1, one /30 per link, one active session per side;
- excluded and named, one reason each, the import still exiting 0:
  - leaf9, a planned device cabled to spine1 (no address on either end, no session; its local
    context data left null);
  - 2001:db8::1/64, an IPv6 address on leaf1's cabled eth1 (which keeps its IPv4 address);
  - 172.16.0.1/24, an IPv4 address in VRF `mgmt` on spine1's cabled eth1 (which keeps its global
    IPv4 address);
  - spine1's active session to the outside peer 203.0.113.1 (AS 64999), outside every link's
    subnet. The peer's address object is assigned to no interface, so a capture by device holds
    it only inside the session.
"""

SITE = "site-a"

DEVICES = [
    # name, asn, local_context_data
    ("leaf1", 65001, {"cassian": {"router_id": "1.1.1.1", "static_routes": [{"prefix": "192.0.2.0/24"}]}}),
    ("spine1", 65002, {"cassian": {"router_id": "2.2.2.2"}}),
    ("leaf2", 65003, {"cassian": {"router_id": "3.3.3.3"}}),
]

# (a_device, a_interface, a_address, b_device, b_interface, b_address)
LINKS = [
    ("leaf1", "eth1", "10.0.0.1/30", "spine1", "eth1", "10.0.0.2/30"),
    ("leaf2", "eth1", "10.0.0.5/30", "spine1", "eth2", "10.0.0.6/30"),
]

OUTSIDE_PEER = ("203.0.113.1/32", 64999)


def seed(api):
    """Create the site through the REST API. `api.post(path, body)` returns the created object."""
    rir = api.post("ipam/rirs/", {"name": "cassian-seed", "slug": "cassian-seed", "is_private": True})
    asn = {}
    for number in [n for _, n, _ in DEVICES] + [OUTSIDE_PEER[1]]:
        asn[number] = api.post("ipam/asns/", {"asn": number, "rir": rir["id"]})["id"]
    vrf = api.post("ipam/vrfs/", {"name": "mgmt"})

    site = api.post("dcim/sites/", {"name": SITE, "slug": SITE, "status": "active"})
    maker = api.post("dcim/manufacturers/", {"name": "cassian-seed", "slug": "cassian-seed"})
    dtype = api.post("dcim/device-types/", {"manufacturer": maker["id"], "model": "frr-router",
                                            "slug": "frr-router"})
    role = api.post("dcim/device-roles/", {"name": "router", "slug": "router", "color": "9e9e9e"})
    platform = api.post("dcim/platforms/", {"name": "frr", "slug": "frr"})

    def device(name, status, context):
        body = {"name": name, "device_type": dtype["id"], "role": role["id"], "site": site["id"],
                "platform": platform["id"], "status": status}
        if context is not None:
            body["local_context_data"] = context
        return api.post("dcim/devices/", body)["id"]

    def interface(dev_id, name):
        return api.post("dcim/interfaces/", {"device": dev_id, "name": name, "type": "1000base-t"})["id"]

    def cable(a_if, b_if):
        api.post("dcim/cables/", {
            "a_terminations": [{"object_type": "dcim.interface", "object_id": a_if}],
            "b_terminations": [{"object_type": "dcim.interface", "object_id": b_if}],
            "status": "connected"})

    def address(ip, if_id=None, vrf_id=None):
        body = {"address": ip, "status": "active"}
        if if_id is not None:
            body.update({"assigned_object_type": "dcim.interface", "assigned_object_id": if_id})
        if vrf_id is not None:
            body["vrf"] = vrf_id
        return api.post("ipam/ip-addresses/", body)["id"]

    def session(name, dev_id, local_ip, local_as, remote_ip, remote_as):
        api.post("plugins/bgp/session/", {
            "name": name, "site": site["id"], "device": dev_id, "local_address": local_ip,
            "local_as": asn[local_as], "remote_address": remote_ip, "remote_as": asn[remote_as],
            "status": "active"})

    dev = {name: device(name, "active", context) for name, _, context in DEVICES}
    iface, addr = {}, {}
    for a_dev, a_if, a_ip, b_dev, b_if, b_ip in LINKS:
        for d, i, ip in ((a_dev, a_if, a_ip), (b_dev, b_if, b_ip)):
            iface[(d, i)] = interface(dev[d], i)
            addr[ip] = address(ip, iface[(d, i)])
        cable(iface[(a_dev, a_if)], iface[(b_dev, b_if)])

    as_of = {name: number for name, number, _ in DEVICES}
    for a_dev, _, a_ip, b_dev, _, b_ip in LINKS:
        for local, l_ip, remote, r_ip in ((a_dev, a_ip, b_dev, b_ip), (b_dev, b_ip, a_dev, a_ip)):
            session(f"{local} to {remote}", dev[local], addr[l_ip], as_of[local], addr[r_ip], as_of[remote])

    # The four objects the importer excludes and names (46-S3-R3).
    leaf9 = device("leaf9", "planned", None)
    cable(interface(leaf9, "eth1"), interface(dev["spine1"], "eth3"))
    address("2001:db8::1/64", iface[("leaf1", "eth1")])
    address("172.16.0.1/24", iface[("spine1", "eth1")], vrf["id"])
    peer = address(OUTSIDE_PEER[0])
    session("spine1 to outside-peer", dev["spine1"], addr["10.0.0.2/30"], as_of["spine1"], peer, OUTSIDE_PEER[1])

    return {"site": SITE, "imported": {"devices": sorted(dev), "links": len(LINKS), "sessions": 2 * len(LINKS)},
            "excluded": ["device leaf9 (planned)", "address 2001:db8::1/64 (IPv6)",
                         "address 172.16.0.1/24 (VRF mgmt)", "session spine1 to 203.0.113.1 (outside peer)"]}
