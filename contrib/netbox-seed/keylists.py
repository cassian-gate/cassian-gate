#!/usr/bin/env python3
"""keylists.py -- the netbox-dump reader's key lists, derived from the schema.

§4.6 (handover REQ-46-47, -48; IR-40). For each endpoint the reader reads, and
each nested object it reads into, the reader carries two key lists: the keys
it reads, and the keys it knows and does not read. A key in neither list is
rejected. This script derives both lists from the published API schema the
capture recorded (tests/importer/fixtures/netbox-seeded/schema.json). The keys
the reader reads are stated below, from the field map and the filter (handover
§7); every other key of the object's schema component is known and not read.

src/cassian_import.py holds the result as literals and never runs this script
(D-14). PF-10, in tests/importer/importer_behavior_proof.py, runs it offline
on the committed schema and checks that the two agree (REQ-46-48).

Where the schema leaves a nested object untyped:
- a cable termination's ``object``, or an IP address's ``assigned_object``,
  whose type field is ``dcim.interface`` takes its lists from the schema's
  ``BriefInterface`` component, and its ``device`` from ``BriefDevice``
  (ruling 46-S4-R1);
- a termination of any other type has no published shape, so its ``object``
  has no lists; only its ``device`` (``BriefDevice``) and a circuit
  termination's ``circuit`` (``BriefCircuit``) have them (ruling 46-S4-R2).

Usage, offline, standard library only:
    python3 contrib/netbox-seed/keylists.py <schema.json>
prints the lists as JSON and exits 0; exits 2 if the schema does not have
the shape the reader expects.
"""
import hashlib
import json
import sys

# The four endpoints of the bundle's manifest (handover §7), by schema path.
ENDPOINTS = {
    "dcim/cables": "/api/dcim/cables/",
    "dcim/devices": "/api/dcim/devices/",
    "ipam/ip-addresses": "/api/ipam/ip-addresses/",
    "plugins/bgp/session": "/api/plugins/bgp/session/",
}

# 46-S4-R1: the one type whose untyped nested object is read with key lists,
# and the schema component they come from.
TYPED_OBJECTS = {"dcim.interface": "BriefInterface"}

# Each object the reader reads into: where its shape is in the schema, and the
# keys the reader reads (handover §7; B-40 to B-46, B-64 to B-72). Where:
#   ("endpoint", E)       the item of endpoint E's list response
#   ("property", L, K)    the component that property K of object L references
#   ("inline", L, K)      the object that property K of object L defines inline
#   ("component", N)      the component named N (46-S4-R1, -R2)
OBJECTS = {
    "dcim/cables": (("endpoint", "dcim/cables"),
                    ("a_terminations", "b_terminations", "id", "status")),
    "dcim/devices": (("endpoint", "dcim/devices"),
                     ("id", "local_context_data", "name", "platform", "site",
                      "status")),
    "ipam/ip-addresses": (("endpoint", "ipam/ip-addresses"),
                          ("address", "assigned_object", "assigned_object_type",
                           "id", "status", "vrf")),
    "plugins/bgp/session": (("endpoint", "plugins/bgp/session"),
                            ("device", "id", "local_as", "remote_address",
                             "remote_as", "status")),
    "asn": (("property", "plugins/bgp/session", "remote_as"), ("asn",)),
    "circuit": (("component", "BriefCircuit"), ("cid",)),
    "device": (("property", "interface", "device"), ("id", "name")),
    "interface": (("component", TYPED_OBJECTS["dcim.interface"]),
                  ("device", "id", "name")),
    "ip-address": (("property", "plugins/bgp/session", "remote_address"),
                   ("address",)),
    "platform": (("property", "dcim/devices", "platform"), ("slug",)),
    "site": (("property", "dcim/devices", "site"), ("slug",)),
    "status": (("inline", "dcim/devices", "status"), ("value",)),
    "termination": (("property", "dcim/cables", "a_terminations"),
                    ("object", "object_type")),
    "vrf": (("property", "ipam/ip-addresses", "vrf"), ("name",)),
}

# The reader's other places that hold one of the objects above. Each must have
# exactly that object's keys, or the derivation stops.
SAME_AS = (
    ("asn", ("property", "plugins/bgp/session", "local_as")),
    ("device", ("property", "plugins/bgp/session", "device")),
    ("status", ("inline", "dcim/cables", "status")),
    ("status", ("inline", "ipam/ip-addresses", "status")),
    ("status", ("inline", "plugins/bgp/session", "status")),
    ("termination", ("property", "dcim/cables", "b_terminations")),
)


class KeylistsError(Exception):
    """The schema does not have the shape the reader expects."""


def _component(schema, name):
    comps = (schema.get("components") or {}).get("schemas") or {}
    if name not in comps:
        raise KeylistsError("component %s is not in the schema" % name)
    return comps[name]


def _referenced(prop):
    """The component a property references: a $ref, a one-member allOf, or
    an array's items. None when the property is untyped."""
    if not isinstance(prop, dict):
        return None
    if "$ref" in prop:
        return prop["$ref"].rsplit("/", 1)[-1]
    one = prop.get("allOf")
    if (isinstance(one, list) and len(one) == 1 and isinstance(one[0], dict)
            and "$ref" in one[0]):
        return one[0]["$ref"].rsplit("/", 1)[-1]
    if prop.get("type") == "array":
        return _referenced(prop.get("items"))
    return None


def resolve(schema, where):
    """The (name, properties) of the schema shape that ``where`` names."""
    kind = where[0]
    if kind == "endpoint":
        path = ENDPOINTS[where[1]]
        try:
            ref = (schema["paths"][path]["get"]["responses"]["200"]["content"]
                   ["application/json"]["schema"])
        except (KeyError, TypeError):
            raise KeylistsError("endpoint %s has no GET 200 JSON response" % path)
        page = _component(schema, _referenced(ref) or "")
        name = _referenced((page.get("properties") or {}).get("results"))
        if name is None:
            raise KeylistsError("endpoint %s's results name no component" % path)
    elif kind == "component":
        name = where[1]
    elif kind in ("property", "inline"):
        parent, props = resolve(schema, OBJECTS[where[1]][0])
        prop = props.get(where[2])
        if prop is None:
            raise KeylistsError("%s has no property %s" % (parent, where[2]))
        if kind == "inline":
            inline = prop.get("properties") if isinstance(prop, dict) else None
            if not isinstance(inline, dict):
                raise KeylistsError("%s.%s is not an inline object"
                                    % (parent, where[2]))
            return "%s.%s" % (parent, where[2]), inline
        name = _referenced(prop)
        if name is None:
            raise KeylistsError("%s.%s references no component"
                                % (parent, where[2]))
    else:
        raise KeylistsError("unknown place %r" % (where,))
    props = _component(schema, name).get("properties")
    if not isinstance(props, dict):
        raise KeylistsError("component %s has no properties" % name)
    return name, props


def derive(schema):
    """{label: {"read": [...], "known": [...]}}, each list sorted."""
    lists = {}
    for label in sorted(OBJECTS):
        where, read = OBJECTS[label]
        name, props = resolve(schema, where)
        missing = sorted(k for k in read if k not in props)
        if missing:
            raise KeylistsError("%s (%s) has no key %s"
                                % (label, name, ", ".join(missing)))
        lists[label] = {"read": sorted(read),
                        "known": sorted(k for k in props if k not in read)}
    for label, where in SAME_AS:
        name, props = resolve(schema, where)
        want = sorted(lists[label]["read"] + lists[label]["known"])
        if sorted(props) != want:
            raise KeylistsError("%s (%s) does not have %s's keys"
                                % (where, name, label))
    return lists


def main(argv):
    if len(argv) != 2:
        print("usage: python3 contrib/netbox-seed/keylists.py <schema.json>")
        return 2
    with open(argv[1], "rb") as f:
        raw = f.read()
    try:
        lists = derive(json.loads(raw.decode("utf-8")))
    except (KeylistsError, ValueError) as exc:
        print("keylists: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"lists": lists,
                      "schema_sha256": hashlib.sha256(raw).hexdigest(),
                      "selection": TYPED_OBJECTS}, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
