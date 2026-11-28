#!/usr/bin/env python3
"""contrib/netbox-seed/capture.py: capture a seeded NetBox export bundle (scope 3.10.6, REQ-46-33).

For each capture, on a fresh Docker Compose stack:
  1. build the official netbox-docker image at the pinned tag with the netbox-bgp plugin, by
     netbox-docker's plugin method (uv pip install, PLUGINS, collectstatic), and start it with
     PostgreSQL and Valkey; every secret is generated in memory and passed by environment only;
  2. create a v2 API token inside the instance (manage.py shell); its plaintext reaches this
     process through a pipe and is never printed or written;
  3. check the instance's versions against pins.env, then seed it with seed.py;
  4. capture the four endpoints (pages merged) and the published API schema, and write the
     manifest from pins.env with the schema's sha256;
  5. check that no written file holds the token, before teardown;
  6. tear the stack down (containers, volumes, the built image).
Then it prints every written file's sha256 and size.

Usage:  python3 capture.py --out DIR [--captures 2]      (DIR must not exist)
        python3 capture.py --self-test                    (offline: the guards, shown failing)
Standard library only. Needs docker with the compose plugin. Run where Docker is (ai-netsim).
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import seed  # noqa: E402

ENDPOINTS = {  # manifest name -> (file, API list path); the site's devices are captured first
    "dcim/devices": ("dcim_devices.json", "dcim/devices/"),
    "dcim/cables": ("dcim_cables.json", "dcim/cables/"),
    "ipam/ip-addresses": ("ipam_ip_addresses.json", "ipam/ip-addresses/"),
    "plugins/bgp/session": ("plugins_bgp_session.json", "plugins/bgp/session/"),
}
SESSION_SCHEMA_PATH = "/api/plugins/bgp/session/"

COMPOSE = """\
services:
  netbox:
    build: {context: ., dockerfile: Dockerfile-Plugins}
    depends_on: [postgres, redis, redis-cache]
    ports: ["127.0.0.1:${CG_PORT}:8080"]
    environment:
      DB_HOST: postgres
      DB_NAME: netbox
      DB_USER: netbox
      DB_PASSWORD: ${CG_DB_PASSWORD}
      REDIS_HOST: redis
      REDIS_PASSWORD: ${CG_REDIS_PASSWORD}
      REDIS_CACHE_HOST: redis-cache
      REDIS_CACHE_PASSWORD: ${CG_REDIS_PASSWORD}
      SECRET_KEY: ${CG_SECRET_KEY}
      API_TOKEN_PEPPER_1: ${CG_PEPPER}
      SKIP_SUPERUSER: "true"
      ALLOWED_HOSTS: "*"
  postgres:
    image: ${CG_POSTGRES_IMAGE}
    environment:
      POSTGRES_DB: netbox
      POSTGRES_USER: netbox
      POSTGRES_PASSWORD: ${CG_DB_PASSWORD}
  redis:
    image: ${CG_VALKEY_IMAGE}
    command: ["sh", "-c", "valkey-server --requirepass \\"$$REDIS_PASSWORD\\""]
    environment:
      REDIS_PASSWORD: ${CG_REDIS_PASSWORD}
  redis-cache:
    image: ${CG_VALKEY_IMAGE}
    command: ["sh", "-c", "valkey-server --requirepass \\"$$REDIS_PASSWORD\\""]
    environment:
      REDIS_PASSWORD: ${CG_REDIS_PASSWORD}
"""
DOCKERFILE = """\
FROM {image}@{digest}
COPY plugin_requirements.txt /opt/netbox/
RUN /usr/local/bin/uv pip install -r /opt/netbox/plugin_requirements.txt
COPY plugins.py /etc/netbox/config/plugins.py
RUN DEBUG="true" SECRET_KEY="dummydummydummydummydummydummydummydummydummydummy" \\
    /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py collectstatic --no-input
"""
TOKEN_SNIPPET = """\
from users.choices import TokenVersionChoices
from users.models import Token, User
u = User.objects.create_superuser('cassian-seed', 'cassian-seed@example.invalid', None)
t = Token.objects.create(user=u, version=TokenVersionChoices.V2)
print('CG-AUTH ' + t.get_auth_header_prefix() + t.token)
"""


def fail(msg):
    print(f"FAIL {msg}", flush=True)
    raise SystemExit(1)


def read_pins(path):
    pins = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.isupper() or key in pins:
            fail(f"pins.env: bad line {line!r}")
        pins[key] = value
    need = {"NETBOX_VERSION", "NETBOX_BGP_VERSION", "NETBOX_DOCKER_TAG", "NETBOX_IMAGE",
            "NETBOX_IMAGE_DIGEST", "POSTGRES_IMAGE", "POSTGRES_IMAGE_DIGEST", "VALKEY_IMAGE",
            "VALKEY_IMAGE_DIGEST", "SITE_SLUG"}
    if set(pins) != need:
        fail(f"pins.env keys {sorted(pins)} != {sorted(need)}")
    return pins


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Api:
    """A REST client whose credential is held privately and never shown."""

    def __init__(self, base, auth):
        self.base = base.rstrip("/") + "/api/"
        self._auth = auth
        self._open = urllib.request.build_opener(urllib.request.ProxyHandler({})).open

    def __repr__(self):
        return "Api(<redacted>)"

    def _req(self, method, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": self._auth, "Accept": "application/json",
            "Content-Type": "application/json"})
        try:
            with self._open(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            detail = e.read()[:1500].decode("utf-8", "replace")
            fail(f"{method} {url.split('/api/', 1)[-1]}: HTTP {e.code}: {detail}")

    def get(self, path, query=""):
        return self._req("GET", self.base + path + (("?" + query) if query else ""))

    def post(self, path, body):
        return json.loads(self._req("POST", self.base + path, body))

    def get_all(self, path, query=""):
        """Every object of a list endpoint, pages merged; the reader never sees paging keys."""
        url = self.base + path + "?" + "&".join(q for q in (query, "limit=1000") if q)
        out = []
        while url:
            page = json.loads(self._req("GET", url))
            out.extend(page["results"])
            url = page.get("next")
        return out


def compose(project, workdir, env, *args, capture_out=False, stdin=None, timeout=1800):
    cmd = ["docker", "compose", "-p", project, "-f", str(workdir / "compose.yml"), *args]
    p = subprocess.run(cmd, cwd=workdir, env=env, input=stdin, text=True, timeout=timeout,
                       stdout=subprocess.PIPE if capture_out else subprocess.DEVNULL,
                       stderr=subprocess.PIPE)
    if p.returncode != 0:
        tail = "\n".join(p.stderr.splitlines()[-25:])
        fail(f"docker compose {' '.join(args[:2])} rc={p.returncode}\n{tail}")
    return p.stdout if capture_out else None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url, limit=900):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    start = time.time()
    while time.time() - start < limit:
        try:
            opener.open(url, timeout=10).close()
            return
        except urllib.error.HTTPError:
            return  # any HTTP answer means the server is up, so migrations have finished
        except (urllib.error.URLError, OSError):
            time.sleep(5)
    fail(f"NetBox did not answer within {limit}s")


def token_parts(auth):
    value = auth.split(" ", 1)[1]          # nbt_<key>.<secret>
    key, _, secret = value.partition(".")
    return [p.encode() for p in (value, key, secret) if len(p) >= 8]


def check_no_token(paths, parts):
    """Fail if any written file holds any part of the token (REQ-46-33)."""
    for path in paths:
        data = Path(path).read_bytes()
        for part in parts:
            if part in data:
                fail(f"TOKEN FOUND in written file {path}")
    return len(paths)


def write_bundle(out, pins, endpoints, schema_bytes, source):
    out.mkdir(parents=True)
    names = {}
    for name, (fname, _) in ENDPOINTS.items():
        (out / fname).write_text(json.dumps(endpoints[name], indent=2, ensure_ascii=False) + "\n")
        names[name] = fname
    (out / "schema.json").write_bytes(schema_bytes)
    manifest = {
        "format": 1,
        "netbox_version": pins["NETBOX_VERSION"],
        "plugins": {"netbox_bgp": pins["NETBOX_BGP_VERSION"]},
        "site": pins["SITE_SLUG"],
        "endpoints": names,
        "schema": {"file": "schema.json", "sha256": sha256(schema_bytes), "source": source},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return sorted(p for p in out.iterdir())


def one_capture(n, out, pins):
    project = f"cgseed{secrets.token_hex(4)}"
    workdir = Path(tempfile.mkdtemp(prefix="cgseed-"))
    port = free_port()
    env = dict(os.environ, CG_PORT=str(port), CG_DB_PASSWORD=secrets.token_hex(24),
               CG_REDIS_PASSWORD=secrets.token_hex(24), CG_SECRET_KEY=secrets.token_urlsafe(60),
               CG_PEPPER=secrets.token_urlsafe(60),
               CG_POSTGRES_IMAGE=f"{pins['POSTGRES_IMAGE']}@{pins['POSTGRES_IMAGE_DIGEST']}",
               CG_VALKEY_IMAGE=f"{pins['VALKEY_IMAGE']}@{pins['VALKEY_IMAGE_DIGEST']}")
    (workdir / "compose.yml").write_text(COMPOSE)
    (workdir / "Dockerfile-Plugins").write_text(
        DOCKERFILE.format(image=pins["NETBOX_IMAGE"], digest=pins["NETBOX_IMAGE_DIGEST"]))
    (workdir / "plugin_requirements.txt").write_text(f"netbox-bgp=={pins['NETBOX_BGP_VERSION']}\n")
    (workdir / "plugins.py").write_text('PLUGINS = ["netbox_bgp"]\n')
    parts = []
    try:
        print(f"CAPTURE {n} stack {project} on 127.0.0.1:{port}", flush=True)
        compose(project, workdir, env, "build", "--pull")
        built = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", f"{project}-netbox"],
                               capture_output=True, text=True, timeout=60)
        if built.returncode != 0:
            fail(f"built image {project}-netbox not found")
        print(f"CAPTURE {n} built-image {built.stdout.strip()} from {pins['NETBOX_IMAGE']}"
              f"@{pins['NETBOX_IMAGE_DIGEST']}", flush=True)
        compose(project, workdir, env, "up", "-d")
        base = f"http://127.0.0.1:{port}"
        wait_http(base + "/api/status/")
        out_tok = compose(project, workdir, env, "exec", "-T", "netbox",
                          "/opt/netbox/netbox/manage.py", "shell", "--no-startup", "--no-imports",
                          "--interface", "python", capture_out=True, stdin=TOKEN_SNIPPET)
        lines = [ln for ln in out_tok.splitlines() if ln.startswith("CG-AUTH ")]
        if len(lines) != 1:
            fail("token creation printed no single CG-AUTH line")
        auth = lines[0][len("CG-AUTH "):]
        del out_tok, lines
        parts = token_parts(auth)
        api = Api(base, auth)
        del auth

        status = json.loads(api.get("status/"))
        got = (status.get("netbox-version"), (status.get("plugins") or {}).get("netbox_bgp"))
        want = (pins["NETBOX_VERSION"], pins["NETBOX_BGP_VERSION"])
        if got != want:
            fail(f"instance versions {got} != pins {want}")
        print(f"CAPTURE {n} versions {got[0]} netbox_bgp {got[1]}", flush=True)

        summary = seed.seed(api)
        print(f"CAPTURE {n} seeded {json.dumps(summary, sort_keys=True)}", flush=True)

        site = pins["SITE_SLUG"]
        devices = api.get_all("dcim/devices/", f"site={site}")
        by_device = "&".join(f"device_id={d['id']}" for d in devices)
        queries = {"dcim/devices": None, "dcim/cables": f"site={site}",
                   "ipam/ip-addresses": by_device, "plugins/bgp/session": by_device}
        endpoints = {"dcim/devices": devices}
        for name, (_, path) in ENDPOINTS.items():
            if name not in endpoints:
                endpoints[name] = api.get_all(path, queries[name])
            print(f"CAPTURE {n} {name}: {len(endpoints[name])} objects", flush=True)
        missing = [d.get("name") for d in endpoints["dcim/devices"] if "local_context_data" not in d]
        if missing:
            fail(f"device objects without local_context_data: {missing}")
        schema_bytes = api.get("schema/", "format=json")
        paths = json.loads(schema_bytes).get("paths", {})
        source = "published" if SESSION_SCHEMA_PATH in paths else "plugin serializer"
        print(f"CAPTURE {n} schema {len(schema_bytes)} B; {SESSION_SCHEMA_PATH} "
              f"{'present' if source == 'published' else 'ABSENT'}", flush=True)

        files = write_bundle(out, pins, endpoints, schema_bytes, source)
        checked = check_no_token(files + sorted(workdir.iterdir()), parts)
        print(f"CAPTURE {n} TOKEN-CHECK OK ({checked} files)", flush=True)
        for f in files:
            print(f"FILE {f} {sha256(f.read_bytes())} {f.stat().st_size}", flush=True)
    finally:
        try:
            compose(project, workdir, env, "down", "-v", "--remove-orphans", "--rmi", "local")
            print(f"CAPTURE {n} torn down", flush=True)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def self_test():
    """Offline: each guard shown failing once (practice 3), then passing."""
    tmp = Path(tempfile.mkdtemp(prefix="cgseed-selftest-"))
    try:
        auth = "Bearer nbt_" + "k" * 12 + "." + "s" * 40
        parts = token_parts(auth)
        clean = tmp / "clean.json"
        clean.write_text('{"ok": true}\n')
        dirty = tmp / "dirty.json"
        dirty.write_text('{"leak": "' + "s" * 40 + '"}\n')
        assert check_no_token([clean], parts) == 1
        try:
            check_no_token([clean, dirty], parts)
            raise AssertionError("token check passed a planted secret")
        except SystemExit:
            print("SELFTEST token-check fires on a planted secret: OK")
        good = tmp / "pins.env"
        good.write_text((HERE / "pins.env").read_text())
        pins = read_pins(good)
        bad = tmp / "bad.env"
        bad.write_text(good.read_text() + "EXTRA=1\n")
        try:
            read_pins(bad)
            raise AssertionError("pins check passed an extra key")
        except SystemExit:
            print("SELFTEST pins check fires on an extra key: OK")
        eps = {name: [] for name in ENDPOINTS}
        files = write_bundle(tmp / "b", pins, eps, b'{"paths": {}}', "plugin serializer")
        man = json.loads((tmp / "b" / "manifest.json").read_text())
        assert list(man) == ["format", "netbox_version", "plugins", "site", "endpoints", "schema"]
        assert man["schema"]["sha256"] == sha256(b'{"paths": {}}') and len(files) == 6
        print("SELFTEST manifest keys and schema digest: OK")
        print("SELFTEST ALL OK")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path)
    ap.add_argument("--captures", type=int, default=2)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.out or a.out.exists():
        fail("--out must name a directory that does not exist")
    if a.captures < 1:
        fail("--captures must be 1 or more")
    pins = read_pins(HERE / "pins.env")
    for n in range(1, a.captures + 1):
        one_capture(n, a.out / f"capture-{n}", pins)
    print("CAPTURE-DONE", flush=True)


if __name__ == "__main__":
    main()
