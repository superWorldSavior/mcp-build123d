#!/usr/bin/env python3
"""Manually copy one reviewed public GHCR image graph without rebuilding it."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
MEDIA = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
MAX_METADATA = 8 * 1024 * 1024


class BootstrapError(Exception):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise BootstrapError("registry redirect is not HTTPS")
        result = super().redirect_request(request, fp, code, msg, headers, newurl)
        if result and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(request.full_url).netloc:
            result.remove_header("Authorization")
        return result


def request(url, headers=None, method="GET"):
    """Return status/headers/body; never include credentials or response errors in logs."""
    opener = urllib.request.build_opener(SafeRedirect())
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=60) as response:
            body = response.read(MAX_METADATA + 1) if method == "GET" else b""
            if len(body) > MAX_METADATA:
                raise BootstrapError("metadata exceeds size limit")
            return response.status, dict(response.headers.items()), body
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), b""
    except urllib.error.URLError:
        raise BootstrapError("network request failed") from None


def select(catalogue, repository, package):
    owner = catalogue.get("destination_owner")
    if owner != "superworldsavior" or repository.lower().split("/")[0] != owner:
        raise BootstrapError("repository or destination owner is outside the reviewed migration")
    found = [e for e in catalogue.get("entries", [])
             if e.get("repository", "").lower() == repository.lower() and e.get("package") == package]
    if len(found) != 1 or not NAME.fullmatch(package):
        raise BootstrapError("package is not uniquely allowlisted for this repository")
    entry = found[0]
    digest = entry.get("source_digest", "")
    if not DIGEST.fullmatch(digest) or entry.get("source") != f"ghcr.io/casys-ai/{package}":
        raise BootstrapError("catalogue source must be the reviewed Casys package and exact sha256 digest")
    aliases = entry.get("source_aliases", [])
    if not isinstance(aliases, list) or len(set(aliases)) != len(aliases) or any(
            not isinstance(t, str) or not TAG.fullmatch(t) or t in ("latest", "main") for t in aliases):
        raise BootstrapError("aliases must be explicit reviewed immutable release tags")
    tag = "bootstrap-sha256-" + digest.split(":")[1]
    return {**entry, "destination": f"ghcr.io/{owner}/{package}",
            "destination_tag": tag, "destination_tags": [tag, *aliases]}


class Registry:
    def __init__(self, image, actor=None, credential=None):
        if not image.startswith("ghcr.io/"):
            raise BootstrapError("only GHCR is supported")
        self.path = image[len("ghcr.io/"):]
        self.actor, self.credential, self.token = actor, credential, None

    def authenticate(self):
        actions = "pull,push" if self.credential else "pull"
        url = "https://ghcr.io/token?" + urllib.parse.urlencode({
            "service": "ghcr.io", "scope": f"repository:{self.path}:{actions}"})
        headers = {}
        if self.credential:
            basic = base64.b64encode(f"{self.actor}:{self.credential}".encode()).decode()
            headers["Authorization"] = "Basic " + basic
        status, _, body = request(url, headers)
        if status != 200:
            raise BootstrapError(f"registry authorization failed for {self.path} (HTTP {status})")
        try:
            parsed = json.loads(body)
            self.token = parsed.get("token") or parsed.get("access_token")
        except (ValueError, AttributeError):
            self.token = None
        if not isinstance(self.token, str) or not self.token:
            raise BootstrapError("registry did not return a token")

    def get(self, kind, reference, method="GET"):
        if self.token is None:
            self.authenticate()
        url = f"https://ghcr.io/v2/{self.path}/{kind}/{urllib.parse.quote(reference, safe=':')}"
        for attempt in range(2):
            result = request(url, {"Authorization": "Bearer " + self.token, "Accept": MEDIA}, method)
            if result[0] != 401 or attempt:
                return result
            self.authenticate()


def checked_json(registry, kind, digest, expected_size=None):
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise BootstrapError("graph contains an unsupported digest")
    status, headers, body = registry.get(kind, digest)
    if status != 200:
        raise BootstrapError(f"{kind} read failed (HTTP {status})")
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise BootstrapError("manifest or config bytes do not match the requested digest")
    returned = next((v for k, v in headers.items() if k.lower() == "docker-content-digest"), digest)
    if returned != digest or (expected_size is not None and len(body) != expected_size):
        raise BootstrapError("manifest or config descriptor identity mismatch")
    try:
        return json.loads(body)
    except ValueError:
        raise BootstrapError("manifest or config is not JSON") from None


def graph(registry, root_digest):
    """Read every manifest, including unknown/unknown attestations, and every config."""
    manifests, configs, layers = {}, {}, {}

    def visit(digest, size=None):
        if digest in manifests:
            return
        if len(manifests) >= 1024:
            raise BootstrapError("manifest graph is too large")
        data = checked_json(registry, "manifests", digest, size)
        if not isinstance(data, dict) or data.get("schemaVersion") != 2 or data.get("mediaType") not in MEDIA.split(", "):
            raise BootstrapError("unsupported manifest type or schema")
        manifests[digest] = data
        if "manifests" in data:
            if not isinstance(data["manifests"], list) or not data["manifests"]:
                raise BootstrapError("empty or invalid image index")
            for descriptor in data["manifests"]:
                visit(descriptor["digest"], descriptor["size"])
        else:
            descriptor = data["config"]
            configs[descriptor["digest"]] = checked_json(registry, "blobs", descriptor["digest"], descriptor["size"])
            for layer in data["layers"]:
                if not DIGEST.fullmatch(layer["digest"]) or not isinstance(layer["size"], int) or layer["size"] < 0:
                    raise BootstrapError("unsupported layer descriptor")
                if layer["digest"] in layers and layers[layer["digest"]] != layer["size"]:
                    raise BootstrapError("conflicting layer sizes")
                layers[layer["digest"]] = layer["size"]

    visit(root_digest)
    return {"manifests": manifests, "configs": configs, "layers": layers}


def require_layers(registry, layers):
    for digest, size in layers.items():
        status, headers, _ = registry.get("blobs", digest, "HEAD")
        lengths = [v for k, v in headers.items() if k.lower() == "content-length"]
        if status != 200 or lengths != [str(size)]:
            raise BootstrapError("destination layer missing or descriptor size differs")


def inspect_tag(registry, tag, digest):
    status, _, body = registry.get("manifests", tag)
    if status == 404:
        return "absent"
    if status != 200:
        raise BootstrapError(f"destination tag cannot be inspected (HTTP {status}); no copy allowed")
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise BootstrapError("destination bootstrap tag already contains a different digest; no overwrite allowed")
    return "same-digest"


def copy(entry, token, actor, runner=subprocess.run):
    with tempfile.TemporaryDirectory(prefix="ghcr-bootstrap-auth-") as task_dir:
        authfile = Path(task_dir) / "auth.json"
        authfile.write_text(json.dumps({"auths": {"ghcr.io": {
            "auth": base64.b64encode(f"{actor}:{token}".encode()).decode()}}}))
        authfile.chmod(0o600)
        child_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN", "GH_API_TOKEN")}
        args = ["skopeo", "copy", "--all", "--preserve-digests", "--src-no-creds",
                "--dest-authfile", str(authfile),
                "docker://" + entry["source"] + "@" + entry["source_digest"],
                "docker://" + entry["destination"] + ":" + entry["destination_tag"]]
        result = runner(args, capture_output=True, text=True, env=child_env, timeout=3600)
        if result.returncode:
            raise BootstrapError(f"skopeo copy failed (exit {result.returncode}); check scoped runner diagnostics")


def package_postconditions(entry, token):
    owner, package = entry["destination"].split("/")[1:]
    base = f"https://api.github.com/users/{owner}/packages/container/{urllib.parse.quote(package, safe='')}"
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    status, _, body = request(base, headers)
    if status != 200:
        raise BootstrapError(f"personal package API is not qualified (HTTP {status})")
    package_data = json.loads(body)
    linked = (package_data.get("repository") or {}).get("full_name", "")
    if linked.lower() != entry["repository"].lower():
        raise BootstrapError("copied package is not linked to the owning personal repository; review package settings")
    versions_status, _, versions_body = request(base + "/versions?per_page=100", headers)
    if versions_status != 200:
        raise BootstrapError(f"personal package versions API is not qualified (HTTP {versions_status})")
    versions = json.loads(versions_body)
    matched = [v for v in versions if v.get("name") == entry["source_digest"]
               and all(t in v.get("metadata", {}).get("container", {}).get("tags", []) for t in entry["destination_tags"])]
    if len(matched) != 1:
        raise BootstrapError("bootstrap digest/tag not confirmed in personal package versions API")
    return {"package_api_status": status, "versions_api_status": versions_status,
            "repository": linked, "visibility": package_data.get("visibility"), "version_id": matched[0]["id"]}


def package_preconditions(entry, token):
    owner, package = entry["destination"].split("/")[1:]
    url = f"https://api.github.com/users/{owner}/packages/container/{urllib.parse.quote(package, safe='')}"
    status, _, body = request(url, {"Authorization": "Bearer " + token,
                                   "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    if status == 404:
        # This explicit, manual seed allows creation; authenticated tag guards run first.
        # The ordinary Chrono release guard must continue to reject first-package 404.
        return {"package_api_status": status, "explicit_bootstrap_creation": True}
    if status != 200:
        raise BootstrapError(f"existing package cannot be inspected (HTTP {status}); no copy allowed")
    linked = (json.loads(body).get("repository") or {}).get("full_name", "")
    if linked.lower() != entry["repository"].lower():
        raise BootstrapError("existing package is not linked to the owning personal repository; no copy allowed")
    return {"package_api_status": status, "repository": linked}


def bootstrap(entry, source, destination, token, actor, receipt, copier=copy,
              postconditions=package_postconditions, preconditions=package_preconditions):
    source_graph = graph(source, entry["source_digest"])
    receipt.update({"source_graph": source_graph, "source_anonymous": True})
    for alias in entry["source_aliases"]:
        if inspect_tag(source, alias, entry["source_digest"]) != "same-digest":
            raise BootstrapError("reviewed source alias is absent; no copy allowed")
    states = {tag: inspect_tag(destination, tag, entry["source_digest"]) for tag in entry["destination_tags"]}
    receipt["destination_initial_states"] = states
    receipt["package_preconditions"] = preconditions(entry, token)
    for tag, state in states.items():
        if state == "absent":
            # Check twice because GHCR does not provide a create-only tag transaction.
            state = inspect_tag(destination, tag, entry["source_digest"])
            if state == "absent":
                copier({**entry, "destination_tag": tag}, token, actor)
                receipt["copied"] = True
        if inspect_tag(destination, tag, entry["source_digest"]) != "same-digest":
            raise BootstrapError("destination tag absent after copy")
    if graph(destination, entry["source_digest"]) != source_graph:
        raise BootstrapError("destination graph differs from public source")
    require_layers(destination, source_graph["layers"])
    receipt["graph_verified"] = True
    receipt["package"] = postconditions(entry, token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--package", required=True)
    parser.add_argument("--mode", choices=("plan", "copy", "verify-public"), default="plan")
    parser.add_argument("--receipt", type=Path, default=Path("ghcr-bootstrap-receipt.json"))
    args = parser.parse_args()
    receipt = {"mode": args.mode, "copied": False, "graph_verified": False,
               "workflow_repository": os.environ.get("GITHUB_REPOSITORY"),
               "workflow_sha": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID")}
    try:
        entry = select(json.loads(args.catalogue.read_text()), args.repository, args.package)
        receipt["entry"] = entry
        if args.mode == "plan":
            receipt["status"] = "offline-plan-only"
        elif args.mode == "verify-public":
            source_graph = graph(Registry(entry["source"]), entry["source_digest"])
            dest = Registry(entry["destination"])
            if any(inspect_tag(dest, tag, entry["source_digest"]) != "same-digest" for tag in entry["destination_tags"]) or graph(dest, entry["source_digest"]) != source_graph:
                raise BootstrapError("anonymous destination graph does not match public source")
            require_layers(dest, source_graph["layers"])
            receipt.update({"status": "anonymous-graph-and-layers-verified", "graph_verified": True,
                            "source_graph": source_graph, "destination_anonymous": True})
        else:
            if os.environ.get("GITHUB_ACTIONS") != "true" or args.repository != os.environ.get("GITHUB_REPOSITORY"):
                raise BootstrapError("copy is allowed only inside its owning GitHub Actions repository")
            token, actor = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_ACTOR")
            if not token or not actor:
                raise BootstrapError("copy requires the implicit workflow token and actor")
            bootstrap(entry, Registry(entry["source"]), Registry(entry["destination"], actor, token), token, actor, receipt)
            receipt["status"] = "authenticated-copy-qualified-public-visibility-not-checked"
        print(json.dumps(receipt, indent=2))
        return 0
    except (BootstrapError, ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        message = str(error) if isinstance(error, BootstrapError) else "invalid metadata, I/O failure, or copy timeout"
        receipt.update({"status": "failed", "error": message})
        print("Bootstrap stopped: " + message)
        return 1
    finally:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
