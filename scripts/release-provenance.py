#!/usr/bin/env python3
"""ADR-017 §7.6/9 local provenance assembly and independent byte/consistency verification.

Build/Verify only, never the signing job. This tool neither signs nor authenticates Apple logs,
GitHub attestations, CI eligibility or job outputs. Publication MUST additionally verify the
attestation/certificate run binding; a successful local verification is not publication approval.
"""
import argparse
import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile

from release_metadata import (CheckError, canonical, digest, file_record, hex_value, keys,
                              parse_json, publisher_requirement, read_regular, require, zip_app_tree)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mbzbugsy/fidomanager"
WORKFLOW = ".github/workflows/release-macos.yml"
SIGNER = "mbzbugsy/fidomanager-release-signer"
EXECUTABLES = ("fidomanager-app", "fido-worker")
TARGETS = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}
CONTEXT_KEYS = "repository tag tag_object_sha commit_sha version arch deployment_target eligibility workflow signer"
APP_NAME = "Fido Manager.app"
CODE_EVIDENCE_SCHEMA = "fidomanager.code-evidence/1"
CODE_EVIDENCE_KEYS = ("schema stapled version source_commit app_tree dmg_sha256 file_sha256 system_dependencies "
                      "dmg_cdhash team_id release_identity cdhash")
MANIFEST_KEYS = "schema product version tag source build build_tools native third_party_notices signing notarization artifacts digest_chain sbom"


def read_json(path):
    return parse_json(read_regular(path))


def nonempty(value, label):
    require(isinstance(value, str) and value.strip() and not any(ord(c) < 32 and c != '\n' for c in value),
            f"missing or invalid {label}")


def positive(value, label):
    require(type(value) is int and value > 0, f"invalid {label}")


def validate_context(context):
    keys(context, CONTEXT_KEYS, "trusted release context")
    require(context["repository"] == REPOSITORY, "repository mismatch")
    require(isinstance(context["version"], str) and
            re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?", context["version"]),
            "invalid release version")
    require(context["tag"] == "v" + context["version"], "tag/version mismatch")
    require(context["version"] == read_json(ROOT / "src-tauri/tauri.conf.json")["version"],
            "release version differs from the reviewed checkout")
    require(hex_value(context["commit_sha"], 40) and hex_value(context["tag_object_sha"], 40), "invalid commit/tag object")
    require(context["arch"] in TARGETS and context["deployment_target"] == "11.0", "unsupported architecture/floor")
    workflow = context["workflow"]
    keys(workflow, "ref sha run_id run_attempt", "workflow")
    require(workflow["ref"] == f'{REPOSITORY}/{WORKFLOW}@refs/tags/{context["tag"]}' and
            workflow["sha"] == context["commit_sha"], "workflow identity mismatch")
    positive(workflow["run_id"], "run ID")
    positive(workflow["run_attempt"], "run attempt")
    keys(context["signer"], "repository sha", "signer")
    require(context["signer"]["repository"] == SIGNER and hex_value(context["signer"]["sha"], 40), "invalid signer pin")
    eligibility = context["eligibility"]
    keys(eligibility, "on_main ci immutable_releases", "eligibility")
    require(eligibility["on_main"] is True, "release commit is not on main")
    ci = eligibility["ci"]
    keys(ci, "workflow head_sha check_runs conclusion", "CI eligibility")
    require(ci["workflow"] == ".github/workflows/ci.yml" and ci["head_sha"] == context["commit_sha"] and
            ci["conclusion"] == "success", "CI eligibility mismatch")
    keys(ci["check_runs"], "validation macos-native-auth macos-packaging", "required CI checks")
    for value in ci["check_runs"].values():
        positive(value, "check run ID")
    require(len(set(ci["check_runs"].values())) == 3, "duplicate check run IDs")
    policy = eligibility["immutable_releases"]
    keys(policy, "enabled response_sha256", "immutable release policy")
    require(policy["enabled"] is True and hex_value(policy["response_sha256"]), "immutable releases required")


def names(context):
    base = f'FidoManager-{context["version"]}-{context["arch"]}'
    return base + ".dmg", base + ".app.zip", base + ".cdx.json"


def native_metadata(identity_bytes, summary_bytes, arch):
    identity, summary = parse_json(identity_bytes), parse_json(summary_bytes)
    require(identity["architecture"] == arch and identity["deployment_target"] == "11.0" and
            identity["fuzz"] is False, "native build identity mismatch")
    require(summary["architecture"] == arch and summary["developer_id_signed"] is False and
            summary["notarized"] is False, "expected unsigned Build package summary")
    result = {}
    for name in ("libfido2", "openssl", "libcbor"):
        lock = read_json(ROOT / "native" / name / "source.lock.json")
        built = identity if name == "libfido2" else identity["dependencies"][name]
        require(built["version"] == lock["version"] and built["source_archive_sha256"] == lock["archive_sha256"] and
                built["deployment_target"] == "11.0" and built["architecture"] == arch,
                f"{name}: native source/build mismatch")
        require(hex_value(built["static_archive_sha256"]), f"{name}: invalid static archive digest")
        item = {"version": lock["version"], "source_sha256": lock["archive_sha256"],
                "static_archive": lock["archive_name"], "static_archive_sha256": built["static_archive_sha256"]}
        if name == "libfido2":
            require(built["revision"] == lock["revision"] and built["patch_sha256"] == lock["patch_sha256"] and
                    built["openssl_api_compat"] == "0x10100000L", "libfido2 pin mismatch")
            item.update(revision=lock["revision"], patch_sha256=lock["patch_sha256"], license="BSD-2-Clause",
                        openssl_api_compat="0x10100000L")
            expected_summary = {key: built[key] for key in ("version", "revision", "source_archive_sha256",
                                                           "patch_sha256", "static_archive_sha256", "deployment_target")}
        else:
            require(built["upstream_tag"] == lock["upstream_tag"] and built["upstream_commit"] == lock["upstream_commit"] and
                    built["license_spdx"] == lock["license_spdx"] and built["license_sha256"] == lock["license_sha256"],
                    f"{name}: native revision/license mismatch")
            require(digest(read_regular(ROOT / "native" / name / "LICENSE.upstream")) == lock["license_sha256"],
                    f"{name}: license bytes mismatch")
            item.update(tag=lock["upstream_tag"], commit=lock["upstream_commit"], license=lock["license_spdx"])
            expected_summary = built
        require(summary["native_dependencies"][name] == expected_summary, f"{name}: package summary mismatch")
        result[name] = item
    openssl = identity["dependencies"]["openssl"]
    require(openssl["openssldir"] == "/var/empty/fidomanager-openssl" and
            openssl["build_options"] == ["no-shared", "no-module", "no-engine", "no-dso", "no-autoload-config",
                                         "no-legacy", "no-apps", "no-tests", "no-docs", "no-ui-console",
                                         "-mmacosx-version-min=11.0"], "OpenSSL policy mismatch")
    result["openssl"].update(openssldir=openssl["openssldir"], build_options=openssl["build_options"])
    require("-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF" in identity["dependencies"]["libcbor"]["build_options"],
            "libcbor LTO must be disabled")
    result["libcbor"]["lto"] = False
    controls = identity["deterministic_controls"]
    require(controls["ZERO_AR_DATE"] == "1" and controls["SOURCE_DATE_EPOCH"] == "1781654400", "deterministic controls mismatch")
    result.update(compiler=identity["compiler"], sdk_version=openssl["sdk_version"],
                  deterministic_controls={k: controls[k] for k in ("SOURCE_DATE_EPOCH", "ZERO_AR_DATE")},
                  build_identity_sha256=digest(identity_bytes), package_summary_sha256=digest(summary_bytes))
    require(summary["third_party_notices_sha256"] == digest(read_regular(ROOT / "THIRD_PARTY_NOTICES.md")),
            "notices digest mismatch")
    return result


def collect_sbom(target, frontend, output):
    """Run only in the unprivileged Build job. No command is taken from input data."""
    require(target in TARGETS.values(), "unsupported Cargo target")
    def capture(args):
        return subprocess.check_output(args, cwd=ROOT)
    metadata = parse_json(capture(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target]))
    trees = {name: capture(["cargo", "tree", "--locked", "-e", "normal", "--target", target,
                            "-p", name, "--prefix", "none", "--format", "{p}", "--no-dedupe"]).decode()
             for name in EXECUTABLES}
    value = {"target": target, "cargo_metadata": metadata, "cargo_trees": trees,
             "cargo_lock_sha256": digest(read_regular(ROOT / "Cargo.lock")),
             "frontend": read_json(frontend)}
    output.write_bytes(canonical(value))


def sbom(inputs, native, context, signing):
    keys(inputs, "target cargo_metadata cargo_trees cargo_lock_sha256 frontend", "SBOM inputs")
    require(inputs["target"] == TARGETS[context["arch"]] and
            inputs["cargo_lock_sha256"] == digest(read_regular(ROOT / "Cargo.lock")), "Cargo input target/lock mismatch")
    keys(inputs["cargo_trees"], "fidomanager-app fido-worker", "Cargo normal closures")
    packages = inputs["cargo_metadata"]["packages"]
    # Read only scalar identity fields from the reviewed Cargo.lock, not arbitrary input TOML.
    locked_rust = []
    for section in read_regular(ROOT / "Cargo.lock").decode().split("[[package]]")[1:]:
        locked_rust.append(dict(re.findall(r'^(name|version|source|checksum) = "([^"\n]+)"$', section, re.M)))
    components, closures = {}, {name: set() for name in EXECUTABLES}
    def add(ref, name, version=None, license=None, **extra):
        component = {"type": "library", "bom-ref": ref, "name": name, **extra}
        if version is not None:
            component["version"] = version
        if license:
            # Cargo still reports legacy slash-separated license declarations. Preserve them
            # as named inventory rather than emit an invalid SPDX expression or infer legal terms.
            component["licenses"] = [{"license": {"name": license}}] if "/" in license else [{"expression": license}]
        if ref in components:
            require(components[ref] == component, "conflicting SBOM component")
        components[ref] = component
        return ref
    for exe in EXECUTABLES:
        tree = inputs["cargo_trees"][exe]
        require(isinstance(tree, str) and tree.strip(), "empty Cargo normal closure")
        for line in tree.splitlines():
            match = re.fullmatch(r"([A-Za-z0-9_-]+) v([^ ]+)(?: .*|)", line)
            require(match is not None, "unrecognized cargo tree package")
            name, version = match.groups()
            candidates = [p for p in packages if p["name"] == name and p["version"] == version]
            require(len(candidates) == 1, "ambiguous/missing Cargo metadata package")
            package = candidates[0]
            pins = [pin for pin in locked_rust if pin.get("name") == name and pin.get("version") == version and
                    pin.get("source") == package.get("source")]
            require(len(pins) == 1, "Cargo package differs from reviewed lockfile")
            extra = {}
            if "checksum" in pins[0]:
                extra["hashes"] = [{"alg": "SHA-256", "content": pins[0]["checksum"]}]
            ref = add(f"cargo:{name}@{version}", name, version, package.get("license"), **extra,
                      properties=[{"name": "fidomanager:source", "value": package.get("source") or f'{REPOSITORY}@{context["commit_sha"]}'}])
            closures[exe].add(ref)
        require(f'cargo:{exe}@{context["version"]}' in closures[exe], "Cargo closure missing executable root")
    frontend = inputs["frontend"]
    keys(frontend, "pnpm_lock_sha256 packages assets", "frontend inventory")
    lock_bytes = read_regular(ROOT / "pnpm-lock.yaml")
    require(frontend["pnpm_lock_sha256"] == digest(lock_bytes), "pnpm lock mismatch")
    # Parse only package entry keys from the pinned pnpm v9 lock format, never arbitrary YAML.
    lock_text = lock_bytes.decode()
    require(lock_text.startswith("lockfileVersion: '9.0'\n") and "\npackages:\n" in lock_text, "unsupported pnpm lock format")
    section = lock_text.split("\npackages:\n", 1)[1].split("\nsnapshots:\n", 1)[0]
    locked = {m[1].strip("'") for m in re.finditer(r"^  (\S+):$", section, re.M)}
    require(isinstance(frontend["packages"], list) and frontend["packages"], "missing bundled npm inventory")
    require(isinstance(frontend["assets"], dict) and "index.html" in frontend["assets"], "missing frontend asset evidence")
    for path, value in frontend["assets"].items():
        require(isinstance(path, str) and not path.startswith("/") and ".." not in path.split("/") and hex_value(value),
                "invalid frontend asset evidence")
    seen = set()
    for package in frontend["packages"]:
        keys(package, "name version license", "npm package")
        key = package["name"] + "@" + package["version"]
        require(key in locked and key not in seen, "unlocked/duplicate npm package")
        seen.add(key)
        closures["fidomanager-app"].add(add("npm:" + key, package["name"], package["version"], package["license"]))
    for name in ("libfido2", "openssl", "libcbor"):
        item = native[name]
        license_hash = digest(read_regular(ROOT / "native" / name / "LICENSE.upstream"))
        properties = [{"name": "fidomanager:license-sha256", "value": license_hash},
                      {"name": "fidomanager:static-archive-sha256", "value": item["static_archive_sha256"]}]
        if name == "libfido2":
            properties.append({"name": "fidomanager:patch-sha256", "value": item["patch_sha256"]})
        closures["fido-worker"].add(add("native:" + name, name, item["version"], item["license"],
                                     hashes=[{"alg": "SHA-256", "content": item["source_sha256"]}], properties=properties))
    # The app's system dependencies are collected from its actual signed executable, by Verify.
    # Native worker system linkage stays pinned by the bundle checker.
    for exe in EXECUTABLES:
        paths = signing["system_dependencies"][exe]
        require(isinstance(paths, list) and paths and all(isinstance(path, str) for path in paths) and
                len(paths) == len(set(paths)), "missing/duplicate system dependencies")
        if exe == "fido-worker":
            require(set(paths) == {"/usr/lib/libz.1.dylib", "/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib",
                                  "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                                  "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"}, "worker linkage evidence mismatch")
        for path in paths:
            require(isinstance(path, str) and path.startswith(("/usr/lib/", "/System/Library/")), "non-system external dependency")
            closures[exe].add(add("system:" + path, path, scope="excluded",
                                 properties=[{"name": "fidomanager:linkage", "value": "external system dependency; unversioned"}]))
        components[exe] = {"type": "application", "bom-ref": exe, "name": exe, "version": context["version"],
                           "hashes": [{"alg": "SHA-256", "content": signing["file_sha256"][exe]}]}
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "fidomanager", "name": "Fido Manager",
                                       "version": context["version"]}},
            "components": [components[key] for key in sorted(components)],
            "dependencies": [{"ref": "fidomanager", "dependsOn": list(EXECUTABLES)}] +
                            [{"ref": exe, "dependsOn": sorted(closures[exe])} for exe in EXECUTABLES],
            "properties": [{"name": "fidomanager:frontend-assets", "value": canonical(frontend["assets"]).decode().strip()}]}


def validate_manifest(manifest, context):
    keys(manifest, MANIFEST_KEYS, "manifest")
    require(manifest["schema"] == "fidomanager.release-manifest/1" and manifest["product"] == "Fido Manager", "manifest schema/product")
    require(manifest["version"] == context["version"] and manifest["tag"] == context["tag"], "manifest version/tag")
    require(manifest["source"] == {"repository": REPOSITORY, "commit": context["commit_sha"], "tag_object": context["tag_object_sha"]}, "manifest source")
    build = manifest["build"]
    keys(build, "workflow workflow_sha run_id run_attempt runner_image macos_sdk xcode rust cargo node pnpm tauri_cli tauri tauri_build target deployment_target reproducibility", "build evidence")
    require(build["workflow"] == WORKFLOW and build["workflow_sha"] == context["workflow"]["sha"] and
            build["run_id"] == context["workflow"]["run_id"] and build["run_attempt"] == context["workflow"]["run_attempt"] and
            build["target"] == TARGETS[context["arch"]] and build["deployment_target"] == "11.0" and
            build["reproducibility"] == "traceable", "build context mismatch")
    package = read_json(ROOT / "package.json")
    require(build["node"] == (ROOT / ".node-version").read_text().strip() and
            build["pnpm"] == package["packageManager"].removeprefix("pnpm@") and
            build["tauri_cli"] == package["devDependencies"]["@tauri-apps/cli"], "build tool pins mismatch")
    for crate, key in (("tauri", "tauri"), ("tauri-build", "tauri_build")):
        versions = re.findall(r'\[\[package\]\]\nname = "' + crate + r'"\nversion = "([^"\n]+)"',
                              read_regular(ROOT / "Cargo.lock").decode())
        require(versions == [build[key]], "Tauri Cargo pin mismatch")
    require(build["macos_sdk"] == manifest["native"]["sdk_version"], "native/app SDK evidence mismatch")
    for key in ("runner_image", "macos_sdk", "xcode", "rust", "cargo", "node", "pnpm", "tauri_cli", "tauri", "tauri_build"):
        nonempty(build[key], key)
    keys(manifest["build_tools"], "cmake pkg-config", "build tools")
    for value in manifest["build_tools"].values():
        nonempty(value, "build tool version")
    notices = manifest["third_party_notices"]
    require(notices == {"path": "Contents/Resources/THIRD_PARTY_NOTICES.md", "sha256": digest(read_regular(ROOT / "THIRD_PARTY_NOTICES.md")),
                        "scope": "native libraries only (libfido2, OpenSSL, libcbor)"}, "notices mismatch")
    signing = manifest["signing"]
    keys(signing, "team_id identity_sha1 authority hardened_runtime entitlements cdhash worker_publisher_requirement release_worker_identity signer", "signing evidence")
    requirement = publisher_requirement("eu.fidomanager.desktop.fido-worker", signing["team_id"])
    require(signing["worker_publisher_requirement"] == requirement and signing["signer"] == context["signer"], "signing requirement/signer mismatch")
    require(hex_value(signing["identity_sha1"], 40) and re.fullmatch(r"Developer ID Application: .+ \(" + signing["team_id"] + r"\)", signing["authority"]), "invalid signing identity")
    require(signing["hardened_runtime"] is True and signing["entitlements"] == {}, "signing policy mismatch")
    keys(signing["cdhash"], "fidomanager-app fido-worker", "code identities")
    for value in signing["cdhash"].values():
        keys(value, context["arch"], "cdhash architectures")
        require(hex_value(value[context["arch"]], 40), "invalid cdhash")
    rid = signing["release_worker_identity"]
    keys(rid, "sha256 worker_file_sha256", "release identity binding")
    require(all(hex_value(v) for v in rid.values()), "invalid release identity digest")
    chain = manifest["digest_chain"]
    keys(chain, "D0 D1 D2 D3 D4 D5", "digest chain")
    require(all(hex_value(v) for v in chain.values()), "invalid digest chain")
    require(chain["D1"] == rid["worker_file_sha256"], "D1 worker mismatch")
    keys(manifest["notarization"], "app dmg stapled", "notarization")
    require(manifest["notarization"]["stapled"] == ["app", "dmg"], "both staples required")
    for name in ("app", "dmg"):
        log = manifest["notarization"][name]
        keys(log, "submission_id status log_sha256", "notarization evidence")
        require(log["status"] == "Accepted" and hex_value(log["log_sha256"]), "invalid notarization evidence")
        nonempty(log["submission_id"], "submission ID")


def notary_log(data, evidence, submitted, expected_hashes):
    log = parse_json(data)
    require(log.get("status") == "Accepted" and log.get("issues") in (None, []) and "issues" in log,
            "notarization failed or has issues")
    require(log.get("jobId") == evidence["submission_id"] and digest(data) == evidence["log_sha256"], "notarization log identity mismatch")
    # No guessed fallback: absence of the empirical sha256 field remains a release gate.
    require(log.get("sha256") == submitted, "notarization submitted digest mismatch/missing")
    tickets = log.get("ticketContents")
    require(isinstance(tickets, list) and tickets, "notarization ticket contents missing")
    actual = {(t.get("arch"), t.get("cdhash")) for t in tickets if isinstance(t, dict)}
    require(expected_hashes <= actual, "notarization ticket missing code identity")


def check_code_evidence(code, context, app_zip_bytes, dmg_sha256):
    """Bind checker evidence to the trusted release context and to the exact final payload bytes.

    The evidence is produced by the candidate checker in Verify; nothing in it is trusted to name
    the release. Version and commit must equal the independent context, the checked DMG must be
    exactly the D5 asset, and the shipped app ZIP (D3) must contain exactly the stapled app tree
    the checker verified, parsed in memory without extraction.
    """
    keys(code, CODE_EVIDENCE_KEYS, "verified code evidence")
    keys(code["file_sha256"], "fidomanager-app fido-worker", "code file digests")
    keys(code["system_dependencies"], "fidomanager-app fido-worker", "system dependencies")
    keys(code["release_identity"], "record_sha256 worker_file_sha256 cdhash", "checked release identity")
    require(code["schema"] == CODE_EVIDENCE_SCHEMA, "unsupported or stale code evidence schema")
    require(code["stapled"] is True, "code evidence is not from a stapled verification")
    require(code["version"] == context["version"] and code["source_commit"] == context["commit_sha"],
            "code evidence was produced for a different release version or source commit")
    require(hex_value(code["dmg_sha256"]) and code["dmg_sha256"] == dmg_sha256,
            "checked DMG differs from the final DMG asset (D5)")
    tree = code["app_tree"]
    keys(tree, "files directories", "verified app tree")
    require(isinstance(tree["files"], dict) and isinstance(tree["directories"], list) and
            tree["directories"] == sorted(set(tree["directories"])), "malformed verified app tree")
    for name, item in tree["files"].items():
        keys(item, "sha256 mode", "verified app file")
        require(isinstance(name, str) and hex_value(item["sha256"]) and type(item["mode"]) is int and
                0 <= item["mode"] <= 0o777, "malformed verified app file")
    files = tree["files"]
    require("Contents/CodeResources" in files, "verified app tree is not stapled")
    require(files.get("Contents/MacOS/fido-worker", {}).get("sha256") == code["file_sha256"].get("fido-worker") and
            files.get("Contents/MacOS/fidomanager-app", {}).get("sha256") == code["file_sha256"].get("fidomanager-app"),
            "verified app tree differs from checked executables")
    require(files.get("Contents/Resources/release-worker-identity.json", {}).get("sha256") ==
            code["release_identity"]["record_sha256"], "verified app tree differs from the release identity record")
    require(zip_app_tree(app_zip_bytes, APP_NAME) == tree,
            "final app ZIP (D3) does not contain exactly the verified stapled app")


def checksums(assets):
    return "".join(f'{assets[name]["sha256"]}  {name}\n' for name in sorted(assets)).encode()


def expected_outputs(directory, context, manifest_input, inputs, identity_bytes, summary_bytes, code):
    """Pure construction over supplied evidence plus exact payload bytes; no output writes."""
    validate_context(context)
    manifest = copy.deepcopy(manifest_input)
    require(set(manifest) == set(MANIFEST_KEYS.split()) - {"artifacts", "sbom", "native"}, "manifest input fields")
    manifest["native"] = native_metadata(identity_bytes, summary_bytes, context["arch"])
    dmg, app_zip, sbom_name = names(context)
    payload_bytes = {name: read_regular(directory / name, 512 * 1024 * 1024) for name in (dmg, app_zip)}
    payload = {name: {"sha256": digest(data), "size": len(data)} for name, data in payload_bytes.items()}
    manifest["artifacts"] = [{"name": name, **payload[name]} for name in (dmg, app_zip)]
    manifest["sbom"] = {"name": sbom_name, "sha256": "0" * 64}
    validate_manifest(manifest, context)
    require(manifest["digest_chain"]["D3"] == payload[app_zip]["sha256"] and
            manifest["digest_chain"]["D5"] == payload[dmg]["sha256"], "final payload digest chain mismatch")
    check_code_evidence(code, context, payload_bytes[app_zip], payload[dmg]["sha256"])
    require(all(hex_value(v) for v in code["file_sha256"].values()) and hex_value(code["dmg_cdhash"], 40), "invalid code evidence")
    require(code["file_sha256"]["fido-worker"] == manifest["digest_chain"]["D1"], "code evidence worker mismatch")
    require(code["team_id"] == manifest["signing"]["team_id"] and code["cdhash"] == manifest["signing"]["cdhash"],
            "checked code signing identities differ from manifest")
    require(code["release_identity"] == {
        "record_sha256": manifest["signing"]["release_worker_identity"]["sha256"],
        "worker_file_sha256": manifest["digest_chain"]["D1"],
        "cdhash": manifest["signing"]["cdhash"]["fido-worker"]}, "checked record identity differs from manifest")
    hashes = {(arch, h) for item in manifest["signing"]["cdhash"].values() for arch, h in item.items()}
    for name, submitted in (("app", "D2"), ("dmg", "D4")):
        data = read_regular(directory / f"notary-{name}.json")
        expected = hashes if name == "app" else hashes | {(None, code["dmg_cdhash"])}
        notary_log(data, manifest["notarization"][name], manifest["digest_chain"][submitted], expected)
    sbom_bytes = canonical(sbom(inputs, manifest["native"], context, code))
    manifest["sbom"]["sha256"] = digest(sbom_bytes)
    manifest_bytes = canonical(manifest)
    assets = {**payload, sbom_name: {"sha256": digest(sbom_bytes), "size": len(sbom_bytes)},
              "release-manifest.json": {"sha256": digest(manifest_bytes), "size": len(manifest_bytes)},
              **{f"notary-{name}.json": file_record(directory / f"notary-{name}.json") for name in ("app", "dmg")}}
    sums = checksums(assets)
    signing = manifest["signing"]
    authorization = {"schema": "fidomanager.release-authorization/2", **context,
                     "worker_identity": {"cdhash": signing["cdhash"]["fido-worker"],
                                         "file_sha256": signing["release_worker_identity"]["worker_file_sha256"],
                                         "record_sha256": signing["release_worker_identity"]["sha256"]},
                     "assets": assets, "sha256sums": {"sha256": digest(sums), "size": len(sums)},
                     "notarization": {f"{name}_submission": manifest["notarization"][name]["submission_id"] for name in ("app", "dmg")}}
    return {sbom_name: sbom_bytes, "release-manifest.json": manifest_bytes, "SHA256SUMS": sums,
            "release-authorization.json": canonical(authorization)}


def check_asset_set(directory, expected):
    require(directory.is_dir() and not directory.is_symlink(), "asset directory must be regular")
    require({p.name for p in directory.iterdir()} == set(expected), "unexpected or missing release asset")
    for name in expected:
        # Validate before any digest use, rejecting directories, hardlinks, FIFOs and links.
        file_record(directory / name)


def generate(directory, context, manifest_input, inputs, identity, summary, code):
    dmg, app_zip, _ = names(context)
    check_asset_set(directory, (dmg, app_zip, "notary-app.json", "notary-dmg.json"))
    outputs = expected_outputs(directory, context, manifest_input, inputs, identity, summary, code)
    # Stage complete bytes before exposing any output. Hard-link promotion is
    # exclusive (never replaces an existing file) and atomic per artifact.
    # On an ordinary I/O failure, remove all artifacts promoted in this call.
    # Verify still requires the complete set and an independent D7.
    for name in outputs:
        require(not os.path.lexists(directory / name), f"output already exists: {name}")
    with tempfile.TemporaryDirectory(prefix=".fidomanager-release-", dir=directory) as temp:
        staging = Path(temp)
        for name, data in outputs.items():
            (staging / name).write_bytes(data)
        promoted = []
        try:
            for name in outputs:
                destination = directory / name
                os.link(staging / name, destination)
                promoted.append(destination)
        except BaseException:
            for destination in reversed(promoted):
                destination.unlink(missing_ok=True)
            raise
    return digest(outputs["release-authorization.json"])


def verify(directory, expected_d7, context, inputs, identity, summary, code, with_attestation=False):
    require(hex_value(expected_d7), "independent expected D7 required")
    raw = read_regular(directory / "release-authorization.json")
    require(digest(raw) == expected_d7, "authorization D7 mismatch")
    authorization = parse_json(raw)
    keys(authorization, "schema " + CONTEXT_KEYS + " worker_identity assets sha256sums notarization", "authorization")
    validate_context(context)
    require({k: authorization[k] for k in CONTEXT_KEYS.split()} == context, "authorization differs from trusted context")
    dmg, app_zip, sbom_name = names(context)
    required = {dmg, app_zip, sbom_name, "notary-app.json", "notary-dmg.json",
                "release-manifest.json", "SHA256SUMS", "release-authorization.json"}
    if with_attestation:
        required.add("release-attestations.sigstore.jsonl")
    check_asset_set(directory, required)
    manifest = read_json(directory / "release-manifest.json")
    validate_manifest(manifest, context)
    seed = {k: v for k, v in manifest.items() if k not in ("artifacts", "sbom", "native")}
    outputs = expected_outputs(directory, context, seed, inputs, identity, summary, code)
    for name, expected in outputs.items():
        require(read_regular(directory / name) == expected, f"{name}: content/consistency mismatch")
    return expected_d7


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect-sbom")
    collect.add_argument("--target", required=True)
    collect.add_argument("--frontend", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    for action in ("generate", "verify"):
        p = sub.add_parser(action)
        p.add_argument("--assets", type=Path, required=True)
        for name in ("context", "sbom-inputs", "build-identity", "package-summary", "code-evidence"):
            p.add_argument("--" + name, type=Path, required=True)
        if action == "generate":
            p.add_argument("--manifest-input", type=Path, required=True)
        else:
            p.add_argument("--with-attestation", action="store_true", help="require final asset set; does NOT authenticate its attestation")
            p.add_argument("--expected-d7", required=True, help="trusted job output; NEVER read from release assets")
    args = parser.parse_args()
    try:
        if args.command == "collect-sbom":
            collect_sbom(args.target, args.frontend, args.output)
            return
        common = (args.assets, read_json(args.context))
        evidence = (read_json(args.sbom_inputs), read_regular(args.build_identity),
                    read_regular(args.package_summary), read_json(args.code_evidence))
        if args.command == "generate":
            d7 = generate(*common, read_json(args.manifest_input), *evidence)
        else:
            d7 = verify(args.assets, args.expected_d7, common[1], *evidence, with_attestation=args.with_attestation)
        print(f"D7={d7}")
        print("PASS: local provenance integrity only; Apple evidence and GitHub attestation authentication remain external gates")
    except (CheckError, KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"FAIL: {error}")


if __name__ == "__main__":
    main()
