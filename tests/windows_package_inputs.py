"""Download and authenticate signed inputs for disposable Windows package tests."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import zipfile


REPOSITORY = "veldnetwork/Veld-Mainnet"
TRUSTED_329_NODE = "1efb09f9069f4cc12c7ff1112d3554a4c53946d30ba74b2eefeb70b6710c1230"


def command(args):
    return subprocess.check_output(list(map(str, args)), timeout=180)


def api(path):
    return json.loads(command(["gh", "api", "repos/" + REPOSITORY + "/" + path]))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(data, destination):
    destination.mkdir()
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert len(archive.infolist()) < 2500
        assert sum(info.file_size for info in archive.infolist()) < 1024**3
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            assert not path.is_absolute() and not {"..", "."}.intersection(path.parts)
            assert not any(char in info.filename for char in ("\\", ":", "\x00"))
            for component in path.parts:
                assert component and component == component.rstrip(" .")
                assert not re.fullmatch(
                    r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", component
                )
            assert info.filename.casefold() not in seen
            seen.add(info.filename.casefold())
            assert ((info.external_attr >> 16) & 0o170000) != 0o120000
            target = destination / info.filename
            assert target.resolve().is_relative_to(destination.resolve())
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
    manifests = list(destination.rglob("SHA256SUMS.txt"))
    assert len(manifests) == 1
    package = manifests[0].parent
    assert all(p.is_relative_to(package) for p in destination.rglob("*") if p.is_file())
    return package


def authenticate(package, verifier, version):
    manifest = package / "SHA256SUMS.txt"
    assert (
        command([verifier, "--verify-release", manifest, package / "SHA256SUMS.txt.sig"]).strip()
        == b"RELEASE-SIGNATURE-VALID"
    )
    lines = manifest.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == ["# veld-release-manifest-v1", "# release-version=" + version]
    names = set()
    for line in lines[2:]:
        assert re.fullmatch(r"[0-9a-f]{64} \*[^\r\n]+", line)
        digest, name = line.split(" *", 1)
        path = PurePosixPath(name)
        assert (
            not path.is_absolute()
            and ".." not in path.parts
            and "\\" not in name
            and ":" not in name
        )
        assert name.casefold() not in names
        names.add(name.casefold())
        assert sha((package / name).read_bytes()) == digest, name
    actual = {
        p.relative_to(package).as_posix().casefold() for p in package.rglob("*") if p.is_file()
    }
    assert actual == names | {"sha256sums.txt", "sha256sums.txt.sig"}


def download(release, destination):
    asset = next(a for a in release["assets"] if a["name"] == "VeldClient-Windows-x64.zip")
    assert asset["size"] < 512 * 1024**2
    data = command(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/octet-stream",
            "repos/" + REPOSITORY + "/releases/assets/" + str(asset["id"]),
        ]
    )
    assert len(data) == asset["size"]
    if asset.get("digest"):
        assert asset["digest"] == "sha256:" + sha(data)
    if release["draft"]:
        feed = destination.parent / "feed"
        feed.mkdir()
        (feed / asset["name"]).write_bytes(data)
        for name in (asset["name"] + ".sha256", asset["name"] + ".sha256.sig"):
            extra = next(a for a in release["assets"] if a["name"] == name)
            assert extra["size"] < 16384
            payload = command(
                [
                    "gh",
                    "api",
                    "-H",
                    "Accept: application/octet-stream",
                    "repos/" + REPOSITORY + "/releases/assets/" + str(extra["id"]),
                ]
            )
            assert len(payload) == extra["size"]
            assert extra["digest"] == "sha256:" + sha(payload)
            (feed / name).write_bytes(payload)
    return unpack(data, destination), {
        "release_id": release["id"],
        "asset_id": asset["id"],
        "sha256": sha(data),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version)
    assert re.fullmatch(r"[0-9a-f]{40}", args.source_commit)
    args.output.mkdir()
    old = api("releases/tags/v3.2.9")
    assert not old["draft"] and not old["prerelease"]
    releases = api("releases?per_page=100")
    new = next(r for r in releases if r["tag_name"] == "v" + args.version)
    assert new["draft"], "Qualification requires the unpublished draft candidate"
    previous, old_identity = download(old, args.output / "previous")
    old_node = previous / "bin/veld-node.exe"
    assert sha(old_node.read_bytes()) == TRUSTED_329_NODE, "Trusted verifier pin mismatch"
    trusted = args.output / "trusted"
    trusted.mkdir()
    verifier = trusted / "veld-node.exe"
    shutil.copyfile(old_node, verifier)
    authenticate(previous, verifier, "3.2.9")
    target, new_identity = download(new, args.output / "target")
    authenticate(target, verifier, args.version)
    checksum = args.output / "feed/VeldClient-Windows-x64.zip.sha256"
    assert (
        command(
            [
                verifier,
                "--verify-release",
                checksum,
                str(checksum) + ".sig",
            ]
        ).strip()
        == b"RELEASE-SIGNATURE-VALID"
    )
    assert checksum.read_text().splitlines() == [
        "# veld-release-zip-v1",
        "# release-version=" + args.version,
        new_identity["sha256"] + " *VeldClient-Windows-x64.zip",
    ]
    identity = json.loads((target / "BUILD-IDENTITY.json").read_text())
    assert identity["version"] == args.version
    assert re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"])
    assert identity["source_commit"] == args.source_commit
    assert (
        identity["source_tree"]
        == command(["git", "rev-parse", args.source_commit + "^{tree}"]).decode().strip()
    )
    assert (
        command(["git", "rev-parse", identity["source_commit"] + "^{tree}"]).decode().strip()
        == identity["source_tree"]
    )
    receipt = {
        "status": "PASS_AUTHENTICATED_INPUTS",
        "previous": str(previous.resolve()),
        "target": str(target.resolve()),
        "verifier": str(verifier.resolve()),
        "previous_identity": old_identity,
        "target_identity": new_identity,
        "source_identity": identity,
    }
    (args.output / "inputs.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["status"])


if __name__ == "__main__":
    main()
