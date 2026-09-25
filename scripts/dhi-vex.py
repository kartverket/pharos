#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote
from urllib.request import urlopen

SUPPRESS_STATUSES = {"not_affected", "fixed"}
BASE_COMPONENTS = ["debian-base", "alpine-base"]


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def normalize_debian_version(version):
    if not version:
        return ""

    if ":" in version:
        version = version.split(":", 1)[1]

    if "-" in version:
        version = version.split("-", 1)[0]

    for suffix in ("+dhi", "+deb"):
        if suffix in version:
            version = version.split(suffix, 1)[0]

    return version


def parse_deb_purl(value):
    if not value.startswith("pkg:deb/debian/"):
        return None

    path = value.removeprefix("pkg:deb/debian/").split("?", 1)[0]

    if "@" not in path:
        return unquote(path), None

    name, version = path.split("@", 1)
    return unquote(name), unquote(version)


def dhi_components(image):
    return [candidate[0] for candidate in dhi_candidates(image)]


def dhi_candidates(image):
    try:
        output = run(
            "docker", "buildx", "imagetools", "inspect", image,
            "--format", "{{json .Provenance.SLSA.buildDefinition.resolvedDependencies}}",
        )
    except subprocess.CalledProcessError as exc:
        print(f"::warning::Could not read provenance for {image}: {exc}", file=sys.stderr)
        return []

    dependencies = json.loads(output) if output and output != "null" else []
    candidates = []

    for dependency in dependencies:
        uri = dependency.get("uri", "")
        digest = dependency.get("digest", {}).get("sha256")
        if not uri.startswith("pkg:docker/dhi.io/") or not digest:
            continue

        name = uri.removeprefix("pkg:docker/dhi.io/").split("?", 1)[0]
        if "@" in name:
            name = name.split("@", 1)[0]

        candidate = (name, f"dhi.io/{name}@sha256:{digest}")
        if name and candidate not in candidates:
            candidates.append(candidate)

    return candidates


def image_layers(image):
    output = run("docker", "image", "inspect", image, "--format", "{{json .RootFS.Layers}}")
    return json.loads(output)


def command_base_layers(image, output_path):
    child_layers = image_layers(image)
    matches = []

    for _, candidate in dhi_candidates(image):
        subprocess.check_call(["docker", "pull", candidate], stdout=sys.stderr)
        base_layers = image_layers(candidate)

        if child_layers[:len(base_layers)] == base_layers:
            matches.append((len(base_layers), candidate, base_layers))

    if not matches:
        print("::error::Could not prove a DHI base-layer boundary from provenance", file=sys.stderr)
        sys.exit(1)

    matches.sort(reverse=True)
    longest_count = matches[0][0]
    longest_matches = [match for match in matches if match[0] == longest_count]

    if len(longest_matches) != 1:
        print("::error::Multiple DHI base images match the child layer prefix", file=sys.stderr)
        sys.exit(1)

    _, base_image, base_layers = longest_matches[0]
    with open(output_path, "w") as target:
        json.dump(base_layers, target)

    print(f"Verified DHI base image: {base_image}")
    print(f"Verified DHI base layers: {len(base_layers)}")

def command_debian_source_map(image, output_path):
    # Most DHI runtime images have no shell, so read the dpkg database
    # from a stopped container instead of executing anything inside it.
    container_id = run("docker", "create", image)
    status_path = output_path.with_suffix(".status")

    try:
        subprocess.check_call(["docker", "cp", f"{container_id}:/var/lib/dpkg/status", str(status_path)])
    finally:
        subprocess.call(["docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL)

    mappings = []

    for record in status_path.read_text().split("\n\n"):
        fields = {}
        current_key = None

        for line in record.splitlines():
            if line.startswith((" ", "\t")) and current_key:
                fields[current_key] += "\n" + line
            elif ":" in line:
                current_key, value = line.split(":", 1)
                fields[current_key] = value.strip()

        package_name = fields.get("Package")
        package_version = fields.get("Version")
        source = fields.get("Source", "")

        if source:
            source_parts = source.split()
            source_name = source_parts[0]
            source_version = source_parts[1].strip("()") if len(source_parts) > 1 else package_version
        else:
            source_name = package_name
            source_version = package_version

        if package_name and package_version and source_name:
            mappings.append(f"{package_name}\t{source_name}\t{package_version}\t{source_version}")

    status_path.unlink(missing_ok=True)

    if not mappings:
        print("::error::Debian package database contained no package mappings", file=sys.stderr)
        sys.exit(1)

    output_path.write_text("\n".join(mappings) + "\n")
    print(f"Extracted {len(mappings)} Debian binary/source package mappings")

def download_component(component, output_dir):
    url = f"https://raw.githubusercontent.com/docker-hardened-images/advisories/main/vex/{component}/dhi-{component}.vex.json"
    output_path = output_dir / f"{component}.vex.json"

    try:
        with urlopen(url) as response:
            document = json.load(response)
    except Exception as exc:
        print(f"No consolidated DHI VEX document for '{component}' (skipping): {exc}")
        return

    with open(output_path, "w") as target:
        json.dump(document, target, separators=(",", ":"))

    statements = len(document.get("statements", []))
    print(f"Downloaded DHI VEX document for '{component}' ({statements} statements)")


def command_download(image, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    components = BASE_COMPONENTS + dhi_components(image)
    seen = set()

    for component in components:
        if component in seen:
            continue

        seen.add(component)
        download_component(component, output_dir)


def add_match(matches, vulnerability_id, package_name, version, statement):
    if not vulnerability_id or not package_name:
        return

    key = (vulnerability_id, package_name, normalize_debian_version(version or ""))
    matches.setdefault(key, []).append(statement)


def load_vex_matches(vex_dir):
    matches = {}

    for path in sorted(vex_dir.glob("*.vex.json")):
        with open(path) as source:
            document = json.load(source)

        for statement in document.get("statements", []):
            status = statement.get("status")
            if status not in SUPPRESS_STATUSES:
                continue

            vulnerability = statement.get("vulnerability", {})
            vulnerability_ids = [vulnerability.get("name"), *vulnerability.get("aliases", [])]
            vulnerability_ids = [item for item in vulnerability_ids if item]

            versioned_products = []
            unversioned_products = []

            for product in statement.get("products", []):
                parsed = parse_deb_purl(product.get("@id", ""))
                if parsed:
                    package_name, version = parsed
                    (versioned_products if version else unversioned_products).append((package_name, version))

                for subcomponent in product.get("subcomponents", []):
                    parsed = parse_deb_purl(subcomponent.get("@id", ""))
                    if parsed:
                        package_name, version = parsed
                        (versioned_products if version else unversioned_products).append((package_name, version))

            statement_context = {
                "status": status,
                "justification": statement.get("justification"),
                "status_notes": statement.get("status_notes"),
                "source": str(path),
            }

            for vulnerability_id in vulnerability_ids:
                for package_name, version in versioned_products:
                    add_match(matches, vulnerability_id, package_name, version, statement_context)

                for package_name, _ in unversioned_products:
                    for _, version in versioned_products:
                        add_match(matches, vulnerability_id, package_name, version, statement_context)

    return matches


def load_source_map(path):
    source_map = {}

    if not path.exists():
        return source_map

    with open(path) as source:
        for line in source:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue

            binary_name, source_name, binary_version, source_version = parts
            if not binary_name or not source_name:
                continue

            source_map[binary_name] = {
                "source_name": source_name,
                "source_version": source_version or binary_version,
                "binary_version": binary_version,
            }

    return source_map


def vulnerability_keys(vulnerability, source_map):
    vulnerability_id = vulnerability.get("VulnerabilityID")
    installed = vulnerability.get("InstalledVersion", "")
    package_name = vulnerability.get("PkgName")
    names = [package_name, vulnerability.get("SrcName"), vulnerability.get("SourceName")]
    versions = [installed, vulnerability.get("SrcVersion"), vulnerability.get("SourceVersion")]

    for name in names:
        if not name:
            continue

        for version in versions:
            if version:
                yield vulnerability_id, name, normalize_debian_version(version)

    source_package = source_map.get(package_name or "")
    if source_package:
        yield vulnerability_id, source_package["source_name"], normalize_debian_version(source_package["source_version"])
        yield vulnerability_id, source_package["source_name"], normalize_debian_version(source_package["binary_version"])


def command_filter(input_path, vex_dir, output_path, suppressed_path, source_map_path, base_layers_path):
    with open(input_path) as source:
        report = json.load(source)

    matches = load_vex_matches(vex_dir)
    source_map = load_source_map(source_map_path)
    with open(base_layers_path) as source:
        base_layers = set(json.load(source))
    print(f"Loaded {len(matches)} DHI VEX match keys")
    print(f"Loaded {len(source_map)} Debian binary/source package mappings")
    print(f"Loaded {len(base_layers)} verified DHI base layers")

    suppressed = []
    kept_count = 0

    for result in report.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities")
        if not vulnerabilities:
            continue

        kept = []
        for vulnerability in vulnerabilities:
            match = None
            layer = vulnerability.get("Layer", {}).get("DiffID")

            if layer in base_layers:
                for key in vulnerability_keys(vulnerability, source_map):
                    if key in matches:
                        match = matches[key][0]
                        break

            if match:
                record = dict(vulnerability)
                record["DhiVex"] = match
                record["Target"] = result.get("Target")
                suppressed.append(record)
            else:
                kept.append(vulnerability)
                kept_count += 1

        result["Vulnerabilities"] = kept

    with open(output_path, "w") as target:
        json.dump(report, target)

    with open(suppressed_path, "w") as target:
        json.dump(suppressed, target)

    print(f"Suppressed {len(suppressed)} findings with DHI VEX post-filter")
    print(f"Kept {kept_count} findings after DHI VEX post-filter")


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""

    if command == "download" and len(sys.argv) == 4:
        command_download(sys.argv[2], Path(sys.argv[3]))
    elif command == "base-layers" and len(sys.argv) == 4:
        command_base_layers(sys.argv[2], Path(sys.argv[3]))
    elif command == "debian-source-map" and len(sys.argv) == 4:
        command_debian_source_map(sys.argv[2], Path(sys.argv[3]))
    elif command == "filter" and len(sys.argv) == 8:
        command_filter(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]))
    else:
        print(
            "Usage:\n"
            "  dhi-vex.py download <image> <output-dir>\n"
            "  dhi-vex.py base-layers <image> <output-json>\n"
            "  dhi-vex.py debian-source-map <image> <output-tsv>\n"
            "  dhi-vex.py filter <trivy-json> <vex-dir> <output-json> <suppressed-json> <source-map> <base-layers>",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()