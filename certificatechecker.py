#!/usr/bin/env python3
"""
Scan OCI/Docker images for certificates listed in distrusted-certs.json.

Image references may be tags or digests, for example:

    nginx:latest
    ghcr.io/org/app:1.2.3
    123456789012.dkr.ecr.eu-north-1.amazonaws.com/app@sha256:...

Authentication for private registries:

    GHCR_USERNAME="your-github-username"
    GHCR_TOKEN="your-github-token"

Image files are CSV: namespace, application, image (with an optional header).
Results are a human-readable table by default; --json emits JSON records.

Exit codes:
    0 - all images are PATCHED
    1 - at least one image is VULNERABLE
    2 - at least one image could not be checked
    3 - usage or certificate database error
"""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import http.client
import json
import os
import posixpath
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import BinaryIO


MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/json",
    ]
)

CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?"
    rb"-----END CERTIFICATE-----",
    re.DOTALL,
)


@dataclass(frozen=True)
class DistrustedCertificate:
    sha256: str
    kind: str
    name: str
    der: bytes
    pem: bytes


@dataclass(frozen=True)
class ImageTarget:
    namespace: str
    application: str
    image: str


@dataclass
class ImageResult:
    image: str
    status: str
    findings: list[dict]
    namespace: str = ""
    application: str = ""
    jvm_detected: bool = False
    jvm_evidence: list[str] = field(default_factory=list)
    java_truststores: list[dict] = field(default_factory=list)
    error: str | None = None


class RegistryError(Exception):
    pass


JAVA_DEFAULT_TRUSTSTORE_NAMES = {"cacerts", "jssecacerts"}
JAVA_TRUSTSTORE_PROPERTY_RE = re.compile(
    r"-Djavax\.net\.ssl\.trustStore=([^\s\"']+)"
)


def is_java_runtime_path(path: str) -> bool:
    normalized = path.lower().strip("/")
    basename = normalized.rsplit("/", 1)[-1]

    return (
        basename in {"libjvm.so", "jvm.dll"}
        or (
            basename in {"java", "java.exe", "javaw.exe"}
            and "/bin/" in f"/{normalized}"
        )
    )


def is_default_java_truststore(path: str) -> bool:
    normalized = path.lower().strip("/")
    basename = normalized.rsplit("/", 1)[-1]
    parts = normalized.split("/")

    return (
        basename in JAVA_DEFAULT_TRUSTSTORE_NAMES
        and (
            "security" in parts
            or normalized == "etc/ssl/certs/java/cacerts"
        )
    )


def image_java_settings(config: dict) -> tuple[set[str], list[str], bool]:
    """Return configured trust-store paths, JVM evidence, and startup detection."""
    image_config = config.get("config", {})
    working_dir = image_config.get("WorkingDir") or "/"
    configured_paths: set[str] = set()
    evidence: list[str] = []
    jvm_startup = False

    env = image_config.get("Env", [])
    entrypoint = image_config.get("Entrypoint", [])
    command = image_config.get("Cmd", [])
    env = env if isinstance(env, list) else []
    entrypoint = entrypoint if isinstance(entrypoint, list) else []
    command = command if isinstance(command, list) else []
    config_values = [
        value for value in env + entrypoint + command if isinstance(value, str)
    ]

    for value in config_values:
        for match in JAVA_TRUSTSTORE_PROPERTY_RE.finditer(value):
            store_path = match.group(1)
            if "$" in store_path:
                evidence.append(
                    f"Unresolved Java trust-store setting: {store_path}"
                )
                jvm_startup = True
                continue

            if not store_path.startswith("/"):
                store_path = posixpath.join(working_dir, store_path)
            store_path = posixpath.normpath(store_path).lstrip("/")
            configured_paths.add(store_path)
            evidence.append(f"Configured Java trust store: {store_path}")
            jvm_startup = True

    for item in entrypoint + command:
        if isinstance(item, str) and re.search(
            r"(^|[/\s])java(?:w)?(?:\.exe)?(?=$|[\s])",
            item,
            re.IGNORECASE,
        ):
            jvm_startup = True
            evidence.append(f"Image startup command: {item}")

    return configured_paths, evidence, jvm_startup


class RegistryClient:
    def __init__(self, registry: str):
        self.registry = registry
        self._bearer_token: str | None = None

        # GitHub Container Registry authentication.
        #
        # GHCR requires a GitHub username and PAT using HTTP Basic auth.
        # The token is only enabled for ghcr.io and is never sent to another
        # registry by this client.
        if registry.lower() in {"ghcr.io", "docker.pkg.github.com"}:
            self.user = (
                os.environ.get("GHCR_USERNAME")
                or os.environ.get("GITHUB_ACTOR")
            )
            self.password = (
                os.environ.get("GHCR_TOKEN")
                or os.environ.get("GITHUB_TOKEN")
            )
        else:
            self.user = None
            self.password = None

    def _authentication_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}

        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self.user and self.password:
            raw = f"{self.user}:{self.password}".encode("utf-8")
            encoded = base64.b64encode(raw).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    def _url(self, path: str) -> str:
        return f"https://{self.registry}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        accept: str | None = None,
        retry_auth: bool = True,
    ) -> tuple[object, bytes]:
        headers = {
            "User-Agent": "emudhra-checker-image-scanner/1.0",
            "Accept": accept or "*/*",
        }
        headers.update(self._authentication_headers())

        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self.user is not None and self.password is not None:
            value = base64.b64encode(
                f"{self.user}:{self.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {value}"

        request = urllib.request.Request(
            self._url(path),
            method=method,
            headers=headers,
        )

        try:
            response = urllib.request.urlopen(request, timeout=60)
            return response, response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and retry_auth:
                challenge = exc.headers.get("WWW-Authenticate", "")
                if challenge.lower().startswith("bearer "):
                    self._authenticate_bearer(challenge)
                    return self._request(
                        method,
                        path,
                        accept=accept,
                        retry_auth=False,
                    )

            body = exc.read().decode("utf-8", errors="replace")
            raise RegistryError(
                f"{method} {self._url(path)} returned HTTP {exc.code}: {body[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RegistryError(
                f"{method} {self._url(path)} failed: {exc.reason}"
            ) from exc

    def _authenticate_bearer(self, challenge: str) -> None:
        values = dict(
            re.findall(
                r'(\w+)="([^"]*)"',
                challenge,
            )
        )

        realm = values.get("realm")
        if not realm:
            raise RegistryError("Registry requested bearer auth without a realm")

        query = {}
        if values.get("service"):
            query["service"] = values["service"]
        if values.get("scope"):
            query["scope"] = values["scope"]

        token_url = realm
        if query:
            token_url += "?" + urllib.parse.urlencode(query)

        headers = {
            "User-Agent": "emudhra-checker-image-scanner/1.0",
        }

        if self.user and self.password:
            raw = f"{self.user}:{self.password}".encode("utf-8")
            encoded = base64.b64encode(raw).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"

        request = urllib.request.Request(token_url, headers=headers)

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                token_data = json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RegistryError(f"Could not obtain registry bearer token: {exc}") from exc

        self._bearer_token = token_data.get("token") or token_data.get("access_token")
        if not self._bearer_token:
            raise RegistryError("Registry bearer token response contained no token")

    def get_json(self, path: str, accept: str) -> dict:
        _, body = self._request("GET", path, accept=accept)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"Invalid JSON returned by registry: {exc}") from exc

    def get_blob(self, repository: str, digest: str) -> tuple[object, bytes]:
        path = f"/v2/{repository}/blobs/{digest}"
        response, body = self._request("GET", path)
        return response, body

    def get_blob_stream(self, repository: str, digest: str):
        path = f"/v2/{repository}/blobs/{digest}"

        headers = {
            "User-Agent": "emudhra-checker-image-scanner/1.0",
            "Accept": "*/*",
        }
        headers.update(self._authentication_headers())

        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self.user is not None and self.password is not None:
            raw = f"{self.user}:{self.password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()

        request = urllib.request.Request(self._url(path), headers=headers)

        try:
            return urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                challenge = exc.headers.get("WWW-Authenticate", "")
                if challenge.lower().startswith("bearer "):
                    self._authenticate_bearer(challenge)
                    return self.get_blob_stream(repository, digest)

            body = exc.read().decode("utf-8", errors="replace")
            raise RegistryError(
                f"GET {self._url(path)} returned HTTP {exc.code}: {body[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RegistryError(
                f"GET {self._url(path)} failed: {exc.reason}"
            ) from exc


def parse_image_reference(image: str) -> tuple[str, str, str]:
    """
    Return registry, repository, reference.

    Docker's default registry and namespace are applied for short references.
    """
    image = image.strip()
    if not image:
        raise ValueError("Empty image reference")

    first, separator, remainder = image.partition("/")
    if not separator or "." not in first and ":" not in first and first != "localhost":
        registry = "registry-1.docker.io"
        repository_and_ref = image
    else:
        registry = first
        repository_and_ref = remainder

    if "@sha256:" in repository_and_ref:
        repository, reference = repository_and_ref.split("@", 1)
    else:
        if ":" in repository_and_ref.rsplit("/", 1)[-1]:
            repository, reference = repository_and_ref.rsplit(":", 1)
        else:
            repository, reference = repository_and_ref, "latest"

    if registry == "registry-1.docker.io" and "/" not in repository:
        repository = "library/" + repository

    return registry, repository, reference


def load_certificates(path: str) -> list[DistrustedCertificate]:
    with open(path, "r", encoding="utf-8") as file:
        document = json.load(file)

    certificates = []
    for item in document.get("certificates", []):
        pem = item["pem"].encode("ascii")
        der = base64.b64decode(
            b"".join(
                line.strip()
                for line in pem.splitlines()
                if not line.startswith(b"-----")
            ),
            validate=True,
        )

        actual_sha256 = hashlib.sha256(der).hexdigest()
        expected_sha256 = item["sha256"].lower()

        if actual_sha256 != expected_sha256:
            raise ValueError(
                f"Certificate fingerprint mismatch for {item['name']}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )

        certificates.append(
            DistrustedCertificate(
                sha256=expected_sha256,
                kind=item["kind"],
                name=item["name"],
                der=der,
                pem=pem,
            )
        )

    if not certificates:
        raise ValueError(f"No certificates found in {path}")

    return certificates


def verify_digest(data: bytes, digest: str) -> None:
    algorithm, expected = digest.split(":", 1)
    if algorithm != "sha256":
        raise RegistryError(f"Unsupported digest algorithm: {algorithm}")

    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise RegistryError(
            f"Digest mismatch: expected {digest}, got sha256:{actual}"
        )


def select_manifest(manifest: dict) -> dict:
    """
    Resolve a multi-platform manifest index.

    Linux amd64 is preferred, followed by linux/arm64, then the first entry.
    """
    manifests = manifest.get("manifests")
    if not manifests:
        return manifest

    preferred = [
        ("linux", "amd64"),
        ("linux", "arm64"),
    ]

    for wanted_os, wanted_arch in preferred:
        for candidate in manifests:
            platform = candidate.get("platform", {})
            if (
                platform.get("os") == wanted_os
                and platform.get("architecture") == wanted_arch
            ):
                return candidate

    return manifests[0]


def find_certificates(
    data: bytes,
    certificates: list[DistrustedCertificate],
) -> list[DistrustedCertificate]:
    found: dict[str, DistrustedCertificate] = {}

    for certificate in certificates:
        if certificate.der in data:
            found[certificate.sha256] = certificate

    for pem_match in CERT_RE.finditer(data):
        normalized = b"\n".join(
            line.strip() for line in pem_match.group(0).splitlines()
        )
        for certificate in certificates:
            expected = b"\n".join(
                line.strip() for line in certificate.pem.splitlines()
            )
            if normalized == expected:
                found[certificate.sha256] = certificate

    return list(found.values())


def scan_layer(
    stream: BinaryIO,
    layer_digest: str,
    certificates: list[DistrustedCertificate],
    filesystem_findings: dict[str, dict],
    java_truststores: dict[str, dict],
    java_runtime_files: dict[str, str],
    configured_truststores: set[str],
) -> None:
    """
    Scan a tar layer and apply Docker whiteout semantics.

    Findings are stored by final filesystem path, so a certificate removed by a
    later layer is not reported.
    """
    raw = stream

    # OCI/Docker layers are normally gzip-compressed. tarfile's streaming mode
    # can read gzip data directly, but explicitly handling it also supports
    # registries that omit the Content-Encoding header.
    buffered = raw
    try:
        buffered = gzip.GzipFile(fileobj=raw, mode="rb")
        tar = tarfile.open(fileobj=buffered, mode="r|")
    except (OSError, tarfile.TarError):
        if buffered is not raw:
            try:
                buffered.close()
            except Exception:
                pass
        tar = tarfile.open(fileobj=raw, mode="r|")

    with tar:
        for member in tar:
            path = member.name.lstrip("./")
            if not path:
                continue

            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            basename = path.rsplit("/", 1)[-1]

            # .wh..wh..opq removes all previous children of this directory.
            if basename == ".wh..wh..opq":
                prefix = parent + "/" if parent else ""
                for paths in (
                    filesystem_findings,
                    java_truststores,
                    java_runtime_files,
                ):
                    for existing in list(paths):
                        if existing.startswith(prefix):
                            del paths[existing]
                continue

            # .wh.<name> removes the named previous file or directory.
            if basename.startswith(".wh."):
                deleted = basename[4:]
                deleted_path = f"{parent}/{deleted}" if parent else deleted

                for paths in (
                    filesystem_findings,
                    java_truststores,
                    java_runtime_files,
                ):
                    for existing in list(paths):
                        if (
                            existing == deleted_path
                            or existing.startswith(deleted_path + "/")
                        ):
                            del paths[existing]
                continue

            if member.isdir():
                continue

            if is_java_runtime_path(path):
                java_runtime_files[path] = layer_digest

            is_truststore = (
                path in configured_truststores
                or is_default_java_truststore(path)
            )

            # A later layer may replace a matching file with a clean one.
            filesystem_findings.pop(path, None)
            java_truststores.pop(path, None)

            if not member.isfile():
                continue

            extracted = tar.extractfile(member)
            if extracted is None:
                continue

            with extracted:
                content = extracted.read()

            matches = find_certificates(content, certificates)
            file_sha256 = hashlib.sha256(content).hexdigest()

            if matches:
                filesystem_findings[path] = {
                    "path": path,
                    "layer_digest": layer_digest,
                    "file_sha256": file_sha256,
                    "certificates": [
                        {
                            "name": cert.name,
                            "kind": cert.kind,
                            "sha256": cert.sha256,
                        }
                        for cert in matches
                    ],
                }

            if is_truststore:
                java_truststores[path] = {
                    "path": path,
                    "layer_digest": layer_digest,
                    "file_sha256": file_sha256,
                    "certificates": [
                        {
                            "name": cert.name,
                            "kind": cert.kind,
                            "sha256": cert.sha256,
                        }
                        for cert in matches
                    ],
                }


def scan_image(
    target: ImageTarget,
    certificates: list[DistrustedCertificate],
) -> ImageResult:
    image = target.image
    try:
        registry, repository, reference = parse_image_reference(image)
        client = RegistryClient(registry)

        manifest_path = f"/v2/{repository}/manifests/{reference}"
        manifest = client.get_json(manifest_path, MANIFEST_ACCEPT)

        selected = select_manifest(manifest)

        # A manifest index points to another manifest by digest.
        if selected is not manifest:
            digest = selected.get("digest")
            if not digest:
                raise RegistryError("Manifest index entry has no digest")

            selected = client.get_json(
                f"/v2/{repository}/manifests/{digest}",
                MANIFEST_ACCEPT,
            )

        config_descriptor = selected.get("config", {})
        config_digest = config_descriptor.get("digest")
        if not config_digest:
            raise RegistryError("Image manifest has no config digest")
        config_response, config_bytes = client.get_blob(
            repository,
            config_digest,
        )
        config_response.close()
        verify_digest(config_bytes, config_digest)
        try:
            image_config = json.loads(config_bytes)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"Invalid image config JSON: {exc}") from exc

        configured_truststores, jvm_evidence, jvm_startup = image_java_settings(
            image_config
        )

        layers = selected.get("layers")
        if not isinstance(layers, list):
            raise RegistryError("Image manifest contains no layers")

        filesystem_findings: dict[str, dict] = {}
        java_truststores: dict[str, dict] = {}
        java_runtime_files: dict[str, str] = {}

        for layer in layers:
            digest = layer.get("digest")
            if not digest:
                raise RegistryError("Image layer has no digest")

            response = client.get_blob_stream(repository, digest)

            # Hash the compressed blob while it is downloaded. The layer itself
            # is then scanned as a streaming tar archive.
            hasher = hashlib.sha256()

            class HashingReader:
                def read(self, size: int = -1) -> bytes:
                    chunk = response.read(size)
                    if chunk:
                        hasher.update(chunk)
                    return chunk

            try:
                scan_layer(
                    HashingReader(),
                    digest,
                    certificates,
                    filesystem_findings,
                    java_truststores,
                    java_runtime_files,
                    configured_truststores,
                )
            finally:
                response.close()

            actual = hasher.hexdigest()
            expected = digest.split(":", 1)[1]
            if actual != expected:
                raise RegistryError(
                    f"Layer digest mismatch for {digest}: sha256:{actual}"
                )

        findings = list(filesystem_findings.values())
        jvm_evidence.extend(
            f"JVM runtime file: {path} (layer {digest})"
            for path, digest in sorted(java_runtime_files.items())
        )
        detected_jvm = jvm_startup or bool(java_runtime_files)

        if findings:
            return ImageResult(
                image=image,
                status="VULNERABLE",
                findings=findings,
                namespace=target.namespace,
                application=target.application,
                jvm_detected=detected_jvm,
                jvm_evidence=jvm_evidence,
                java_truststores=list(java_truststores.values()),
            )

        return ImageResult(
            image=image,
            status="PATCHED",
            findings=[],
            namespace=target.namespace,
            application=target.application,
            jvm_detected=detected_jvm,
            jvm_evidence=jvm_evidence,
            java_truststores=list(java_truststores.values()),
        )

    except Exception as exc:
        return ImageResult(
            image=image,
            status="UNKNOWN",
            findings=[],
            namespace=target.namespace,
            application=target.application,
            error=str(exc),
        )


def is_csv_header(row: list[str]) -> bool:
    if len(row) < 3:
        return False

    header = [
        column.strip().lstrip("\ufeff").casefold()
        for column in row[:3]
    ]
    return (
        header[0] in {"namespace", "kubernetes namespace"}
        and header[1] in {"application", "application name", "app"}
        and header[2] in {"image", "image name", "image reference"}
    )


def read_images(args: argparse.Namespace) -> list[ImageTarget]:
    targets = [
        ImageTarget(namespace="", application="", image=image.strip())
        for image in args.images
        if image.strip()
    ]

    if args.image_file:
        source = args.image_file
        if source == "-":
            file = sys.stdin
        else:
            file = open(source, "r", encoding="utf-8-sig", newline="")

        try:
            reader = csv.reader(file)
            first_record = True
            for row in reader:
                if not row or all(not column.strip() for column in row):
                    continue
                if row[0].lstrip().startswith("#"):
                    continue
                if first_record and is_csv_header(row):
                    first_record = False
                    continue
                first_record = False

                if len(row) < 3:
                    raise ValueError(
                        f"{source}:{reader.line_num}: expected at least 3 "
                        "CSV columns (namespace, application, image)"
                    )

                namespace, application, image = (
                    column.strip() for column in row[:3]
                )
                if not namespace or not application or not image:
                    raise ValueError(
                        f"{source}:{reader.line_num}: namespace, application, "
                        "and image must not be empty"
                    )
                targets.append(
                    ImageTarget(
                        namespace=namespace,
                        application=application,
                        image=image,
                    )
                )
        except csv.Error as exc:
            raise ValueError(f"{source}:{reader.line_num}: invalid CSV: {exc}") from exc
        finally:
            if file is not sys.stdin:
                file.close()

    # Preserve order while removing duplicate input records.
    unique_targets: dict[tuple[str, str, str], ImageTarget] = {}
    for target in targets:
        key = (target.namespace, target.application, target.image)
        unique_targets.setdefault(key, target)
    return list(unique_targets.values())


def print_results_table(results: list[ImageResult]) -> None:
    headers = [
        "namespace",
        "application name",
        "image name",
        "vulnerability status",
    ]
    rows = [
        [
            result.namespace or "-",
            result.application or "-",
            result.image,
            result.status,
        ]
        for result in results
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]

    print(" | ".join(header.ljust(width) for header, width in zip(headers, widths)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(width) for value, width in zip(row, widths)))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan OCI/Docker images for distrusted certificates, including "
            "Java trust stores."
        )
    )
    parser.add_argument(
        "images",
        nargs="*",
        help="Image references to scan",
    )
    parser.add_argument(
        "-f",
        "--image-file",
        help=(
            "CSV with namespace, application, and image in the first three "
            "columns; use '-' for stdin"
        ),
    )
    parser.add_argument(
        "-c",
        "--certificates",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "distrusted-certs.json",
        ),
        help="Certificate database JSON file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON object per image",
    )

    args = parser.parse_args()
    try:
        images = read_images(args)
    except (OSError, ValueError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 3

    if not images:
        parser.error("provide image references or a non-empty --image-file")

    try:
        certificates = load_certificates(args.certificates)
    except Exception as exc:
        print(f"certificate database error: {exc}", file=sys.stderr)
        return 3

    exit_code = 0
    results = []

    for target in images:
        label = (
            f"{target.namespace}/{target.application} ({target.image})"
            if target.namespace or target.application
            else target.image
        )
        print(f"Scanning {label}...", file=sys.stderr)
        result = scan_image(target, certificates)
        results.append(result)

        if result.status == "VULNERABLE":
            exit_code = max(exit_code, 1)
        elif result.status == "UNKNOWN":
            exit_code = max(exit_code, 2)

    if args.json:
        for result in results:
            print(json.dumps(result.__dict__, indent=2))
    else:
        print_results_table(results)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())