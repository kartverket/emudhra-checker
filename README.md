# emudhra-checker

**Disclosure: eMudhra-checker has been developed with the aid of Github Copilot and Claude Code**

Scans container images for the certificates affected by the October 2026
eMudhra CA key compromise. It reads images straight from the registry (no
Docker daemon needed), walks every layer, and reports each image as
`VULNERABLE`, `PARTIALLY_MITIGATED`, `MITIGATED`, `PATCHED` or `UNKNOWN`.

It is made to check whole clusters. The input is one CSV file per cluster,
with the namespace, name, image and Kubernetes kind of each workload. The
output is one sorted report as a table, CSV or JSON.

## Build

Requires Go 1.27.3 or later. Go 1.27.3 is also the release whose
`crypto/x509` rejects the compromised intermediate keys, so the scanner's own
registry connections are protected.

```bash
go build ./cmd/emudhra-checker
```

This produces a single `./emudhra-checker` binary. To install it in your Go
bin directory instead:

```bash
go install github.com/kartverket/emudhra-checker/cmd/emudhra-checker@latest
```

The certificate database (`internal/certdb/distrusted-certs.json`) is
embedded in the binary, so it runs on its own. Use `-c` to scan with a
different database file.

## Usage

Scan a few images directly:

```bash
./emudhra-checker nginx:1.27 registry.example.com/team/app:1.2.3
```

Scan one cluster from an input file (see [Input files](#input-files) for how
to export one per cluster):

```bash
./emudhra-checker -f inputs/cluster-a.txt
```

Scan several clusters in one run. Repeat `-f` once per file:

```bash
./emudhra-checker -o csv -f inputs/cluster-a.txt -f inputs/cluster-b.txt > report.csv
```

To scan every file in `inputs/`, build the `-f` flags in a loop. Do not write
`-f inputs/*.txt`: the shell expands it to `-f inputs/cluster-a.txt
inputs/cluster-b.txt …`, and every file after the first is read as an image
name.

```bash
args=()
for file in inputs/*.txt; do args+=(-f "$file"); done
./emudhra-checker -o csv "${args[@]}" > report.csv
```

The cluster name is the file name without its extension, so
`inputs/cluster-a.txt` becomes `cluster-a`. Use `-f -` to read from stdin (the
cluster column is then empty).

The report goes to stdout. Progress and errors go to stderr as structured log
lines ([log/slog](https://pkg.go.dev/log/slog) text format). The first line
names the build and the parallelism in use. Each image gets one line when it
starts and one line when it finishes, with its status and duration. For an
image that the scanner cannot check, the line gives the reason. While images
run, a `still scanning` line lists them every 30 seconds with their duration.
Thus a large download does not look like a hang:

```text
level=INFO msg=starting version=v0.0.0-20261023154123-d43beacc5eae+dirty go=go1.27.3 parallelism=10 parallelism_from=default
level=INFO msg="scanning image" image=registry.example.com/team/api:1.4.0
level=INFO msg="scanning image" image=registry.example.com/team/map-server:2.1
level=INFO msg="scanned image" status=VULNERABLE image=registry.example.com/team/api:1.4.0 duration=4.2s
level=ERROR msg="could not check image" status=ERR_DOCKER_PULL image=registry.example.com/team/private:2.0 duration=700ms error="cannot pull image: fetch manifest: GET https://registry.example.com/token?...: DENIED: denied"
level=INFO msg="still scanning" finished=150 in_progress=1 images="registry.example.com/team/map-server:2.1 (2m30s)"
level=INFO msg=finished rows=351 images=153
```

Each line also starts with a `time=` field. `version` is the module version
that Go records at build time. For a build from a git checkout, it names the
commit, with `+dirty` when there were uncommitted changes. Image lines name
only the image, because one scan serves every row that uses the image. The
report shows the rows.

### Options

| Flag | Meaning |
|---|---|
| `-f`, `--image-file FILE` | CSV input file. Repeat for several clusters. `-` reads stdin. |
| `-o`, `--output FORMAT` | `table` (default), `csv`, or `json`. |
| `-l`, `--local` | Read all images from the local Docker installation, not from their registries (see [Local images](#local-images)). |
| `-c`, `--certificates FILE` | Certificate database to use instead of the embedded one. |
| `--parallel N` | Images to scan at the same time, 1–10 (default 10). |
| `-h`, `--help` | Show the options. |

`CERTIFICATECHECKER_PARALLELISM` sets the default for `--parallel`.

Each image is downloaded and scanned once per run, however many rows name it.
This also applies to a failed pull: the scanner does not try it again for the
next row. References with a different spelling for the same image count as one
(`nginx` and `docker.io/library/nginx:latest`, or `app:v1@sha256:…` and
`app@sha256:…`). Workers only get images that have not started. Thus a long
run of rows with the same image does not delay the other images.

## Input files

Each row is `namespace,name,image,kind`. The `kind` column is optional. It
holds the Kubernetes kind of the workload as written, for example
`Deployment`, `StatefulSet`, `CronJob` or the kind of a custom resource. The
scanner skips a header row, blank lines and lines that start with `#`. It
ignores further columns.

```csv
namespace,name,image,kind
"shop","web","registry.example.com/team/web:1.4.0","Deployment"
"ops","backup","registry.example.com/team/backup@sha256:9f86d0...","CronJob"
```

To export the workloads of several clusters, list their kubeconfig contexts
in `CONTEXTS`. The loop writes one input file per context
(`inputs/cluster-a.txt`, `inputs/cluster-b.txt` and so on). Thus each context
name becomes the cluster name in the report. The loop needs `kubectl` and
`jq`. It writes one row for each container and init container of each
Deployment, StatefulSet, DaemonSet and CronJob.

```bash
CONTEXTS='cluster-a cluster-b cluster-c'
mkdir -p inputs
# $(echo ...) splits the list in both bash and zsh.
for context in $(echo "$CONTEXTS"); do
  kubectl --context "$context" get deployments,statefulsets,daemonsets,cronjobs -A -o json |
    jq -r '.items[] as $item
      | ($item.spec.template.spec // $item.spec.jobTemplate.spec.template.spec) as $pod
      | (($pod.initContainers // []) + ($pod.containers // []))[]
      | [$item.metadata.namespace, $item.metadata.name, .image, $item.kind]
      | @csv' > "inputs/$context.txt"
done
```

A custom resource keeps its image in a field of its own. To add a custom
resource, append its rows to the same file. Replace `myapps.example.com`
with the resource name, and `.spec.image` with the path to the image:

```bash
kubectl --context "$context" get myapps.example.com -A -o json |
  jq -r '.items[] | [.metadata.namespace, .metadata.name, .spec.image, .kind] | @csv' \
  >> "inputs/$context.txt"
```

Then scan all files with the `-f` loop from [Usage](#usage).

For the `Application` and `SKIPJob` resources of the open-source
[Skiperator](https://github.com/kartverket/skiperator) operator, see
[Scan Skiperator resources](docs/skiperator.md).

## Output

Every format is sorted by cluster, then namespace, then name, then image (and
kind, when the rest is equal).

The default table:

```text
cluster | namespace | kind        | application name | image name               | vulnerability status | components         | mitigation
--------+-----------+-------------+------------------+--------------------------+----------------------+--------------------+-------------------------------
dev     | web       | Deployment  | busy             | busybox:1.36             | PATCHED              | -                  | -
prod    | base      | CronJob     | cleanup          | alpine:3.20              | VULNERABLE           | -                  | -
prod    | team      | Deployment  | api              | registry.example.com/api | VULNERABLE           | go:outdated        | -
prod    | team      | StatefulSet | billing          | registry.example.com/bil | MITIGATED            | jdk:outdated       | blocked.certs
prod    | team      | Deployment  | ledger           | registry.example.com/led | PARTIALLY_MITIGATED  | go:fixed jdk:fixed | blocked.certs (partial: 16/48)
```

`-o csv` writes one row per image with these columns:

| Column | Content |
|---|---|
| `cluster`, `namespace`, `kind`, `application`, `image` | From the input. |
| `status` | `VULNERABLE`, `PARTIALLY_MITIGATED`, `MITIGATED`, `PATCHED`, `ERR_DOCKER_PULL` or `UNKNOWN`. |
| `jvm_detected` | `true` if the image contains or starts a JVM. |
| `components` | The runtimes and libraries found, with the worst status of each kind: `fixed`, `outdated` or `unknown`, as in `go:outdated jdk:fixed`. Empty if there are none. |
| `outdated` | Runtimes and libraries that predate the fix, as `path (version)`, joined with `; `. |
| `mitigation` | `blocked.certs` or `blocked.certs (partial: N/48)` when the JDKs of the image block the compromised intermediates. Empty if they do not. |
| `certificates` | Names of the distrusted certificates found, joined with `; `. |
| `paths` | Files that contain them, joined with `; `. A file that the image distrusts has `(distrusted)` or `(disabled)` after its path. |
| `error` | Why the scan of the image did not complete (only for `ERR_DOCKER_PULL` and `UNKNOWN`). |

`-o json` writes one indented JSON object per image. Each object has the layer
digest and file hash of each finding, and the evidence for JVM detection. It
also lists every Java trust store found, with or without matches. `components`
lists every runtime, library and JDK `blocked.certs` file found, with `kind`,
`path`, `version` and `status`. For `blocked.certs`, it also gives how many
fingerprints the file lists. Use `jq -s` to read the stream as one array.

### What the statuses mean

- `VULNERABLE`: at least one file in the final image filesystem contains a
  listed certificate that the image still trusts, in PEM or DER form. This
  includes CA bundles, Java `cacerts`/JKS files, and root stores compiled
  into binaries.
- `PARTIALLY_MITIGATED`: like `VULNERABLE`, but the JDKs block only some
  encodings of the compromised intermediates in `blocked.certs`. A re-encoded
  certificate gets past the list (see [Java blocked.certs](#java-blockedcerts)).
- `MITIGATED`: like `VULNERABLE`, but the `blocked.certs` of each JDK lists
  every encoding of the compromised intermediates. Java refuses the leaked
  keys. Other programs in the image (curl, Python, Node.js) still trust the
  roots in the system CA bundle.
- `PATCHED`: the image was scanned completely, and every listed certificate
  that was found is distrusted (see below), or none was found. This does not
  prove that the image is safe (see limitations).
- `ERR_DOCKER_PULL`: the scanner cannot download the image. The tag or digest
  does not exist, the registry needs credentials that are missing or refused
  (see [Registry access](#registry-access)), or the registry failed. With
  `--local`, the local Docker installation does not have the image. The
  `error` field says which.
- `UNKNOWN`: the scanner downloaded the image but cannot read it, for
  example a layer that is not a valid tar archive. The `error` field says why.

### Distrusted certificates

Some images keep a listed certificate but distrust it. These findings are
reported with their `trust` state in JSON, and they do not make the image
`VULNERABLE`:

- `distrusted`: the file is in a p11-kit blocklist directory, such as
  `/etc/pki/ca-trust/source/blocklist` on Red Hat and Fedora, or
  `/etc/ca-certificates/trust-source/blocklist` on Arch. p11-kit distrusts
  every certificate in it.
- `disabled`: the file is in `/usr/share/ca-certificates`, and
  `/etc/ca-certificates.conf` deselects it with a `!` line (Debian and
  Ubuntu).

All other findings are `trusted`.

### Runtime and library versions

Several runtimes and libraries have releases that reject the compromised
intermediates, whatever the CA bundle of the image contains. The scanner finds
these runtimes and libraries in the image. Then it compares their version with
the fixed releases on [the incident
page](https://emudhra.we-have-a-problem.com/).
`internal/scan/fixed-versions.json` keeps these releases, with the date when
they were checked.

| Kind | Found in | Fixed releases |
|---|---|---|
| `go` | Every Go executable (the Go version it was built with) | 1.26.10, 1.27.3 |
| `jdk` | The `release` file in each JDK or JRE (`JAVA_VERSION`) | 8u511 b32, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2, 27.0.1.0.2 |
| `node` | Each `node` executable (the release URLs compiled into it) | 22.23.4, 24.22.1, 26.12.1 |
| `certifi` | The `certifi-<version>.dist-info` directory of each installed copy | 2026.10.19 |
| `pip` | The `pip-<version>.dist-info` directory, and the pip wheel that CPython bundles for `ensurepip` | 26.2.2 |

Node.js keeps its own copy of the CA roots in the `node` executable. Thus an
outdated Node.js trusts the compromised CAs also on a fixed base image. The
scanner reports the executable as a finding. In JSON, the `note` of a `node`
component shows two settings. The first is when the image makes Node.js use
the system CA bundle (`--use-openssl-ca` in `NODE_OPTIONS` or on the command
line). The second is when the image adds certificates (`NODE_EXTRA_CA_CERTS`).

pip has its own copy of certifi in `pip/_vendor`. CPython releases with a fix
(3.13.17, 3.14.9, 3.15.1) differ from older releases in the pip wheel that
they bundle. The scanner reports that wheel as a `pip` component.

Each one is reported as a component:

- `fixed`: at or above the fixed release of its line, or a newer line than
  any listed.
- `outdated`: below the fixed release of its line, or a line that got no fix
  (such as Go 1.25, JDK 22 or JDK 26). The CSV `outdated` column and the JSON
  `fixed` field name the release to upgrade to.
- `unknown`: a version that cannot be compared, such as a Go development
  build.

This is information only, and it does not change the image status. A
`VULNERABLE` image with only `fixed` components still has the roots in its CA
bundle. Other programs in the image (curl, Python) still trust these roots.
Packed binaries (UPX) hide their Go version. A distribution backport of a fix,
or the version numbers of a JDK vendor, can hide a fix from the version check.

### Java blocked.certs

A JDK refuses any certificate whose SHA-256 fingerprint is listed in
`$JAVA_HOME/lib/security/blocked.certs`. Listing the compromised
intermediates there makes Java reject the leaked keys even though `cacerts`
still trusts the eMudhra and AAA roots. When the scanner finds this, the
`mitigation` column says `blocked.certs`, and the image is `MITIGATED`
instead of `VULNERABLE`.

A complete list has 48 fingerprints, not 16. The JVM calculates the hash of a
certificate exactly as it receives the certificate. Each intermediate has more
than one valid encoding. The parameters of the signature algorithm can be
present or absent (NULL). The ECDSA-signed intermediates also have a second
valid signature (r, n−s). The scanner calculates the 48 fingerprints from the
certificate database, as OpenJDK's `BlockedCertsConverter` does. A list with
only the 16 usual fingerprints shows as `blocked.certs (partial: 16/48)`, and
the image is `PARTIALLY_MITIGATED`, because a crafted re-encoding gets past
it. [The eMudhra CA compromise: why
your JVM is
vulnerable](https://glaforge.dev/posts/2026/10/21/the-emudhra-ca-compromise-why-your-jvm-is-vulnerable-and-how-to-fix-it/)
gives the full list and shows how to add it.

The scanner reads every `…/lib/security/blocked.certs` that is left in the
final image, and JDK 8's `blacklisted.certs`, which holds the same list. When
an image has several JDKs, the weakest one decides the `mitigation` and the
status. A JDK with no compromised intermediates in its list keeps the image
`VULNERABLE`.

`MITIGATED` protects only Java. Other programs in the image (curl, Python,
Node.js) still use the system CA bundle, which trusts the roots. The
`paths` column shows where these roots are.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All images are `PATCHED` or `MITIGATED`. |
| 1 | At least one image is `VULNERABLE` or `PARTIALLY_MITIGATED`. |
| 2 | At least one image is `ERR_DOCKER_PULL` or `UNKNOWN`, or the command line is wrong. |
| 3 | An input file, the certificate database or `CERTIFICATECHECKER_PARALLELISM` is invalid. |
| 130 | Interrupted with Ctrl-C (SIGINT) or SIGTERM. |

`ERR_DOCKER_PULL` and `UNKNOWN` (2) take precedence over `VULNERABLE` and
`PARTIALLY_MITIGATED` (1).
Ctrl-C stops the run. The scanner cancels the downloads in progress and starts
no new images. It writes one log line and no report, and exits with 130. A
second Ctrl-C ends it at once.

## Registry access

Public images on any OCI registry work without credentials. For private
images, the tool uses the same credentials as `docker pull`: the Docker config
file (`~/.docker/config.json`, or `$DOCKER_CONFIG/config.json`) and the
credential helpers that it names. No Docker daemon is necessary.

```bash
docker login registry.example.com
gcloud auth configure-docker REGION-docker.pkg.dev  # adds the Google Artifact Registry helper
```

Any credential helper in the Docker config works, for example the helpers
for Google Artifact Registry, Amazon ECR and Azure Container Registry. If the
registry refuses the stored credentials, the scanner tries once more without
credentials. Thus a stale login does not block public images.

Requests that fail with HTTP 429 or a server error are retried with backoff.

### Local images

To scan images that only the local Docker installation has, such as images
that you built and did not push, add `-l` (`--local`):

```bash
./emudhra-checker -l myapp:dev
```

The scanner then reads every image with `docker image save` and does not
contact a registry. The `docker` CLI must be in `PATH`, and it uses the
active Docker context. Each export goes to a temporary file in `$TMPDIR`,
which the scanner removes after the scan. Thus free disk space equal to
`--parallel` times the largest image is necessary.

The image is the platform that Docker has, for example `linux/arm64` on an
Apple silicon Mac. The registry scan prefers `linux/amd64`. For local images,
the `layer_digest` of a finding is the digest of the uncompressed layer (its
diff ID).

## How it works

1. Resolve the image reference with
   [go-containerregistry](https://github.com/google/go-containerregistry).
   For multi-platform images, `linux/amd64` is preferred, then `linux/arm64`,
   then the first entry.
2. Read the image config to find JVM start commands and
   `-Djavax.net.ssl.trustStore` settings.
3. Stream each layer (gzip, zstd or uncompressed) and verify its digest.
   Search every regular file for the DER bytes and the PEM text of each
   listed certificate.
4. Apply OCI whiteouts, so a certificate deleted or replaced in a later layer
   is not reported.
5. Give each finding its trust state (see
   [Distrusted certificates](#distrusted-certificates)).
6. Compare the versions of Go, JDK, Node.js, certifi and pip with the fixed
   releases, and read the JDK `blocked.certs` files.

The certificate database lists the four anchor roots and the sixteen affected
intermediates, including the cross-signs by Sectigo's `AAA Certificate
Services`. Each entry's PEM is checked against its SHA-256 fingerprint at
start-up.

## Limitations

- Certificates match on their exact bytes. A re-issued certificate with the
  same key, or a bare public key in a trust-anchor table, is not found.
- Certificates inside password-protected PKCS#12 keystores are encrypted and
  are not found.
- Archives inside the image (`.jar`, `.whl`, `.zip`) are not unpacked.
  Certificates in their compressed content are not found.
- Each file is read into memory while it is scanned, so very large files in
  an image cost memory multiplied by `--parallel`.

## Development

```bash
go test -race ./...
golangci-lint run ./...
```

The code is split by concern. All packages except the command are under
`internal/`, so other modules cannot import them.

| Package | Responsibility |
|---|---|
| `cmd/emudhra-checker` | Flags, exit codes, progress output. |
| `internal/certdb` | The embedded certificate database and certificate matching. |
| `internal/registry` | Fetching images: Docker credentials, platform choice. |
| `internal/inventory` | Reading the cluster input files. |
| `internal/scan` | Walking layers (whiteouts, gzip/zstd), Java and Go binary checks, parallel scans. |
| `internal/report` | Sorting and writing the table, CSV and JSON output. |

`certdb`, `registry` and `inventory` import no other internal package. `scan`
uses all three, and `report` uses `scan`. Tests that need unexported code are
in `*_internal_test.go` files. The other tests use only the exported API.

The lint configuration in `.golangci.yml` is
[maratori/golangci-lint-config](https://github.com/maratori/golangci-lint-config)
v2.15.0, with only the module prefix changed. Keep it in step with the
installed golangci-lint version.
