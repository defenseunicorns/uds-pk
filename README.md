# UDS Package Kit

## Overview

UDS Package Kit is a tool designed to assist in developing, maintaining, and publishing UDS Packages.

## Features

- Automated release and tag creation in GitLab and GitHub
- Customizable release configuration file
- Comparing grype scans using the cyclonedx-json format

## Installation

Install the latest release with:

```bash
curl -fsSL https://raw.githubusercontent.com/defenseunicorns/uds-pk/main/install.sh | bash
```

The script detects your OS and architecture, verifies the binary against the published checksums, and installs to `$HOME/.local/bin`. Override the target with `INSTALL_DIR` or pin a release with `VERSION`:

```bash
curl -fsSL https://raw.githubusercontent.com/defenseunicorns/uds-pk/main/install.sh | VERSION=v0.1.6 INSTALL_DIR="/usr/local/bin" bash
```

> [!NOTE]
> `$HOME/.local/bin` is not on `PATH` by default on macOS. If `uds-pk` isn't found after installing, add it with `export PATH="$HOME/.local/bin:$PATH"` in your shell profile.

Alternatively, download a binary directly from the [GitHub Releases](https://github.com/defenseunicorns/uds-pk/releases) page.

## Usage

After installation, you can use uds-pk via the command line:

> [!TIP]
> To view available commands run `uds-pk help`

## Release Example

Pseudo flow for CI/CD:

```bash
uds-pk release check [flavor]

uds-pk release update-yaml [flavor]

# publish the package #

uds-pk release <platform> [flavor]
```

### Gitlab

When running `uds-pk release gitlab` you are expected to have an environment variable set to a GitLab token that has write permissions for your current project. This defaults to `GITLAB_RELEASE_TOKEN` but can be changed with the `--token-var-name` flag.

### GitHub

When running `uds-pk release github` you are expected to have an environment variable set to a GitHub token that has write permissions for your current project. This defaults to `GITHUB_TOKEN` but can be changed with the `--token-var-name` flag.

### Release Configuration

UDS Package Kit release commands are configured using a YAML file named releaser.yaml in your project's root directory.

```yaml
flavors:
  - name: upstream
    version: "1.0.0-uds.0"
  - name: registry1
    version: "2.0.0-uds.0"
  - name: unicorn
    version: "1.0.0-uds.0"
  - version: "1.0.0-flavorless.0" # A flavor without a name is valid and will be used when the [flavor] argument is not provided to the various release commands.

charts:
  - path: chart
    versionFromFlavor: true
    updateAppVersion: true
  - path: charts/installer
    version: "2.4.0"

packages:
  - name: second-package
    path: second-package/
    flavors:
      - name: upstream
        version: "1.0.0-uds.0"
      - name: registry1
        version: "2.0.0-uds.0"
      - name: unicorn
        version: "1.0.0-uds.0"
      - version: "1.0.0-flavorless.0" # A flavor without a name is valid and will be used when the [flavor] argument is not provided to the various release commands.
    charts:
      - path: second-package/chart
        versionFromFlavor: true

# The bundles entry is only used when `uds release bundle CMD BUNDLE_NAME` is used
bundles:
  - name: dev
    path: bundles/dev/
    version: 0.0.2
  - name: prod
    path: bundles/prod/
    version: 0.0.1
```

### Custom Helm Chart Versions

`uds-pk release update-yaml` updates the `version` field in each configured custom chart's `Chart.yaml`, in addition to `zarf.yaml`. It updates the version and matching local package source in `bundle/bundle.uds.hcl`, and the version and matching package ref in `bundle/uds-bundle.yaml`, when those files exist. If both formats are present, both are updated regardless of release mode. Errors preparing either bundle prevent changes to all files. Package-scoped updates with `--package` do not require a root bundle file and skip HCL bundles without a matching local package source. Define `charts` at the top level for charts owned by the root package or within a `packages` entry for charts owned by that package. Chart paths are relative to the release directory passed with `--dir`.

Each chart requires `path` and exactly one version source:

- **`version`** sets an explicit chart version that does not change with the selected flavor.
- **`versionFromFlavor: true`** sets the chart version to the selected flavor's version.

Set `updateAppVersion: true` to also set `appVersion` to the selected flavor's version. When `appVersion` is absent, `update-yaml` adds it. Otherwise, `appVersion` is unchanged by default.

Without `--package`, `update-yaml` updates only top-level charts. With `--package PACKAGE`, it updates only the charts declared for that package. The command does not discover charts automatically; every managed chart must be listed in `releaser.yaml`.

### Multi-Package Support

UDS Package Kit supports multiple packages in a single repository. The `packages` section in the YAML file allows you to define multiple packages, each with its own flavors configuration. The `name` field under `packages` specifies the package name, and the `path` field specifies the relative path to the directory with the package's `zarf.yaml`. Having both the top level `flavors` and `packages` is supported and encouraged. The top level `flavors` are used for the base package in the repo (the `zarf.yaml` at the root) and the `packages` section is used for any additional packages in the repo.

To refer to a package in the `packages` section, you can use the `--package` flag when running the release command. For example:

```bash
uds-pk release gitlab [flavor] --package second-package
```

This command will release the `second-package` with the specified flavor.

### Flavorless Support

UDS Package Kit supports flavorless releases. If you want to release a package without specifying a flavor, you can define a flavor without a name in the `releaser.yaml` file. This is useful for packages that do not have a need for different flavors. When running any `uds-pk release` command simply omit the flavor argument:

```bash
uds-pk release gitlab
uds-pk release github
uds-pk release show
uds-pk release check -p second-package
uds-pk release update-yaml
```

When using flavorless support, tags will simply be the version specified, or in the case of multi-package support the package name and the version joined with a hyphen, e.g. `second-package-1.0.0-flavorless.0`.

### Bundle Release Support

UDS Package Kit supports releasing UDS Bundles directly without packages present. The functionality is similar to the package support, but the sub commands are under `uds-pk release bundle` and a bundle name is required along with that bundle being defined in the `bundles` section of the `releaser.yaml` file. For example:

```bash
uds-pk release bundle gitlab BUNDLE_NAME
uds-pk release bundle github BUNDLE_NAME
uds-pk release bundle show BUNDLE_NAME
uds-pk release bundle check BUNDLE_NAME
uds-pk release bundle update-yaml BUNDLE_NAME
```

```yaml
bundles:
  - name: dev
    path: bundles/dev/
    version: 0.0.2
  - name: prod
    path: bundles/prod/
    version: 0.0.1
```

### Release Notes and Changelogs

Generate Markdown for the root package, a named package, or a bundle using local Git history:

```bash
# Root package with a flavor; write notes to stdout
uds-pk release notes upstream --from 1.0.0-uds.0-upstream

# Named package; write standalone notes and maintain its changelog
uds-pk release notes upstream --package second-package \
  --from second-package-1.0.0-uds.0-upstream \
  --output notes/second-package.md --changelog second-package/CHANGELOG.md

# Flavorless named package
uds-pk release notes --package second-package --from second-package-1.0.0-flavorless.0

# Bundle with explicit shared package history
uds-pk release bundle notes dev --from dev-0.0.1 --include-path second-package

# First release; include all reachable history
uds-pk release notes upstream --initial --output release-notes.md
```

Each invocation selects one target using the same configuration and tag conventions as the other release commands. Repeat the command for additional packages, flavors, or bundles. Bundle generation also works with a bundle-only `releaser.yaml` and requires no `zarf.yaml`.

| Flag | Behavior |
| --- | --- |
| `--dir`, `-d` | Directory containing the working-tree `releaser.yaml`; defaults to `.`. Repository discovery starts here, so the command can run from outside the repository. |
| `--package`, `-p` | Named package from `packages`; omit to select the root package. Available on `release notes`. |
| `--from REF` | Exclude this baseline revision and its ancestors. Required unless `--initial` is selected. |
| `--initial` | Include all history reachable from the end revision for a first release. Mutually exclusive with `--from`. |
| `--to REF` | Include changes through this revision; defaults to `HEAD`. |
| `--output FILE` | Write standalone notes to this file instead of stdout. |
| `--changelog FILE` | Also insert or refresh this release's section in a persistent changelog. |
| `--include-path PATH` | Include an additional shared file or directory; repeat the flag for multiple paths. |

Relative output, changelog, package, chart, bundle, and include paths resolve from `--dir`. Absolute output and changelog paths are also supported. Include paths must be relative and stay within the repository. Parent directories for output files are created as needed. Notes and changelog destinations must be distinct files.

Choose the previous revision for the same package, flavor, or bundle explicitly. The command accepts local tags, branches, and commit hashes; it does not infer a baseline from other targets' tags. The baseline must be an ancestor of the end revision. Equal endpoints produce an explicit no-changes section. Fetch required refs before generation. If a shallow clone truncates the requested history, run `git fetch --unshallow`; generation does not fetch automatically.

The selected version and formatted tag come from the working-tree `releaser.yaml`. `--to` changes the Git history endpoint only. When regenerating an older release, use its corresponding checkout and release configuration. Notes show the configured tag, resolved revision and baseline hashes, and the endpoint commit's UTC date, which is a revision date rather than the publication date.

Root releases include repository-wide history. Named packages include changes in their configured package and chart directories. Bundles include their configured bundle directory. Use `--include-path` to add shared code, dependency directories, or `releaser.yaml` changes explicitly; bundle generation does not recursively include bundled packages. Moves and deletions count for the affected paths. A commit touching multiple selected paths appears once. Flavor selection controls the version and tag; it does not independently filter files within a package.

Notes group conventional commits into Breaking Changes, Features, Bug Fixes, Performance, Dependencies, Documentation, Maintenance, and Other Changes. Breaking markers and multiline breaking-change footers take precedence; `deps` scopes select Dependencies before ordinary type classification. Unknown and non-conventional messages remain visible. Merge wrappers are omitted while commits on merged branches are retained. Categories and commit ordering are deterministic, and Git-derived text is escaped for Markdown.

Common GitHub and GitLab remotes produce commit and full-history comparison links. GitLab subgroup paths and hosts named `gitlab.*` or containing `.gitlab.` are recognized. Missing or unsupported remotes produce plain commit references with an explanation. Generation requires no hosting tokens or hosted API calls.

With `--changelog`, a missing file starts with `# Changelog`. New generated sections are inserted newest-first by revision date. Each block has `uds-pk:release` and `uds-pk:end` HTML markers keyed by target kind, name, flavor, and tag. Repeating generation replaces that block in place, including manual edits inside it. Preambles, handwritten sections, and other blocks are preserved. Malformed or duplicate markers and handwritten headings for the same tag return errors for review.

Without `--output`, stdout contains only the notes, including when `--changelog` is used. With `--output`, successful generation is silent. Errors go to stderr. Both artifacts are rendered and their destinations validated before writing; existing permissions are preserved, and each file is replaced atomically. Replacing two files is not a cross-file transaction, so a later replacement failure can leave the earlier file updated.

Generation reads history and writes only requested artifacts. Tag creation, hosted release creation, version updates, and publishing continue through the existing release commands; automatically consuming the generated notes in those workflows is separate follow-up work.

## Scan Comparison

The `compare-scans` command allows you to compare two grype scans using the cyclonedx-json output format. This can be useful to identify new, existing, and fixed vulnerabilities between two different scans.

> [!NOTE]
> We prefer the syft format for SBOMs, but grype doesn't output scans in syft, and the native grype format is not useful for vulnerability comparison. The cyclonedx-json format is the best option for this use case but Syft should be used elsewhere.

### `compare-scans` Usage

```bash
uds-pk compare-scans BASE_SCAN NEW_SCAN [flags]
```

- BASE_SCAN: The file path to the base scan JSON file.
- NEW_SCAN: The file path to the new scan JSON file.

### Flags

`-d`, `--allow-different-images`: Allow comparing scans for different images. By default, the command will error out if the scans are for different images.

Example

```bash
uds-pk compare-scans base_scan.json new_scan.json
```

This command will output a markdown table summarizing the new, existing, and fixed vulnerabilities between the two scans. If the scans are for different images, you can use the `--allow-different-images` flag to bypass the error:

```bash
uds-pk compare-scans base_scan.json new_scan.json --allow-different-images
```

### Output

The output will include a summary of the new, existing, and fixed vulnerabilities, followed by detailed tables for each category. The tables will be rendered in a collapsible format for better readability. The output is meant to be used in github comments/issues.

```markdown
### <base_image>:<base_version> -> <new_image>:<new_version>

New vulnerabilities: <count>
Fixed vulnerabilities: <count>
Existing vulnerabilities: <count>

<details>
<summary>New vulnerabilities</summary>

|  ID | Severity  |  URL |
|:----|:----------|:-----|
| ... | ... | ... |

</details>

<details>
<summary>Fixed vulnerabilities</summary>

|  ID |  Severity |  URL |
|:----|:----------|:-----|
| ... | ... | ... |

</details>

<details>
<summary>Existing vulnerabilities</summary>

|  ID |  Severity |  URL |
|:----|:----------|:-----|
| ... | ... | ... |

</details>

---
```

## STIG Checklist Generation

The `stig generate-checklist` command creates a `.cklb` checklist for every supported STIG entry in a profile YAML. XCCDF source files are automatically downloaded from DISA — no local copies required.

### Usage

```bash
# Auto-download XCCDF for a supported STIG
uds-pk stig generate-checklist --profile stig-profile.yaml

# Provide your own XCCDF file
uds-pk stig generate-checklist --profile stig-profile.yaml --xccdf /path/to/stig.xml

# Enrich DISA checklist findings with results from the matching SSG data stream
uds-pk stig generate-checklist --profile stig-profile.yaml \
  --xccdf /path/to/disa-manual-xccdf.xml \
  --results /path/to/final-results.xml \
  --results-datastream /path/to/ssg-rhel9-ds.xml

# Provide XCCDF and output paths for two STIG entries
uds-pk stig generate-checklist --profile stig-profile.yaml \
  --xccdf /path/to/asd.xml,/path/to/rhel9.xml \
  --output my-app-asd-v6r4.cklb,my-app-rhel9-v2r7.cklb
```

For multiple supported entries, pass comma-separated paths to `--xccdf` or `--output`. Values are matched to supported `stigs` entries in profile order; omit `--xccdf` to auto-download sources or `--output` to use the default filenames.

`--results` and `--results-datastream` must be supplied together. The scan profile ID is read from the results and checked against the data stream. The results must be an XCCDF 1.1 or 1.2 Benchmark with one TestResult; its embedded STIG rule references and selected profile settings must match the active checklist benchmark in the SSG data stream. The benchmark IDs and versions must also match. Scan dispositions apply only when both the DISA rule version ID and SV rule revision match the SSG references; mismatched revisions retain the profile disposition. Supply results from the system being assessed; the command cannot establish image identity from the scan target.

For each finding, a profile override takes precedence over an unambiguous scan result, then a profile characteristic heuristic, then `not_reviewed`. `pass`, `fail`, and `notapplicable` map to `not_a_finding`, `open`, and `not_applicable` only when every SSG rule mapped to that DISA rule has a result and the statuses agree. Other or conflicting results leave the heuristic disposition in place. Mapped SSG rule IDs, raw results, and the source of the final disposition are appended to `finding_details`, including when a human override supplies the disposition.

If `--output` is omitted, the default filename is:

```text
<app_name>-<stig>-<revision>.cklb
```

Examples:

```text
my-app-asd-v6r4.cklb
generic-rhel9-k8s-server-rhel9-v2r7.cklb
```

### STIG Result Comparison

`uds-pk stig compare-results` compares two XCCDF Benchmark result files and reports whether the newer scan regresses from the baseline. It is intended for CI gates and reviewable compliance evidence.

```bash
uds-pk stig compare-results BASE_RESULTS NEW_RESULTS [--output evidence.txt]
```

The command prints a deterministic evidence report to stdout. `--output` writes the identical report to a file, including when regressions are found.

```bash
uds-pk stig compare-results base-results.xml final-results.xml --output stig-comparison.txt
```

Exit codes are:

| Code | Meaning |
|------|---------|
| `0` | Valid comparison with no regressions |
| `1` | Valid comparison with one or more regressions |
| `2` | Invalid arguments, unreadable/invalid XCCDF, incomparable result sets, or evidence-write failure |

All XCCDF result statuses are preserved in the report. A change to a lower tier is a regression:

| Tier | Statuses |
|------|----------|
| Failing | `fail`, `error`, `unknown` |
| Unevaluated | `notchecked`, `notselected` |
| Acceptable | `pass`, `fixed`, `notapplicable`, `informational` |

The two inputs must be XCCDF 1.1 or 1.2 `Benchmark` documents that contain exactly one `TestResult`, the same benchmark ID and version, the same selected profile, and the same rule-result identities. Multiple instances of a rule are compared using their rule ID and instance details.

The evidence report includes scan metadata, a count for every XCCDF status, in-scope counts, sorted regressions, improvements, reclassifications, and the final PASS/FAIL verdict.

Example CI gate:

```bash
uds-pk stig compare-results base-results.xml final-results.xml --output stig-comparison.txt
case $? in
  0) echo "No STIG regressions" ;;
  1) echo "STIG regression detected"; exit 1 ;;
  2) echo "STIG comparison could not run"; exit 2 ;;
esac
```

### Supported STIGs

| ID | STIG | Auto-download |
|----|------|---------------|
| `asd_v6r4` | Application Security and Development, V6R4 | Yes |
| `rhel9_v2r7` | Red Hat Enterprise Linux 9, V2R7 | Yes |

### Profile Schema

Profiles use `kind: UDS STIG Profile` and list one or more STIGs under the `stigs` key. Every entry with a supported ID produces its own checklist. `metadata.version` is the STIG profile schema version and must match the `uds-pk` release used to process it.

Pin editor and CI validation to the schema asset from the same `uds-pk` release you use. Replace `X.Y.Z` in the URL and profile with that release version:

```yaml
# yaml-language-server: $schema=https://github.com/defenseunicorns/uds-pk/releases/download/vX.Y.Z/stig-profile-X.Y.Z.schema.json
kind: UDS STIG Profile
metadata:
  name: example-app
  version: X.Y.Z
```

### ASD Profile Example

```yaml
kind: UDS STIG Profile
metadata:
  name: example-app
  fqdn: app.example.mil
  description: >-
    Example application deployed behind platform identity and networking controls.
  version: X.Y.Z

stigs:
  - id: asd_v6r4
    description: Application Security and Development STIG, Version 6, Revision 4
    characteristics:
      uses_soap: false
      uses_saml: false
      uses_xml: false
      uses_database: false
      uses_passwords: false
      has_user_input: false
      is_stateless: true
      language: go
    platform:
      auth_provider: Keycloak
      auth_proxy: authservice
      service_mesh: Istio
      container_runtime: Kubernetes
      network_policies: true
      cicd_sast: Semgrep
```

### RHEL9 Profile Example

```yaml
kind: UDS STIG Profile
metadata:
  name: generic-rhel9-k8s-server
  fqdn: k8s-node01.airgap.local
  description: >-
    Red Hat Enterprise Linux 9 server hosting a standalone Kubernetes deployment
    in a small air-gapped network.
  version: X.Y.Z

stigs:
  - id: rhel9_v2r7
    description: Red Hat Enterprise Linux 9 STIG, Version 2, Release 7
    characteristics:
      is_container_host: true
      is_kubernetes_node: true
      is_standalone_server: true
      has_gui: false
      boots_to_multi_user_target: true
      uses_fips_mode: true
      uses_selinux: true
      uses_auditd: true
      uses_journald: true
      uses_firewall: true
      uses_ssh: true
      uses_sudo: true
      uses_aide: true
      uses_removable_media: false
      usb_storage_disabled: true
      is_air_gapped: true
      separate_tmp: true
      separate_var: true
      separate_var_log: true
      separate_var_log_audit: true
      separate_var_tmp: true
    platform:
      os_name: "Red Hat Enterprise Linux 9"
      os_version: "RHEL 9"
      host_role: "Standalone Kubernetes server"
      selinux_mode: "enforcing"
      audit_service: "auditd"
      firewall: "firewalld"
      file_integrity: "AIDE"
      kubernetes_distribution: "k0s"
      mount_strategy: "dedicated partitions for /tmp, /var, /var/log, /var/log/audit, and /var/tmp"
```

### Multi-STIG Profiles

A single profile can list multiple STIGs. Each supported entry generates a separate checklist:

```yaml
kind: UDS STIG Profile
metadata:
  name: my-app
  version: X.Y.Z

stigs:
  - id: asd_v6r4
    characteristics: { ... }
    platform: { ... }
  - id: rhel9_v2r7
    characteristics: { ... }
    platform: { ... }
```

### Overrides

Each STIG entry can include an `overrides` map keyed by rule version ID. Each override can set:

- `status`
- `finding_details`
- `comments`

Example:

```yaml
stigs:
  - id: asd_v6r4
    overrides:
      APSC-DV-000010:
        status: not_a_finding
        finding_details: Session handling is delegated to the platform identity layer.

  - id: rhel9_v2r7
    overrides:
      RHEL-09-231010:
        status: not_applicable
        finding_details: Control is not applicable in this air-gapped enclave design.
        comments: Documented architectural exception with compensating controls.
```
