# UDS Package Kit

## Overview

UDS Package Kit is a tool designed to assist in developing, maintaining, and publishing UDS Packages.

## Features

- Automated release and tag creation in GitLab and GitHub
- Customizable release configuration file
- Comparing grype scans using the cyclonedx-json format

## Installation

Download the latest UDS Package Kit binaries from the [GitHub Releases](https://github.com/defenseunicorns/uds-pk/releases) page.

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

# The bundles entry is only used when `uds release bundle CMD BUNDLE_NAME` is used
bundles:
  - name: dev
    path: bundles/dev/
    version: 0.0.2
  - name: prod
    path: bundles/prod/
    version: 0.0.1
```

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

|  ID  | Severity   |  URL  |
|:----:|:----------:|:-----:|
| ... | ... | ... |

</details>

<details>
<summary>Fixed vulnerabilities</summary>

|  ID  |  Severity  |  URL  |
|:----:|:----------:|:-----:|
| ... | ... | ... |

</details>

<details>
<summary>Existing vulnerabilities</summary>

|  ID  |  Severity  |  URL  |
|:----:|:----------:|:-----:|
| ... | ... | ... |

</details>

---
```
