# Development Guide

This guide outlines core essentials you need to know for developing in this project.
This guide outlines core essentials for developing in this project.

## Table of Contents

- [Setup and Configuration](#setup-and-configuration)
  - [IDE Setup](#ide-setup)
  - [Consuming SNAPSHOTS](#consuming-snapshots-from-maven-central)
- [Development Workflow](#development-workflow)
  - [Testing and Verification](#testing-format-and-lint)
  - [Documentation](#documentation)
  - [Pull Request Process](#pull-request-workflow)
- [Release Process](#the-release-workflow)
  - [CI Release](#ci-release-process)
  - [Local Release](#local-release-process)
  - [Troubleshooting](#troubleshooting)

## Setup and Configuration

### IDE Setup

#### VSCode

1. Install [Checkstyle For Java](https://marketplace.visualstudio.com/items?itemName=shengchen.vscode-checkstyle)
2. Open workspace settings - settings.json (for example with Ctrl+Shift+P → Preferences: Workspace Settings (JSON)) and add:

    ```json
    "[java]": {
        "editor.defaultFormatter": "redhat.java",
    },
    "java.format.settings.url": "development/format/eclipse-java-google-style.xml",
    "java.format.settings.profile": "GoogleStyle",
    "editor.formatOnSave": true,
    "java.checkstyle.configuration": "development/lint/google_checks.xml",
    "java.checkstyle.version": "1x.xx.x"
    ```

#### IntelliJ

1. **Code Style**
   - Settings → `Editor → Code Style → Java`
   - Click gear → `Import Scheme → Eclipse XML Profile`
   - Select `development/format/eclipse-java-google-style.xml`

2. **Checkstyle**
   - Install "CheckStyle-IDEA" plugin
   - Settings → `Tools → Checkstyle`
   - Click the built-in Google Style Check

## Consuming SNAPSHOTS from Maven Central

Configure your pom.xml file with:

```xml
<repositories>
  <repository>
    <name>Central Portal Snapshots</name>
    <id>central-portal-snapshots</id>
    <url>https://central.sonatype.com/repository/maven-snapshots/</url>
    <releases>
      <enabled>false</enabled>
    </releases>
    <snapshots>
      <enabled>true</enabled>
    </snapshots>
  </repository>
</repositories>
```

## Development Workflow

### Testing, Format and Lint

Run Maven verification:

```shell
mvn clean verify
```

### Documentation

Generate Javadocs:

```shell
mvn javadoc:javadoc
```

View documentation in your browser:

```shell
<browser> target/reports/apidocs/index.html
```

### Pull Request Workflow

When submitting a PR, CI will automatically run several checks. To avoid surprises, run these checks locally first.

#### Pull Request Workflow Prerequisites

- [Podman](https://podman.io/)

#### Running Code Quality Checks Locally

1. Run the quality check script:

   ```shell
   ./development/code_quality.sh
   ```

2. Fix any identified issues

3. Update your PR with fixes

4. Verify CI passes in the updated PR

#### Quality Check Details

- **Linting with megalinter**: BASH, Markdown, YAML, GitHub Actions, security scanning
- **License Compliance**: REUSE tool ensures proper copyright information
- **Commit Structure**: Conform checks commit messages for changelog generation
- **Dependency Analysis**: Scans for vulnerabilities, outdated packages, and license issues
- **OpenSSF Scorecard**: Validates security best practices

#### Handling Failed Checks

If any checks fail in the CI pipeline:

1. Review the CI error logs
2. Run checks locally to reproduce the issues
3. Make necessary fixes in your local environment
4. Update your Pull Request
5. Verify all checks pass in the updated PR

## The Release Workflow

Releases to Maven Central can be done in two ways - by CI or locally.

### Release Workflow Prerequisites

1. **For CI releases**:
   - Push access to the repository (ability to push tags)
   - For production releases: Your GitHub username in AUTHORIZED_RELEASE_DEVELOPERS list
   - For SNAPSHOT releases: Any contributor with tag push access

2. **For local releases only**:
   - Valid GPG key pair for signing artifacts
   - GPG key uploaded to key servers (e.g., `keyserver.ubuntu.com`)
   - Maven Central credentials in settings.xml

### CI Release Process

1. **For SNAPSHOT releases**:

   ```shell
   # Tag with -SNAPSHOT suffix (use -f to force if tag already exists)
   git tag -sf v0.0.3-SNAPSHOT -m 'v0.0.3-SNAPSHOT'
   # Push the tag to trigger the CI workflow (use -f to force update on remote)
   git push -f origin tag v0.0.3-SNAPSHOT
   ```

   > **NOTE**: Always use the same SNAPSHOT tag version until ready for a production release.

2. **For Production releases**:

   ```shell
   # Tag with the desired version (no SNAPSHOT suffix)
   git tag -s v1.0.0 -m 'v1.0.0'
   # Push the tag to trigger the CI workflow
   git push origin tag v1.0.0
   ```

   > **NOTE**: The tag version will be used in the POM file.

3. **Monitor the workflow** in GitHub Actions to ensure successful completion.

   > **NOTE**: If the workflow fails due to authorization issues, contact the repository administrator to add your GitHub username to the AUTHORIZED_RELEASE_DEVELOPERS list.

### Local Release Process

1. **Configure settings.xml**:
   - Ensure `.mvn/settings.xml` contains your Maven Central username and token
   - Verify credentials are in the correct server section with the proper server ID
   - Make sure your GPG key is available in your environment

2. **Run the deploy command**:

   ```shell
   mvn deploy --settings .mvn/settings.xml -Pcentral-release
   ```

3. **Verify the release** in your Sonatype account or Maven Central.

### Troubleshooting

- For CI failures: Check "jreleaser-logs" artifact for detailed error information
- For authorization issues: Verify your GitHub username is in AUTHORIZED_RELEASE_DEVELOPERS
- For GPG problems: Ensure your key is correctly configured in your environment.
