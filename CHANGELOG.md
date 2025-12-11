# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2-SNAPSHOT] - 2025-12-11

### Changed

- Update justfile and reuseableci
- Update reuseablci, justkit etc
- Update dependency com.puppycrawl.tools:checkstyle to v12.2.0 (#115)
- Update dependency org.bouncycastle:bcprov-jdk18on to v1.83 (#114)
- Update diggsweden/reusable-ci action to v2.3.8 (#113)
- Update diggsweden/reusable-ci action to v2.3.1 (#111)
- Update dependency org.apache.maven.plugins:maven-source-plugin to v3.4.0 (#110)
- Update github actions (#109)
- Update dependency com.puppycrawl.tools:checkstyle to v12.1.2 (#108)
- Update diggsweden/reusable-ci action to v2.2.3 (#107)
- Update dependency se.swedenconnect.security:credentials-support to v2.1.0 (#106)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.6 (#105)
- Update dependency org.junit.jupiter:junit-jupiter to v6
- Update diggsweden/reusable-ci action to v2.1.1 (#104)
- Update jackson to v2.20.1 (#103)
- Update dependency org.junit.jupiter:junit-jupiter to v5.14.1 (#102)
- Update dependency com.puppycrawl.tools:checkstyle to v12.1.1 (#101)
- Update dependency com.puppycrawl.tools:checkstyle to v12.1.0 (#100)
- Update dependency com.puppycrawl.tools:checkstyle to v12
- Pin sha and version
- Adjust settings
- Use base renovate config
- Use reuseable-ci v2
- Use reusable-ci v1
- Update dependency org.junit.jupiter:junit-jupiter to v5.14.0 (#94)
- Update dependency org.apache.maven.plugins:maven-enforcer-plugin to v3.6.2 (#93)
- Update dependency com.puppycrawl.tools:checkstyle to v11.1.0 (#92)
- Update dependency org.sonatype.central:central-publishing-maven-plugin to v0.9.0 (#91)
- Update orhun/git-cliff-action action to v4.6.0 (#90)
- Update test to v5.20.0 (#89)
- Update dependency org.apache.maven.plugins:maven-compiler-plugin to v3.14.1 (#88)
- Update dependency org.projectlombok:lombok to v1.18.42 (#87)
- Update dependency org.bouncycastle:bcprov-jdk18on to v1.82 (#86)
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.12.0 (#85)
- Update dependency net.revelc.code.formatter:formatter-maven-plugin to v2.29.0 (#84)
- Update dependency se.swedenconnect.security:credentials-support to v2.0.7 (#83)
- Update dependency org.apache.maven.plugins:maven-surefire-plugin to v3.5.4 (#82)
- Update dependency net.revelc.code.formatter:formatter-maven-plugin to v2.28.0 (#81)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.5 (#80)
- Update dependency org.projectlombok:lombok to v1.18.40 (#79)
- Update java non-major (#78)
- Update dependency com.fasterxml.jackson.core:jackson-databind to v2.20.0 (#77)
- Update actions/setup-java action to v5
- Update orhun/git-cliff-action action to v4.5.1 (#71)
- Update java non-major (#67)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.4.2 (#69)
- Update jackson to v2.19.2 (#70)
- Update test
- Update dependency se.swedenconnect.security:credentials-support to v2.0.6
- Update dependency com.puppycrawl.tools:checkstyle to v11
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.11.3
- Update actions/checkout action to v5
- Extend commit description lint length
- Update jackson to v2.19.1 (#66)
- Update dependency org.junit.jupiter:junit-jupiter to v5.13.1 (#65)
- Update dependency org.bouncycastle:bcprov-jdk18on to v1.81 (#64)
- Update dependency com.puppycrawl.tools:checkstyle to v10.25.0 (#63)
- Update dependency org.junit.jupiter:junit-jupiter to v5.13.0 (#62)
- Update dependency com.puppycrawl.tools:checkstyle to v10.24.0 (#61)
- Update test to v5.18.0 (#60)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.3 (#59)
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.18.0 (#57)
- Update dependency com.puppycrawl.tools:checkstyle to v10.23.1 (#56)
- Update jackson to v2.19.0 (#55)
- Update dependency org.junit.jupiter:junit-jupiter to v5.12.2 (#54)
- Update actions/setup-java action to v4.7.1 (#53)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.2 (#52)

### Fixed

- Fix lint warning

### Removed

- Remove jreleaser from pom


## [0.9.1] - 2025-04-09

### Changed

- Update dependency credentials-support
- Update dependency maven-surefire-plugin

### Fixed

- Change name in jreleaser


## [0.9.0] - 2025-04-09

### Changed

- Update test to v5.17.0 (#51)
- Update codequality script deps
- Update workflow, code_quality script and artifactId to token-lib
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.1 (#50)
- Update dependency com.puppycrawl.tools:checkstyle to v10.23.0 (#49)
- Update dependency se.digg.cose:cose-lib to v2.0.0 (#48)
- Update dependency org.projectlombok:lombok to v1.18.38 (#47)
- Update java non-major (#41)
- Update crazy-max/ghaction-import-gpg action to v6.3.0 (#45)
- Make kid in sd jwt tokens configurable
- Update actions/upload-artifact action to v4.6.2 (#24)
- Update test to v5.16.1 (#40)
- Update credentials-support to v2.0.4
- Update dependency org.junit.jupiter:junit-jupiter to v5.12.1 (#39)
- Update slf4j to v2.0.17 (#33)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.0.2 (#32)
- Update maven-compiler-plugin to v3.14.0
- Update renovate.json

### Fixed

- Use published cose-lib


## [0.1.0-SNAPSHOT] - 2025-03-13

### Added

- Add support for MAC device authentication in mDL
- Add disclosed attribute parsing
- Add nice rel
- Add development.md
- Add initial release workflow
- Add license info and pass license lint
- Add checkout phase to test
- Add always to test run
- Add commit conf
- Add renovate conf
- Add perm for openssf
- Adds initial pr workflow
- Add linters etc

### Changed

- Refactor central portal release
- Update dependency com.puppycrawl.tools:checkstyle to v10.21.4 (#37)
- Update test to v5.16.0 (#36)
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.17.0 (#34)
- Update java non-major (#31)
- Adjust license header
- Cleanup lint errs, minor cleanup
- Improve usage documentation
- Update dependency org.apache.maven.plugins:maven-deploy-plugin to v3.1.4 (#30)
- Update dependency com.puppycrawl.tools:checkstyle to v10.21.3 (#25)
- Update dependency org.junit.jupiter:junit-jupiter to v5.12.0 (#23)
- Use snapshots from central
- Reformat and adjust for google-style-java format
- Update step-security/harden-runner action to v2.11.0 (#19)
- Update javadoc
- Make all checks pass
- Update COSE-lib dependency
- Fetch whole history, only allow SNAPSHOT
- Change token for rel
- Merge pull request #11 from diggsweden/mdl-presentation
- Merge branch 'main' into mdl-presentation
- Complementing test cases
- Cleanups
- Cleanups
- SD JWT Token presenter
- Presentation validator for SD JWT
- Mdl and SD JWT presentation validation working
- Parsing mdl presentations
- Structural updates for presentation
- Version update
- Working mdl presentation
- Pin dependencies
- Update maven-plugins
- Update test
- Format workflow
- Format with checkstyle
- Clean up pom, add cose
- Update README.md
- Create README.md
- Project sources
- Gitignore

### Fixed

- Update jackson to v2.18.3 (#35)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.0.2 (#27)
- Update slf4j to v2.0.17 (#26)
- Make project pass lint and ci
- Update unit tests
- Update dependency se.swedenconnect.security:credentials-support to v2.0.3
- Use cose-lib
- Update dependency credentials-support to v2.0.2
- Fix missing perm for test


[0.9.2-SNAPSHOT]: https://github.com/diggsweden/eudiw-wallet-token-lib/compare/v0.9.1..v0.9.2-SNAPSHOT
[0.9.1]: https://github.com/diggsweden/eudiw-wallet-token-lib/compare/v0.9.0..v0.9.1
[0.9.0]: https://github.com/diggsweden/eudiw-wallet-token-lib/compare/v0.1.0-SNAPSHOT..v0.9.0

<!-- generated by git-cliff -->
