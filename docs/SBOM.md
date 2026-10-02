# Local SBOM and Dependency-Track workflow

This project generates a CycloneDX Software Bill of Materials (SBOM) with
[Syft](https://github.com/anchore/syft) and can be reviewed locally with
[OWASP Dependency-Track](https://dependencytrack.org/).

Dependency-Track is free and open source under the Apache 2.0 license. Running
it locally still consumes Docker resources, and a production deployment needs
backups, persistent storage, upgrades, and access controls.

## 1. Install Syft

On macOS with Homebrew:

```bash
brew install syft
```

Verify the installation:

```bash
syft version
```

## 2. Generate the SBOM

From the repository root:

```bash
make sbom
```

To generate a release-specific BOM, set `SBOM_VERSION`:

```bash
SBOM_VERSION=1.0.0 make sbom
```

The generated file is:

```text
artifacts/firewall-manager-sbom.json
```

The `artifacts/` directory is intentionally gitignored because the SBOM is a
generated release artifact.

## 3. Start Dependency-Track locally

For local evaluation only:

```bash
docker run -d \
  --name dependency-track \
  -p 8080:8080 \
  -v dependency-track-data:/data \
  dependencytrack/bundled
```

Open <http://localhost:8080>. The initial login is:

```text
Username: admin
Password: admin
```

Change the password immediately after the first login. Dependency-Track may
take several minutes to initialize vulnerability data during first startup.

To stop it while preserving its data:

```bash
docker stop dependency-track
```

To start it again:

```bash
docker start dependency-track
```

## 4. Create a project

In the Dependency-Track UI:

1. Open **Projects**.
2. Select **Create Project**.
3. Use these values:
   - **Project Name:** `firewall-manager`
   - **Version:** `local` or the application release version
   - **Classifier:** `Application`
   - **Team:** leave blank unless teams are configured
   - **Project Collection Logic:** `None`
   - **Parent:** leave blank
4. Create the project.

## 5. Upload the SBOM

Open the newly created project and choose **Upload BOM** or **Upload
CycloneDX BOM**. Select:

```text
/Users/nick/Documents/GitHub/firewall-manager/artifacts/firewall-manager-sbom.json
```

After processing, the project displays components, versions, vulnerabilities,
licenses, and policy findings.

## 6. Wait for vulnerability feeds and analysis

Dependency-Track imports the components immediately, then correlates them with
its vulnerability and repository data. On the first startup, the NVD mirror
can take several minutes or longer. During that period, the project may show
components but no vulnerability results yet.

Check progress with:

```bash
docker logs --tail 200 dependency-track
```

Look for completion messages from `NistMirrorTask`, `InternalAnalysisTask`, and
`PolicyEngine`. Refresh the project after those tasks complete. A project with
zero findings after analysis is a valid result; it means no matching findings
were reported by the enabled sources.

The optional OSS Index analyzer is skipped unless an OSS Index API token is
configured. NVD and the other enabled sources can still provide results
without that optional token.

## 7. Repeat for a release

Generate a new SBOM for each release or materially changed build. Use a
release-specific project version instead of `local`, for example:

```text
firewall-manager / 1.0.0
firewall-manager / 1.1.0
```

Keep the SBOM with the release evidence and record the Dependency-Track project
and version in the production release checklist.

## Security notes

- Do not expose the local Dependency-Track port to the public internet.
- Replace the default password immediately.
- Use persistent, backed-up storage for production.
- Protect Dependency-Track with HTTPS, authentication, and restricted network
  access in production.
- Treat SBOMs as potentially sensitive because they reveal dependency versions
  and may reveal private package names.
