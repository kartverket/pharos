# Pharos

<p align="center">
<img src="https://i.imgur.com/LUS8fWC.png"  width="20%">
<br/>
<sub><i>pharos</i> - (historical) An ancient lighthouse or beacon to guide sailors.</sub>
</p>

<hr/>

A GitHub action for running security scans that should be run before deploying to SKIP.

The action runs a Trivy configuration scan and a Trivy image vulnerability scan when an image is provided. VEX (Vulnerability Exploitability eXchange) can be enabled to suppress findings that an advisory source identifies as fixed or not affected.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image_url` | No | | Image reference in `registry/repository:tag` or `registry/repository@digest` form. Required to run the image scan. |
| `trivy` | No | `true` | Whether to run the Trivy image vulnerability scan. |
| `trivy_vex` | No | `false` | Enable VEX processing for the Trivy image scan. |
| `trivy_vex_provider` | No | `aqua` | VEX provider: `aqua` or `dhi`. |
| `docker_username` | No | | Username for authenticating to `dhi.io` when scanning a private DHI image. Supply with `docker_token`. |
| `docker_token` | No | | Access token for authenticating to `dhi.io` when scanning a private DHI image. |
| `tfsec` | No | `true` | Whether to run the Trivy configuration scan (formerly TFSec). |
| `allow_severity_level` | No | `medium` | Highest severity allowed while succeeding. Accepted values: `medium`, `high`, or `critical` (case-sensitive). |
| `disable_severity_check` | No | `false` | Skip the severity check against open code-scanning alerts. |
| `trivy_category` | No | `Trivy` | SARIF category used to distinguish Trivy runs, for example scans of different images. |
| `scan_platform_modules` | No | `false` | Enable access setup for `kartverket/terraform-modules`. |
| `skip_dirs` | No | | Comma-separated directories for Trivy config scanning to skip. |
| `skip_files` | No | `catalog-info.yaml` | Comma-separated files for Trivy config scanning to skip. |

### VEX providers

With `trivy_vex: "true"` and the default `trivy_vex_provider: "aqua"`, Trivy uses its VEX repository support with Aqua's VEX Hub. The scan summary includes VEX suppression details.

For Docker Hardened Images, set `trivy_vex_provider: "dhi"`. The action downloads the DHI VEX advisories for the image's DHI components, and then scans the image with Trivy, and applies an additional filter only when it can verify the DHI base-layer from the given image provenance. The post-filter suppresses matching Debian or Alpine package findings in those base layers when the VEX status is `fixed` or `not_affected`; findings in application layers and unmatched findings remain. The job summary lists the post-filter suppressions and remaining findings.

The runner needs Docker Buildx and permission to pull the image and the DHI base images used to verify the layer boundary. For private `dhi.io` images, provide `docker_username` and `docker_token`. DHI advisory documents are fetched from Docker's public advisories repository.

### Example usage

Using the action is very simple, and may be added as a separate job in your workflow, or as a step in an existing job.

The job which runs the action must have the following permissions:

- `actions: read`
- `packages: read`
- `contents: read`
- `security-events: write`

```yaml
pharos-job:
  name: Run Pharos with Required Permissions
  permissions:
    actions: read
    packages: read
    contents: read
    security-events: write
  runs-on: ubuntu-latest
  steps:
    - name: "Run Pharos"
      uses: kartverket/pharos@112c1589d5022bc0cdf3353cb4c6047aa4a3a26f #v0.6.2 
      with:
        image_url: $IMAGE_URL
```

Here, the `$IMAGE_URL` variable would typically come from the output of a previous build step or job.

To scan a DHI image with DHI VEX, configure the action like this:
```yaml
- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@vX
  with:
    driver: docker-container
```
```yaml
- name: Run Pharos with DHI VEX
  uses: kartverket/pharos@<ref>
  with:
    image_url: ${{ needs.build.outputs.image_url }}
    trivy_vex: "true"
    trivy_vex_provider: dhi
    docker_username: ${{ secrets.DHI_USERNAME }}
    docker_token: ${{ secrets.DHI_TOKEN }}
```

For a public image, the `docker_username` and `docker_token` inputs can be left out if the runner can pull the image and its DHI base images without authentication.