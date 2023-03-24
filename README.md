# Pharos

<p align="center">
<img src="https://i.imgur.com/LUS8fWC.png"  width="20%">
<br/>
<sub><i>pharos</i> - (historical) An ancient lighthouse or beacon to guide sailors.</sub>
</p>

<hr/>

A GitHub action for running different Security Scans, that should be run before deploying to SKIP.

Currently the action contains two scans, TFSec and Trivy. To use Trivy, an image must be provided as an input.

As of v0.1.0 only GitHub registries are tested and supported.

### Inputs

| Key                  | Required | Description                                                                                                                                                                                                                         |
| -------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| image_url            |          | The Docker image url must be of the form `registry/repository:tag` or `registry/repository@digest` for run-security-scans. It is not required; however, in order to run Trivy image_url must be supplied.                           |
| trivy                |          | An optional boolean that determines whether trivy-scan will be run. Defaults to 'true'.                                                                                                                                             |
| tfsec                |          | An optional boolean that determines whether tfsec-scan will be run. Defaults to 'true'.                                                                                                                                             |
| allow_severity_level |          | A string which determines the highest level of severity the security scans can find while still succeeding workflows. Only `medium`, `high` and `critical` are allowed as input strings. Note that these values are case sensitive. |

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
      uses: kartverket/pharos@v0.1.0
      with:
        image_url: $IMAGE_URL
```

Here, the `$IMAGE_URL` variable would typically come from the output of a previous build step or job.
