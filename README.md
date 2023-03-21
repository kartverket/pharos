# Pharos

<sub><sup>_pharos_ - (historical) An ancient lighthouse or beacon to guide sailors.</sup></sub>

<hr/>

A GitHub action for running different Security Scans, that should be run before deploying to SKIP.

Currently the action contains two scans, TFSec and Trivy. To use Trivy, an image must be provided as an input. Scans will not run on draft pull requests.

### Inputs

| Key                  | Required | Description                                                                                                                                                                                                                         |
| -------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| image_url            |          | The Docker image url must be of the form `registry/repository:tag` or `registry/repository@digest` for run-security-scans. It is not required; however, in order to run Trivy image_url must be supplied.                           |
| trivy                |          | An optional boolean that determines whether trivy-scan will be run. Defaults to 'true'.                                                                                                                                             |
| tfsec                |          | An optional boolean that determines whether tfsec-scan will be run. Defaults to 'true'.                                                                                                                                             |
| allow_severity_level |          | A string which determines the highest level of severity the security scans can find while still succeeding workflows. Only `medium`, `high` and `critical` are allowed as input strings. Note that these values are case sensitive. |
