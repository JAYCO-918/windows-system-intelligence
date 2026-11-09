# Security Policy

## 🛡️ Read-Only Safety Guarantee

Windows System Intelligence (WSI) is engineered from the ground up as a **strictly non-destructive, read-only diagnostic and inventory engine**:

- **No System Modifications**: WSI will never write to, modify, or delete registry keys, system files, system services, or host configuration.
- **Read-Only Registry Enforcement**: All registry interactions are performed using `winreg.KEY_READ` with explicit 64-bit and 32-bit hive enumeration.
- **No Direct Hardware or Destructive Testing**: WSI inspects passive metadata and diagnostic logs. Destructive validation scenarios must execute against synthetic datasets in disposable virtual machines.
- **No Unrestricted Elevation**: WSI operates within standard user privileges for user-scoped collectors and gracefully reports permission-restricted artifacts when run without elevation.

## Reporting a Vulnerability

If you discover any aspect of WSI that performs an inadvertent write or modification to the host operating system, or if you identify a security issue in our collectors, please report it privately:

1. **Do not create a public issue** on GitHub.
2. Email security inquiries or vulnerability reports to the project maintainers.
3. Include a description of the issue, affected collector/analyzer, and reproduction steps.

We review all reports and respond with an acknowledgment and remediation plan within 48 hours.
