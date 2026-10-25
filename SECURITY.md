# Security policy

**CR01-SC is not production-ready. Do not use it to protect real secrets.**
There is no side-channel assurance or established constant-time behavior.
The project has no independent security audit, formal protocol proof,
quantum-security proof or certification. Local checks do not provide these.

## Report privately

Email [cr01@smart-fox-innovation.com](mailto:cr01@smart-fox-innovation.com)
about suspected cryptographic flaws, implementation bugs or secret exposure.
Please contact us privately first; do not put exploit details in public issues,
discussions or social media while the finding is being investigated.

Useful reports include:

- the version or archive SHA-256 and relevant platform/backend versions;
- a small reproduction using synthetic test data;
- expected behavior, observed behavior and possible impact;
- what you reproduced, and what remains theoretical.

Do not email real private keys, credentials, customer data or operational
secrets. Non-sensitive bugs may use the validation-failure issue template.
This policy promises no response time or remediation deadline.

## Preview status

This is a research preview. No security-maintenance commitment is made.

V2 requires authenticated peer pins, protected identity files, trustworthy OS
randomness and a fresh full handshake after restart. It does not provide
session resumption, VM/live-memory rollback detection, automatic recovery after
endpoint compromise or a production network service. Buffer cleansing is
best effort, not process-wide secure memory.

See the [protocol limits](docs/PROTOCOL.md#limits) and
[test results](docs/RESULTS.md). Independent design and side-channel review,
key-lifecycle policy and deployment-specific assessment remain necessary;
passing the supplied checks is not permission or approval to deploy.
