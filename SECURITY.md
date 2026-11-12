# Security Policy

SafeNook is a secrets vault, so security reports are the most valuable contributions we get. Thank you for taking the time.

## Supported versions

SafeNook is in **pre-alpha**. There are no released versions yet, and only the `main` branch is supported. Please do not store real secrets in it until 1.0.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting).

Please include:

- what is affected (component, file format, command);
- steps to reproduce or a proof of concept;
- the impact you expect (for example: secret disclosure, integrity bypass, denial of service).

We aim to acknowledge reports within 7 days and to agree on a disclosure timeline with you. Credit is given in the release notes unless you prefer otherwise.

## Scope

In scope: the vault format and cryptography, the `nook` CLI, and (once they exist) the agent, sync and server components.

Protection against attackers who already control the user's account or machine while
the vault is unlocked is not currently guaranteed. Reaching version 1.0 alone will
not establish that protection. The precise threat model and security guarantees
must be agreed before implementing vault storage. The [SN-002 threat model](docs/threat-model.md)
and [vault specification](docs/vault-format.md) are drafts pending the
[owner decisions](docs/SN-002-DECISIONS.md), not implemented security guarantees.

The first functionally useful milestone is still pre-alpha. The proposed stable
release criteria include format review, negative tests, backup/restore validation
and security review; installation or a working demo alone is not sufficient.
