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

Out of scope until 1.0: hardening against attackers who already control the user's account or machine while the vault is unlocked. The threat model will be documented in `docs/threat-model.md`.
