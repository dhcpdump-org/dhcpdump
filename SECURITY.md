# Security Policy

## Supported Versions

Security fixes are made against the latest release and the development branch. Older releases are not updated.

The latest release is published at https://github.com/dhcpdump-org/dhcpdump/releases

## Scope

`dhcpdump` decodes DHCP packets taken straight off the wire, so anything that can reach the monitored link is untrusted input. Memory safety problems in the decoder, and anything a crafted packet can make the tool do to the terminal it prints to, are in scope. Capturing from an interface needs privileges; use `-Z <user>` to drop them once the interface is open, so the decoder does not run as root.

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please **do not open a public GitHub issue**. Instead, follow these steps:

1. Email a detailed description of the issue to: **bbonev@devuan.org**
2. Include steps to reproduce the vulnerability (PoC), examples, or code.
3. Specify which version of the software you are using.

Reports may be encrypted to the project signing key, fingerprint `BA60 BC20 F37E 5944 4D6D 2500 1365 7209 13D2 F22D`, which covers the address above.

### Our Response Process

* **Acknowledgment:** You will receive a response within 7 days.
* **Investigation:** We will keep you updated on our progress as we fix the issue.
* **Disclosure:** Once a patch is released, we will publish a security advisory and credit you for the discovery (unless you prefer anonymity).

