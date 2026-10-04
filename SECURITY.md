# Security policy

Report vulnerabilities privately — do not open a public issue for anything
affecting signature verification, scope enforcement, or chain integrity.

Email: savagetism@icloud.com

Include: affected version, reproduction or theory of the flaw, and what an
attacker gains.

Scope of concern:

- Signature bypass on propose/ratify/revoke
- TreatyBook chain insertion, reorder, or silent edit
- Scope checks that can be skipped while a treaty is inactive
- Key confusion between initiator and counterparty

Out of scope: transport-layer attacks (artifacts are signatures over
canonical JSON — the channel is yours), and malicious code running on a
counterparty's own machine (the treaty proves consent, it does not sandbox
the peer).
