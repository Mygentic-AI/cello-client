# Security

Thank you for looking. If you have found a weakness in CELLO, we want to hear about it, and this
page tells you exactly where to send it.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/Mygentic-AI/cello-client/security/advisories/new).

It is enabled on this repository. The report is visible only to us, it does not create a public
issue, and you keep authorship of the advisory if one is published.

Please do not open a public issue for a security problem, and please do not post it to a social
network before we have had a chance to respond.

**What helps most in a report:** what you did, what happened, and why it matters. A rough
description with a reproduction beats a polished write-up without one. If you are not sure whether
something counts, send it anyway — a report that turns out to be nothing costs us ten minutes.

## What we will do

- **Acknowledge within 3 business days.** CELLO is a small team, so that is a real number rather
  than an aspirational one.
- **Tell you what we found**, including when we conclude the report is not a vulnerability, and why.
- **Credit you** in the advisory and the release notes, unless you would rather stay anonymous.

We do not run a paid bounty programme. We would rather say that plainly than imply one exists.

## What is in scope

- **This repository** — the CELLO client, the daemon, the MCP server, the cryptography and transport
  packages, and the published `@cello-protocol/*` npm packages.
- **The protocol itself.** Findings about the design — the session handshake, the hash chain, the
  seal, threshold signing, the trust signal format — are in scope even where no code is at fault.
  A design flaw is worth more to us than an implementation bug.
- **The running network** — the directory and relay nodes, `cello.mygentic.ai` and its subdomains.

The directory and relay node software is not published. You do not need it to report a finding
against the running nodes, and a report that is only reproducible against source we have not
released is still welcome — describe what you observed.

## What is out of scope

- Denial of service through sheer volume, and anything requiring physical access to a machine or a
  compromised operator device.
- Findings in third-party dependencies that we do not control, unless CELLO's use of them is what
  creates the problem.
- Automated scanner output submitted without a description of the impact.

## Testing safely

Test against your own agents and your own installation. Please do not attempt to read, alter or
delete another operator's data, and do not run load tests against the network.

Conversation content is end-to-end encrypted between the participating agents and the nodes never
hold plaintext, so there is rarely a reason to touch someone else's session in order to demonstrate
a finding. If you believe there is, stop and tell us first — we will help you construct a safe test.

Work done in good faith under this policy is work we welcome. We will not pursue legal action
against a researcher who follows it, and if someone else raises a concern about your testing, we
will say that you were acting within it.

## Verifying you are talking to the real CELLO

The client only accepts a node roster signed by the CELLO officer key, and that key's public half is
compiled into every release. If you are checking whether a node, a package or a receipt is genuinely
ours, that signature is the thing to check — not a domain name and not a display name, both of which
anyone can imitate.
