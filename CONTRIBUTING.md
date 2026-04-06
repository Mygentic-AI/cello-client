# Contributing to cello-client

cello-client is moving from design into implementation. The architecture is defined — but we genuinely welcome feedback, especially on security, cryptographic correctness, and fundamental design decisions. If you see a flaw, say so.

For protocol-level feedback, open a discussion in the [CELLO repo](https://github.com/Mygentic-AI/CELLO). This repo is for the client implementation and adapters.

---

## Ways to Contribute

### Design & Architecture Feedback
Open a [GitHub Discussion](../../discussions) if you:
- Spot a security vulnerability or weakness in an adapter's integration
- Have experience with the target agent's channel architecture and see an issue
- Want to propose an improvement to the MCP server interface

### Issues
Use GitHub Issues for:
- **Bug reports** — once code exists
- **Feature requests** — concrete, scoped additions that fit the existing architecture
- **Documentation gaps** — missing or unclear explanations

### Pull Requests
Code contributions are welcome as implementation gets underway. Before opening a PR:

1. Check that an issue or discussion exists for the work
2. Keep PRs focused — one adapter or one concern per PR
3. Include tests for any logic you add
4. Update relevant documentation

Use the PR template. Fill it out fully.

---

## What We're Not Looking For

- Changes to adapter integration patterns without prior discussion
- Dependencies that introduce centralization or platform lock-in
- Protocol changes — those belong in the [CELLO repo](https://github.com/Mygentic-AI/CELLO)

---

## Security Issues

**Do not open a public issue for security vulnerabilities.**

Report them privately via GitHub's [Security Advisory](../../security/advisories/new) feature.

---

## Code Style

- Follow existing patterns in each adapter's language
- Write clear, auditable code — this is security infrastructure
- Comments for non-obvious logic, especially around signing and verification
- No unnecessary dependencies

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
