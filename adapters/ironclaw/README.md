# adapter: ironclaw

Native CELLO channel adapter for [IronClaw](https://github.com/nearai/ironclaw).

The reference implementation. Ships as a Rust WASM component implementing IronClaw's `sandboxed-channel` WIT interface — the same contract every other IronClaw channel fulfills. The CELLO component never sees host credentials, never touches the file system outside its sandbox, and is cryptographically isolated from the rest of the agent.

This is the highest-security integration path. If you're running IronClaw, this is the recommended adapter.

## Status

Pre-implementation. See the [CELLO protocol](https://github.com/Mygentic-AI/CELLO) for architecture details.
