/**
 * Who holds each agent, and whether that agent is reachable right now — M15D 001-DAEMON.
 *
 * An agent has ZERO OR ONE holder. The holder is a CALLER, not a socket: a web-endpoint client
 * (`endpoint:<oauth client id>`), the CLI (`cli:<host>`, one caller per machine), or a long-lived
 * socket such as the plugin (`socket:<connectionId>`). `caller-identity.ts` decides which; nothing a
 * client types can choose it.
 *
 * A second caller is refused (`agent_held`) unless it forces, and a forced take marks the old holder
 * DISPLACED so its next guarded call is refused naming who took it.
 *
 * REACHABLE NOW means a counterparty's message would reach someone at once: the holder has a live
 * event channel (a socket that receives doorbells) or a receive/await waiting as the agent, or the
 * agent has a listener (the Hermes cello bridge, which wakes the agent and never holds it). There is
 * no silence timer. The attended/unattended state a counterparty sees, and whether the away reply
 * fires, both read `isReachable`.
 *
 * Keyed on the agent's PUBKEY, never its name: the name is a mutable label.
 */

export interface Caller {
  /** Opaque, set by the daemon from the socket or the endpoint's verified token. */
  readonly key: string;
  /** Display only ("ChatGPT", "Claude Code", "cli"). */
  readonly label: string;
}

export interface HolderView {
  label: string;
  since: string;
  last_active: string;
}

interface Holder {
  agentName: string;
  callerKey: string;
  label: string;
  since: number;
  lastActive: number;
  /** Connections that receive this agent's doorbells on the holder's behalf. */
  channels: Set<string>;
  /** In-flight receive/await calls, by connection. */
  waits: Map<string, number>;
}

export type HoldCheck =
  | { ok: true }
  | { ok: false; reason: "agent_held"; holder: HolderView }
  | { ok: false; reason: "agent_displaced"; holder: HolderView; by_label: string };

export interface HolderRegistryOpts {
  /** The agent's stable key (pubkey). Undefined for an agent this daemon does not know. */
  agentKey: (agentName: string) => string | undefined;
  /** Fires when an agent becomes reachable or stops being reachable. */
  onReachability: (agentName: string, reachable: boolean) => void;
  now?: () => number;
}

export class HolderRegistry {
  readonly #holders = new Map<string, Holder>();
  /** agentKey → the listener's connection id and the agent name it listens for. */
  readonly #listeners = new Map<string, { connectionId: string; agentName: string }>();
  /** callerKey → agentKey → label of whoever took it. Reported once, then dropped. */
  readonly #displaced = new Map<string, Map<string, string>>();
  readonly #opts: HolderRegistryOpts;
  readonly #now: () => number;

  constructor(opts: HolderRegistryOpts) {
    this.#opts = opts;
    this.#now = opts.now ?? Date.now;
  }

  #key(agentName: string): string | undefined {
    return this.#opts.agentKey(agentName);
  }

  #view(h: Holder): HolderView {
    return { label: h.label, since: new Date(h.since).toISOString(), last_active: new Date(h.lastActive).toISOString() };
  }

  #reachable(key: string): boolean {
    if (this.#listeners.has(key)) return true;
    const h = this.#holders.get(key);
    return h !== undefined && (h.channels.size > 0 || h.waits.size > 0);
  }

  /** Run a mutation and report any reachability change it caused. */
  #mutate<T>(agentNames: string[], fn: () => T): T {
    const before = new Map<string, boolean>();
    for (const name of agentNames) {
      const key = this.#key(name);
      if (key !== undefined) before.set(name, this.#reachable(key));
    }
    const result = fn();
    for (const [name, was] of before) {
      const now = this.#reachable(this.#key(name)!);
      if (now !== was) this.#opts.onReachability(name, now);
    }
    return result;
  }

  holderView(agentName: string): HolderView | null {
    const key = this.#key(agentName);
    const h = key === undefined ? undefined : this.#holders.get(key);
    return h ? this.#view(h) : null;
  }

  isReachable(agentName: string): boolean {
    const key = this.#key(agentName);
    return key !== undefined && this.#reachable(key);
  }

  /** The agent this caller holds, if any. A caller holds at most one agent. */
  heldBy(callerKey: string): string | undefined {
    for (const h of this.#holders.values()) if (h.callerKey === callerKey) return h.agentName;
    return undefined;
  }

  /** May `caller` act as `agentName`? Reads never ask; send/receive/close/initiate/await do. */
  check(agentName: string, caller: Caller): HoldCheck {
    const key = this.#key(agentName);
    if (key === undefined) return { ok: true };
    const h = this.#holders.get(key);
    if (!h || h.callerKey === caller.key) return { ok: true };
    const marks = this.#displaced.get(caller.key);
    const by = marks?.get(key);
    if (by !== undefined) {
      marks!.delete(key);
      if (marks!.size === 0) this.#displaced.delete(caller.key);
      return { ok: false, reason: "agent_displaced", holder: this.#view(h), by_label: by };
    }
    return { ok: false, reason: "agent_held", holder: this.#view(h) };
  }

  /**
   * Make `caller` the holder. Refused when another caller holds it and `force` is not set. Taking
   * an agent releases any other agent this caller held. `channel` registers the calling socket for
   * doorbells (plugin, stream-holding endpoint session); a one-shot call passes none.
   */
  take(
    agentName: string,
    caller: Caller,
    opts: { force?: boolean; channel?: string } = {},
  ): { ok: true; displaced?: { callerKey: string; label: string; channels: string[] }; released?: string } | Extract<HoldCheck, { ok: false }> {
    const key = this.#key(agentName);
    if (key === undefined) return { ok: true };
    const current = this.#holders.get(key);
    if (current && current.callerKey !== caller.key && !opts.force) {
      return { ok: false, reason: "agent_held", holder: this.#view(current) };
    }
    const previouslyHeld = this.heldBy(caller.key);
    const touched = [agentName, ...(previouslyHeld && previouslyHeld !== agentName ? [previouslyHeld] : [])];
    return this.#mutate(touched, () => {
      let released: string | undefined;
      if (previouslyHeld && previouslyHeld !== agentName) {
        this.#holders.delete(this.#key(previouslyHeld)!);
        released = previouslyHeld;
      }
      const now = this.#now();
      let displaced: { callerKey: string; label: string; channels: string[] } | undefined;
      if (current && current.callerKey !== caller.key) {
        displaced = { callerKey: current.callerKey, label: current.label, channels: [...current.channels] };
        let marks = this.#displaced.get(current.callerKey);
        if (!marks) { marks = new Map(); this.#displaced.set(current.callerKey, marks); }
        marks.set(key, caller.label);
      }
      const holder: Holder = current && current.callerKey === caller.key
        ? current
        : { agentName, callerKey: caller.key, label: caller.label, since: now, lastActive: now, channels: new Set(), waits: new Map() };
      holder.lastActive = now;
      if (opts.channel !== undefined) holder.channels.add(opts.channel);
      this.#holders.set(key, holder);
      this.#displaced.get(caller.key)?.delete(key);
      return { ok: true as const, ...(displaced ? { displaced } : {}), ...(released ? { released } : {}) };
    });
  }

  /** Drop `caller`'s hold. Returns false when it held nothing there. */
  release(agentName: string, caller: Caller): boolean {
    const key = this.#key(agentName);
    if (key === undefined) return false;
    const h = this.#holders.get(key);
    if (!h || h.callerKey !== caller.key) return false;
    this.#mutate([agentName], () => this.#holders.delete(key));
    return true;
  }

  /** The Hermes cello bridge: wakes the agent and makes it reachable; never holds. One per agent. */
  setListener(agentName: string, connectionId: string): void {
    const key = this.#key(agentName);
    if (key === undefined) return;
    this.#mutate([agentName], () => this.#listeners.set(key, { connectionId, agentName }));
  }

  dropListener(agentName: string, connectionId: string): boolean {
    const key = this.#key(agentName);
    if (key === undefined || this.#listeners.get(key)?.connectionId !== connectionId) return false;
    this.#mutate([agentName], () => this.#listeners.delete(key));
    return true;
  }

  /**
   * A receive/await is waiting as `agentName`. The caller becomes holder when nobody holds it (the
   * guard has already refused another caller's hold). Returns the function that ends the wait.
   */
  beginWait(agentName: string, caller: Caller, connectionId: string): () => void {
    const key = this.#key(agentName);
    if (key === undefined) return () => {};
    this.#mutate([agentName], () => {
      if (!this.#holders.has(key)) this.take(agentName, caller);
      const h = this.#holders.get(key)!;
      h.lastActive = this.#now();
      h.waits.set(connectionId, (h.waits.get(connectionId) ?? 0) + 1);
    });
    let ended = false;
    return () => {
      if (ended) return;
      ended = true;
      this.#mutate([agentName], () => {
        const h = this.#holders.get(key);
        if (!h || h.callerKey !== caller.key) return;
        const n = (h.waits.get(connectionId) ?? 1) - 1;
        if (n <= 0) h.waits.delete(connectionId);
        else h.waits.set(connectionId, n);
      });
    };
  }

  /** Record activity by the holder (any guarded call it made). */
  touch(agentName: string, caller: Caller): void {
    const key = this.#key(agentName);
    const h = key === undefined ? undefined : this.#holders.get(key);
    if (h && h.callerKey === caller.key) h.lastActive = this.#now();
  }

  /**
   * A socket closed. A `socket:` caller IS that socket, so its hold ends. Any other caller keeps its
   * hold and loses only this socket's channel and waits.
   */
  dropConnection(connectionId: string): void {
    const affected = new Set<string>();
    for (const h of this.#holders.values()) {
      if (h.callerKey === `socket:${connectionId}` || h.channels.has(connectionId) || h.waits.has(connectionId)) affected.add(h.agentName);
    }
    for (const l of this.#listeners.values()) if (l.connectionId === connectionId) affected.add(l.agentName);
    if (affected.size === 0) {
      this.#displaced.delete(`socket:${connectionId}`);
      return;
    }
    this.#mutate([...affected], () => {
      for (const [key, h] of this.#holders) {
        if (h.callerKey === `socket:${connectionId}`) { this.#holders.delete(key); continue; }
        h.channels.delete(connectionId);
        h.waits.delete(connectionId);
      }
      for (const [key, l] of this.#listeners) if (l.connectionId === connectionId) this.#listeners.delete(key);
    });
    this.#displaced.delete(`socket:${connectionId}`);
  }

  /** The agent was stopped or removed: nobody holds or listens to it any more. */
  clearAgent(agentName: string): void {
    const key = this.#key(agentName);
    if (key === undefined) return;
    this.#mutate([agentName], () => {
      this.#holders.delete(key);
      this.#listeners.delete(key);
    });
    for (const marks of this.#displaced.values()) marks.delete(key);
  }

  /** Connections that receive this agent's doorbells: the holder's channels and the listener. */
  routeFor(agentName: string): string[] {
    const key = this.#key(agentName);
    if (key === undefined) return [];
    const out = [...(this.#holders.get(key)?.channels ?? [])];
    const l = this.#listeners.get(key);
    if (l && !out.includes(l.connectionId)) out.push(l.connectionId);
    return out;
  }
}
