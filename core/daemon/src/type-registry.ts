/**
 * DOD-REGISTRY-1 (client half) — in-memory type registry cache.
 *
 * The registry is a signed canonical-JSON document mapping signal type strings to their
 * classification (class, lifecycle, default TTL, display label). The daemon polls the
 * directory for new versions and keeps the latest verified document here.
 *
 * INV-TYPE-CARRY: an absent type is valid-but-unclassified, never an error. This is the
 * whole reason the registry is DATA not code — adding a new type requires no release.
 */

export interface RegistryTypeEntry {
  class: number;
  label: string;
  lifecycle: string;
  default_ttl_days: number | null;
}

export interface RegistryDocument {
  version: number;
  types: Record<string, RegistryTypeEntry>;
  signature: string;
}

export interface TypeClassification {
  type: string;
  class: number;
  label: string;
  lifecycle: string;
  defaultTtlDays: number | null;
  classified: true;
}

export interface UnclassifiedType {
  type: string;
  classified: false;
}

export type TypeLookupResult = TypeClassification | UnclassifiedType;

export class TypeRegistry {
  #doc: RegistryDocument | null = null;

  get currentVersion(): number | null {
    return this.#doc?.version ?? null;
  }

  get currentDocument(): RegistryDocument | null {
    return this.#doc;
  }

  update(doc: RegistryDocument): void {
    this.#doc = doc;
  }

  classify(type: string): TypeLookupResult {
    if (!this.#doc || !(type in this.#doc.types)) {
      return { type, classified: false };
    }
    const entry = this.#doc.types[type];
    return {
      type,
      class: entry.class,
      label: entry.label,
      lifecycle: entry.lifecycle,
      defaultTtlDays: entry.default_ttl_days,
      classified: true,
    };
  }
}
