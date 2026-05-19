// Consumer routing for k8s service-principal exchange.
//
// Kept pure so namespace-to-consumer policy can be tested without importing
// the DB client or JWT minting path from service-exchange.ts.

/** Per-consumer lineage policy.
 *
 *  - `per-session` (default for per-user pods like tank-operator's session
 *    pods): the pod carries lineage annotations and actor_email is read from
 *    the bound pod at exchange time.
 *
 *  - `pod-stable` (shared services and orchestrators): the service identity is
 *    stable across pod restarts. There is no per-pod human actor unless the
 *    consumer explicitly opts into actor_email override.
 */
export type ConsumerConfig =
  | { slug: string; mode: "per-session" }
  | {
      slug: string;
      mode: "pod-stable";
      stableId: string;
      /** When true, the route handler may forward a caller-supplied
       *  actor_email to the mint. Defaults to false. */
      allowActorOverride?: boolean;
    };

type PodStableConsumer = Extract<ConsumerConfig, { mode: "pod-stable" }>;

const TANK_OPERATOR_ORCHESTRATOR: PodStableConsumer = {
  slug: "tank-operator",
  mode: "pod-stable",
  stableId: "orchestrator",
  // The orchestrator calls mcp-github on behalf of the SPA user so the repo
  // picker can enumerate the user's resolved GitHub installation.
  allowActorOverride: true,
};

/** Map from k8s namespace to consumer config. Each consumer slug must have a
 *  matching subdomain registered in RESERVED_SERVICE_EMAIL_DOMAINS in
 *  src/synthetic-email.ts. */
const NAMESPACE_TO_CONSUMER: Record<string, ConsumerConfig> = {
  "tank-operator-sessions": { slug: "tank", mode: "per-session" },
  "mcp-k8s": {
    slug: "mcp-k8s",
    mode: "pod-stable",
    stableId: "mcp-k8s",
  },
  "mcp-argocd": {
    slug: "mcp-argocd",
    mode: "pod-stable",
    stableId: "mcp-argocd",
  },
  "mcp-azure-personal": {
    slug: "mcp-azure-personal",
    mode: "pod-stable",
    stableId: "mcp-azure-personal",
  },
  hermes: {
    slug: "hermes",
    mode: "pod-stable",
    stableId: "hermes",
  },
  "tank-operator": TANK_OPERATOR_ORCHESTRATOR,
};

const TANK_OPERATOR_SLOT_NAMESPACE = /^tank-operator-slot-([1-9][0-9]*)$/;

export function consumerForNamespace(namespace: string): ConsumerConfig | undefined {
  const ns = namespace.trim();
  const staticConsumer = NAMESPACE_TO_CONSUMER[ns];
  if (staticConsumer) {
    return staticConsumer;
  }
  const slot = TANK_OPERATOR_SLOT_NAMESPACE.exec(ns);
  if (!slot) {
    return undefined;
  }
  return {
    ...TANK_OPERATOR_ORCHESTRATOR,
    stableId: `orchestrator-slot-${slot[1]}`,
  };
}
