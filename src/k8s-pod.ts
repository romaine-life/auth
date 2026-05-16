// In-cluster k8s API client for reading pod annotations.
//
// Used by /api/auth/exchange/k8s to resolve a session pod's lineage at
// exchange time:
//   - `tank-operator/owner-email` → `actor_email` claim on the issued JWT
//   - `tank-operator/session-id`  → synthetic email's stable identifier
//     and JWT `sub`
//
// The auth pod uses its own in-cluster ServiceAccount token (mounted at
// /var/run/secrets/kubernetes.io/serviceaccount/token) and reaches the
// API server at kubernetes.default.svc. The cluster CA is trusted via
// the `NODE_EXTRA_CA_CERTS` env var (set on the auth Deployment to
// /var/run/secrets/kubernetes.io/serviceaccount/ca.crt), so native
// fetch's TLS validates without per-request agent wiring and we avoid
// pulling in `undici`/`@kubernetes/client-node`.
//
// RBAC: cross-namespace Role + RoleBinding in each consumer namespace
// granting `pods/get` to (auth/auth). See
// k8s/templates/rbac-service-consumers.yaml.

import { readFile } from "node:fs/promises";

/** Annotations a session pod is required to expose for service-exchange
 *  to succeed. Missing either is a hard 4xx from the exchange endpoint —
 *  better to refuse the exchange than to mint an unowned/unscoped JWT. */
export interface PodLineage {
  /** From `tank-operator/owner-email` — the human whose session this pod
   *  is serving. Becomes the `actor_email` claim on the issued JWT. */
  ownerEmail: string;
  /** From `tank-operator/session-id` — the stable identifier across pod
   *  restarts within a session. Becomes the synthetic email's
   *  `pod-<sessionId>@...` body and the JWT `sub`. */
  sessionId: string;
}

const ANNOTATION_OWNER_EMAIL = "tank-operator/owner-email";
const ANNOTATION_SESSION_ID = "tank-operator/session-id";

const DEFAULT_API_HOST = "https://kubernetes.default.svc";
const TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

let cachedToken: string | null = null;

async function loadSaToken(): Promise<string> {
  // Each call re-reads the token file. The kubelet rotates projected SA
  // tokens before expiry, and we want to pick up the new bytes without
  // restarting. The token is small (~1KB), and a cache that lives
  // longer than rotation would surface as confusing 401s from the API
  // server. Read per call.
  const token = (await readFile(TOKEN_PATH, "utf8")).trim();
  if (!token) throw new Error(`empty SA token at ${TOKEN_PATH}`);
  cachedToken = token;
  return token;
}

/** Test-only: clear the cached token. */
export function _resetK8sPodCache(): void {
  cachedToken = null;
}

interface PodResource {
  metadata?: {
    annotations?: Record<string, string>;
  };
}

/** Fetch the named pod and extract the lineage annotations. Throws on
 *  any failure: pod not found, missing annotations, API server error.
 *  Caller maps to 4xx. */
export async function readPodLineage(
  namespace: string,
  podName: string,
  opts?: { fetchImpl?: typeof fetch },
): Promise<PodLineage> {
  if (!namespace || !podName) {
    throw new Error("namespace and podName are required");
  }
  const apiHost = (process.env.K8S_API_HOST ?? DEFAULT_API_HOST).replace(/\/$/, "");
  const token = await loadSaToken();
  const url = `${apiHost}/api/v1/namespaces/${encodeURIComponent(
    namespace,
  )}/pods/${encodeURIComponent(podName)}`;

  const fetchImpl = opts?.fetchImpl ?? fetch;
  const res = await fetchImpl(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });
  if (res.status === 404) {
    throw new Error(`pod ${namespace}/${podName} not found`);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`pod GET failed: HTTP ${res.status} ${body.slice(0, 200)}`);
  }
  const pod = (await res.json()) as PodResource;
  return extractLineage(pod, namespace, podName);
}

/** Pure extractor — separated from the fetch path so tests can exercise
 *  the annotation-shape contract without standing up an in-cluster API. */
export function extractLineage(
  pod: PodResource,
  namespace: string,
  podName: string,
): PodLineage {
  const annotations = pod.metadata?.annotations ?? {};
  const ownerEmail = annotations[ANNOTATION_OWNER_EMAIL]?.trim();
  const sessionId = annotations[ANNOTATION_SESSION_ID]?.trim();
  if (!ownerEmail) {
    throw new Error(
      `pod ${namespace}/${podName} missing annotation ${ANNOTATION_OWNER_EMAIL}`,
    );
  }
  if (!sessionId) {
    throw new Error(
      `pod ${namespace}/${podName} missing annotation ${ANNOTATION_SESSION_ID}`,
    );
  }
  return { ownerEmail, sessionId };
}

export const _annotations = {
  ownerEmail: ANNOTATION_OWNER_EMAIL,
  sessionId: ANNOTATION_SESSION_ID,
} as const;

// Silence unused-import warning under future strictness; cachedToken
// is read indirectly via the per-call re-read pattern.
void cachedToken;
