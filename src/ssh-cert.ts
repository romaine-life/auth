// OpenSSH user-certificate signing primitive for auth.romaine.life.
//
// This is the SECOND class of signing key the service owns. The first is
// the JWKS/JWT key behind Better Auth's signJWT (see src/mint-jwt.ts); it
// signs JSON Web Tokens. This module signs OpenSSH *user certificates* — a
// distinct wire format (OpenSSH PROTOCOL.certkeys) over a distinct ed25519
// CA key (env SSH_CA_PRIVATE_KEY, synced from Key Vault). The two key
// classes never mix: a JWT verifier must never accept an SSH cert and an
// sshd must never accept a JWT.
//
// Why hand-rolled instead of a library: the OpenSSH cert body is a small,
// fully-specified SSH-string-encoded structure, and the signature over it
// is a plain ed25519 sign that Node's stdlib `crypto.sign(null, …)` does
// natively. Pulling a third-party SSH crypto dependency into the identity
// provider's trust boundary for ~150 lines of stable binary encoding is
// the kind of incidental surface the repo quality bar pushes back on. The
// contract test (src/ssh-cert.test.ts) proves the output verifies under
// real `ssh-keygen -L` when openssh-client is present, and always proves
// the cert decodes + the signature verifies cryptographically.
//
// See the route handler at POST /api/auth/exchange/ssh-cert and the
// orchestration in src/ssh-cert-exchange.ts.

import crypto from "node:crypto";

/** Default validity window. Mirrors glimmung's retired signer
 *  (10 minutes) so the cutover preserves the settled contract: short
 *  enough that a leaked cert is near-useless, long enough to cover
 *  orchestrator setup plus the rest of the phase. */
export const SSH_CERT_DEFAULT_TTL_SECONDS = 10 * 60;

/** Upper bound on any caller-requested TTL. Matches glimmung's old
 *  sshCertMaxTTL. A caller asking for more is REJECTED, not clamped —
 *  silent downgrade hides a misconfigured caller. */
export const SSH_CERT_MAX_TTL_SECONDS = 60 * 60;

/** Lower bound; stops a misconfiguration from minting useless certs. */
export const SSH_CERT_MIN_TTL_SECONDS = 60;

/** Backdates ValidAfter so small clock skew between auth and the remote
 *  host does not kill the cert before it lands. Mirrors glimmung's
 *  sshCertSkew. */
export const SSH_CERT_SKEW_SECONDS = 30;

/** The only certificate extensions auth will stamp. permit-pty matches
 *  glimmung's retired signer; every forwarding/X11/user-rc extension is
 *  intentionally excluded. Critical options are never honored from a
 *  caller — the map is always empty. */
export const SSH_CERT_ALLOWED_EXTENSIONS: ReadonlySet<string> = new Set(["permit-pty"]);

const CERT_KEY_TYPE = "ssh-ed25519-cert-v01@openssh.com";
const ED25519_KEY_TYPE = "ssh-ed25519";
const CERT_TYPE_USER = 1;

// ── SSH wire encoders (RFC 4251 §5) ────────────────────────────────────
function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

function u64(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

function sshString(value: Buffer | string): Buffer {
  const b = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return Buffer.concat([u32(b.length), b]);
}

/** A name-list packed as concatenated SSH strings (used for
 *  ValidPrincipals). */
function packNameList(names: string[]): Buffer {
  return Buffer.concat(names.map((n) => sshString(n)));
}

/** Extensions/critical-options block: concatenated (name, data) string
 *  pairs, name-sorted as OpenSSH does. Flag extensions carry an empty
 *  data string. */
function packExtensions(names: string[]): Buffer {
  const sorted = [...names].sort();
  const parts: Buffer[] = [];
  for (const name of sorted) {
    parts.push(sshString(name));
    parts.push(sshString(Buffer.alloc(0)));
  }
  return Buffer.concat(parts);
}

// ── ed25519 key helpers ────────────────────────────────────────────────
/** Extract the raw 32-byte ed25519 public point from a KeyObject. The
 *  SPKI DER for ed25519 ends with the 32-byte key. */
function rawEd25519PublicKey(pub: crypto.KeyObject): Buffer {
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32);
}

/** The `ssh-ed25519` public key blob: string("ssh-ed25519") +
 *  string(raw32). This is both the on-the-wire pubkey and the body of an
 *  authorized_keys line. */
function ed25519PublicKeyBlob(rawPub: Buffer): Buffer {
  return Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(rawPub)]);
}

export class SshCaUnconfiguredError extends Error {
  constructor(message = "SSH CA private key not configured") {
    super(message);
    this.name = "SshCaUnconfiguredError";
  }
}

/** A loaded CA keypair ready to sign user certs. One per process. */
export class SshCertSigner {
  private constructor(
    private readonly caPrivate: crypto.KeyObject,
    private readonly caPublic: crypto.KeyObject,
  ) {}

  /** Load from a PKCS#8 PEM ed25519 private key (the form synced from
   *  Key Vault into env SSH_CA_PRIVATE_KEY). Node cannot parse the
   *  OpenSSH private-key container, so the CA key is stored as PKCS#8;
   *  generate with `ssh-keygen -t ed25519 … && ssh-keygen -p -m PKCS8`
   *  or `openssl genpkey -algorithm ed25519`. Empty input throws
   *  SshCaUnconfiguredError so the endpoint fails closed. */
  static fromPkcs8Pem(pem: string): SshCertSigner {
    const trimmed = (pem ?? "").trim();
    if (!trimmed) throw new SshCaUnconfiguredError();
    let priv: crypto.KeyObject;
    try {
      priv = crypto.createPrivateKey({ key: trimmed, format: "pem" });
    } catch (e) {
      throw new Error(`parse SSH CA private key: ${(e as Error).message}`);
    }
    if (priv.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `SSH CA private key must be ed25519, got ${priv.asymmetricKeyType ?? "unknown"}`,
      );
    }
    const pub = crypto.createPublicKey(priv);
    return new SshCertSigner(priv, pub);
  }

  /** The CA public key as an authorized_keys / TrustedUserCAKeys line:
   *  `ssh-ed25519 <base64> <comment>`. This is what a host trusts. */
  publicKeyAuthorizedKey(comment = "auth.romaine.life-ssh-ca"): string {
    const blob = ed25519PublicKeyBlob(rawEd25519PublicKey(this.caPublic));
    return `${ED25519_KEY_TYPE} ${blob.toString("base64")} ${comment}`.trim();
  }

  /** Sign a user certificate over `userPublicKey` (a parsed ed25519
   *  public key). All security-relevant fields are caller-supplied but
   *  validated/clamped by the exchange layer before reaching here. */
  signUserCert(params: SignUserCertParams): SignedUserCert {
    const {
      userPublicKey,
      keyId,
      principals,
      extensions,
      validAfter,
      validBefore,
      nonce = crypto.randomBytes(32),
      serial = 0,
    } = params;

    if (!keyId.trim()) throw new Error("key id required");
    if (principals.length === 0) throw new Error("at least one principal required");

    const caPubBlob = ed25519PublicKeyBlob(rawEd25519PublicKey(this.caPublic));

    // Body = everything the signature covers (i.e. the whole cert minus
    // the trailing signature string). Field order is fixed by
    // PROTOCOL.certkeys for ssh-ed25519-cert-v01.
    const body = Buffer.concat([
      sshString(CERT_KEY_TYPE),
      sshString(nonce),
      sshString(ed25519PublicKeyToRaw(userPublicKey)),
      u64(serial),
      u32(CERT_TYPE_USER),
      sshString(keyId),
      sshString(packNameList(principals)),
      u64(validAfter),
      u64(validBefore),
      sshString(Buffer.alloc(0)), // critical options: none, ever
      sshString(packExtensions(extensions)),
      sshString(Buffer.alloc(0)), // reserved
      sshString(caPubBlob), // signature key
    ]);

    const rawSig = crypto.sign(null, body, this.caPrivate); // 64-byte ed25519
    const sigBlob = Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(rawSig)]);
    const cert = Buffer.concat([body, sshString(sigBlob)]);

    return {
      certType: CERT_KEY_TYPE,
      certB64: cert.toString("base64"),
      authorizedKeyLine: `${CERT_KEY_TYPE} ${cert.toString("base64")}`,
      validBefore,
    };
  }
}

export interface SignUserCertParams {
  userPublicKey: crypto.KeyObject;
  keyId: string;
  principals: string[];
  extensions: string[];
  validAfter: number;
  validBefore: number;
  /** Test-only override; production uses a random 32-byte nonce. */
  nonce?: Buffer;
  serial?: number;
}

export interface SignedUserCert {
  certType: string;
  /** Base64 of the marshaled certificate (no key-type prefix). */
  certB64: string;
  /** `ssh-ed25519-cert-v01@openssh.com <base64>` — the form written to a
   *  `-cert.pub` file and passed to `ssh -i`. */
  authorizedKeyLine: string;
  /** Seconds-since-epoch the cert expires (mirrors ValidBefore). */
  validBefore: number;
}

/** Raw 32-byte point from a parsed ed25519 public KeyObject. */
function ed25519PublicKeyToRaw(pub: crypto.KeyObject): Buffer {
  if (pub.asymmetricKeyType !== "ed25519") {
    throw new Error("user public key must be ed25519");
  }
  return rawEd25519PublicKey(pub);
}

/** Parse a request-supplied authorized_keys-format public key, accepting
 *  only `ssh-ed25519` (the key type glimmung's orchestrator mints).
 *  Rejects certificates (re-signing a cert is never the intended flow)
 *  and any non-ed25519 type. Returns a KeyObject usable by signUserCert.
 */
export function parseUserEd25519PublicKey(raw: string): crypto.KeyObject {
  const trimmed = (raw ?? "").trim();
  if (!trimmed) throw new Error("public_key required");
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) throw new Error("public_key must be authorized_keys format");
  const [type, b64] = parts;
  if (type !== ED25519_KEY_TYPE) {
    throw new Error(`public_key must be ${ED25519_KEY_TYPE}, got ${type}`);
  }
  let blob: Buffer;
  try {
    blob = Buffer.from(b64, "base64");
  } catch {
    throw new Error("public_key base64 is invalid");
  }
  // blob = string("ssh-ed25519") + string(raw32). Validate framing.
  const r = new SshReader(blob);
  const innerType = r.readString().toString("utf8");
  if (innerType !== ED25519_KEY_TYPE) {
    throw new Error("public_key blob type mismatch");
  }
  const rawPub = r.readString();
  if (rawPub.length !== 32) {
    throw new Error("public_key ed25519 point must be 32 bytes");
  }
  // Wrap the raw point as SPKI DER so Node can import it. ed25519 SPKI
  // prefix is a fixed 12-byte header followed by the 32-byte key.
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([spkiPrefix, rawPub]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

/** Minimal SSH wire reader — exposed for the public-key parser and the
 *  contract test's structural decode. */
export class SshReader {
  private offset = 0;
  constructor(private readonly buf: Buffer) {}
  readString(): Buffer {
    const n = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    const s = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return s;
  }
  readU32(): number {
    const n = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return n;
  }
  readU64(): bigint {
    const n = this.buf.readBigUInt64BE(this.offset);
    this.offset += 8;
    return n;
  }
  remaining(): number {
    return this.buf.length - this.offset;
  }
}
