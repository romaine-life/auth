import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SshCertSigner,
  SshCaUnconfiguredError,
  SshReader,
  parseUserEd25519PublicKey,
  SSH_CERT_DEFAULT_TTL_SECONDS,
} from "./ssh-cert.js";

// Contract test for the OpenSSH user-cert signing primitive. This is the
// evidence for the "auth owns SSH cert issuance" feature contract:
//   (1) the cert decodes to the OpenSSH PROTOCOL.certkeys structure with
//       the exact fields we asked for;
//   (2) the ed25519 signature over the cert body verifies under the CA
//       public key (so a host that trusts the CA will accept it);
//   (3) when openssh-client is present, `ssh-keygen -L` parses the cert
//       and reports the same principal / key id / validity / extension
//       (the real-world consumer's own parser agreeing with ours).
//
// (3) is skipped (not failed) when ssh-keygen is unavailable so the suite
// runs in a bare pod; CI installs openssh-client so the cross-check is a
// hard gate there.

/** Generate an ed25519 CA keypair and return its PKCS#8 PEM private key
 *  (the form auth loads from env SSH_CA_PRIVATE_KEY). */
function genCaPkcs8Pem(): string {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

/** authorized_keys-format ed25519 public key, as glimmung's orchestrator
 *  would submit it. */
function genUserAuthorizedKey(): { line: string; pub: crypto.KeyObject } {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  const blob = Buffer.concat([
    sshStr("ssh-ed25519"),
    sshStr(raw),
  ]);
  return { line: `ssh-ed25519 ${blob.toString("base64")} runner`, pub: publicKey };
}

function sshStr(b: Buffer | string): Buffer {
  const buf = typeof b === "string" ? Buffer.from(b) : b;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
}

function haveSshKeygen(): boolean {
  try {
    execFileSync("ssh-keygen", ["--help"], { stdio: "ignore" });
    return true;
  } catch (e) {
    // ssh-keygen prints usage to stderr and exits non-zero on --help, but
    // ENOENT (not found) is the case we skip on.
    return (e as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

test("empty / non-ed25519 key → SshCaUnconfiguredError / clear error", () => {
  assert.throws(() => SshCertSigner.fromPkcs8Pem(""), SshCaUnconfiguredError);
  assert.throws(() => SshCertSigner.fromPkcs8Pem("   "), SshCaUnconfiguredError);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPem = rsa.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  assert.throws(() => SshCertSigner.fromPkcs8Pem(rsaPem), /must be ed25519/);
});

test("CA public key renders as a single authorized_keys line", () => {
  const signer = SshCertSigner.fromPkcs8Pem(genCaPkcs8Pem());
  const line = signer.publicKeyAuthorizedKey();
  const parts = line.split(" ");
  assert.strictEqual(parts[0], "ssh-ed25519");
  assert.ok(parts[1].length > 0);
  assert.strictEqual(parts[2], "auth.romaine.life-ssh-ca");
  // round-trips back through our own ed25519 pubkey parser
  assert.doesNotThrow(() => parseUserEd25519PublicKey(`ssh-ed25519 ${parts[1]} x`));
});

test("parseUserEd25519PublicKey rejects non-ed25519 and certificates", () => {
  assert.throws(() => parseUserEd25519PublicKey(""), /required/);
  assert.throws(() => parseUserEd25519PublicKey("ssh-rsa AAAA x"), /must be ssh-ed25519/);
  assert.throws(
    () => parseUserEd25519PublicKey("ssh-ed25519-cert-v01@openssh.com AAAA x"),
    /must be ssh-ed25519/,
  );
});

test("signed cert decodes to the requested structure and the signature verifies", () => {
  const caPem = genCaPkcs8Pem();
  const signer = SshCertSigner.fromPkcs8Pem(caPem);
  const caPub = crypto.createPublicKey(crypto.createPrivateKey({ key: caPem, format: "pem" }));
  const { line: userLine } = genUserAuthorizedKey();
  const userPub = parseUserEd25519PublicKey(userLine);

  const now = Math.floor(Date.now() / 1000);
  const signed = signer.signUserCert({
    userPublicKey: userPub,
    keyId: "glimmung-run:spirelens/7.1",
    principals: ["spirelens-agent"],
    extensions: ["permit-pty"],
    validAfter: now - 30,
    validBefore: now + SSH_CERT_DEFAULT_TTL_SECONDS,
  });

  assert.ok(signed.authorizedKeyLine.startsWith("ssh-ed25519-cert-v01@openssh.com "));

  // Decode the cert body field-by-field per PROTOCOL.certkeys.
  const cert = Buffer.from(signed.certB64, "base64");
  const r = new SshReader(cert);
  assert.strictEqual(r.readString().toString(), "ssh-ed25519-cert-v01@openssh.com");
  r.readString(); // nonce
  // pk: string(ssh-ed25519)+string(raw32) is itself NOT re-wrapped here;
  // the field is the raw 32-byte point for ed25519 certs.
  const pk = r.readString();
  assert.strictEqual(pk.length, 32);
  r.readU64(); // serial
  assert.strictEqual(r.readU32(), 1); // user cert
  assert.strictEqual(r.readString().toString(), "glimmung-run:spirelens/7.1");
  const principalsBlob = r.readString();
  const pr = new SshReader(principalsBlob);
  assert.strictEqual(pr.readString().toString(), "spirelens-agent");
  assert.strictEqual(pr.remaining(), 0);
  const validAfter = Number(r.readU64());
  const validBefore = Number(r.readU64());
  assert.strictEqual(validAfter, now - 30);
  assert.strictEqual(validBefore, now + SSH_CERT_DEFAULT_TTL_SECONDS);
  assert.strictEqual(r.readString().length, 0); // critical options: none
  const extBlob = r.readString();
  const er = new SshReader(extBlob);
  assert.strictEqual(er.readString().toString(), "permit-pty");
  assert.strictEqual(er.readString().length, 0); // permit-pty data is empty
  assert.strictEqual(er.remaining(), 0);
  assert.strictEqual(r.readString().length, 0); // reserved

  // signature key blob = ssh-ed25519 CA pubkey
  const sigKeyBlob = r.readString();
  const skr = new SshReader(sigKeyBlob);
  assert.strictEqual(skr.readString().toString(), "ssh-ed25519");

  // The signature is the final field. The body it covers is everything up
  // to (not including) that trailing signature string: cert minus its
  // 4-byte length prefix and its contents.
  const sigBlob = r.readString();
  assert.strictEqual(r.remaining(), 0);
  const sr = new SshReader(sigBlob);
  assert.strictEqual(sr.readString().toString(), "ssh-ed25519");
  const rawSig = sr.readString();
  assert.strictEqual(rawSig.length, 64);

  const body = cert.subarray(0, cert.length - (4 + sigBlob.length));
  assert.ok(
    crypto.verify(null, body, caPub, rawSig),
    "cert signature must verify under the CA public key",
  );
});

test("ssh-keygen -L agrees with our encoder (skipped without openssh-client)", (t) => {
  if (!haveSshKeygen()) {
    t.skip("ssh-keygen not available");
    return;
  }
  const signer = SshCertSigner.fromPkcs8Pem(genCaPkcs8Pem());
  const { line: userLine } = genUserAuthorizedKey();
  const userPub = parseUserEd25519PublicKey(userLine);
  const now = Math.floor(Date.now() / 1000);
  const signed = signer.signUserCert({
    userPublicKey: userPub,
    keyId: "glimmung-run:spirelens/7.1",
    principals: ["spirelens-agent"],
    extensions: ["permit-pty"],
    validAfter: now - 30,
    validBefore: now + 600,
  });

  const dir = mkdtempSync(join(tmpdir(), "sshcert-"));
  try {
    const certPath = join(dir, "id-cert.pub");
    writeFileSync(certPath, signed.authorizedKeyLine + "\n");
    const out = execFileSync("ssh-keygen", ["-L", "-f", certPath], { encoding: "utf8" });
    assert.match(out, /Type:\s+ssh-ed25519-cert-v01@openssh\.com user certificate/);
    assert.match(out, /Key ID:\s+"glimmung-run:spirelens\/7\.1"/);
    assert.match(out, /spirelens-agent/);
    assert.match(out, /permit-pty/);
    assert.doesNotMatch(out, /permit-port-forwarding/);
    assert.doesNotMatch(out, /permit-agent-forwarding/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
