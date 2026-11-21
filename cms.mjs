// DER subset used by m2send: a single RSA recipient and AES-256-GCM.
const SEQUENCE = 0x30;
const SET = 0x31;
const INTEGER = 0x02;
const OCTETS = 0x04;
const OID = 0x06;
const BIT_STRING = 0x03;
const EXPLICIT_0 = 0xa0;
const EXPLICIT_1 = 0xa1;
const IMPLICIT_0 = 0x80;
const CERT_LIMIT = 8192;
const TAG_BYTES = 16;

const utf8 = new TextEncoder();

function join(...parts) {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function der(tag, ...parts) {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const length = [];
  if (size >= 128) {
    for (let value = size; value > 0; value = Math.floor(value / 256)) {
      length.unshift(value % 256);
    }
  }
  const header = size < 128 ? [tag, size] : [tag, 0x80 + length.length, ...length];
  return join(Uint8Array.from(header), ...parts);
}

const seq = (...parts) => der(SEQUENCE, ...parts);
const octets = (bytes) => der(OCTETS, bytes);
const integer = (value) => der(INTEGER, Uint8Array.of(value));

function oid(hex) {
  return der(OID, Uint8Array.from(hex.match(/../g), byte => Number.parseInt(byte, 16)));
}

class DerReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  get next() {
    return this.bytes[this.offset];
  }

  read(tag) {
    const start = this.offset;
    if (this.next !== tag || start + 2 > this.bytes.length) invalid();
    this.offset++;
    let size = this.bytes[this.offset++];
    if (size >= 128) {
      const count = size - 128;
      if (!count || count > 4 || this.offset + count > this.bytes.length || !this.next) invalid();
      size = 0;
      for (let i = 0; i < count; i++) size = size * 256 + this.bytes[this.offset++];
      if (size < 128) invalid();
    }
    const contentStart = this.offset;
    this.offset += size;
    if (this.offset > this.bytes.length) invalid();
    return {
      bytes: this.bytes.subarray(start, this.offset),
      value: this.bytes.subarray(contentStart, this.offset),
    };
  }

  enter(tag) {
    return new DerReader(this.read(tag).value);
  }

  expect(tag, expected) {
    if (!equal(this.read(tag).bytes, expected)) invalid();
  }

  end() {
    if (this.offset !== this.bytes.length) invalid();
  }
}

function outer(bytes) {
  const reader = new DerReader(bytes);
  const sequence = reader.enter(SEQUENCE);
  reader.end();
  return sequence;
}

function equal(left, right) {
  return left.length === right.length && left.every((byte, i) => byte === right[i]);
}

function invalid() {
  throw new Error("対応していない形式か、データが壊れています。");
}

const NULL = der(0x05);
const DATA = oid("2a864886f70d010701");
const AUTH_ENVELOPED_DATA = oid("2a864886f70d0109100117");
const AES_256_GCM = oid("60864801650304012e");
const RSA_OAEP = oid("2a864886f70d010107");
const MGF1 = oid("2a864886f70d010108");
const SHA256 = oid("608648016503040201");
const RSA_SHA256 = seq(oid("2a864886f70d01010b"), NULL);
const SHA256_ALGORITHM = seq(SHA256);
const OAEP_ALGORITHM = seq(RSA_OAEP, seq(
  der(EXPLICIT_0, SHA256_ALGORITHM),
  der(EXPLICIT_1, seq(MGF1, SHA256_ALGORITHM)),
));

function checkSha256(reader) {
  reader.expect(OID, SHA256);
  if (reader.next === 0x05) reader.expect(0x05, NULL);
  reader.end();
}

function checkOaep(reader) {
  reader.expect(OID, RSA_OAEP);
  const params = reader.enter(SEQUENCE);
  const hash = params.enter(EXPLICIT_0);
  checkSha256(hash.enter(SEQUENCE));
  hash.end();
  const mask = params.enter(EXPLICIT_1);
  const algorithm = mask.enter(SEQUENCE);
  algorithm.expect(OID, MGF1);
  checkSha256(algorithm.enter(SEQUENCE));
  algorithm.end();
  mask.end();
  params.end();
  reader.end();
}

function certTime(date) {
  const iso = date.toISOString().slice(0, 19).replace(/[-:T]/g, "");
  return date.getUTCFullYear() < 2050
    ? der(0x17, utf8.encode(iso.slice(2) + "Z"))
    : der(0x18, utf8.encode(iso + "Z"));
}

export async function createRecipient() {
  const signing = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const keys = await crypto.subtle.generateKey({
    ...signing,
    modulusLength: 2048,
    publicExponent: Uint8Array.of(1, 0, 1),
  }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
  const rawPrivateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey));
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = (serial[0] & 0x3f) | 0x40;
  const name = seq(der(SET, seq(oid("550403"), der(0x0c, utf8.encode("m2send")))));
  const now = Date.now();
  const tbs = seq(
    der(EXPLICIT_0, integer(2)),
    der(INTEGER, serial),
    RSA_SHA256,
    name,
    seq(certTime(new Date(now - 60_000)), certTime(new Date(now + 86_400_000))),
    name,
    spki,
  );
  try {
    const signature = new Uint8Array(await crypto.subtle.sign(signing, keys.privateKey, tbs));
    const cert = seq(tbs, RSA_SHA256, der(BIT_STRING, Uint8Array.of(0), signature));
    const privateKey = await importPrivateKey(rawPrivateKey, true);
    return { cert, privateKey };
  } finally {
    rawPrivateKey.fill(0);
  }
}

export function importPrivateKey(bytes, extractable = false) {
  return crypto.subtle.importKey(
    "pkcs8", bytes, { name: "RSA-OAEP", hash: "SHA-256" }, extractable, ["unwrapKey"],
  );
}

export async function readRecipient(cert) {
  if (cert.length > CERT_LIMIT) invalid();
  const envelope = outer(cert);
  const tbs = envelope.read(SEQUENCE);
  envelope.expect(SEQUENCE, RSA_SHA256);
  const signature = envelope.read(BIT_STRING).value;
  envelope.end();
  if (signature[0] !== 0) invalid();

  const fields = new DerReader(tbs.value);
  if (fields.next === EXPLICIT_0) {
    const version = fields.enter(EXPLICIT_0);
    version.expect(INTEGER, integer(2));
    version.end();
  }
  const serial = fields.read(INTEGER).bytes;
  fields.expect(SEQUENCE, RSA_SHA256);
  const issuer = fields.read(SEQUENCE).bytes;
  fields.read(SEQUENCE); // Validity is certificate metadata, not an identity or expiry policy.
  const subject = fields.read(SEQUENCE).bytes;
  const spki = fields.read(SEQUENCE).bytes;
  if (fields.next === 0xa3) fields.read(0xa3); // Optional X.509 extensions.
  fields.end();
  if (!equal(issuer, subject)) invalid();

  const verificationKey = await crypto.subtle.importKey(
    "spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  if (verificationKey.algorithm.modulusLength !== 2048 ||
      !await crypto.subtle.verify("RSASSA-PKCS1-v1_5", verificationKey, signature.subarray(1), tbs.bytes)) invalid();
  const publicKey = await crypto.subtle.importKey(
    "spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["wrapKey"],
  );
  return { publicKey, issuerAndSerial: seq(issuer, serial) };
}

export async function encrypt(plaintext, recipient) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = new Uint8Array(await crypto.subtle.wrapKey("raw", key, recipient.publicKey, "RSA-OAEP"));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  return seq(AUTH_ENVELOPED_DATA, der(EXPLICIT_0, seq(
    integer(0),
    der(SET, seq(integer(0), recipient.issuerAndSerial, OAEP_ALGORITHM, octets(wrappedKey))),
    seq(DATA, seq(AES_256_GCM, seq(octets(iv), integer(TAG_BYTES))),
      der(IMPLICIT_0, sealed.subarray(0, sealed.length - TAG_BYTES))),
    octets(sealed.subarray(sealed.length - TAG_BYTES)),
  )));
}

export async function decrypt(cms, privateKey) {
  const info = outer(cms);
  info.expect(OID, AUTH_ENVELOPED_DATA);
  const content = info.enter(EXPLICIT_0);
  info.end();
  const envelope = content.enter(SEQUENCE);
  content.end();
  envelope.expect(INTEGER, integer(0));
  const recipients = envelope.enter(SET);
  const recipient = recipients.enter(SEQUENCE);
  recipients.end();
  recipient.expect(INTEGER, integer(0));
  const identifier = recipient.enter(SEQUENCE);
  identifier.read(SEQUENCE);
  identifier.read(INTEGER);
  identifier.end();
  checkOaep(recipient.enter(SEQUENCE));
  const wrappedKey = recipient.read(OCTETS).value;
  recipient.end();
  if (wrappedKey.length !== 256) invalid();

  const encrypted = envelope.enter(SEQUENCE);
  encrypted.expect(OID, DATA);
  const algorithm = encrypted.enter(SEQUENCE);
  algorithm.expect(OID, AES_256_GCM);
  const params = algorithm.enter(SEQUENCE);
  algorithm.end();
  const iv = params.read(OCTETS).value;
  params.expect(INTEGER, integer(TAG_BYTES));
  params.end();
  const ciphertext = encrypted.read(IMPLICIT_0).value;
  encrypted.end();
  const tag = envelope.read(OCTETS).value;
  envelope.end();
  if (iv.length !== 12 || tag.length !== TAG_BYTES) invalid();

  const key = await crypto.subtle.unwrapKey(
    "raw", wrappedKey, privateKey, "RSA-OAEP", { name: "AES-GCM" }, false, ["decrypt"],
  );
  if (key.algorithm.length !== 256) invalid();
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, key, join(ciphertext, tag),
  ));
}

export function encodeBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

export function decodeBase64(text) {
  return Uint8Array.from(atob(text), character => character.charCodeAt(0));
}

export function pem(label, bytes) {
  const lines = encodeBase64(bytes).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

export function readPem(label, text) {
  const pattern = new RegExp(`^-----BEGIN ${label}-----[\\r\\n]+([A-Za-z0-9+/=\\r\\n]+)[\\r\\n]+-----END ${label}-----$`);
  const match = pattern.exec(text.trim());
  if (!match) invalid();
  return decodeBase64(match[1]);
}

export function recipientLink(pageUrl, cert) {
  const url = new URL(pageUrl);
  const value = encodeBase64(cert).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  url.search = "";
  url.hash = `v=1&recipient=${value}`;
  return url.href;
}

export function certFromLink(link, pageUrl) {
  const url = new URL(link);
  const page = new URL(pageUrl);
  const match = /^#v=1&recipient=([A-Za-z0-9_-]+)$/.exec(url.hash);
  if (!match || url.origin !== page.origin || url.pathname.replace(/\/index\.html$/, "/") !==
      page.pathname.replace(/\/index\.html$/, "/") || match[1].length > Math.ceil(CERT_LIMIT * 4 / 3)) invalid();
  return decodeBase64(match[1].replaceAll("-", "+").replaceAll("_", "/"));
}
