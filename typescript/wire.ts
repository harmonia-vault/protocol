// 固定顺序字符串数组是签名契约；该模块不决定设备信任或当前权限。
export interface Mutation {
  accountId: string; accountGeneration: string; deviceId: string;
  environmentId: string; keyVersion: string; grantGeneration: string;
  operation: "put" | "delete"; idempotencyKey: string; name: string; payload: string;
}
export interface Grant {
  accountId: string; accountGeneration: string; issuerDeviceId: string;
  subjectDeviceId: string; subjectSigningPublicKey: string;
  subjectReceivingPublicKey: string; environmentId: string; keyVersion: string;
  grantGeneration: string; role: "ro" | "rw" | "admin" | "none";
  expiresAt: string; idempotencyKey: string; envelope: string;
}
const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const name = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const maxUint64 = 18446744073709551615n;
export const maxValueBytes = 65536;
function check(condition: boolean): asserts condition {
  if (!condition) throw new Error("invalid Harmonia v1 wire value");
}
function checkId(value: string): void { check(typeof value === "string" && id.test(value)); }
function decimal(value: string, positive: boolean): void {
  check(typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value));
  const n = BigInt(value); check(n <= maxUint64 && (!positive || n > 0n));
}
export function encodeBase64url(value: Uint8Array): string {
  let binary = ""; for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
export function decodeBase64url(value: string, min: number, max: number): Uint8Array {
  check(typeof value === "string" && value.length <= Math.ceil(max * 4 / 3) && /^[A-Za-z0-9_-]*$/.test(value));
  let binary: string;
  try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")); }
  catch { throw new Error("invalid Harmonia v1 base64url"); }
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  check(bytes.length >= min && bytes.length <= max && encodeBase64url(bytes) === value);
  return bytes;
}
function canonical(fields: string[]): Uint8Array { return new TextEncoder().encode(JSON.stringify(fields)); }
export function mutationSigningBytes(m: Mutation): Uint8Array {
  for (const value of [m.accountId, m.deviceId, m.environmentId, m.idempotencyKey]) checkId(value);
  for (const value of [m.accountGeneration, m.keyVersion, m.grantGeneration]) decimal(value, true);
  check(typeof m.name === "string" && name.test(m.name) && !m.name.toUpperCase().startsWith("__HARMONIA_"));
  if (m.operation === "put") decodeBase64url(m.payload, 40, maxValueBytes + 40);
  else check(m.operation === "delete" && m.payload === "");
  return canonical(["harmonia/mutation/v1", m.accountId, m.accountGeneration, m.deviceId,
    m.environmentId, m.keyVersion, m.grantGeneration, m.operation, m.idempotencyKey, m.name, m.payload]);
}
export function grantSigningBytes(g: Grant): Uint8Array {
  for (const value of [g.accountId, g.issuerDeviceId, g.subjectDeviceId, g.environmentId, g.idempotencyKey]) checkId(value);
  for (const value of [g.accountGeneration, g.keyVersion, g.grantGeneration]) decimal(value, true);
  decimal(g.expiresAt, false);
  decodeBase64url(g.subjectSigningPublicKey, 32, 32); decodeBase64url(g.subjectReceivingPublicKey, 32, 32);
  if (g.role === "none") check(g.envelope === "");
  else { check(["ro", "rw", "admin"].includes(g.role)); decodeBase64url(g.envelope, 80, 80); }
  return canonical(["harmonia/grant/v1", g.accountId, g.accountGeneration, g.issuerDeviceId,
    g.subjectDeviceId, g.subjectSigningPublicKey, g.subjectReceivingPublicKey, g.environmentId,
    g.keyVersion, g.grantGeneration, g.role, g.expiresAt, g.idempotencyKey, g.envelope]);
}
