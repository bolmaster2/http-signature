import crypto from "crypto";
import { signatureHeaders } from "http-message-sig";

const base = process.argv[2] || "http://localhost:3000";

const signer = {
  keyid: "key-1",
  alg: "hmac-sha256",
  sign: (data) => {
    const hmac = crypto.createHmac("sha256", "MySecureKey");
    hmac.update(data);
    return Uint8Array.from(hmac.digest());
  },
};

function urlFor(path) {
  return `${base.replace(/\/$/, "")}${path}`;
}

function cleanUrl(url) {
  const u = new URL(url);
  u.hash = "";
  return u.toString();
}

async function assertStatus(res, expected, label) {
  if (res.status === expected) {
    console.log(`✅ ${label}`);
    return true;
  }
  console.error(
    `❌ ${label}: expected ${expected}, got ${res.status} - ${await res.text()}`
  );
  return false;
}

async function testUnsignedRequestRejected() {
  const res = await fetch(urlFor("/protected"));
  return assertStatus(res, 401, "Unsigned request rejected (401)");
}

async function testSignedRequest() {
  const url = cleanUrl(urlFor("/protected"));
  const headers = await signatureHeaders(
    { method: "GET", url, headers: {} },
    { signer, components: ["@method", "@authority", "@target-uri"], created: Math.floor(Date.now() / 1000) }
  );
  const res = await fetch(url, { headers });
  return assertStatus(res, 200, "Signed request accepted (200)");
}

async function testQueryComponent() {
  const url = cleanUrl(urlFor("/protected?foo=bar"));
  const headers = await signatureHeaders(
    { method: "GET", url, headers: {} },
    { signer, components: ["@method", "@authority", "@query"], created: Math.floor(Date.now() / 1000) }
  );
  const res = await fetch(url, { headers });
  return assertStatus(res, 200, "Signed request with @query component accepted (200)");
}

async function testPathComponent() {
  const url = cleanUrl(urlFor("/protected"));
  const headers = await signatureHeaders(
    { method: "GET", url, headers: {} },
    { signer, components: ["@method", "@authority", "@path"], created: Math.floor(Date.now() / 1000) }
  );
  const res = await fetch(url, { headers });
  return assertStatus(res, 200, "Signed request with @path component accepted (200)");
}

async function testDateHeaderComponent() {
  const url = cleanUrl(urlFor("/protected"));
  const date = new Date().toUTCString();
  const sigHeaders = await signatureHeaders(
    { method: "GET", url, headers: { date } },
    { signer, components: ["@method", "@authority", "date"], created: Math.floor(Date.now() / 1000) }
  );
  const res = await fetch(url, { headers: { ...sigHeaders, Date: date } });
  return assertStatus(res, 200, "Signed request with date header component accepted (200)");
}

async function testPostWithBodyAndContentDigest() {
  const url = urlFor("/webhook");
  const body = JSON.stringify({ event: "user.created", id: 42 });
  const digestBytes = crypto.createHash("sha256").update(body).digest();
  const contentDigest = `sha-256=:${digestBytes.toString("base64")}:`;

  const sigHeaders = await signatureHeaders(
    { method: "POST", url, headers: { "content-type": "application/json", "content-digest": contentDigest } },
    { signer, components: ["@method", "@authority", "content-type", "content-digest"], created: Math.floor(Date.now() / 1000) }
  );

  const res = await fetch(url, {
    method: "POST",
    headers: { ...sigHeaders, "Content-Type": "application/json", "Content-Digest": contentDigest },
    body,
  });
  return assertStatus(res, 200, "POST with body and content-digest accepted (200)");
}

async function testPostWithMismatchedContentDigest() {
  const url = urlFor("/webhook");
  const body = JSON.stringify({ event: "user.created", id: 42 });
  const digestBytes = crypto.createHash("sha256").update(body).digest();
  const contentDigest = `sha-256=:${digestBytes.toString("base64")}:`;

  const sigHeaders = await signatureHeaders(
    { method: "POST", url, headers: { "content-type": "application/json", "content-digest": contentDigest } },
    { signer, components: ["@method", "@authority", "content-type", "content-digest"], created: Math.floor(Date.now() / 1000) }
  );

  const tamperedBody = JSON.stringify({ event: "user.created", id: 99 });
  const res = await fetch(url, {
    method: "POST",
    headers: { ...sigHeaders, "Content-Type": "application/json", "Content-Digest": contentDigest },
    body: tamperedBody,
  });
  return assertStatus(res, 401, "POST with mismatched content-digest rejected (401)");
}

async function testMissingContentDigestHeaderRejected() {
  const url = urlFor("/webhook");
  const body = JSON.stringify({ event: "user.created", id: 42 });
  const digestBytes = crypto.createHash("sha256").update(body).digest();
  const contentDigest = `sha-256=:${digestBytes.toString("base64")}:`;

  // Sign with content-digest in the components and headers
  const sigHeaders = await signatureHeaders(
    { method: "POST", url, headers: { "content-type": "application/json", "content-digest": contentDigest } },
    { signer, components: ["@method", "@authority", "content-type", "content-digest"], created: Math.floor(Date.now() / 1000) }
  );

  // Send the request WITHOUT the Content-Digest header
  const res = await fetch(url, {
    method: "POST",
    headers: { ...sigHeaders, "Content-Type": "application/json" },
    body,
  });
  return assertStatus(res, 401, "POST with content-digest signed but header missing rejected (401)");
}

async function testContentDigestKeyParameter() {
  const url = urlFor("/webhook");
  const body = JSON.stringify({ event: "user.created", id: 42 });
  const digestBytes = crypto.createHash("sha256").update(body).digest();
  const contentDigest = `sha-256=:${digestBytes.toString("base64")}:`;

  // The ;key="sha-256" parameter means only the sha-256 member value should be
  // used in the signature base, not the full Content-Digest header.
  // RFC 9421 Section 2.1.2 - the value is just the dictionary member: `:${base64}:`
  const memberValue = `:${digestBytes.toString("base64")}:`;

  const created = Math.floor(Date.now() / 1000);
  const sigInputParams = `("@method" "@authority" "content-type" "content-digest";key="sha-256");created=${created};keyid="key-1";alg="hmac-sha256"`;

  const baseLines = [
    `"@method": POST`,
    `"@authority": ${new URL(url).host}`,
    `"content-type": application/json`,
    `"content-digest";key="sha-256": ${memberValue}`,
    `"@signature-params": ${sigInputParams}`,
  ];
  const baseString = baseLines.join("\n");

  const hmac = crypto.createHmac("sha256", "MySecureKey");
  hmac.update(baseString);
  const sig = hmac.digest().toString("base64");

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Digest": contentDigest,
      "Signature-Input": `sig1=${sigInputParams}`,
      Signature: `sig1=:${sig}:`,
    },
    body,
  });
  return assertStatus(res, 200, "content-digest;key=\"sha-256\" accepted (200)");
}

async function testFullCoverageMultiComponent() {
  const url = cleanUrl(urlFor("/protected?a=1&b=2"));
  const headers = await signatureHeaders(
    { method: "GET", url, headers: {} },
    { signer, components: ["@method", "@path", "@query", "@scheme", "@authority"], created: Math.floor(Date.now() / 1000) }
  );
  const res = await fetch(url, { headers });
  return assertStatus(res, 200, "Full-coverage multi-component GET accepted (200)");
}

async function main() {
  const results = await Promise.all([
    testUnsignedRequestRejected(),
    testSignedRequest(),
    testQueryComponent(),
    testPathComponent(),
    testDateHeaderComponent(),
    testPostWithBodyAndContentDigest(),
    testPostWithMismatchedContentDigest(),
    testMissingContentDigestHeaderRejected(),
    testContentDigestKeyParameter(),
    testFullCoverageMultiComponent(),
  ]);

  if (results.some((ok) => !ok)) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
