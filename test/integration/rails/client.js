import crypto from "crypto";
import { signatureHeaders } from "http-message-sig";

function pass(msg) {
  console.log(`✅ ${msg}`);
}

function fail(msg) {
  console.error(`❌ ${msg}`);
}

async function main() {
  const base = process.argv[2] || "http://localhost:3000";
  const url = `${base.replace(/\/$/, "")}/protected`;
  const targetUri = new URL(url);
  targetUri.hash = "";
  const targetUriStr = targetUri.toString();

  const signer = {
    keyid: "key-1",
    alg: "hmac-sha256",
    sign: (data) => {
      const hmac = crypto.createHmac("sha256", "MySecureKey");
      hmac.update(data);
      return Uint8Array.from(hmac.digest());
    },
  };

  let failed = false;

  // Unsigned request should be rejected
  try {
    const res = await fetch(url);
    if (res.status === 401) {
      pass("Unsigned request rejected (401)");
    } else {
      fail(`Unsigned request: expected 401, got ${res.status}`);
      failed = true;
    }
  } catch (err) {
    fail(`Unsigned request error: ${err.message}`);
    failed = true;
  }

  // Signed request should succeed
  const signedHeaders = await signatureHeaders(
    { method: "GET", url: targetUriStr, headers: {} },
    {
      signer,
      components: ["@method", "@authority", "@target-uri"],
      created: Math.floor(Date.now() / 1000),
    }
  );

  const signedRes = await fetch(url, { headers: signedHeaders });
  if (signedRes.status === 200) {
    pass("Signed request accepted (200)");
  } else {
    fail(
      `Signed request: expected 200, got ${signedRes.status} - ${await signedRes.text()}`
    );
    failed = true;
  }

  // Signed request with @query component (RFC 9421 interop)
  const queryUrl = `${base.replace(/\/$/, "")}/protected?foo=bar`;
  const queryTargetUri = new URL(queryUrl);
  queryTargetUri.hash = "";

  const querySignedHeaders = await signatureHeaders(
    { method: "GET", url: queryTargetUri.toString(), headers: {} },
    {
      signer,
      components: ["@method", "@authority", "@query"],
      created: Math.floor(Date.now() / 1000),
    }
  );

  const queryRes = await fetch(queryUrl, { headers: querySignedHeaders });
  if (queryRes.status === 200) {
    pass("Signed request with @query component accepted (200)");
  } else {
    fail(
      `Signed request with @query: expected 200, got ${queryRes.status} - ${await queryRes.text()}`
    );
    failed = true;
  }

  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
