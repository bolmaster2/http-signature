import crypto from "crypto";
import { signatureHeaders } from "http-message-sig";

async function main() {
  const base = process.argv[2] || "http://localhost:3000";
  const url = `${base.replace(/\/$/, "")}/protected`;
  const host = new URL(url).host;

  // Unsigned request should be rejected
  let unsignedStatus;
  try {
    const res = await fetch(url);
    unsignedStatus = res.status;
  } catch (err) {
    console.error("Unsigned request error:", err);
    if (err?.response) {
      console.error("Response body:", await err.response.text?.());
    }
    unsignedStatus = err.status ?? err.response?.status;
  }

  if (unsignedStatus !== 401) {
    console.error(`Expected 401 for unsigned request, got ${unsignedStatus}`);
    process.exit(1);
  }

  // Signed request should succeed
  const dateHeader = new Date().toUTCString();
  const headers = {};

  const signer = {
    keyid: "key-1",
    alg: "hmac-sha256",
    sign: (data) => {
      const hmac = crypto.createHmac("sha256", "MySecureKey");
      hmac.update(data);
      return Uint8Array.from(hmac.digest());
    },
  };

  const signedHeaders = await signatureHeaders(
    { method: "GET", url, headers },
    {
      signer,
      components: ["@method", "@authority", "@path"],
      created: Math.floor(Date.now() / 1000),
    }
  );

  const fetchHeaders = signedHeaders;

  const successRes = await fetch(url, { headers: fetchHeaders });
  if (successRes.status !== 200) {
    console.error(`Expected 200 for signed request, got ${successRes.status}`);
    console.error("Response body:", await successRes.text?.());

    console.error("Request URL:", url);
    console.error("Signed headers:", signedHeaders);
    console.error("Headers:", headers);
    process.exit(1);
  }

  console.log(
    "Unsigned request rejected (401) and signed request succeeded (200)."
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
