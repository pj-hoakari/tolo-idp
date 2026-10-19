import test from "node:test";
import assert from "node:assert/strict";

const base = process.env.TEST_APP_URL ?? "http://localhost:3000";
const endpoint = `${base}/api/tolo-idp/tokens`;

test("refresh and revoke require a Better Auth session", async () => {
  for (const action of ["refresh", "revoke"]) {
    const response = await fetch(endpoint, {
      method: "POST", headers: { Origin: new URL(base).origin, "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "Sign in required" });
  }
});

test("token operations reject foreign and missing origins", async () => {
  for (const origin of ["http://untrusted.invalid", null]) {
    const headers = { "Content-Type": "application/json" };
    if (origin) headers.Origin = origin;
    const response = await fetch(endpoint, { method: "POST", headers, body: JSON.stringify({ action: "revoke" }) });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "origin_not_allowed" });
  }
});

test("malformed token operations are rejected", async () => {
  for (const body of ["{", "null", '{"action":"delete"}']) {
    const response = await fetch(endpoint, {
      method: "POST", headers: { Origin: new URL(base).origin, "Content-Type": "application/json" }, body,
    });
    assert.equal(response.status, 400);
  }
});
