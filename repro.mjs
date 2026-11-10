// With DynamoStorage, replaying a refresh token after the reuse window is
// detected, but auth.invalidate(subject) deletes nothing, so the token it was
// rotated into keeps working. The same steps with MemoryStorage revoke it.
import { CreateTableCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { issuer } from "@openauthjs/openauth";
import { CodeProvider } from "@openauthjs/openauth/provider/code";
import { DynamoStorage } from "@openauthjs/openauth/storage/dynamo";
import { MemoryStorage } from "@openauthjs/openauth/storage/memory";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const endpoint = "http://localhost:8000"; // DynamoDB Local: `npm run db`
const table = `repro-${Date.now()}`;
Object.assign(process.env, {
  AWS_REGION: "us-east-1",
  AWS_ACCESS_KEY_ID: "local",
  AWS_SECRET_ACCESS_KEY: "local",
});

// `npm run repro -- --log` prints the DynamoDB requests for refresh tokens,
// with the \x1f separator shown as <1f>.
if (process.argv.includes("--log")) {
  const fetch = globalThis.fetch;
  const show = (s) => JSON.stringify(s).replaceAll("\\u001f", "<1f>");
  globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    const action = req.headers.get("x-amz-target")?.split(".")[1];
    const body = action ? JSON.parse(await req.clone().text()) : undefined;
    const res = await fetch(req);
    if (action === "Query" && body.ExpressionAttributeValues[":pk"].S.startsWith("oauth:refresh")) {
      const { Items } = await res.clone().json();
      console.log(`  Query      pk ${show(body.ExpressionAttributeValues[":pk"].S)} -> ${Items.length} items`);
    }
    if (action === "DeleteItem" && body.Key.pk.S.startsWith("oauth:refresh")) {
      console.log(`  DeleteItem pk ${show(body.Key.pk.S)}, sk ${show(body.Key.sk.S)}`);
    }
    return res;
  };
}

await new DynamoDBClient({ endpoint }).send(
  new CreateTableCommand({
    TableName: table,
    BillingMode: "PAY_PER_REQUEST",
    AttributeDefinitions: [
      { AttributeName: "pk", AttributeType: "S" },
      { AttributeName: "sk", AttributeType: "S" },
    ],
    KeySchema: [
      { AttributeName: "pk", KeyType: "HASH" },
      { AttributeName: "sk", KeyType: "RANGE" },
    ],
  }),
);

function makeIssuer(storage) {
  let lastCode;
  const app = issuer({
    storage,
    subjects: createSubjects({ user: object({ email: string() }) }),
    // A short reuse window so the script doesn't wait 60s. Retention keeps
    // used tokens so reuse is detected.
    ttl: { reuse: 1, retention: 3600 },
    allow: async () => true,
    providers: {
      code: CodeProvider({
        sendCode: async (_claims, code) => void (lastCode = code),
        request: async () => new Response("ok"),
      }),
    },
    success: (ctx, value) => ctx.subject("user", { email: value.claims.email }),
  });
  return { app, lastCode: () => lastCode };
}

const form = (fields, cookie = "") => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded", cookie },
  body: new URLSearchParams(fields).toString(),
});

// Signs in with the code provider and returns the refresh token.
async function signIn({ app, lastCode }) {
  const cookies = new Map();
  const keep = (res) => {
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      cookies.set(pair.split("=")[0], pair);
    }
    return res;
  };
  const cookie = () => [...cookies.values()].join("; ");
  const redirect_uri = "http://localhost/callback";
  const params = new URLSearchParams({
    client_id: "repro",
    redirect_uri,
    response_type: "code",
    provider: "code",
  });
  keep(await app.request(`/authorize?${params}`));
  keep(await app.request("/code/authorize", { headers: { cookie: cookie() } }));
  keep(await app.request("/code/authorize", form({ action: "request", email: "a@example.com" }, cookie())));
  const verified = await app.request("/code/authorize", form({ action: "verify", code: lastCode() }, cookie()));
  const code = new URL(verified.headers.get("location")).searchParams.get("code");
  const res = await app.request(
    "/token",
    form({ grant_type: "authorization_code", code, redirect_uri, client_id: "repro" }),
  );
  return (await res.json()).refresh_token;
}

const refresh = async ({ app }, refresh_token) => {
  const res = await app.request("/token", form({ grant_type: "refresh_token", refresh_token }));
  return res.status;
};

async function run(name, storage) {
  const auth = makeIssuer(storage);
  const first = await signIn(auth);

  // Someone else uses the token first and gets the rotated token.
  const res = await auth.app.request("/token", form({ grant_type: "refresh_token", refresh_token: first }));
  const rotated = (await res.json()).refresh_token;

  // After the reuse window, the first token is replayed: reuse is detected,
  // so OpenAuth calls auth.invalidate(subject) and returns invalid_grant.
  await new Promise((r) => setTimeout(r, 1500));
  const replay = await refresh(auth, first);

  // The rotated token should now be revoked.
  const after = await refresh(auth, rotated);
  console.log(
    `${name.padEnd(14)} replay: ${replay}, rotated token after replay: ${after}` +
      (after === 400 ? "  (revoked, as expected)" : "  (NOT revoked: bug)"),
  );
  return after === 400;
}

const memoryOk = await run("MemoryStorage", MemoryStorage());
const dynamoOk = await run("DynamoStorage", DynamoStorage({ table, endpoint }));
process.exitCode = memoryOk && dynamoOk ? 0 : 1;
