import express from "express";
import crypto from "crypto";

// Guard against missing secret at startup
const SECRET = process.env.GITHUB_WEBHOOK_SECRET;
if (!SECRET) {
  console.error("GITHUB_WEBHOOK_SECRET is not set. Exiting.");
  process.exit(1);
}

const app = express();

// Capture raw body before JSON parsing so signature validation uses original bytes
app.use(
  express.json({
    limit: "2mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Validate GitHub signature using the raw request body
function isValidSignature(req) {
  const signature = req.headers["x-hub-signature-256"];

  // Reject early if header is absent to avoid timingSafeEqual length mismatch
  if (!signature) {
    return false;
  }

  const expected = `sha256=${crypto
    .createHmac("sha256", SECRET)
    .update(req.rawBody)
    .digest("hex")}`;

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);

  // timingSafeEqual requires equal-length buffers
  if (sigBuf.length !== expBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(sigBuf, expBuf);
}

app.post("/webhook", (req, res) => {
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("application/json")) {
    return res.status(415).send("Unsupported Media Type");
  }

  if (!isValidSignature(req)) {
    return res.status(401).send("Invalid signature");
  }

  const event = req.headers["x-github-event"];
  const payload = req.body;

  console.log(`Received event: ${event}`);

  if (event === "workflow_run") {
    const run = payload.workflow_run;

    // Only process completed runs — logs are unavailable before completion
    if (payload.action !== "completed") {
      return res.status(200).send("OK");
    }

    console.log("Workflow Run Metadata:", {
      id: run.id,
      name: run.name,
      status: run.status,
      conclusion: run.conclusion,
      repo: payload.repository.full_name,
      actor: run.actor?.login ?? null,
      created_at: run.created_at,
      updated_at: run.updated_at,
    });

    // TODO: enqueue run.id for log retrieval
    // TODO: store metadata in your data store
  }

  res.status(200).send("OK");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Webhook listening on port ${PORT}`);
});
