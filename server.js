
const express = require("express");
const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json({ limit: "10kb" }));

app.use("/validate", rateLimit({
  windowMs: 60 * 1000,
  limit: 20
}));

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  ADMIN_SECRET
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !ADMIN_SECRET) {
  throw new Error("Missing environment variables");
}

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY
);

const hashKey = key =>
  crypto.createHash("sha256").update(key).digest("hex");

function adminOnly(req, res, next) {
  const supplied = req.get("x-admin-secret") || "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_SECRET);

  if (a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    name: "BY TAI BA KHI KEY API",
    status: "online"
  });
});

// Tạo key với thời hạn tùy chọn
app.post("/admin/keys", adminOnly, async (req, res) => {
  try {
    const days = Number(req.body.days);

    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      return res.status(400).json({
        error: "days must be from 1 to 3650"
      });
    }

    const key = "TAIBABAKHI-" +
      crypto.randomBytes(24).toString("hex");

    const expiresAt = new Date(
      Date.now() + days * 86400000
    ).toISOString();

    const { data, error } = await db
      .from("issued_keys")
      .insert({
        key_hash: hashKey(key),
        expires_at: expiresAt
      })
      .select("id")
      .single();

    if (error) throw error;

    res.status(201).json({
      key,
      id: data.id,
      expires_at: expiresAt
    });
  } catch (error) {
    console.error("Key creation failed");
    res.status(500).json({
      error: "Could not create key"
    });
  }
});

// Kiểm tra key
app.post("/validate", async (req, res) => {
  try {
    const key = typeof req.body.key === "string"
      ? req.body.key.trim()
      : "";

    if (!/^TAIBABAKHI-[a-f0-9]{48}$/.test(key)) {
      return res.status(400).json({ valid: false });
    }

    const { data, error } = await db
      .from("issued_keys")
      .select("expires_at, revoked")
      .eq("key_hash", hashKey(key))
      .maybeSingle();

    if (error) throw error;

    const valid = Boolean(
      data &&
      !data.revoked &&
      Date.parse(data.expires_at) > Date.now()
    );

    res.json({ valid });
  } catch {
    res.status(503).json({
      valid: false,
      error: "Verification unavailable"
    });
  }
});

// Thu hồi key bằng ID
app.post(
  "/admin/keys/:id/revoke",
  adminOnly,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("issued_keys")
        .update({ revoked: true })
        .eq("id", req.params.id)
        .select("id")
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return res.status(404).json({
          error: "Key not found"
        });
      }

      res.json({
        revoked: true,
        id: data.id
      });
    } catch {
      res.status(500).json({
        error: "Could not revoke key"
      });
    }
  }
);

const port = process.env.PORT || 10000;

app.listen(port, "0.0.0.0", () => {
  console.log("BY TAI BA KHI KEY API started");
});
