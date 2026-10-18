
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
app.get("/create-short-link", async (req, res) => {
  try {
    const destination =
      "https://tai-ba-khi-key-system-1.onrender.com/getkey";

    const params = new URLSearchParams({
      api: process.env.LINK4M_API_KEY,
      url: destination
    });

    const response = await fetch(
  `https://link4m.co/api-shorten/v2?${params}`
);

const raw = await response.text();

let result;
try {
  result = JSON.parse(raw);
} catch {
  console.error(
    "Link4M returned non-JSON:",
    response.status,
    raw.slice(0, 300)
  );

  return res.status(502).json({
    error: "Link4M returned HTML instead of JSON",
    httpStatus: response.status
  });
}

    if (result.status !== "success") {
      return res.status(400).json({
        error: "Link4M could not create the short link"
      });
    }

    res.json({
      shortenedUrl: result.shortenedUrl
    });
  } catch (error) {
    console.error("Link4M request failed:", error.message);

    res.status(502).json({
      error: "Link4M request failed",
      detail: error.message
    });
  }
});
app.get("/getkey", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>BY TÀI BÁ KHÍ - GET KEY</title>
      <style>
        body {
          background: #10051f;
          color: white;
          font-family: Arial, sans-serif;
          text-align: center;
          padding: 40px 16px;
        }
        .box {
          max-width: 400px;
          margin: auto;
          padding: 24px;
          border: 1px solid #a855f7;
          border-radius: 16px;
          background: #1b0b30;
        }
        button {
          background: #a855f7;
          color: white;
          border: 0;
          border-radius: 10px;
          padding: 12px 20px;
          font-size: 16px;
        }
      </style>
    </head>
    <body>
      <div class="box">
        <h2>BY TÀI BÁ KHÍ HUB</h2>
        <p>Trang nhận key đang được thiết lập.</p>
        <p>Hoàn thành bước vượt link để tiếp tục.</p>
      </div>
    </body>
    </html>
  `);
});
