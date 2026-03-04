import express from "express";
import crypto from "crypto";
import "dotenv/config";
import { Resend } from "resend";

const app = express();

/**
 * ✅ IMPORTANT:
 * Shopify webhook HMAC verification requires the *raw* request body bytes.
 * We use express.raw() ONLY for the Shopify webhook route.
 */
app.use("/webhooks/orders-create", express.raw({ type: "*/*" }));

/**
 * For everything else (callback, etc.) we can use normal JSON parsing.
 */
app.use(express.json({ type: "*/*" }));

// ========= ENV CONFIG =========
const PROCARD_API_BASE =
  process.env.PROCARD_API_BASE || "https://kartelat-stage.paysera-ks.com/api";

const MERCHANT_ID = process.env.MERCHANT_ID;
const MERCHANT_SECRET = process.env.MERCHANT_SECRET;

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL; // your tunnel/domain base
const SHOPIFY_WEBHOOK_SECRET = String(process.env.SHOPIFY_WEBHOOK_SECRET || "").trim();

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM;
const TEST_EMAIL_TO = process.env.TEST_EMAIL_TO; // if set, all emails go here

// ✅ Shopify Admin API (to mark the order PAID)
const SHOPIFY_SHOP = process.env.SHOPIFY_SHOP; // e.g. dyqanibio.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN; // Custom app Admin API token
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2025-01";
// ===============================

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

// Remove trailing zeros like docs require: 100.00 -> 100, 100.50 -> 100.5
function normalizeAmount(amount) {
  const n = Number(amount);
  if (!Number.isFinite(n)) return String(amount);
  return String(n);
}

function hmacSha512Hex(secret, message) {
  return crypto.createHmac("sha512", secret).update(message, "utf8").digest("hex");
}

/**
 * Verify Shopify webhook:
 * - header: X-Shopify-Hmac-Sha256
 * - digest: base64(HMAC_SHA256(app_secret, rawBody))
 */
function verifyShopifyWebhookRaw(req, rawBodyBuffer) {
  const headerHmac = String(req.get("X-Shopify-Hmac-Sha256") || "").trim();
  if (!SHOPIFY_WEBHOOK_SECRET || !rawBodyBuffer) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBodyBuffer)
    .digest("base64");

  const a = Buffer.from(digest, "utf8");
  const b = Buffer.from(headerHmac, "utf8");
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

async function procardPurchaseCreatePaymentUrl({
  order_id,
  amount,
  currency_iso,
  description,
  approve_url,
  decline_url,
  cancel_url,
  callback_url,
  email,
  phone,
  add_params = {},
  language = "en",
}) {
  if (!MERCHANT_ID || !MERCHANT_SECRET) {
    throw new Error("Missing MERCHANT_ID or MERCHANT_SECRET in .env");
  }
  if (!PROCARD_API_BASE) {
    throw new Error("Missing PROCARD_API_BASE in .env");
  }

  const amountNorm = normalizeAmount(amount);

  // signature string: merchant_id;order_id;amount;currency_iso;description
  const signString = `${MERCHANT_ID};${order_id};${amountNorm};${currency_iso};${description}`;
  const signature = hmacSha512Hex(MERCHANT_SECRET, signString);

  const payload = {
    operation: "Purchase",
    merchant_id: MERCHANT_ID,
    order_id: String(order_id),
    amount: Number(amountNorm),
    currency_iso,
    description,
    approve_url,
    decline_url,
    cancel_url,
    callback_url,
    language,
    add_params,
    email: email || "",
    phone: phone || "",
    redirect: 0, // returns url in response
    auth_type: 1,
  };

  const r = await fetch(`${PROCARD_API_BASE}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, signature }),
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok || data?.result !== 0 || !data?.url) {
    throw new Error(`Procard Purchase error: HTTP ${r.status} ${JSON.stringify(data)}`);
  }
  return data.url;
}

// Optional: verify Procard callback signature (merchantSignature)
function verifyProcardCallbackSignature(body) {
  if (!MERCHANT_ID || !MERCHANT_SECRET) return false;

  // merchantSignature string: merchant_id;orderReference;amount;currency
  const amountNorm = normalizeAmount(body?.amount);
  const signString = `${MERCHANT_ID};${body?.orderReference};${amountNorm};${body?.currency}`;
  const expected = hmacSha512Hex(MERCHANT_SECRET, signString);
  return String(body?.merchantSignature || "").toLowerCase() === expected.toLowerCase();
}

async function sendPaymentEmail({ to, orderName, amount, currency, paymentUrl }) {
  if (!resend) throw new Error("RESEND_API_KEY not set");
  if (!EMAIL_FROM) throw new Error("EMAIL_FROM not set");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5">
      <h2>Complete your payment</h2>
      <p>Order: <strong>${orderName}</strong></p>
      <p>Amount: <strong>${amount} ${currency}</strong></p>
      <p>
        <a href="${paymentUrl}"
           style="display:inline-block;padding:12px 18px;text-decoration:none;border-radius:8px;background:#111;color:#fff">
          Complete Payment
        </a>
      </p>
      <p>If the button doesn’t work, open this link:<br/>${paymentUrl}</p>
    </div>
  `;

  await resend.emails.send({
    from: EMAIL_FROM,
    to,
    subject: `Complete your payment – ${orderName}`,
    html,
  });
}

/**
 * ✅ Shopify Admin GraphQL: Mark order as PAID
 * Requires your Custom App Admin API access token with write_orders
 */
async function shopifyMarkOrderPaid(orderIdNumeric) {
  if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_TOKEN) {
    throw new Error("Missing SHOPIFY_SHOP or SHOPIFY_ADMIN_TOKEN in .env");
  }

  const gid = `gid://shopify/Order/${orderIdNumeric}`;

  const query = `
    mutation MarkAsPaid($input: OrderMarkAsPaidInput!) {
      orderMarkAsPaid(input: $input) {
        order { id name displayFinancialStatus }
        userErrors { field message }
      }
    }
  `;

  const resp = await fetch(
    `https://${SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
      },
      body: JSON.stringify({
        query,
        variables: { input: { id: gid } },
      }),
    }
  );

  const json = await resp.json().catch(() => ({}));
  const userErrors = json?.data?.orderMarkAsPaid?.userErrors || [];

  if (!resp.ok || userErrors.length || (json?.errors || []).length) {
    throw new Error(
      `orderMarkAsPaid failed: HTTP ${resp.status} userErrors=${JSON.stringify(
        userErrors
      )} errors=${JSON.stringify(json?.errors || [])}`
    );
  }

  return json?.data?.orderMarkAsPaid?.order;
}

/**
 * ✅ Very safe "success" detection:
 * We DON'T know Procard's success field yet, so we only mark as paid if:
 * - signature valid
 * - has core fields
 * - status matches common success values
 *
 * After you see one successful callback payload, you can tighten this.
 */
function procardLooksSuccessful(body) {
  const hasCore = body?.orderReference && body?.amount != null && body?.currency;
  if (!hasCore) return false;

  const statusRaw =
    body?.transactionStatus ??
    body?.status ??
    body?.state ??
    body?.result ??
    body?.approved ??
    body?.success;

  if (statusRaw === true) return true;

  const s = String(statusRaw ?? "").toLowerCase();
  return (
    s === "success" ||
    s === "paid" ||
    s === "approved" ||
    s === "completed" ||
    s === "ok" ||
    s === "true" ||
    s === "1"
  );
}

// Simple in-memory dedupe (dev). Use DB/Redis in prod.
const processed = new Set();
function alreadyProcessed(key) {
  if (!key) return false;
  if (processed.has(key)) return true;
  processed.add(key);
  setTimeout(() => processed.delete(key), 60 * 60 * 1000).unref?.();
  return false;
}

app.get("/", (req, res) => res.send("OK"));

// Shopify webhook: orders/create  ✅ RAW BODY route
app.post("/webhooks/orders-create", async (req, res) => {
  try {
    const rawBody = req.body; // Buffer

    if (!verifyShopifyWebhookRaw(req, rawBody)) {
      console.log("❌ Invalid Shopify webhook HMAC");
      return res.status(401).send("Invalid webhook");
    }

    const order = JSON.parse(rawBody.toString("utf8"));

    const gateways = order?.payment_gateway_names || [];
    const isPayseraManual = gateways.some((g) =>
      String(g || "").toLowerCase().includes("pay online")
    );

    console.log("✅ orders/create webhook received");
    console.log("Order ID:", order?.id);
    console.log("Order name:", order?.name);
    console.log("Total:", order?.total_price, order?.currency);
    console.log("Gateways:", gateways);

    if (!isPayseraManual) return res.status(200).send("OK");
    if (!PUBLIC_BASE_URL) throw new Error("Missing PUBLIC_BASE_URL in .env");

    const amount = String(order?.total_price || "0");
    const currency = String(order?.currency || "EUR");
    const description = `Payment for order ${order?.name || order?.id}`;

    const paymentUrl = await procardPurchaseCreatePaymentUrl({
      order_id: String(order?.id),
      amount,
      currency_iso: currency,
      description,
      approve_url: "https://dyqanibio.com",
      decline_url: "https://dyqanibio.com",
      cancel_url: "https://dyqanibio.com",
      callback_url: `${PUBLIC_BASE_URL}/procard/callback`,
      email: order?.email || "",
      phone: order?.phone || "",
      add_params: {
        shopify_order_id: String(order?.id),
        shopify_order_name: String(order?.name || ""),
      },
      language: "en",
    });

    console.log("✅ PROCARD payment URL:", paymentUrl);

    const recipient = TEST_EMAIL_TO || order?.email;
    if (recipient) {
      await sendPaymentEmail({
        to: recipient,
        orderName: order?.name || `Order ${order?.id}`,
        amount,
        currency,
        paymentUrl,
      });
      console.log("✅ Payment email sent to:", recipient, TEST_EMAIL_TO ? "(TEST MODE)" : "");
    } else {
      console.log("⚠️ No recipient email found");
    }
  } catch (e) {
    console.log("❌ orders/create handler error:", String(e?.message || e));
  }

  return res.status(200).send("OK");
});

// ✅ Procard callback (JSON route) — now marks order as PAID on success
app.post("/procard/callback", async (req, res) => {
  try {
    console.log("✅ procard callback received");
    console.log("Body:", req.body);

    const ok = verifyProcardCallbackSignature(req.body);
    console.log("Signature valid:", ok);

    if (!ok) return res.status(401).send("Invalid signature");

    // Dedup key: order + amount + currency + optional transaction id
    const txnId = req.body?.transactionId || req.body?.transaction_id || req.body?.reference || "";
    const key = `${req.body?.orderReference}:${req.body?.amount}:${req.body?.currency}:${txnId}`;
    if (alreadyProcessed(key)) {
      console.log("↩️ Duplicate callback ignored:", key);
      return res.status(200).send("OK");
    }

    // Only mark as paid if callback looks like a SUCCESS
    const success = procardLooksSuccessful(req.body);
    console.log("Looks successful:", success);

    if (!success) return res.status(200).send("OK");

    const shopifyOrderId = String(req.body?.orderReference || "").trim();
    if (!shopifyOrderId) {
      console.log("❌ Missing orderReference in callback");
      return res.status(200).send("OK");
    }

    const order = await shopifyMarkOrderPaid(shopifyOrderId);
    console.log("✅ Shopify order marked PAID:", order?.name, order?.displayFinancialStatus);

    return res.status(200).send("OK");
  } catch (e) {
    console.log("❌ procard callback handler error:", String(e?.message || e));
    // keep 200 so provider doesn't spam retries while you debug
    return res.status(200).send("OK");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));