const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const admin = require("firebase-admin");
const twilio = require("twilio");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ✅ Firebase Admin Setup
const serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_CREDENTIALS);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const auth = admin.auth();

// ✅ Twilio Setup
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);
const verifySid = process.env.TWILIO_SERVICE_SID;

app.get("/", (req, res) => {
  res.send("Welcome to the Marsos Auth API");
});

// ✅ Send OTP (Twilio SMS)
app.post("/send-otp", async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: "Phone number is required." });
  }

  try {
    const verification = await twilioClient.verify.v2
      .services(verifySid)
      .verifications.create({ to: phone, channel: "sms" });

    console.log("OTP sent to:", phone);
    res.json({ success: true, status: verification.status });
  } catch (error) {
    console.error("Twilio send-otp error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ✅ Verify OTP and return Firebase Custom Token
app.post("/verify-otp", async (req, res) => {
  const { phone, code } = req.body;

  if (!phone || !code) {
    return res.status(400).json({ error: "Phone and code are required." });
  }

  try {
    const verificationCheck = await twilioClient.verify.v2
      .services(verifySid)
      .verificationChecks.create({ to: phone, code });

    if (verificationCheck.status === "approved") {
      let user;
      try {
        user = await auth.getUserByPhoneNumber(phone);
      } catch {
        user = await auth.createUser({ phoneNumber: phone });
      }

      const token = await auth.createCustomToken(user.uid);
      console.log("OTP verified. Custom token issued.");
      return res.json({ success: true, token });
    }

    return res.status(401).json({ error: "Invalid or expired OTP." });
  } catch (error) {
    console.error("Twilio verify-otp error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
