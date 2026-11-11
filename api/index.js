// src/server/app.ts
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import session from "express-session";
import MongoStore from "connect-mongo";

// src/server/db/connection.ts
import mongoose from "mongoose";
mongoose.set("bufferCommands", false);
var cached = global.mongooseCache || { conn: null, promise: null };
if (!global.mongooseCache) {
  global.mongooseCache = cached;
}
var lastConnectionError = null;
function sanitizeMongoUri(raw) {
  if (!raw) return "";
  return raw.trim().replace(/^["'`\s]+|["'`\s]+$/g, "");
}
async function connectToDatabase() {
  const uri = sanitizeMongoUri(process.env.MONGODB_URI);
  if (!uri) {
    lastConnectionError = "MONGODB_URI environment variable is missing or empty.";
    return null;
  }
  if (cached.conn && cached.conn.connection.readyState === 1) {
    lastConnectionError = null;
    return cached.conn;
  }
  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 1e4,
      connectTimeoutMS: 1e4
    };
    cached.promise = mongoose.connect(uri, opts).then((m) => {
      lastConnectionError = null;
      return m;
    }).catch((err) => {
      lastConnectionError = err?.message || String(err);
      cached.promise = null;
      throw err;
    });
  }
  try {
    cached.conn = await cached.promise;
    lastConnectionError = null;
    return cached.conn;
  } catch (error) {
    lastConnectionError = error?.message || String(error);
    cached.promise = null;
    throw error;
  }
}
function getDatabaseStatus() {
  const state = mongoose.connection.readyState;
  const rawUri = process.env.MONGODB_URI;
  const cleanUri = sanitizeMongoUri(rawUri);
  const uriConfigured = Boolean(cleanUri);
  let diagnostic;
  if (!uriConfigured) {
    diagnostic = "MONGODB_URI is not set. Add MONGODB_URI in your Vercel Project Settings > Environment Variables or .env file.";
  } else if (lastConnectionError) {
    if (lastConnectionError.includes("whitelist") || lastConnectionError.includes("closed") || lastConnectionError.includes("ServerSelection")) {
      diagnostic = "Atlas Network Access restriction: Ensure 0.0.0.0/0 (Allow Access from Anywhere) is added to your MongoDB Atlas Network Access.";
    } else if (lastConnectionError.includes("bad auth") || lastConnectionError.includes("Authentication failed")) {
      diagnostic = "Atlas Authentication failed: Verify username and password in Database Access in MongoDB Atlas.";
    } else {
      diagnostic = lastConnectionError;
    }
  }
  switch (state) {
    case 1:
      return {
        isConnected: true,
        readyState: 1,
        host: mongoose.connection.host,
        name: mongoose.connection.name,
        message: "Connected to MongoDB Atlas",
        uriConfigured: true
      };
    case 2:
      return {
        isConnected: false,
        readyState: 2,
        message: "Connecting to MongoDB Atlas...",
        diagnostic: "Handshake in progress with Atlas cluster shards.",
        uriConfigured: true
      };
    default:
      return {
        isConnected: false,
        readyState: state,
        message: uriConfigured ? "Disconnected from MongoDB Atlas" : "MONGODB_URI environment variable not configured",
        diagnostic,
        lastError: lastConnectionError || void 0,
        uriConfigured
      };
  }
}
async function ensureDatabaseConnected(_req, res, next) {
  if (mongoose.connection.readyState === 1) {
    return next();
  }
  if (process.env.MONGODB_URI) {
    try {
      await connectToDatabase();
      if (mongoose.connection.readyState === 1) {
        return next();
      }
    } catch {
    }
  }
  return res.status(503).json({
    success: false,
    error: "Database service is currently unreachable. Please verify MONGODB_URI configuration."
  });
}

// src/server/routes/authRoutes.ts
import { Router } from "express";

// src/server/controllers/authController.ts
import { z } from "zod";

// src/server/models/User.ts
import mongoose2, { Schema } from "mongoose";
var UserSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Full name is required"],
      trim: true,
      maxlength: [100, "Name cannot exceed 100 characters"]
    },
    email: {
      type: String,
      required: [true, "Email address is required"],
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    phone: {
      type: String,
      default: "",
      trim: true
    },
    passwordHash: {
      type: String,
      select: false
      // Do not expose password hashes by default
    },
    role: {
      type: String,
      enum: ["customer", "rider", "admin"],
      default: "customer",
      required: true,
      index: true
    },
    isEmailVerified: {
      type: Boolean,
      default: false
    },
    googleId: {
      type: String,
      sparse: true,
      unique: true,
      index: true
    },
    avatarUrl: {
      type: String
    },
    isSuspended: {
      type: Boolean,
      default: false
    },
    mfaEnabled: {
      type: Boolean,
      default: false
    },
    mfaSecret: {
      type: String,
      select: false
    },
    passwordResetToken: {
      type: String,
      select: false
    },
    passwordResetExpires: {
      type: Date,
      select: false
    },
    emailVerificationToken: {
      type: String,
      select: false
    },
    emailVerificationExpires: {
      type: Date,
      select: false
    },
    lastLoginAt: {
      type: Date
    }
  },
  {
    timestamps: true
  }
);
UserSchema.methods.toJSON = function() {
  const obj = this.toObject();
  obj.id = obj._id ? obj._id.toString() : "";
  delete obj.passwordHash;
  delete obj.mfaSecret;
  delete obj.passwordResetToken;
  delete obj.passwordResetExpires;
  delete obj.emailVerificationToken;
  delete obj.emailVerificationExpires;
  return obj;
};
var User = mongoose2.models.User || mongoose2.model("User", UserSchema);

// src/server/models/RiderProfile.ts
import mongoose3, { Schema as Schema2 } from "mongoose";
var RiderProfileSchema = new Schema2(
  {
    userId: {
      type: Schema2.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
      index: true
    },
    residentialLocation: {
      type: String,
      required: true,
      trim: true
    },
    vehicleType: {
      type: String,
      enum: ["motorcycle", "scooter", "bicycle", "van", "cargo_tricycle"],
      default: "motorcycle",
      required: true
    },
    vehicleRegistrationNumber: {
      type: String,
      trim: true,
      uppercase: true
    },
    licenseNumber: {
      type: String,
      trim: true,
      uppercase: true
    },
    ghanaCardNumber: {
      type: String,
      trim: true,
      uppercase: true
    },
    approvalStatus: {
      type: String,
      enum: ["pending", "approved", "rejected", "suspended"],
      default: "pending",
      required: true,
      index: true
    },
    rejectionReason: {
      type: String,
      trim: true
    },
    isOnline: {
      type: Boolean,
      default: false,
      index: true
    },
    currentLocation: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point"
      },
      coordinates: {
        type: [Number]
        // [lng, lat]
      },
      updatedAt: {
        type: Date
      }
    },
    rating: {
      type: Number,
      default: 5,
      min: 1,
      max: 5
    },
    totalCompletedDeliveries: {
      type: Number,
      default: 0,
      min: 0
    },
    earningsToday: {
      type: Number,
      default: 0,
      min: 0
    },
    earningsWeek: {
      type: Number,
      default: 0,
      min: 0
    },
    earningsTotal: {
      type: Number,
      default: 0,
      min: 0
    },
    documents: {
      ghanaCardStored: { type: Boolean, default: false },
      drivingLicenseStored: { type: Boolean, default: false },
      documentStorageRef: { type: String, select: false },
      // protected private reference
      uploadedAt: { type: Date }
    }
  },
  {
    timestamps: true
  }
);
RiderProfileSchema.index({ currentLocation: "2dsphere" });
var RiderProfile = mongoose3.models.RiderProfile || mongoose3.model("RiderProfile", RiderProfileSchema);

// src/server/models/Delivery.ts
import mongoose4, { Schema as Schema3 } from "mongoose";
var DeliverySchema = new Schema3(
  {
    trackingReference: {
      type: String,
      required: true,
      unique: true,
      index: true,
      uppercase: true
    },
    customerId: {
      type: Schema3.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    customerName: { type: String, required: true },
    customerPhone: { type: String, required: true },
    riderId: {
      type: Schema3.Types.ObjectId,
      ref: "User",
      index: true
    },
    riderName: { type: String },
    riderPhone: { type: String },
    riderVehicle: { type: String },
    status: {
      type: String,
      enum: [
        "awaiting_payment",
        "payment_confirmed",
        "awaiting_rider",
        "rider_assigned",
        "rider_accepted",
        "picked_up",
        "in_transit",
        "delivered",
        "cancelled",
        "failed"
      ],
      default: "awaiting_payment",
      required: true,
      index: true
    },
    type: {
      type: String,
      enum: ["standard", "express", "same_day"],
      default: "standard",
      required: true
    },
    pickup: {
      address: { type: String, required: true },
      digitalAddress: { type: String },
      landmark: { type: String },
      contactName: { type: String, required: true },
      contactPhone: { type: String, required: true },
      city: { type: String, default: "Accra" },
      coordinates: {
        lat: { type: Number },
        lng: { type: Number }
      }
    },
    destination: {
      address: { type: String, required: true },
      digitalAddress: { type: String },
      landmark: { type: String },
      recipientName: { type: String, required: true },
      recipientPhone: { type: String, required: true },
      city: { type: String, default: "Accra" },
      coordinates: {
        lat: { type: Number },
        lng: { type: Number }
      }
    },
    parcel: {
      description: { type: String, required: true },
      category: { type: String, default: "documents" },
      size: { type: String, enum: ["small", "medium", "large", "bulky"], default: "small" },
      weightKg: { type: Number },
      isFragile: { type: Boolean, default: false },
      specialInstructions: { type: String }
    },
    pricing: {
      baseFee: { type: Number, default: 0 },
      distanceFee: { type: Number, default: 0 },
      serviceTypeFee: { type: Number, default: 0 },
      fragileFee: { type: Number, default: 0 },
      totalAmountPesewas: { type: Number, required: true, default: 0 },
      totalAmountGhs: { type: Number, required: true, default: 0 },
      currency: { type: String, default: "GHS" }
    },
    paymentStatus: {
      type: String,
      enum: ["pending", "paid", "failed", "refunded"],
      default: "pending",
      index: true
    },
    paymentReference: {
      type: String,
      sparse: true,
      index: true
    },
    timeline: [
      {
        status: { type: String, required: true },
        timestamp: { type: Date, default: Date.now },
        note: { type: String },
        actorId: { type: Schema3.Types.ObjectId, ref: "User" },
        actorRole: { type: String }
      }
    ],
    proofOfDelivery: {
      recipientName: { type: String },
      notes: { type: String },
      photoUrl: { type: String },
      signatureUrl: { type: String },
      deliveredAt: { type: Date }
    }
  },
  {
    timestamps: true
  }
);
var Delivery = mongoose4.models.Delivery || mongoose4.model("Delivery", DeliverySchema);

// src/server/models/Payment.ts
import mongoose5, { Schema as Schema4 } from "mongoose";
var PaymentSchema = new Schema4(
  {
    deliveryId: {
      type: Schema4.Types.ObjectId,
      ref: "Delivery",
      required: true,
      index: true
    },
    trackingReference: {
      type: String,
      required: true,
      index: true
    },
    customerId: {
      type: Schema4.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    amountPesewas: {
      type: Number,
      required: true,
      min: 0
    },
    amountGhs: {
      type: Number,
      required: true,
      min: 0
    },
    currency: {
      type: String,
      default: "GHS",
      required: true
    },
    channel: {
      type: String,
      default: "mobile_money"
    },
    status: {
      type: String,
      enum: ["pending", "success", "failed", "refunded"],
      default: "pending",
      index: true
    },
    paystackReference: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    paystackTransactionId: {
      type: String
    },
    gatewayResponse: {
      type: String
    },
    paidAt: {
      type: Date
    },
    metadata: {
      type: Schema4.Types.Mixed
    }
  },
  {
    timestamps: true
  }
);
var Payment = mongoose5.models.Payment || mongoose5.model("Payment", PaymentSchema);

// src/server/models/Refund.ts
import mongoose6, { Schema as Schema5 } from "mongoose";
var RefundSchema = new Schema5(
  {
    deliveryId: {
      type: Schema5.Types.ObjectId,
      ref: "Delivery",
      required: true,
      index: true
    },
    trackingReference: {
      type: String,
      required: true,
      index: true
    },
    customerId: {
      type: Schema5.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    amountPesewas: { type: Number, required: true },
    amountGhs: { type: Number, required: true },
    currency: { type: String, default: "GHS" },
    reason: { type: String, required: true },
    status: {
      type: String,
      enum: [
        "requested",
        "under_review",
        "approved",
        "rejected",
        "processing",
        "processed",
        "failed"
      ],
      default: "requested",
      index: true
    },
    adminDecisionNotes: { type: String },
    paystackRefundReference: { type: String }
  },
  {
    timestamps: true
  }
);
var Refund = mongoose6.models.Refund || mongoose6.model("Refund", RefundSchema);

// src/server/models/RiderOffer.ts
import mongoose7, { Schema as Schema6 } from "mongoose";
var RiderOfferSchema = new Schema6(
  {
    deliveryId: {
      type: Schema6.Types.ObjectId,
      ref: "Delivery",
      required: true,
      index: true
    },
    riderId: {
      type: Schema6.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    status: {
      type: String,
      enum: ["pending", "accepted", "rejected", "expired"],
      default: "pending",
      index: true
    },
    offeredAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true
    },
    respondedAt: {
      type: Date
    }
  },
  {
    timestamps: true
  }
);
RiderOfferSchema.index({ deliveryId: 1, riderId: 1 });
var RiderOffer = mongoose7.models.RiderOffer || mongoose7.model("RiderOffer", RiderOfferSchema);

// src/server/models/AuditLog.ts
import mongoose8, { Schema as Schema7 } from "mongoose";
var AuditLogSchema = new Schema7(
  {
    actorId: {
      type: Schema7.Types.ObjectId,
      ref: "User",
      index: true
    },
    actorEmail: {
      type: String,
      trim: true
    },
    actorRole: {
      type: String
    },
    action: {
      type: String,
      required: true,
      index: true
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "low",
      index: true
    },
    details: {
      type: String,
      required: true
    },
    ipAddress: {
      type: String
    },
    userAgent: {
      type: String
    },
    metadata: {
      type: Schema7.Types.Mixed
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);
var AuditLog = mongoose8.models.AuditLog || mongoose8.model("AuditLog", AuditLogSchema);

// src/server/models/systemModels.ts
import mongoose9, { Schema as Schema8 } from "mongoose";
var NotificationSchema = new Schema8(
  {
    userId: { type: Schema8.Types.ObjectId, ref: "User", required: true, index: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, default: "order_update" },
    isRead: { type: Boolean, default: false, index: true },
    metadata: { type: Schema8.Types.Mixed }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
var Notification = mongoose9.models.Notification || mongoose9.model("Notification", NotificationSchema);
var ReviewSchema = new Schema8(
  {
    deliveryId: { type: Schema8.Types.ObjectId, ref: "Delivery", required: true, unique: true },
    customerId: { type: Schema8.Types.ObjectId, ref: "User", required: true, index: true },
    riderId: { type: Schema8.Types.ObjectId, ref: "User", required: true, index: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, trim: true }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
var Review = mongoose9.models.Review || mongoose9.model("Review", ReviewSchema);
var SupportTicketSchema = new Schema8(
  {
    authorId: { type: Schema8.Types.ObjectId, ref: "User", required: true, index: true },
    authorName: { type: String, required: true },
    authorRole: { type: String, enum: ["customer", "rider"], required: true },
    trackingReference: { type: String, index: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: {
      type: String,
      enum: ["open", "under_review", "resolved", "closed"],
      default: "open",
      index: true
    },
    adminResponse: { type: String },
    resolvedAt: { type: Date }
  },
  { timestamps: true }
);
var SupportTicket = mongoose9.models.SupportTicket || mongoose9.model("SupportTicket", SupportTicketSchema);
var PricingSettingsSchema = new Schema8(
  {
    baseFee: { type: Number, required: true, default: 15 },
    perKmRate: { type: Number, required: true, default: 2.5 },
    expressMultiplier: { type: Number, required: true, default: 1.5 },
    sameDayMultiplier: { type: Number, required: true, default: 1.25 },
    fragileHandlingFee: { type: Number, required: true, default: 5 },
    cancellationBeforeAcceptanceFee: { type: Number, default: 0 },
    cancellationAfterAcceptanceFee: { type: Number, default: 5 },
    currency: { type: String, default: "GHS", required: true },
    isPublished: { type: Boolean, default: true },
    publishedBy: { type: Schema8.Types.ObjectId, ref: "User" },
    effectiveDate: { type: Date, default: Date.now }
  },
  { timestamps: true }
);
var PricingSettings = mongoose9.models.PricingSettings || mongoose9.model("PricingSettings", PricingSettingsSchema);
var PolicySchema = new Schema8(
  {
    slug: { type: String, required: true, unique: true, index: true },
    title: { type: String, required: true },
    version: { type: String, required: true, default: "1.0.0" },
    complianceNotes: { type: String, default: "Compliant with Ghana Data Protection Act (Act 843)" },
    content: { type: String, required: true },
    lastUpdated: { type: String, default: "November 2026" },
    updatedBy: { type: Schema8.Types.ObjectId, ref: "User" }
  },
  { timestamps: true }
);
var Policy = mongoose9.models.Policy || mongoose9.model("Policy", PolicySchema);
var ConsentRecordSchema = new Schema8(
  {
    userId: { type: Schema8.Types.ObjectId, ref: "User", index: true },
    ipAddress: { type: String },
    policySlug: { type: String, required: true },
    policyVersion: { type: String, required: true },
    consentPurpose: { type: String, required: true },
    isGranted: { type: Boolean, required: true },
    timestamp: { type: Date, default: Date.now }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
var ConsentRecord = mongoose9.models.ConsentRecord || mongoose9.model("ConsentRecord", ConsentRecordSchema);
var PrivacyRequestSchema = new Schema8(
  {
    userId: { type: Schema8.Types.ObjectId, ref: "User", required: true, index: true },
    requestType: {
      type: String,
      enum: ["access", "rectification", "deletion", "objection"],
      required: true
    },
    status: {
      type: String,
      enum: ["pending", "in_progress", "completed", "rejected"],
      default: "pending",
      index: true
    },
    reason: { type: String },
    adminNotes: { type: String },
    completedAt: { type: Date }
  },
  { timestamps: true }
);
var PrivacyRequest = mongoose9.models.PrivacyRequest || mongoose9.model("PrivacyRequest", PrivacyRequestSchema);
var PaymentWebhookEventSchema = new Schema8(
  {
    eventId: { type: String, required: true, unique: true, index: true },
    event: { type: String, required: true },
    reference: { type: String, required: true, index: true },
    status: {
      type: String,
      enum: ["received", "processed", "failed"],
      default: "received",
      index: true
    },
    payload: { type: Schema8.Types.Mixed, required: true },
    processedAt: { type: Date }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
var PaymentWebhookEvent = mongoose9.models.PaymentWebhookEvent || mongoose9.model("PaymentWebhookEvent", PaymentWebhookEventSchema);

// src/server/services/authService.ts
import argon2 from "argon2";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
var googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    // 64 MB
    timeCost: 3,
    parallelism: 1
  });
}
async function verifyPassword(hash, plainText) {
  try {
    return await argon2.verify(hash, plainText);
  } catch {
    return false;
  }
}
function generateSecureToken() {
  const token = crypto.randomBytes(32).toString("hex");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  return { token, hash };
}
async function verifyGoogleIdToken(idToken) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error("GOOGLE_CLIENT_ID is not configured on the backend server.");
  }
  const client = new OAuth2Client(clientId);
  const ticket = await client.verifyIdToken({
    idToken,
    audience: clientId
  });
  const payload = ticket.getPayload();
  if (!payload || !payload.sub || !payload.email) {
    throw new Error("Invalid Google authentication payload received.");
  }
  return {
    googleId: payload.sub,
    email: payload.email.toLowerCase().trim(),
    name: payload.name || payload.email.split("@")[0],
    picture: payload.picture,
    emailVerified: Boolean(payload.email_verified)
  };
}
async function verifyGoogleAccessToken(accessToken) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error("GOOGLE_CLIENT_ID is not configured on the backend server.");
  }
  const response = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!response.ok) {
    throw new Error("Failed to verify Google access token with Google identity services.");
  }
  const userInfo = await response.json();
  if (!userInfo.sub || !userInfo.email) {
    throw new Error("Invalid Google user profile data received.");
  }
  return {
    googleId: userInfo.sub,
    email: userInfo.email.toLowerCase().trim(),
    name: userInfo.name || userInfo.email.split("@")[0],
    picture: userInfo.picture,
    emailVerified: Boolean(userInfo.email_verified)
  };
}
async function exchangeGoogleAuthCode(code, redirectUri) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error("GOOGLE_CLIENT_ID is not configured on the backend server.");
  }
  const client = new OAuth2Client(clientId, process.env.GOOGLE_CLIENT_SECRET, redirectUri);
  const { tokens } = await client.getToken(code);
  if (tokens.id_token) {
    return verifyGoogleIdToken(tokens.id_token);
  }
  if (tokens.access_token) {
    return verifyGoogleAccessToken(tokens.access_token);
  }
  throw new Error("Failed to retrieve authentication tokens from Google code exchange.");
}
function createAuthToken(userId, role) {
  const secret = process.env.SESSION_SECRET || "kargoflow_ghana_secure_session_token_2026_supersecret";
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      userId,
      role,
      exp: Date.now() + 14 * 24 * 60 * 60 * 1e3
      // 14 days
    })
  ).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}
function verifyAuthToken(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const secret = process.env.SESSION_SECRET || "kargoflow_ghana_secure_session_token_2026_supersecret";
    const expectedSignature = crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (Date.now() > data.exp) {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

// src/server/services/auditService.ts
async function logSecurityEvent(params) {
  try {
    await AuditLog.create({
      action: params.action,
      details: params.details,
      severity: params.severity || "low",
      actorId: params.actorId,
      actorEmail: params.actorEmail,
      actorRole: params.actorRole,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      metadata: params.metadata
    });
  } catch (err) {
    console.warn("[AuditLog] Failed to persist audit entry:", err.message);
  }
}

// src/server/controllers/authController.ts
var RegisterCustomerSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters").max(100),
  email: z.string().email("Valid email address is required").toLowerCase().trim(),
  phone: z.string().min(9, "Valid Ghanaian phone number is required").trim(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  termsAccepted: z.literal(true, {
    message: "You must accept the statutory Terms and Privacy Policy."
  })
});
var RegisterRiderSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters").max(100),
  email: z.string().email("Valid email is required").toLowerCase().trim(),
  phone: z.string().min(9, "Valid phone number is required").trim(),
  residentialLocation: z.string().min(2, "Residential location is required"),
  vehicleType: z.enum(["motorcycle", "scooter", "bicycle", "van", "cargo_tricycle"]),
  vehicleRegistrationNumber: z.string().optional(),
  ghanaCardNumber: z.string().optional(),
  licenseNumber: z.string().optional(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  termsAccepted: z.literal(true)
});
var LoginSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1, "Password is required"),
  role: z.enum(["customer", "rider", "admin"]).optional(),
  mfaCode: z.string().optional()
});
var authController = {
  /**
   * Customer Registration
   * POST /api/auth/register
   */
  async registerCustomer(req, res) {
    try {
      const parsed = RegisterCustomerSchema.parse(req.body);
      const existingUser = await User.findOne({ email: parsed.email });
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: "An account with this email address is already registered."
        });
      }
      const passwordHash = await hashPassword(parsed.password);
      const emailToken = generateSecureToken();
      const user = await User.create({
        name: parsed.name,
        email: parsed.email,
        phone: parsed.phone,
        passwordHash,
        role: "customer",
        isEmailVerified: false,
        emailVerificationToken: emailToken.hash,
        emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1e3)
        // 24 hours
      });
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          req.session.userId = user._id.toString();
          req.session.userRole = "customer";
          resolve();
        });
      });
      await logSecurityEvent({
        action: "CUSTOMER_REGISTRATION",
        details: `Customer account registered for ${user.email}`,
        actorId: user._id,
        actorEmail: user.email,
        actorRole: "customer",
        ipAddress: req.ip
      });
      const token = createAuthToken(user._id.toString(), user.role);
      return res.status(201).json({
        success: true,
        message: "Customer registration successful.",
        data: {
          token,
          user: user.toJSON()
        }
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          error: err.issues[0]?.message || "Invalid input data"
        });
      }
      return res.status(500).json({
        success: false,
        error: err.message || "Internal server error during registration"
      });
    }
  },
  /**
   * Rider Registration
   * POST /api/auth/register-rider
   */
  async registerRider(req, res) {
    try {
      const parsed = RegisterRiderSchema.parse(req.body);
      const existingUser = await User.findOne({ email: parsed.email });
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: "An account with this email address is already registered."
        });
      }
      const passwordHash = await hashPassword(parsed.password);
      const user = await User.create({
        name: parsed.name,
        email: parsed.email,
        phone: parsed.phone,
        passwordHash,
        role: "rider",
        isEmailVerified: false
      });
      const riderProfile = await RiderProfile.create({
        userId: user._id,
        residentialLocation: parsed.residentialLocation,
        vehicleType: parsed.vehicleType,
        vehicleRegistrationNumber: parsed.vehicleRegistrationNumber,
        ghanaCardNumber: parsed.ghanaCardNumber,
        licenseNumber: parsed.licenseNumber,
        approvalStatus: "pending",
        // Awaiting administrator approval
        isOnline: false
      });
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          req.session.userId = user._id.toString();
          req.session.userRole = "rider";
          resolve();
        });
      });
      await logSecurityEvent({
        action: "RIDER_APPLICATION_SUBMITTED",
        details: `Rider application registered for ${user.email} (${parsed.vehicleType})`,
        actorId: user._id,
        actorEmail: user.email,
        actorRole: "rider",
        ipAddress: req.ip
      });
      return res.status(201).json({
        success: true,
        message: "Rider application submitted successfully and is pending administrator approval.",
        data: {
          user: user.toJSON(),
          profile: riderProfile
        }
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          error: err.issues[0]?.message || "Invalid input data"
        });
      }
      return res.status(500).json({
        success: false,
        error: err.message || "Internal server error during rider application"
      });
    }
  },
  /**
   * Standard Account Login
   * POST /api/auth/login
   */
  async login(req, res) {
    try {
      const { email, password, role, mfaCode } = LoginSchema.parse(req.body);
      const user = await User.findOne({ email }).select("+passwordHash +mfaSecret");
      if (!user || !user.passwordHash) {
        await logSecurityEvent({
          action: "LOGIN_FAILED_UNKNOWN_USER",
          details: `Failed login attempt for nonexistent user ${email}`,
          severity: "medium",
          ipAddress: req.ip
        });
        return res.status(401).json({
          success: false,
          error: "Invalid email address or password."
        });
      }
      if (user.isSuspended) {
        return res.status(403).json({
          success: false,
          error: "This account has been suspended by operational administration."
        });
      }
      const isPasswordValid = await verifyPassword(user.passwordHash, password);
      if (!isPasswordValid) {
        await logSecurityEvent({
          action: "LOGIN_FAILED_BAD_PASSWORD",
          details: `Failed password verification for user ${email}`,
          actorId: user._id,
          actorEmail: user.email,
          actorRole: user.role,
          severity: "medium",
          ipAddress: req.ip
        });
        return res.status(401).json({
          success: false,
          error: "Invalid email address or password."
        });
      }
      if (role && user.role !== role) {
        return res.status(403).json({
          success: false,
          error: `This account is registered as a ${user.role}. Please use the corresponding portal.`
        });
      }
      if (user.role === "admin") {
        if (!mfaCode || mfaCode.length !== 6) {
          return res.status(403).json({
            success: false,
            error: "Administrator access requires a valid 6-digit multi-factor verification code.",
            requiresMfa: true
          });
        }
      }
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          req.session.userId = user._id.toString();
          req.session.userRole = user.role;
          resolve();
        });
      });
      user.lastLoginAt = /* @__PURE__ */ new Date();
      await user.save();
      await logSecurityEvent({
        action: "LOGIN_SUCCESS",
        details: `Successful login for ${user.email} (${user.role})`,
        actorId: user._id,
        actorEmail: user.email,
        actorRole: user.role,
        ipAddress: req.ip
      });
      const token = createAuthToken(user._id.toString(), user.role);
      return res.status(200).json({
        success: true,
        message: "Signed in successfully.",
        data: {
          token,
          user: user.toJSON()
        }
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          error: err.issues[0]?.message || "Invalid login credentials"
        });
      }
      return res.status(500).json({
        success: false,
        error: err.message || "Authentication error"
      });
    }
  },
  /**
   * Google Identity Services & OAuth 2.0 Sign-In
   * POST /api/auth/google
   */
  async googleAuth(req, res) {
    try {
      const { idToken, accessToken, code, redirectUri, role } = req.body;
      if (!idToken && !accessToken && !code) {
        return res.status(400).json({
          success: false,
          error: "Google authentication credential (idToken, accessToken, or authorization code) is required."
        });
      }
      let googlePayload;
      if (idToken) {
        googlePayload = await verifyGoogleIdToken(idToken);
      } else if (accessToken) {
        googlePayload = await verifyGoogleAccessToken(accessToken);
      } else if (code) {
        const targetRedirectUri = redirectUri || `${req.protocol}://${req.get("host")}/auth/callback`;
        googlePayload = await exchangeGoogleAuthCode(code, targetRedirectUri);
      } else {
        return res.status(400).json({ success: false, error: "No valid credential provided." });
      }
      let user = await User.findOne({ googleId: googlePayload.googleId });
      if (!user) {
        const existingByEmail = await User.findOne({ email: googlePayload.email });
        if (existingByEmail) {
          return res.status(409).json({
            success: false,
            error: "An account with this email already exists via standard credentials. Please sign in with your password to link your Google identity."
          });
        }
        if (role === "admin") {
          return res.status(403).json({
            success: false,
            error: "Google Sign-In cannot create administrative accounts. Unauthorized."
          });
        }
        const assignedRole = role === "rider" ? "rider" : "customer";
        user = await User.create({
          name: googlePayload.name,
          email: googlePayload.email,
          phone: "",
          googleId: googlePayload.googleId,
          avatarUrl: googlePayload.picture,
          role: assignedRole,
          isEmailVerified: googlePayload.emailVerified
        });
        if (assignedRole === "rider") {
          await RiderProfile.create({
            userId: user._id,
            residentialLocation: "Accra Metro",
            vehicleType: "motorcycle",
            approvalStatus: "pending",
            isOnline: false
          });
        }
      }
      if (user.isSuspended) {
        return res.status(403).json({
          success: false,
          error: "This account has been suspended by operational administration."
        });
      }
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          req.session.userId = user._id.toString();
          req.session.userRole = user.role;
          resolve();
        });
      });
      user.lastLoginAt = /* @__PURE__ */ new Date();
      await user.save();
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      await logSecurityEvent({
        action: "GOOGLE_AUTH_SUCCESS",
        details: `Google authentication successful for ${user.email} (${user.role})`,
        actorId: user._id,
        actorEmail: user.email,
        actorRole: user.role,
        ipAddress: req.ip
      });
      const token = createAuthToken(user._id.toString(), user.role);
      return res.status(200).json({
        success: true,
        message: "Google authentication successful.",
        data: {
          token,
          user: user.toJSON()
        }
      });
    } catch (err) {
      return res.status(401).json({
        success: false,
        error: err.message || "Google token verification failed."
      });
    }
  },
  /**
   * Session Retrieval
   * GET /api/auth/me
   */
  async getMe(req, res) {
    let userId = req.session?.userId;
    if (!userId && req.headers.authorization?.startsWith("Bearer ")) {
      const rawToken = req.headers.authorization.split(" ")[1];
      const payload = verifyAuthToken(rawToken);
      if (payload?.userId) {
        userId = payload.userId;
      }
    }
    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthenticated session." });
    }
    const user = await User.findById(userId);
    if (!user) {
      req.session.destroy(() => {
      });
      return res.status(401).json({ success: false, error: "User not found." });
    }
    return res.status(200).json({
      success: true,
      data: user.toJSON()
    });
  },
  /**
   * Logout
   * POST /api/auth/logout
   */
  async logout(req, res) {
    const userId = req.session?.userId;
    if (userId) {
      await logSecurityEvent({
        action: "USER_LOGOUT",
        details: `User signed out`,
        actorId: userId,
        ipAddress: req.ip
      });
    }
    req.session.destroy((err) => {
      if (err) {
        console.warn("[Session] Error destroying session on logout:", err);
      }
      res.clearCookie("kargoflow.sid", { path: "/" });
      return res.status(200).json({ success: true, message: "Signed out successfully." });
    });
  },
  /**
   * Password Reset Request
   * POST /api/auth/forgot-password
   */
  async forgotPassword(req, res) {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email address is required." });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user) {
      const resetToken = generateSecureToken();
      user.passwordResetToken = resetToken.hash;
      user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1e3);
      await user.save();
      await logSecurityEvent({
        action: "PASSWORD_RESET_REQUESTED",
        details: `Password reset token generated for ${user.email}`,
        actorId: user._id,
        actorEmail: user.email,
        ipAddress: req.ip
      });
    }
    return res.status(200).json({
      success: true,
      message: "If an account exists with this email, recovery instructions have been sent."
    });
  },
  /**
   * Reset Password with Token
   * POST /api/auth/reset-password
   */
  async resetPassword(req, res) {
    const { token, newPassword } = req.body;
    if (!token || !newPassword || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Valid reset token and password (min 8 characters) are required."
      });
    }
    const crypto2 = await import("crypto");
    const tokenHash = crypto2.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      passwordResetToken: tokenHash,
      passwordResetExpires: { $gt: /* @__PURE__ */ new Date() }
    }).select("+passwordResetToken +passwordResetExpires");
    if (!user) {
      return res.status(400).json({
        success: false,
        error: "Password reset link is invalid or has expired."
      });
    }
    user.passwordHash = await hashPassword(newPassword);
    user.passwordResetToken = void 0;
    user.passwordResetExpires = void 0;
    await user.save();
    await logSecurityEvent({
      action: "PASSWORD_RESET_COMPLETED",
      details: `Password reset successfully completed for ${user.email}`,
      actorId: user._id,
      actorEmail: user.email,
      ipAddress: req.ip
    });
    return res.status(200).json({
      success: true,
      message: "Password updated successfully. You can now log in with your new credentials."
    });
  },
  /**
   * Change Password (for logged-in users)
   * POST /api/auth/change-password
   */
  async changePassword(req, res) {
    if (!req.session?.userId) {
      return res.status(401).json({ success: false, error: "Authentication required." });
    }
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Current password and new password (min. 8 characters) are required."
      });
    }
    const user = await User.findById(req.session.userId).select("+passwordHash");
    if (!user || !user.passwordHash) {
      return res.status(404).json({ success: false, error: "User account not found." });
    }
    const isMatch = await verifyPassword(user.passwordHash, currentPassword);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: "Current password is incorrect." });
    }
    user.passwordHash = await hashPassword(newPassword);
    await user.save();
    await logSecurityEvent({
      action: "PASSWORD_CHANGED",
      details: `Password updated by user`,
      actorId: user._id,
      actorEmail: user.email,
      ipAddress: req.ip
    });
    return res.status(200).json({ success: true, message: "Password updated successfully." });
  },
  /**
   * Email Verification
   * POST /api/auth/verify-email
   */
  async verifyEmail(req, res) {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, error: "Verification token is required." });
    }
    const crypto2 = await import("crypto");
    const tokenHash = crypto2.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      emailVerificationToken: tokenHash,
      emailVerificationExpires: { $gt: /* @__PURE__ */ new Date() }
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        error: "Verification link is invalid or has expired."
      });
    }
    user.isEmailVerified = true;
    user.emailVerificationToken = void 0;
    user.emailVerificationExpires = void 0;
    await user.save();
    await logSecurityEvent({
      action: "EMAIL_VERIFIED",
      details: `Email verified successfully for ${user.email}`,
      actorId: user._id,
      actorEmail: user.email,
      ipAddress: req.ip
    });
    return res.status(200).json({
      success: true,
      message: "Email address verified successfully.",
      data: { verified: true }
    });
  },
  /**
   * Protected One-Time Admin Setup / Bootstrap
   * POST /api/auth/bootstrap-admin
   * Only allows execution if zero admins exist, or if authorized via ADMIN_SETUP_TOKEN
   */
  async bootstrapAdmin(req, res) {
    try {
      const { name, email, phone, password, setupToken } = req.body;
      const adminCount = await User.countDocuments({ role: "admin" });
      const envToken = process.env.ADMIN_SETUP_TOKEN;
      if (adminCount > 0) {
        if (!envToken || setupToken !== envToken) {
          return res.status(403).json({
            success: false,
            error: "Administrator account already initialized. Public admin setup is disabled."
          });
        }
      }
      if (!name || !email || !password || password.length < 10) {
        return res.status(400).json({
          success: false,
          error: "Name, email, and strong password (min. 10 chars) are required for administrator provisioning."
        });
      }
      const passwordHash = await hashPassword(password);
      const admin = await User.create({
        name,
        email: email.toLowerCase().trim(),
        phone: phone || "+233 24 000 0000",
        passwordHash,
        role: "admin",
        isEmailVerified: true,
        mfaEnabled: true
      });
      await logSecurityEvent({
        action: "ADMIN_BOOTSTRAPPED",
        details: `Initial administrator provisioned for ${admin.email}`,
        severity: "critical",
        actorId: admin._id,
        actorEmail: admin.email,
        actorRole: "admin",
        ipAddress: req.ip
      });
      return res.status(201).json({
        success: true,
        message: "Primary administrator provisioned successfully.",
        data: {
          admin: admin.toJSON()
        }
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: err.message || "Admin bootstrap error"
      });
    }
  }
};

// src/server/middleware/auth.ts
async function requireAuth(req, res, next) {
  let userId = req.session?.userId;
  if (!userId && req.headers.authorization?.startsWith("Bearer ")) {
    const rawToken = req.headers.authorization.split(" ")[1];
    const payload = verifyAuthToken(rawToken);
    if (payload?.userId) {
      userId = payload.userId;
      if (req.session) {
        req.session.userId = payload.userId;
        req.session.userRole = payload.role;
      }
    }
  }
  if (!userId) {
    return res.status(401).json({
      success: false,
      error: "Authentication required. Please sign in to access this resource."
    });
  }
  try {
    const user = await User.findById(userId);
    if (!user) {
      req.session.destroy(() => {
      });
      return res.status(401).json({
        success: false,
        error: "Authenticated session is invalid or user no longer exists."
      });
    }
    if (user.isSuspended) {
      req.session.destroy(() => {
      });
      return res.status(403).json({
        success: false,
        error: "This account has been suspended by operational administration."
      });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Session verification failed due to internal service error."
    });
  }
}

// src/server/routes/authRoutes.ts
var router = Router();
router.use(ensureDatabaseConnected);
router.post("/register", authController.registerCustomer);
router.post("/register-rider", authController.registerRider);
router.post("/login", authController.login);
router.post("/google", authController.googleAuth);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.post("/verify-email", authController.verifyEmail);
router.post("/bootstrap-admin", authController.bootstrapAdmin);
router.get("/me", requireAuth, authController.getMe);
router.post("/logout", requireAuth, authController.logout);
router.post("/change-password", requireAuth, authController.changePassword);
var authRoutes_default = router;

// src/server/app.ts
var app = express();
app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: false,
    // Vite SPA handles script loading
    crossOriginEmbedderPolicy: false
  })
);
var allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim()) : [process.env.APP_BASE_URL || "http://localhost:3000"];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== "production") {
        return callback(null, true);
      }
      return callback(null, true);
    },
    credentials: true
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());
connectToDatabase().catch((err) => {
  console.warn("[MongoDB] Initial connection notice:", err.message);
});
var sessionSecret = process.env.SESSION_SECRET || "kargoflow_dev_session_secret_ghana_2026";
var cleanMongoUri = sanitizeMongoUri(process.env.MONGODB_URI);
var sessionStore;
if (cleanMongoUri) {
  try {
    sessionStore = MongoStore.create({
      mongoUrl: cleanMongoUri,
      collectionName: "sessions",
      ttl: 14 * 24 * 60 * 60,
      // 14 days
      autoRemove: "native",
      touchAfter: 24 * 3600
      // lazy session update
    });
    sessionStore.on("error", (storeErr) => {
      console.warn("[SessionStore] MongoStore background notice:", storeErr?.message || storeErr);
    });
  } catch (err) {
    console.warn("[SessionStore] Failed to initialize MongoStore, falling back to memory session store:", err?.message || err);
    sessionStore = void 0;
  }
}
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: "kargoflow.sid",
    cookie: {
      httpOnly: true,
      secure: true,
      // Required for SameSite=None in iframe
      sameSite: "none",
      // Required for cross-origin iframe preview environment
      maxAge: 14 * 24 * 60 * 60 * 1e3
      // 14 days
    }
  })
);
app.get(["/auth/callback", "/auth/callback/"], (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Google Authentication - KargoFlow</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f8fafc; color: #1e293b; }
          .card { background: white; padding: 28px 32px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); text-align: center; max-width: 360px; }
          .spinner { width: 36px; height: 36px; border: 3px solid #e2e8f0; border-top-color: #0f766e; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
          @keyframes spin { to { transform: rotate(360deg); } }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="spinner"></div>
          <h3 style="margin: 0 0 8px; font-size: 16px;">Authenticating with Google...</h3>
          <p style="margin: 0; font-size: 13px; color: #64748b;">Completing sign-in. This window will close automatically.</p>
        </div>
        <script>
          (function() {
            try {
              const urlParams = new URLSearchParams(window.location.search);
              const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
              const code = urlParams.get('code');
              const accessToken = hashParams.get('access_token');
              const idToken = hashParams.get('id_token');
              const error = urlParams.get('error') || hashParams.get('error');

              if (window.opener) {
                window.opener.postMessage({
                  type: 'GOOGLE_AUTH_CALLBACK',
                  code: code,
                  accessToken: accessToken,
                  idToken: idToken,
                  error: error
                }, '*');
                setTimeout(() => window.close(), 600);
              } else {
                window.location.href = '/';
              }
            } catch (e) {
              console.error(e);
            }
          })();
        </script>
      </body>
    </html>
  `);
});
app.get(["/", "/api", "/api/"], (_req, res) => {
  res.json({
    status: "ok",
    service: "KargoFlow Ghana API Engine",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.use(["/auth", "/api/auth"], authRoutes_default);
app.get(["/health", "/api/health"], async (_req, res) => {
  if (process.env.MONGODB_URI && mongooseConnectionReadyState() !== 1) {
    try {
      await connectToDatabase();
    } catch {
    }
  }
  const dbStatus = getDatabaseStatus();
  return res.status(200).json({
    status: "ok",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    service: "KargoFlow Ghana API Engine",
    environment: process.env.NODE_ENV || "development",
    database: {
      status: dbStatus.isConnected ? "connected" : "disconnected",
      message: dbStatus.message,
      readyState: dbStatus.readyState,
      diagnostic: dbStatus.diagnostic,
      lastError: dbStatus.lastError,
      uriConfigured: dbStatus.uriConfigured,
      host: dbStatus.host,
      databaseName: dbStatus.name
    },
    integrations: {
      googleAuth: Boolean(process.env.GOOGLE_CLIENT_ID),
      paystack: Boolean(process.env.PAYSTACK_SECRET_KEY),
      resendEmail: Boolean(process.env.RESEND_API_KEY)
    }
  });
});
function mongooseConnectionReadyState() {
  return getDatabaseStatus().readyState;
}
var app_default = app;

// src/server/vercelHandler.ts
async function handler(req, res) {
  if (process.env.MONGODB_URI) {
    try {
      await connectToDatabase();
    } catch (err) {
      console.error("[Vercel Serverless] Database connection notice:", err?.message || err);
    }
  }
  return app_default(req, res);
}
export {
  handler as default
};
