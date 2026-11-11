import argon2 from 'argon2';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export interface GoogleVerifiedPayload {
  googleId: string;
  email: string;
  name: string;
  picture?: string;
  emailVerified: boolean;
}

/**
 * Hash password securely using Argon2id algorithm.
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64 MB
    timeCost: 3,
    parallelism: 1,
  });
}

/**
 * Verify password against an Argon2 hash.
 */
export async function verifyPassword(hash: string, plainText: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plainText);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically secure random token (e.g. for password resets or email verification).
 */
export function generateSecureToken(): { token: string; hash: string } {
  const token = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, hash };
}

/**
 * Verify Google ID Token via Google Identity Services and google-auth-library.
 */
export async function verifyGoogleIdToken(idToken: string): Promise<GoogleVerifiedPayload> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error('GOOGLE_CLIENT_ID is not configured on the backend server.');
  }

  const client = new OAuth2Client(clientId);
  const ticket = await client.verifyIdToken({
    idToken,
    audience: clientId,
  });

  const payload = ticket.getPayload();
  if (!payload || !payload.sub || !payload.email) {
    throw new Error('Invalid Google authentication payload received.');
  }

  return {
    googleId: payload.sub,
    email: payload.email.toLowerCase().trim(),
    name: payload.name || payload.email.split('@')[0],
    picture: payload.picture,
    emailVerified: Boolean(payload.email_verified),
  };
}

/**
 * Verify Google Access Token via Google OAuth2 userinfo endpoint and tokeninfo.
 */
export async function verifyGoogleAccessToken(accessToken: string): Promise<GoogleVerifiedPayload> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error('GOOGLE_CLIENT_ID is not configured on the backend server.');
  }

  // 1. Fetch user profile from Google userinfo API
  const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to verify Google access token with Google identity services.');
  }

  const userInfo = await response.json();
  if (!userInfo.sub || !userInfo.email) {
    throw new Error('Invalid Google user profile data received.');
  }

  return {
    googleId: userInfo.sub,
    email: userInfo.email.toLowerCase().trim(),
    name: userInfo.name || userInfo.email.split('@')[0],
    picture: userInfo.picture,
    emailVerified: Boolean(userInfo.email_verified),
  };
}

/**
 * Exchange Google authorization code for tokens and extract user payload.
 */
export async function exchangeGoogleAuthCode(
  code: string,
  redirectUri: string
): Promise<GoogleVerifiedPayload> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error('GOOGLE_CLIENT_ID is not configured on the backend server.');
  }

  const client = new OAuth2Client(clientId, process.env.GOOGLE_CLIENT_SECRET, redirectUri);
  const { tokens } = await client.getToken(code);

  if (tokens.id_token) {
    return verifyGoogleIdToken(tokens.id_token);
  }

  if (tokens.access_token) {
    return verifyGoogleAccessToken(tokens.access_token);
  }

  throw new Error('Failed to retrieve authentication tokens from Google code exchange.');
}

export interface AuthTokenPayload {
  userId: string;
  role: string;
  exp: number;
}

/**
 * Generate a cryptographically signed authentication JWT token.
 * Enables resilient authentication in third-party cookie restricted iframes.
 */
export function createAuthToken(userId: string, role: string): string {
  const secret = process.env.SESSION_SECRET || 'kargoflow_ghana_secure_session_token_2026_supersecret';
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      userId,
      role,
      exp: Date.now() + 14 * 24 * 60 * 60 * 1000, // 14 days
    })
  ).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

/**
 * Verify signed authentication JWT token.
 */
export function verifyAuthToken(token: string): AuthTokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const secret = process.env.SESSION_SECRET || 'kargoflow_ghana_secure_session_token_2026_supersecret';
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${header}.${payload}`)
      .digest('base64url');

    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const data: AuthTokenPayload = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Date.now() > data.exp) {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}


