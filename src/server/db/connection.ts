import mongoose from 'mongoose';
import type { Request, Response, NextFunction } from 'express';

// Avoid hung requests when disconnected by disabling default command buffering
mongoose.set('bufferCommands', false);

/**
 * Global cache interface for Mongoose connection reuse in Serverless / Vercel Functions.
 */
interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
}

declare global {
  // eslint-disable-next-line no-var
  var mongooseCache: MongooseCache | undefined;
}

const cached: MongooseCache = global.mongooseCache || { conn: null, promise: null };
if (!global.mongooseCache) {
  global.mongooseCache = cached;
}

export interface DatabaseStatus {
  isConnected: boolean;
  readyState: number;
  host?: string;
  name?: string;
  message: string;
  diagnostic?: string;
  lastError?: string;
  uriConfigured: boolean;
}

let lastConnectionError: string | null = null;

/**
 * Strips outer quotes, whitespace, and formatting anomalies from connection strings.
 */
export function sanitizeMongoUri(raw?: string | null): string {
  if (!raw) return '';
  return raw.trim().replace(/^["'`\s]+|["'`\s]+$/g, '');
}

/**
 * Connect to MongoDB Atlas with connection reuse suitable for Vercel Functions and Express.
 */
export async function connectToDatabase(): Promise<typeof mongoose | null> {
  const uri = sanitizeMongoUri(process.env.MONGODB_URI);

  if (!uri) {
    lastConnectionError = 'MONGODB_URI environment variable is missing or empty.';
    return null;
  }

  if (cached.conn && cached.conn.connection.readyState === 1) {
    lastConnectionError = null;
    return cached.conn;
  }

  if (!cached.promise) {
    const opts: mongoose.ConnectOptions = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    };

    cached.promise = mongoose
      .connect(uri, opts)
      .then((m) => {
        lastConnectionError = null;
        return m;
      })
      .catch((err) => {
        lastConnectionError = err?.message || String(err);
        cached.promise = null;
        throw err;
      });
  }

  try {
    cached.conn = await cached.promise;
    lastConnectionError = null;
    return cached.conn;
  } catch (error: any) {
    lastConnectionError = error?.message || String(error);
    cached.promise = null;
    throw error;
  }
}

/**
 * Query current database health and connection state.
 */
export function getDatabaseStatus(): DatabaseStatus {
  const state = mongoose.connection.readyState;
  const rawUri = process.env.MONGODB_URI;
  const cleanUri = sanitizeMongoUri(rawUri);
  const uriConfigured = Boolean(cleanUri);

  let diagnostic: string | undefined;
  if (!uriConfigured) {
    diagnostic = 'MONGODB_URI is not set. Add MONGODB_URI in your Vercel Project Settings > Environment Variables or .env file.';
  } else if (lastConnectionError) {
    if (lastConnectionError.includes('whitelist') || lastConnectionError.includes('closed') || lastConnectionError.includes('ServerSelection')) {
      diagnostic = 'Atlas Network Access restriction: Ensure 0.0.0.0/0 (Allow Access from Anywhere) is added to your MongoDB Atlas Network Access.';
    } else if (lastConnectionError.includes('bad auth') || lastConnectionError.includes('Authentication failed')) {
      diagnostic = 'Atlas Authentication failed: Verify username and password in Database Access in MongoDB Atlas.';
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
        message: 'Connected to MongoDB Atlas',
        uriConfigured: true,
      };
    case 2:
      return {
        isConnected: false,
        readyState: 2,
        message: 'Connecting to MongoDB Atlas...',
        diagnostic: 'Handshake in progress with Atlas cluster shards.',
        uriConfigured: true,
      };
    default:
      return {
        isConnected: false,
        readyState: state,
        message: uriConfigured
          ? 'Disconnected from MongoDB Atlas'
          : 'MONGODB_URI environment variable not configured',
        diagnostic,
        lastError: lastConnectionError || undefined,
        uriConfigured,
      };
  }
}

/**
 * Express middleware to ensure database connection before executing controller actions
 */
export async function ensureDatabaseConnected(
  _req: Request,
  res: Response,
  next: NextFunction
) {
  if (mongoose.connection.readyState === 1) {
    return next();
  }

  if (process.env.MONGODB_URI) {
    try {
      await connectToDatabase();
      if ((mongoose.connection.readyState as number) === 1) {
        return next();
      }
    } catch {
      // Catch and return 503 below
    }
  }

  return res.status(503).json({
    success: false,
    error: 'Database service is currently unreachable. Please verify MONGODB_URI configuration.',
  });
}

