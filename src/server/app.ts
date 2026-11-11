import express, { type Request, type Response, type NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import { connectToDatabase, getDatabaseStatus } from './db/connection';
import authRoutes from './routes/authRoutes';

const app = express();

// Trust proxy for secure cookies behind Vercel / Cloud Run load balancers
app.set('trust proxy', 1);

// Security Headers with Helmet
app.use(
  helmet({
    contentSecurityPolicy: false, // Vite SPA handles script loading
    crossOriginEmbedderPolicy: false,
  })
);

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
  : [process.env.APP_BASE_URL || 'http://localhost:3000'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, or same-origin)
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
        return callback(null, true);
      }
      return callback(null, true);
    },
    credentials: true,
  })
);

// Body Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Connect to MongoDB Atlas (non-blocking for fast serverless startup)
connectToDatabase().catch((err) => {
  console.warn('[MongoDB] Initial connection notice:', err.message);
});

// Session Configuration with MongoStore
const sessionSecret = process.env.SESSION_SECRET || 'kargoflow_dev_session_secret_ghana_2026';
const isProduction = process.env.NODE_ENV === 'production';

let sessionStore: session.Store | undefined;
if (process.env.MONGODB_URI) {
  sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60, // 14 days
    autoRemove: 'native',
    touchAfter: 24 * 3600, // lazy session update
  });
}

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: 'kargoflow.sid',
    cookie: {
      httpOnly: true,
      secure: true,      // Required for SameSite=None in iframe
      sameSite: 'none',  // Required for cross-origin iframe preview environment
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
    },
  })
);

// OAuth Popup Callback Handler - Handles cross-window postMessage and closes popup
app.get(['/auth/callback', '/auth/callback/'], (_req: Request, res: Response) => {
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

// Root API endpoint
app.get(['/api', '/api/'], (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'KargoFlow Ghana API Engine',
    timestamp: new Date().toISOString(),
  });
});

// Mount API Sub-Routers (support both /api/auth and /auth)
app.use(['/auth', '/api/auth'], authRoutes);

/**
 * Health check & runtime diagnostic endpoint
 * GET /api/health or /health
 */
app.get(['/health', '/api/health'], async (_req: Request, res: Response) => {
  // Attempt connection if currently disconnected
  if (process.env.MONGODB_URI && mongooseConnectionReadyState() !== 1) {
    try {
      await connectToDatabase();
    } catch {
      // Handled in status report
    }
  }

  const dbStatus = getDatabaseStatus();

  return res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'KargoFlow Ghana API Engine',
    environment: process.env.NODE_ENV || 'development',
    database: {
      status: dbStatus.isConnected ? 'connected' : 'disconnected',
      message: dbStatus.message,
      readyState: dbStatus.readyState,
    },
    integrations: {
      googleAuth: Boolean(process.env.GOOGLE_CLIENT_ID),
      paystack: Boolean(process.env.PAYSTACK_SECRET_KEY),
      resendEmail: Boolean(process.env.RESEND_API_KEY),
    },
  });
});

function mongooseConnectionReadyState(): number {
  return getDatabaseStatus().readyState;
}

export default app;
