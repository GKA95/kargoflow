import { Request, Response, NextFunction } from 'express';
import { User, IUser, UserRole } from '../models';
import { verifyAuthToken } from '../services/authService';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    userRole?: UserRole;
    isAdminMfaPending?: boolean;
    adminTempUserId?: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
    }
  }
}

/**
 * Authentication guard middleware: Verifies session authenticity and loads user.
 * Supports both Express sessions and Bearer JWT tokens for cross-origin iframe resilience.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  let userId = req.session?.userId;

  // Fallback to Bearer token in Authorization header if 3rd-party cookies are blocked by iframe
  if (!userId && req.headers.authorization?.startsWith('Bearer ')) {
    const rawToken = req.headers.authorization.split(' ')[1];
    const payload = verifyAuthToken(rawToken);
    if (payload?.userId) {
      userId = payload.userId;
      if (req.session) {
        req.session.userId = payload.userId;
        req.session.userRole = payload.role as UserRole;
      }
    }
  }

  if (!userId) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please sign in to access this resource.',
    });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({
        success: false,
        error: 'Authenticated session is invalid or user no longer exists.',
      });
    }

    if (user.isSuspended) {
      req.session.destroy(() => {});
      return res.status(403).json({
        success: false,
        error: 'This account has been suspended by operational administration.',
      });
    }

    req.user = user;
    next();
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Session verification failed due to internal service error.',
    });
  }
}

/**
 * Role-Based Access Control middleware: Enforces strict backend authorization.
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required prior to permission validation.',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Requires one of [${allowedRoles.join(', ')}] permissions.`,
      });
    }

    next();
  };
}
