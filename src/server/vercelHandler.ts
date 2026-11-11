import type { Request, Response } from 'express';
import app from './app';
import { connectToDatabase } from './db/connection';

/**
 * Vercel Serverless Function entry point.
 * Pre-bundled by esbuild into api/index.js for robust production execution on Vercel without ERR_MODULE_NOT_FOUND errors.
 */
export default async function handler(req: Request, res: Response) {
  if (process.env.MONGODB_URI) {
    try {
      await connectToDatabase();
    } catch (err: any) {
      console.error('[Vercel Serverless] Database connection notice:', err?.message || err);
    }
  }

  return app(req, res);
}
