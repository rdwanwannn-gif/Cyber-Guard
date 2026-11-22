import dotenv from 'dotenv';
import express from 'express';
import { createSocApp } from '../server/app';
import { SecurityWorkspaceStore } from '../server/state';

dotenv.config();

declare global {
  // eslint-disable-next-line no-var
  var __sentinelGridStore: SecurityWorkspaceStore | undefined;
}

function getStore(): SecurityWorkspaceStore {
  if (!globalThis.__sentinelGridStore) {
    globalThis.__sentinelGridStore = new SecurityWorkspaceStore();
  }
  return globalThis.__sentinelGridStore;
}

const socApp = createSocApp(getStore(), {
  wsSupported: false,
});

const vercelHandler = express();
vercelHandler.set('trust proxy', 1);

// Normalize rewritten Vercel Serverless Function paths (/api/index?__vercel_path=...)
vercelHandler.use((req, _res, next) => {
  const rawPathParam = req.query.__vercel_path;
  if (typeof rawPathParam === 'string' && req.url.startsWith('/api/index')) {
    const cleanSubPath = rawPathParam.replace(/^\/+/, '');
    const parsed = new URL(req.url, 'http://localhost');
    parsed.searchParams.delete('__vercel_path');
    const qs = parsed.searchParams.toString();
    req.url = `/api/${cleanSubPath}${qs ? `?${qs}` : ''}`;
  }
  next();
});

vercelHandler.use(socApp);

export default vercelHandler;
