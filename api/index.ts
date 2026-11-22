import type { IncomingMessage, ServerResponse } from 'node:http';
import socApp from './_soc-app.mjs';

type VercelIncomingMessage = IncomingMessage & {
  query?: Record<string, string | string[] | undefined>;
  body?: unknown;
  _body?: boolean;
};

function normalizeVercelApiUrl(req: VercelIncomingMessage) {
  const parsed = new URL(req.url || '/', 'http://localhost');
  const queryPath = req.query?.__vercel_path ?? parsed.searchParams.get('__vercel_path');
  const rawSubPath = Array.isArray(queryPath) ? queryPath.join('/') : queryPath;

  if (typeof rawSubPath === 'string' && rawSubPath.length > 0) {
    parsed.searchParams.delete('__vercel_path');
    const qs = parsed.searchParams.toString();
    const cleanSubPath = rawSubPath.replace(/^\/+/, '');
    req.url = `/api/${cleanSubPath}${qs ? `?${qs}` : ''}`;
    return;
  }

  if (!parsed.pathname.startsWith('/api')) {
    const qs = parsed.searchParams.toString();
    const cleanPathname = parsed.pathname === '/' ? '/health' : parsed.pathname;
    req.url = `/api${cleanPathname.startsWith('/') ? cleanPathname : `/${cleanPathname}`}${qs ? `?${qs}` : ''}`;
  }
}

export default function handler(req: VercelIncomingMessage, res: ServerResponse) {
  try {
    normalizeVercelApiUrl(req);
    return socApp(req as never, res as never);
  } catch (err) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      const message = err instanceof Error ? err.message : 'Vercel authentication handler error';
      res.end(JSON.stringify({ error: message }));
    }
  }
}
