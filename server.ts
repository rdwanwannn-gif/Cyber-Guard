import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import dotenv from 'dotenv';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import { WebSocket, WebSocketServer } from 'ws';
import type { ThreatCategory, UserRole } from './src/lib/types';
import { createSocApp } from './server/app';
import { SecurityWorkspaceStore } from './server/state';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const store = new SecurityWorkspaceStore();

async function startServer() {
  const wss = new WebSocketServer({ noServer: true });
  const authedSockets = new Set<WebSocket>();
  const wsClientMeta = new Map<
    WebSocket,
    { sessionId: string; userId: string; roleKey: UserRole }
  >();

  function broadcastEvent(type: string, payload: unknown) {
    const serialized = JSON.stringify({ type, payload });
    for (const client of authedSockets) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(serialized);
      }
    }
  }

  function broadcastAdminEvent(type: string, payload: unknown) {
    const serialized = JSON.stringify({ type, payload });
    for (const client of authedSockets) {
      const meta = wsClientMeta.get(client);
      if (client.readyState === WebSocket.OPEN && meta?.roleKey === 'admin') {
        client.send(serialized);
      }
    }
  }

  function sendUserEvent(userId: string, type: string, payload: unknown) {
    const serialized = JSON.stringify({ type, payload });
    for (const [client, meta] of wsClientMeta.entries()) {
      if (client.readyState === WebSocket.OPEN && meta.userId === userId) {
        client.send(serialized);
      }
    }
  }

  function revokeUserSockets(userId: string, reason: string) {
    const msg = JSON.stringify({ type: 'session:revoked', payload: { reason } });
    for (const [client, meta] of wsClientMeta.entries()) {
      if (meta.userId === userId) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(msg);
          client.close(4003, reason.slice(0, 100));
        }
        authedSockets.delete(client);
        wsClientMeta.delete(client);
      }
    }
  }

  const app = createSocApp(store, {
    wsSupported: true,
    broadcastEvent,
    broadcastAdminEvent,
    sendUserEvent,
    revokeUserSockets,
  });

  const server = http.createServer(app);

  server.on('upgrade', (req, socket, head) => {
    const urlPath = (req.url || '').split('?')[0];
    if (urlPath !== '/ws') {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });

  wss.on('connection', (ws) => {
    let authenticated = false;
    const authTimer = setTimeout(() => {
      if (!authenticated && ws.readyState === WebSocket.OPEN) {
        ws.close(4001, 'Authentication timeout');
      }
    }, 5000);

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as { type?: string; token?: string };
        if (msg.type === 'auth' && msg.token) {
          const session = store.verifyBearerToken(msg.token);
          if (session) {
            authenticated = true;
            clearTimeout(authTimer);
            authedSockets.add(ws);
            wsClientMeta.set(ws, {
              sessionId: session.id,
              userId: session.userId,
              roleKey: session.roleKey,
            });
            ws.send(JSON.stringify({ type: 'auth:ok', payload: { sessionId: session.id } }));
          } else {
            ws.close(4003, 'Invalid token');
          }
        }
      } catch {
        // Ignore malformed client frames
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimer);
      authedSockets.delete(ws);
      wsClientMeta.delete(ws);
    });
  });

  // Real-time network traffic telemetry loop (broadcasts only when authenticated clients connect)
  setInterval(() => {
    const tick = store.generateLiveTrafficTick();
    if (authedSockets.size > 0) {
      broadcastEvent('traffic:tick', {
        sample: tick.sample,
        newLog: tick.newLog,
        cluster: tick.cluster,
        siemConnectors: store.siemConnectors,
      });
    }
  }, 1500);

  // Continuous live attack simulation loop (runs waves while simulation.running is active)
  let activeDrillWaves = 0;
  const simCategories: ThreatCategory[] = [
    'ddos_volumetric',
    'sqli_probe',
    'ssh_bruteforce',
    'c2_beacon',
    'data_exfiltration',
    'lateral_movement',
  ];
  setInterval(() => {
    if (!store.simulation.running) {
      activeDrillWaves = 0;
      return;
    }
    const chosen: ThreatCategory =
      store.simulation.scenario === 'mixed'
        ? simCategories[activeDrillWaves % simCategories.length]
        : store.simulation.scenario;
    activeDrillWaves += 1;
    if (activeDrillWaves >= 10) {
      store.simulation.running = false;
    }
    const result = store.triggerThreatScenario(chosen);
    if (authedSockets.size > 0) {
      broadcastEvent('threat:detected', result);
      broadcastEvent('simulation:state', { simulation: store.simulation });
    }
  }, 2800);

  // Vite middleware in dev; static dist serving in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found');
      }
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelGrid SOC server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
