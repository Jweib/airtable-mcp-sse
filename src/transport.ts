import http from 'node:http';
import type { AddressInfo } from 'node:net';
import assert from 'node:assert';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { AirtableMCPServer } from './mcpServer.js';
import { AirtableService } from './airtableService.js';

const MCP_PATH = '/sse';
const MESSAGES_PATH = '/messages';

function setCommonHeaders(res: http.ServerResponse) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-MCP-Auth, X-MCP-Session-Id, X-Session-Id, Authorization');
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  sessions: Map<string, SSEServerTransport>
) {
  setCommonHeaders(res);

  // 0) Bloque toute découverte OIDC partout
  if (url.pathname.includes('/.well-known')) {
    return sendJson(res, 404, { error: 'Not found' });
  }

  // 0-bis) Préflights neutres (évite la validation Dust)
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  // 0-ter) Healthcheck ROOT SANS AUTH
  if (url.pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    return sendJson(res, 200, {
      ok: true,
      service: 'airtable-mcp-sse',
      transport: 'sse',
      endpoints: { sse: MCP_PATH, messages: MESSAGES_PATH },
    });
  }

  // 0-quater) Dust envoie souvent un POST JSON-RPC sur "/" pendant l’ajout
  if (url.pathname === '/' && req.method === 'POST') {
    try {
      const raw = await readBody(req);
      let parsed: any = {};
      try { parsed = raw ? JSON.parse(raw) : {}; } catch { /* ignore */ }

      // Toujours répondre au format JSON-RPC valide
      const id = parsed?.id ?? null;
      const method = typeof parsed?.method === 'string' ? parsed.method : 'ping';

      // On renvoie un "result" générique (pas d’auth requise pour la découverte)
      return sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: {
          ok: true,
          methodEcho: method,
          service: 'airtable-mcp-sse',
          transport: 'sse',
          endpoints: { sse: MCP_PATH, messages: MESSAGES_PATH },
        },
      });
    } catch (e) {
      // En cas de souci de parsing, renvoyer une erreur JSON-RPC valide
      return sendJson(res, 200, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
    }
  }

  // === À partir d’ici : endpoints protégés par secret persistant ===
  const mcpSecret = process.env.MCP_SECRET;
  const xMcpAuth = req.headers['x-mcp-auth'] as string | undefined;
  const authHeader = req.headers.authorization;
  const bearer = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;

  if (!mcpSecret) {
    return sendJson(res, 500, { error: 'Server misconfigured: missing MCP_SECRET' });
  }
  // Accepte X-MCP-Auth OU Authorization: Bearer (compat UI Dust si besoin)
  if ((xMcpAuth ?? bearer) !== mcpSecret) {
    return sendJson(res, 403, { error: 'Invalid or missing X-MCP-Auth token' }); // ⚠️ jamais 401
  }

  // 1) GET /sse : ouvre la session SSE (clé Airtable côté serveur)
  if (req.method === 'GET' && url.pathname === MCP_PATH) {
    const apiKey = process.env.AIRTABLE_API_KEY;
    if (!apiKey) {
      return sendJson(res, 500, { error: 'Server misconfigured: missing AIRTABLE_API_KEY' });
    }

    const airtableService = new AirtableService(apiKey);
    const server = new AirtableMCPServer(airtableService);

    // SDK actuel : 2 args (path, res) — mettra content-type: text/event-stream
    const transport = new SSEServerTransport(MCP_PATH, res);

    sessions.set(transport.sessionId, transport);
    await server.connect(transport);

    res.on('close', () => {
      sessions.delete(transport.sessionId);
    });
    return; // ne pas end(): SSE reste ouvert
  }

  // 2) POST /sse ou /messages : messages JSON-RPC vers la session ouverte
  if (req.method === 'POST' && (url.pathname === MCP_PATH || url.pathname === MESSAGES_PATH)) {
    const sessionId =
      url.searchParams.get('sessionId') ||
      (req.headers['x-mcp-session-id'] as string | undefined) ||
      (req.headers['x-session-id'] as string | undefined);

    if (!sessionId) {
      return sendJson(res, 400, { error: 'Missing sessionId' });
    }

    const transport = sessions.get(sessionId);
    if (!transport) {
      return sendJson(res, 404, { error: 'Session not found' });
    }

    return await transport.handlePostMessage(req, res);
  }

  // 3) 404 JSON pour le reste (Dust aime le JSON)
  return sendJson(res, 404, { error: 'Not found' });
}

export async function startHttpServer(config: { host?: string; port?: number }): Promise<http.Server> {
  const { host, port } = config;
  const httpServer = http.createServer();
  await new Promise<void>((resolve, reject) => {
    httpServer.on('error', reject);
    httpServer.listen(port, host, () => {
      httpServer.removeListener('error', reject);
      resolve();
    });
  });
  return httpServer;
}

export function httpAddressToString(address: string | AddressInfo | null): string {
  assert(address, 'Could not bind server socket');
  if (typeof address === 'string') return address;
  const resolvedPort = address.port;
  let resolvedHost = address.family === 'IPv4' ? address.address : `[${address.address}]`;
  if (resolvedHost === '0.0.0.0' || resolvedHost === '[::]') resolvedHost = 'localhost';
  return `http://${resolvedHost}:${resolvedPort}`;
}

export function startHttpTransport(httpServer: http.Server) {
  const sseSessions = new Map<string, SSEServerTransport>();

  httpServer.on('request', async (req, res) => {
    try {
      const url = new URL(`http://localhost${req.url ?? '/'}`);
      await handleRequest(req, res, url, sseSessions);
    } catch (err) {
      sendJson(res, 500, { error: 'Internal Server Error' });
      // eslint-disable-next-line no-console
      console.error('[transport] Unhandled error:', err);
    }
  });

  const baseUrl = httpAddressToString(httpServer.address());
  const message = [
    `Listening on ${baseUrl}`,
    'Put this in your client config:',
    JSON.stringify(
      {
        mcpServers: {
          airtable: {
            url: `${baseUrl}${MCP_PATH}`,
          },
        },
      },
      undefined,
      2
    ),
  ].join('\n');

  // eslint-disable-next-line no-console
  console.error(message);
}
