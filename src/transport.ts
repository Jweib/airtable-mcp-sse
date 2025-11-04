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

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  sessions: Map<string, SSEServerTransport>
) {
  setCommonHeaders(res);

  // 0) Bloque toute découverte OIDC (où qu’elle apparaisse)
  if (url.pathname.includes('/.well-known')) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ error: 'Not found' }));
  }

  // 0-bis) Préflights neutres
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  // 0-ter) Healthcheck ROOT SANS AUTH — Content-Type JSON (Dust l’attend)
  if (url.pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
      ok: true,
      service: 'airtable-mcp-sse',
      transport: 'sse',
      endpoints: { sse: MCP_PATH, messages: MESSAGES_PATH }
    }));
  }

  // === À partir d’ici : endpoints protégés ===
  const mcpSecret = process.env.MCP_SECRET;
  const xMcpAuth = req.headers['x-mcp-auth'] as string | undefined;
  const authHeader = req.headers.authorization;
  const bearer = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;

  if (!mcpSecret) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ error: 'Server misconfigured: missing MCP_SECRET' }));
  }
  // Accepte X-MCP-Auth OU Authorization: Bearer (compat UI Dust)
  if ((xMcpAuth ?? bearer) !== mcpSecret) {
    res.statusCode = 403; // ne JAMAIS renvoyer 401 pour éviter un flow OAuth
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ error: 'Invalid or missing X-MCP-Auth token' }));
  }

  // 1) GET /sse : ouvre la session SSE
  if (req.method === 'GET' && url.pathname === MCP_PATH) {
    const apiKey = process.env.AIRTABLE_API_KEY;
    if (!apiKey) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ error: 'Server misconfigured: missing AIRTABLE_API_KEY' }));
    }

    const airtableService = new AirtableService(apiKey);
    const server = new AirtableMCPServer(airtableService);

    // SDK actuel : (path, res) → il posera Content-Type: text/event-stream lui-même
    const transport = new SSEServerTransport(MCP_PATH, res);

    sessions.set(transport.sessionId, transport);
    await server.connect(transport);

    res.on('close', () => {
      sessions.delete(transport.sessionId);
    });
    return; // ne pas res.end(): SSE reste ouvert
  }

  // 2) POST /sse ou /messages : message JSON-RPC
  if (req.method === 'POST' && (url.pathname === MCP_PATH || url.pathname === MESSAGES_PATH)) {
    const sessionId =
      url.searchParams.get('sessionId') ||
      (req.headers['x-mcp-session-id'] as string | undefined) ||
      (req.headers['x-session-id'] as string | undefined);

    if (!sessionId) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ error: 'Missing sessionId' }));
    }

    const transport = sessions.get(sessionId);
    if (!transport) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ error: 'Session not found' }));
    }

    return await transport.handlePostMessage(req, res);
  }

  // 3) 404 JSON pour le reste (évite le "Unexpected content type")
  res.statusCode = 404;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error: 'Not found' }));
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
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Internal Server Error' }));
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
