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
  // CORS permissif (utile si Dust fait des préflights)
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

  // 0) Bloque toute découverte OIDC (peut arriver même sous /sse)
  if (url.pathname.includes('/.well-known')) {
    res.statusCode = 404;
    return res.end('Not found');
  }

  // 0-bis) OPTIONS neutre (évite 404/405 qui déclenchent la validation Dust)
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  // 0-ter) Liveness root SANS AUTH (Dust "Automatic" fait GET /)
  if (url.pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    res.statusCode = 200;
    return res.end('Airtable MCP SSE server is up');
  }

  // === À partir d’ici : endpoints protégés → vérif du token persisté ===
  const mcpSecret = process.env.MCP_SECRET;
  const xMcpAuth = req.headers['x-mcp-auth'] as string | undefined;
  const authHeader = req.headers.authorization;
  const bearer = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;

  if (!mcpSecret) {
    res.statusCode = 500;
    return res.end('Server misconfigured: missing MCP_SECRET');
  }
  // Accepte X-MCP-Auth OU Authorization: Bearer (compat UI Dust si besoin)
  if ((xMcpAuth ?? bearer) !== mcpSecret) {
    res.statusCode = 403; // ⚠️ ne jamais renvoyer 401 pour éviter le flow OAuth Dust
    return res.end('Invalid or missing X-MCP-Auth token');
  }

  // 1) GET /sse : ouvre la session SSE
  if (req.method === 'GET' && url.pathname === MCP_PATH) {
    // Clé Airtable côté serveur (Railway), pas depuis Dust
    const apiKey = process.env.AIRTABLE_API_KEY;
    if (!apiKey) {
      res.statusCode = 500;
      return res.end('Server misconfigured: missing AIRTABLE_API_KEY');
    }

    const airtableService = new AirtableService(apiKey);
    const server = new AirtableMCPServer(airtableService);

    // SDK actuel : 2 arguments (path, res)
    const transport = new SSEServerTransport(MCP_PATH, res);

    // Enregistre la session tant que le flux est ouvert
    sessions.set(transport.sessionId, transport);
    await server.connect(transport);

    // Nettoyage à la fermeture de la socket SSE
    res.on('close', () => {
      sessions.delete(transport.sessionId);
    });

    // Ne pas appeler res.end() : le flux SSE reste ouvert
    return;
  }

  // 2) POST /sse ou /messages : envoi d'un message JSON-RPC vers la session
  if (req.method === 'POST' && (url.pathname === MCP_PATH || url.pathname === MESSAGES_PATH)) {
    const sessionId =
      url.searchParams.get('sessionId') ||
      (req.headers['x-mcp-session-id'] as string | undefined) ||
      (req.headers['x-session-id'] as string | undefined);

    if (!sessionId) {
      res.statusCode = 400;
      return res.end('Missing sessionId');
    }

    const transport = sessions.get(sessionId);
    if (!transport) {
      res.statusCode = 404;
      return res.end('Session not found');
    }

    return await transport.handlePostMessage(req, res);
  }

  // 3) Toute autre route → 404
  res.statusCode = 404;
  res.end('Not found');
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
      res.end('Internal Server Error');
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
