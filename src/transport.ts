import http from 'node:http';
import type { AddressInfo } from 'node:net';
import assert from 'node:assert';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { AirtableMCPServer } from './mcpServer.js';
import { AirtableService } from './airtableService.js';

const MCP_PATH = '/sse';
const MESSAGES_PATH = '/messages';

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  sessions: Map<string, SSEServerTransport>
) {
  // 1) Bloque toute découverte OIDC (Dust s’y essaie si 401 est vu quelque part)
  if (url.pathname.startsWith('/.well-known')) {
    res.statusCode = 404;
    return res.end('Not found');
  }

  // 2) Auth persistante côté Dust → MCP via X-MCP-Auth
  const mcpSecret = process.env.MCP_SECRET;
  const xMcpAuth = req.headers['x-mcp-auth'];
  if (!mcpSecret) {
    res.statusCode = 500;
    return res.end('Server misconfigured: missing MCP_SECRET');
  }
  if (!xMcpAuth || xMcpAuth !== mcpSecret) {
    res.statusCode = 403;
    return res.end('Invalid or missing X-MCP-Auth token');
  }

  // 3) Routage SSE classique (GET /sse + POST /messages?sessionId=...)
  if (req.method === 'GET' && url.pathname === MCP_PATH) {
    // 🔑 La clé Airtable vient de l’ENV serveur (Railway) — pas du header Authorization
    const apiKey = process.env.AIRTABLE_API_KEY;
    if (!apiKey) {
      res.statusCode = 500;
      return res.end('Server misconfigured: missing AIRTABLE_API_KEY');
    }

    const airtableService = new AirtableService(apiKey);
    const server = new AirtableMCPServer(airtableService);

    // ✅ Construction correcte du transport SSE (path + req + res)
    const transport = new SSEServerTransport(MCP_PATH, res);

    // Enregistre la session tant que la connexion SSE est ouverte
    sessions.set(transport.sessionId, transport);

    // Connexion du serveur MCP au transport
    await server.connect(transport);

    // Nettoyage à la fermeture de la socket SSE
    res.on('close', () => {
      sessions.delete(transport.sessionId);
    });

    // Ne pas appeler res.end() ici : SSE garde le flux ouvert
    return;
  }

  if (req.method === 'POST' && (url.pathname === MESSAGES_PATH || url.pathname === MCP_PATH)) {
  // 1) Récupère le sessionId (query ou header)
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

  // 2) Laisse le SDK lire le body et router le message
  return await transport.handlePostMessage(req, res);
}

  // 4) Toute autre route → 404
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
      const url = new URL(`http://localhost${req.url}`);
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
