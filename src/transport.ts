import http from 'node:http';
import type { AddressInfo } from 'node:net';
import assert from 'node:assert';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { AirtableMCPServer } from './mcpServer.js';
import { AirtableService } from './airtableService.js';

async function handleSSE(req: http.IncomingMessage, res: http.ServerResponse, url: URL, sessions: Map<string, SSEServerTransport>) {
  if (req.method === 'POST') {
    const sessionId = url.searchParams.get('sessionId');
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
  } else if (req.method === 'GET') {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.statusCode = 401;
      return res.end('Missing or invalid Authorization header. Expected: "Bearer <API_KEY>"');
    }
    const apiKey = authHeader.substring('Bearer '.length);

    const airtableService = new AirtableService(apiKey);
    const server = new AirtableMCPServer(airtableService);

    const transport = new SSEServerTransport('/sse', res);
    sessions.set(transport.sessionId, transport);
    await server.connect(transport);
    res.on('close', () => {
      sessions.delete(transport.sessionId);
    });
    return;
  }

  res.statusCode = 405;
  res.end('Method not allowed');
}

export async function startHttpServer(config: { host?: string, port?: number }): Promise<http.Server> {
  const { host, port } = config;
  const httpServer = http.createServer();
  await new Promise<void>((resolve, reject) => {
    httpServer.on('error', reject);
    httpServer.listen(port, host, () => {
      resolve();
      httpServer.removeListener('error', reject);
    });
  });
  return httpServer;
}

export function httpAddressToString(address: string | AddressInfo | null): string {
  assert(address, 'Could not bind server socket');
  if (typeof address === 'string')
    return address;
  const resolvedPort = address.port;
  let resolvedHost = address.family === 'IPv4' ? address.address : `[${address.address}]`;
  if (resolvedHost === '0.0.0.0' || resolvedHost === '[::]')
    resolvedHost = 'localhost';
  return `http://${resolvedHost}:${resolvedPort}`;
}

export function startHttpTransport(httpServer: http.Server) {
  const sseSessions = new Map<string, SSEServerTransport>();
  httpServer.on('request', async (req, res) => {
    const url = new URL(`http://localhost${req.url}`);
    await handleSSE(req, res, url, sseSessions);
  });
  const url = httpAddressToString(httpServer.address());
  const message = [
    `Listening on ${url}`,
    'Put this in your client config:',
    JSON.stringify({
      'mcpServers': {
        'airtable': {
          'url': `${url}/sse`
        }
      }
    }, undefined, 2),
  ].join('\n');
    // eslint-disable-next-line no-console
  console.error(message);
}
