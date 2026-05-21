import {
  describe, test, expect, beforeEach, afterEach,
} from 'vitest';
import type {
  CallToolResult,
  JSONRPCMessage,
  JSONRPCRequest,
  JSONRPCResponse,
  ListResourcesResult,
  ListToolsResult,
  ReadResourceResult,
} from '@modelcontextprotocol/sdk/types.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AirtableMCPServer } from './mcpServer.js';
import { AirtableService } from './airtableService.js';

// Run me with:
// AIRTABLE_API_KEY=pat1234.abcd RUN_INTEGRATION=TRUE npm run test -- 'src/e2e.test.ts'
const parseListBasesToolResult = (text: string): Array<{ id: string; name: string; permissionLevel: string }> => {
  const parsed = JSON.parse(text) as { bases?: Array<{ id: string; name: string; permissionLevel: string }> };
  return parsed.bases ?? [];
};

const parseListTablesForBaseResult = (text: string): Array<{ id: string; name: string; primaryFieldId: string }> => {
  const parsed = JSON.parse(text) as { tables?: Array<{ id: string; name: string; primaryFieldId: string }> };
  return parsed.tables ?? [];
};

(process.env.RUN_INTEGRATION ? describe : describe.skip)('AirtableMCPServer Integration', () => {
  let server: AirtableMCPServer;
  let serverTransport: InMemoryTransport;
  let clientTransport: InMemoryTransport;

  beforeEach(async () => {
    const apiKey = process.env.AIRTABLE_API_KEY;
    if (!apiKey) {
      throw new Error('AIRTABLE_API_KEY environment variable is required for integration tests');
    }

    const airtableService = new AirtableService(apiKey);
    server = new AirtableMCPServer(airtableService);
    [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
  });

  const sendRequest = async <T>(message: JSONRPCRequest): Promise<T> => {
    return new Promise((resolve, reject) => {
      // Set up response handler
      clientTransport.onmessage = (response: JSONRPCMessage) => {
        const typedResponse = response as JSONRPCResponse;
        if ('result' in typedResponse) {
          resolve(typedResponse.result as T);
          return;
        }
        reject(new Error('No result in response'));
      };

      clientTransport.send(message);
    });
  };

  test('should list available tools', async () => {
    const result = await sendRequest<ListToolsResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/list',
      params: {},
    });

    expect(result.tools.map((t) => t.name).sort()).toEqual([
      'create_field',
      'create_records_for_table',
      'create_table',
      'delete_records_for_table',
      'get_record',
      'get_table_schema',
      'list_bases',
      'list_records_for_table',
      'list_tables_for_base',
      'search_bases',
      'search_records',
      'update_field',
      'update_records_for_table',
      'update_table',
    ]);
    expect(result.tools.find((t) => t.name === 'list_records_for_table')).toMatchObject({
      description: expect.any(String),
      inputSchema: expect.objectContaining({
        type: 'object',
      }),
    });
  });

  test('should list bases', async () => {
    const result = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: {
        name: 'list_bases',
        arguments: {},
      },
    });

    expect(result).toMatchObject({
      content: [{
        type: 'text',
        mimeType: 'application/json',
        text: expect.any(String),
      }],
      isError: false,
    });

    const content = JSON.parse(result.content[0]!.text as string);
    expect(content).toHaveProperty('bases');
    expect(Array.isArray(content.bases)).toBe(true);
    expect(content.bases.length).toBeGreaterThan(0);
    expect(content.bases[0]).toMatchObject({
      id: expect.any(String),
      name: expect.any(String),
      permissionLevel: expect.any(String),
    });
  });

  test('should list tables in a base', async () => {
    // First get a base ID
    const basesResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: {
        name: 'list_bases',
        arguments: {},
      },
    });

    const bases = parseListBasesToolResult(basesResult.content[0]!.text as string);
    expect(bases.length).toBeGreaterThan(0);
    const baseId = bases[0]!.id;

    // Then list tables
    const result = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '2',
      method: 'tools/call',
      params: {
        name: 'list_tables_for_base',
        arguments: {
          baseId,
        },
      },
    });

    expect(result).toMatchObject({
      content: [{
        type: 'text',
        mimeType: 'application/json',
        text: expect.any(String),
      }],
      isError: false,
    });

    const tables = parseListTablesForBaseResult(result.content[0]!.text as string);
    if (tables.length > 0) {
      expect(tables[0]).toMatchObject({
        id: expect.any(String),
        name: expect.any(String),
        primaryFieldId: expect.any(String),
      });
    }
  });

  test('should list records in a table', async () => {
    // First get a base ID
    const basesResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: {
        name: 'list_bases',
        arguments: {},
      },
    });

    const bases = parseListBasesToolResult(basesResult.content[0]!.text as string);
    expect(bases.length).toBeGreaterThan(0);
    const baseId = bases[0]!.id;

    // Then get a table ID
    const tablesResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '2',
      method: 'tools/call',
      params: {
        name: 'list_tables_for_base',
        arguments: {
          baseId,
        },
      },
    });

    const tables = parseListTablesForBaseResult(tablesResult.content[0]!.text as string);
    if (tables.length === 0) {
      // eslint-disable-next-line no-console
      console.warn('Skipping list_records_for_table test as no tables found');
      return;
    }
    const tableId = tables[0]!.id;

    const result = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '3',
      method: 'tools/call',
      params: {
        name: 'list_records_for_table',
        arguments: {
          baseId,
          tableId,
          pageSize: 10,
        },
      },
    });

    expect(result).toMatchObject({
      content: [{
        type: 'text',
        mimeType: 'application/json',
        text: expect.any(String),
      }],
      isError: false,
    });

    const content = JSON.parse(result.content[0]!.text as string);
    expect(content).toHaveProperty('records');
    expect(Array.isArray(content.records)).toBe(true);
    if (content.records.length > 0) {
      expect(content.records[0]).toMatchObject({
        id: expect.any(String),
        cellValuesByFieldId: expect.any(Object),
      });
    }
  });

  test('should search records with view filtering', async () => {
    // First get a base ID
    const basesResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: {
        name: 'list_bases',
        arguments: {},
      },
    });

    const bases = parseListBasesToolResult(basesResult.content[0]!.text as string);
    expect(bases.length).toBeGreaterThan(0);
    const baseId = bases[0]!.id;

    const tablesResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '2',
      method: 'tools/call',
      params: {
        name: 'list_tables_for_base',
        arguments: { baseId },
      },
    });

    const tables = parseListTablesForBaseResult(tablesResult.content[0]!.text as string);
    if (tables.length === 0) {
      // eslint-disable-next-line no-console
      console.warn('Skipping search_records test as no tables found');
      return;
    }

    const tableId = tables[0]!.id;

    const schemaResult = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '2b',
      method: 'tools/call',
      params: {
        name: 'get_table_schema',
        arguments: { baseId, tableId },
      },
    });

    const tableSchema = JSON.parse(schemaResult.content[0]!.text as string);
    const textField = tableSchema.fields?.find(
      (field: { type: string }) => field.type === 'singleLineText'
        || field.type === 'multilineText',
    );
    if (!textField) {
      // eslint-disable-next-line no-console
      console.warn('Skipping search_records test: no text field found');
      return;
    }

    const result = await sendRequest<CallToolResult>({
      jsonrpc: '2.0',
      id: '3',
      method: 'tools/call',
      params: {
        name: 'search_records',
        arguments: {
          baseId,
          table: tableId,
          query: 'a',
          fields: [textField.id],
          pageSize: 10,
        },
      },
    });

    expect(result).toMatchObject({
      content: [{
        type: 'text',
        mimeType: 'application/json',
        text: expect.any(String),
      }],
      isError: false,
    });

    const content = JSON.parse(result.content[0]!.text as string);
    expect(content).toHaveProperty('records');
    expect(Array.isArray(content.records)).toBe(true);
    // Records might be empty if no matches or if the view has filters that exclude all records
  });

  test('should list and read resources', async () => {
    // First list resources
    const listResult = await sendRequest<ListResourcesResult>({
      jsonrpc: '2.0',
      id: '1',
      method: 'resources/list',
      params: {},
    });

    expect(listResult).toMatchObject({
      resources: expect.any(Array),
    });

    if (listResult.resources.length === 0) {
      // eslint-disable-next-line no-console
      console.warn('Skipping resource read test as no resources found');
      return;
    }

    // Then read the first resource
    const resource = listResult.resources[0]!;
    const readResult = await sendRequest<ReadResourceResult>({
      jsonrpc: '2.0',
      id: '2',
      method: 'resources/read',
      params: {
        uri: resource.uri,
      },
    });

    expect(readResult).toMatchObject({
      contents: [{
        uri: resource.uri,
        mimeType: 'application/json',
        text: expect.any(String),
      }],
    });

    const content = JSON.parse(readResult.contents[0]!.text as string);

    expect(content).toMatchObject({
      baseId: expect.any(String),
      tableId: expect.any(String),
      name: expect.any(String),
      fields: expect.any(Array),
    });
  });

  afterEach(async () => {
    await server.close();
  });
});
