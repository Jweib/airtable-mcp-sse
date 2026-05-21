import {
  describe, test, expect, vi, beforeEach, afterEach,
} from 'vitest';
import type {
  JSONRPCMessage, JSONRPCRequest, JSONRPCResponse, Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { IAirtableService } from './types.js';
import { AirtableMCPServer } from './mcpServer.js';

const OFFICIAL_TOOL_NAMES = [
  'list_records_for_table',
  'search_records',
  'get_table_schema',
  'create_records_for_table',
  'update_records_for_table',
  'delete_records_for_table',
  'list_bases',
  'search_bases',
  'list_tables_for_base',
  'get_record',
  'create_table',
  'update_table',
  'create_field',
  'update_field',
];

describe('AirtableMCPServer', () => {
  let server: AirtableMCPServer;
  let mockAirtableService: IAirtableService;
  let serverTransport: InMemoryTransport;
  let clientTransport: InMemoryTransport;

  beforeEach(async () => {
    vi.clearAllMocks();

    mockAirtableService = {
      listBases: vi.fn().mockResolvedValue({
        bases: [
          { id: 'base1', name: 'Test Base', permissionLevel: 'create' },
        ],
      }),
      getBaseSchema: vi.fn().mockResolvedValue({
        tables: [
          {
            id: 'tbl1',
            name: 'Test Table',
            description: 'Test Description',
            fields: [{ id: 'fld1', name: 'Name', type: 'singleLineText' }],
            views: [],
            primaryFieldId: 'fld1',
          },
        ],
      }),
      listRecordsPage: vi.fn().mockResolvedValue({
        records: [
          {
            id: 'rec1',
            createdTime: '2026-01-01T00:00:00.000Z',
            fields: { Name: 'Test Record' },
          },
        ],
      }),
      getRecord: vi.fn().mockResolvedValue({
        id: 'rec1',
        fields: { Name: 'Test Record' },
      }),
      createRecordsPage: vi.fn().mockResolvedValue([
        {
          id: 'rec1',
          createdTime: '2026-01-01T00:00:00.000Z',
          fields: { Name: 'New Record' },
        },
      ]),
      updateRecordsPage: vi.fn().mockResolvedValue([
        {
          id: 'rec1',
          createdTime: '2026-01-01T00:00:00.000Z',
          fields: { Name: 'Updated Record' },
        },
      ]),
      deleteRecordsPage: vi.fn().mockResolvedValue([
        { id: 'rec1', deleted: true },
      ]),
      createTable: vi.fn().mockResolvedValue({
        id: 'tbl1',
        name: 'New Table',
        fields: [],
        views: [],
        primaryFieldId: 'fld1',
      }),
      updateTable: vi.fn().mockResolvedValue({
        id: 'tbl1',
        name: 'Updated Table',
        fields: [],
        views: [],
        primaryFieldId: 'fld1',
      }),
      createField: vi.fn().mockResolvedValue({
        id: 'fld1',
        name: 'New Field',
        type: 'singleLineText',
      }),
      updateField: vi.fn().mockResolvedValue({
        id: 'fld1',
        name: 'Updated Field',
        type: 'singleLineText',
      }),
    };

    server = new AirtableMCPServer(mockAirtableService);
    [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
  });

  const sendRequest = async (message: JSONRPCRequest): Promise<JSONRPCResponse> => {
    return new Promise((resolve) => {
      clientTransport.onmessage = (response: JSONRPCMessage) => {
        resolve(response as JSONRPCResponse);
      };

      clientTransport.send(message);
    });
  };

  describe('server functionality', () => {
    test('handles list_resources request', async () => {
      const response = await sendRequest({
        jsonrpc: '2.0',
        id: '1',
        method: 'resources/list',
        params: {},
      });

      expect(response.result).toEqual({
        resources: [{
          uri: 'airtable://base1/tbl1/schema',
          mimeType: 'application/json',
          name: 'Test Base: Test Table schema',
        }],
      });
    });

    test('handles read_resource request', async () => {
      const response = await sendRequest({
        jsonrpc: '2.0',
        id: '1',
        method: 'resources/read',
        params: {
          uri: 'airtable://base1/tbl1/schema',
        },
      });

      expect(response.result).toEqual({
        contents: [{
          uri: 'airtable://base1/tbl1/schema',
          mimeType: 'application/json',
          text: JSON.stringify({
            baseId: 'base1',
            tableId: 'tbl1',
            name: 'Test Table',
            description: 'Test Description',
            primaryFieldId: 'fld1',
            fields: [{ id: 'fld1', name: 'Name', type: 'singleLineText' }],
            views: [],
          }),
        }],
      });
    });

    test('exposes only official-aligned tools', async () => {
      const response = await sendRequest({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/list',
        params: {},
      });

      const toolNames = (response.result.tools as Tool[]).map((tool) => tool.name).sort();
      expect(toolNames).toEqual([...OFFICIAL_TOOL_NAMES].sort());
    });

    test('handles list_records_for_table tool call', async () => {
      const response = await sendRequest({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: {
          name: 'list_records_for_table',
          arguments: {
            baseId: 'appAAAAAAAAAAAAAA',
            tableId: 'tbl1',
            pageSize: 10,
          },
        },
      });

      expect(response.result).toEqual({
        content: [{
          type: 'text',
          mimeType: 'application/json',
          text: JSON.stringify({
            records: [{
              id: 'rec1',
              createdTime: '2026-01-01T00:00:00.000Z',
              cellValuesByFieldId: { fld1: 'Test Record' },
            }],
            metadata: { totalRecordCount: 1 },
          }),
        }],
        isError: false,
      });
    });
  });

  afterEach(async () => {
    await server.close();
  });
});
