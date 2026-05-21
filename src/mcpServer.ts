import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  CallToolResult,
  ListToolsResult,
  ReadResourceResult,
  ListResourcesResult,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  ListRecordsForTableArgsSchema,
  GetTableSchemaArgsSchema,
  GetRecordArgsSchema,
  CreateRecordsForTableArgsSchema,
  UpdateRecordsForTableArgsSchema,
  DeleteRecordsForTableArgsSchema,
  CreateTableArgsSchema,
  UpdateTableArgsSchema,
  CreateFieldArgsSchema,
  UpdateFieldArgsSchema,
  SearchRecordsArgsSchema,
  ListBasesArgsSchema,
  SearchBasesArgsSchema,
  ListTablesForBaseArgsSchema,
  IAirtableService,
  IAirtableMCPServer,
} from './types.js';
import { listRecordsForTable } from './tools/listRecordsForTable.js';
import { searchRecords } from './tools/searchRecords.js';
import { createRecordsForTable } from './tools/createRecordsForTable.js';
import { updateRecordsForTable } from './tools/updateRecordsForTable.js';
import { deleteRecordsForTable } from './tools/deleteRecordsForTable.js';
import { getTableSchema } from './tools/getTableSchema.js';
import { listBases } from './tools/listBases.js';
import { searchBases } from './tools/searchBases.js';
import { listTablesForBase } from './tools/listTablesForBase.js';

const getInputSchema = (schema: z.ZodType<object>): ListToolsResult['tools'][0]['inputSchema'] => {
  const jsonSchema = zodToJsonSchema(schema);
  if (!('type' in jsonSchema) || jsonSchema.type !== 'object') {
    throw new Error(`Invalid input schema to convert in airtable-mcp-server: expected an object but got ${'type' in jsonSchema ? jsonSchema.type : 'no type'}`);
  }
  return { ...jsonSchema, type: 'object' };
};

const formatToolResponse = (data: unknown, isError = false): CallToolResult => {
  return {
    content: [{
      type: 'text',
      mimeType: 'application/json',
      text: JSON.stringify(data),
    }],
    isError,
  };
};

export class AirtableMCPServer implements IAirtableMCPServer {
  private server: Server;

  private airtableService: IAirtableService;

  private readonly SCHEMA_PATH = 'schema';

  constructor(airtableService: IAirtableService) {
    this.airtableService = airtableService;
    this.server = new Server(
      {
        name: 'airtable-mcp-server',
        version: '2.0.0',
      },
      {
        capabilities: {
          resources: {},
          tools: {},
        },
      },
    );
    this.initializeHandlers();
  }

  private initializeHandlers(): void {
    this.server.setRequestHandler(ListResourcesRequestSchema, this.handleListResources.bind(this));
    this.server.setRequestHandler(ReadResourceRequestSchema, this.handleReadResource.bind(this));
    this.server.setRequestHandler(ListToolsRequestSchema, this.handleListTools.bind(this));
    this.server.setRequestHandler(CallToolRequestSchema, this.handleCallTool.bind(this));
  }

  private async handleListResources(): Promise<ListResourcesResult> {
    const { bases } = await this.airtableService.listBases();
    const resources = await Promise.all(bases.map(async (base) => {
      const schema = await this.airtableService.getBaseSchema(base.id);
      return schema.tables.map((table) => ({
        uri: `airtable://${base.id}/${table.id}/${this.SCHEMA_PATH}`,
        mimeType: 'application/json',
        name: `${base.name}: ${table.name} schema`,
      }));
    }));

    return {
      resources: resources.flat(),
    };
  }

  private async handleReadResource(request: z.infer<typeof ReadResourceRequestSchema>): Promise<ReadResourceResult> {
    const { uri } = request.params;
    const match = uri.match(/^airtable:\/\/([^/]+)\/([^/]+)\/schema$/);

    if (!match || !match[1] || !match[2]) {
      throw new Error('Invalid resource URI');
    }

    const [, baseId, tableId] = match;
    const schema = await this.airtableService.getBaseSchema(baseId);
    const table = schema.tables.find((t) => t.id === tableId);

    if (!table) {
      throw new Error(`Table ${tableId} not found in base ${baseId}`);
    }

    return {
      contents: [
        {
          uri: request.params.uri,
          mimeType: 'application/json',
          text: JSON.stringify({
            baseId,
            tableId: table.id,
            name: table.name,
            description: table.description,
            primaryFieldId: table.primaryFieldId,
            fields: table.fields,
            views: table.views,
          }),
        },
      ],
    };
  }

  // eslint-disable-next-line class-methods-use-this
  private async handleListTools(): Promise<ListToolsResult> {
    return {
      tools: [
        {
          name: 'list_records_for_table',
          description: 'List records from a table (official MCP-aligned format)',
          inputSchema: getInputSchema(ListRecordsForTableArgsSchema),
        },
        {
          name: 'search_records',
          description: 'Search records in a table by text query (official MCP-aligned format)',
          inputSchema: getInputSchema(SearchRecordsArgsSchema),
        },
        {
          name: 'get_table_schema',
          description: 'Get the full schema for a specific table (official MCP-aligned format)',
          inputSchema: getInputSchema(GetTableSchemaArgsSchema),
        },
        {
          name: 'create_records_for_table',
          description: 'Create up to 50 records in a table (official MCP-aligned format)',
          inputSchema: getInputSchema(CreateRecordsForTableArgsSchema),
        },
        {
          name: 'update_records_for_table',
          description: 'Update up to 50 records in a table (official MCP-aligned format)',
          inputSchema: getInputSchema(UpdateRecordsForTableArgsSchema),
        },
        {
          name: 'delete_records_for_table',
          description: 'Delete up to 50 records from a table (official MCP-aligned format)',
          inputSchema: getInputSchema(DeleteRecordsForTableArgsSchema),
        },
        {
          name: 'list_bases',
          description: 'List all accessible Airtable bases (official MCP-aligned format)',
          inputSchema: getInputSchema(ListBasesArgsSchema),
        },
        {
          name: 'search_bases',
          description: 'Search accessible bases by name (official MCP-aligned format)',
          inputSchema: getInputSchema(SearchBasesArgsSchema),
        },
        {
          name: 'list_tables_for_base',
          description: 'List table identifiers in a base (official MCP-aligned compact format)',
          inputSchema: getInputSchema(ListTablesForBaseArgsSchema),
        },
        {
          name: 'get_record',
          description: 'Get a specific record by ID',
          inputSchema: getInputSchema(GetRecordArgsSchema),
        },
        {
          name: 'create_table',
          description: 'Create a new table in a base',
          inputSchema: getInputSchema(CreateTableArgsSchema),
        },
        {
          name: 'update_table',
          description: 'Update a table\'s name or description',
          inputSchema: getInputSchema(UpdateTableArgsSchema),
        },
        {
          name: 'create_field',
          description: 'Create a new field in a table',
          inputSchema: getInputSchema(CreateFieldArgsSchema),
        },
        {
          name: 'update_field',
          description: 'Update a field\'s name or description',
          inputSchema: getInputSchema(UpdateFieldArgsSchema),
        },
      ],
    };
  }

  private async handleCallTool(request: z.infer<typeof CallToolRequestSchema>): Promise<CallToolResult> {
    try {
      switch (request.params.name) {
        case 'list_records_for_table': {
          const args = ListRecordsForTableArgsSchema.parse(request.params.arguments);
          const result = await listRecordsForTable(this.airtableService, {
            baseId: args.baseId,
            tableId: args.tableId,
            pageSize: args.pageSize ?? 1000,
            ...(args.cursor !== undefined ? { cursor: args.cursor } : {}),
            ...(args.fieldIds !== undefined ? { fieldIds: args.fieldIds } : {}),
            ...(args.sort !== undefined ? {
              sort: args.sort.map((sortOption) => ({
                fieldId: sortOption.fieldId,
                ...(sortOption.direction !== undefined ? { direction: sortOption.direction } : {}),
              })),
            } : {}),
            ...(args.recordIds !== undefined ? { recordIds: args.recordIds } : {}),
            ...(args.filters !== undefined ? { filters: args.filters } : {}),
          });
          return formatToolResponse(result);
        }

        case 'search_records': {
          const args = SearchRecordsArgsSchema.parse(request.params.arguments);
          const result = await searchRecords(this.airtableService, {
            baseId: args.baseId,
            table: args.table,
            query: args.query,
            fields: args.fields,
            ...(args.pageSize !== undefined ? { pageSize: args.pageSize } : {}),
            ...(args.cursor !== undefined ? { cursor: args.cursor } : {}),
          });
          return formatToolResponse(result);
        }

        case 'get_table_schema': {
          const args = GetTableSchemaArgsSchema.parse(request.params.arguments);
          const result = await getTableSchema(this.airtableService, args);
          return formatToolResponse(result);
        }

        case 'list_bases': {
          ListBasesArgsSchema.parse(request.params.arguments ?? {});
          const result = await listBases(this.airtableService);
          return formatToolResponse(result);
        }

        case 'search_bases': {
          const args = SearchBasesArgsSchema.parse(request.params.arguments);
          const result = await searchBases(this.airtableService, { query: args.query });
          return formatToolResponse(result);
        }

        case 'list_tables_for_base': {
          const args = ListTablesForBaseArgsSchema.parse(request.params.arguments);
          const result = await listTablesForBase(this.airtableService, { baseId: args.baseId });
          return formatToolResponse(result);
        }

        case 'get_record': {
          const args = GetRecordArgsSchema.parse(request.params.arguments);
          const record = await this.airtableService.getRecord(args.baseId, args.tableId, args.recordId);
          return formatToolResponse({
            id: record.id,
            fields: record.fields,
          });
        }

        case 'create_records_for_table': {
          const args = CreateRecordsForTableArgsSchema.parse(request.params.arguments);
          const result = await createRecordsForTable(this.airtableService, {
            baseId: args.baseId,
            tableId: args.tableId,
            records: args.records,
          });
          return formatToolResponse(result);
        }

        case 'update_records_for_table': {
          const args = UpdateRecordsForTableArgsSchema.parse(request.params.arguments);
          const result = await updateRecordsForTable(this.airtableService, {
            baseId: args.baseId,
            tableId: args.tableId,
            records: args.records,
          });
          return formatToolResponse(result);
        }

        case 'delete_records_for_table': {
          const args = DeleteRecordsForTableArgsSchema.parse(request.params.arguments);
          const result = await deleteRecordsForTable(this.airtableService, {
            baseId: args.baseId,
            tableId: args.tableId,
            recordIds: args.recordIds,
          });
          return formatToolResponse(result);
        }

        case 'create_table': {
          const args = CreateTableArgsSchema.parse(request.params.arguments);
          const table = await this.airtableService.createTable(
            args.baseId,
            args.name,
            args.fields,
            args.description,
          );
          return formatToolResponse(table);
        }

        case 'update_table': {
          const args = UpdateTableArgsSchema.parse(request.params.arguments);
          const table = await this.airtableService.updateTable(
            args.baseId,
            args.tableId,
            { name: args.name, description: args.description },
          );
          return formatToolResponse(table);
        }

        case 'create_field': {
          const args = CreateFieldArgsSchema.parse(request.params.arguments);
          const field = await this.airtableService.createField(
            args.baseId,
            args.tableId,
            args.nested.field,
          );
          return formatToolResponse(field);
        }

        case 'update_field': {
          const args = UpdateFieldArgsSchema.parse(request.params.arguments);
          const field = await this.airtableService.updateField(
            args.baseId,
            args.tableId,
            args.fieldId,
            {
              name: args.name,
              description: args.description,
            },
          );
          return formatToolResponse(field);
        }

        default: {
          throw new Error(`Unknown tool: ${request.params.name}`);
        }
      }
    } catch (error) {
      return formatToolResponse(
        `Error in tool ${request.params.name}: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
  }

  async connect(transport: Transport): Promise<void> {
    await this.server.connect(transport);
  }

  async close(): Promise<void> {
    await this.server.close();
  }
}
