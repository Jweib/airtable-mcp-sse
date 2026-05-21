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
  ListRecordsArgsSchema,
  ListRecordsForTableArgsSchema,
  GetTableSchemaArgsSchema,
  ListTablesArgsSchema,
  DescribeTableArgsSchema,
  GetRecordArgsSchema,
  CreateRecordArgsSchema,
  CreateRecordsForTableArgsSchema,
  UpdateRecordsArgsSchema,
  DeleteRecordsArgsSchema,
  CreateTableArgsSchema,
  UpdateTableArgsSchema,
  CreateFieldArgsSchema,
  UpdateFieldArgsSchema,
  SearchRecordsArgsSchema,
  DescribeBaseArgsSchema,
  DescribeAllBasesArgsSchema,
  Table,
  TableDetailLevelSchema,
  IAirtableService,
  IAirtableMCPServer,
} from './types.js';
import { listRecordsForTable } from './tools/listRecordsForTable.js';
import { searchRecords } from './tools/searchRecords.js';
import { createRecordsForTable } from './tools/createRecordsForTable.js';
import { getTableSchema } from './tools/getTableSchema.js';

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

const formatTableDetails = (table: Table, detailLevel: z.infer<typeof TableDetailLevelSchema>) => {
  switch (detailLevel) {
    case 'tableIdentifiersOnly':
      return {
        id: table.id,
        name: table.name,
      };
    case 'identifiersOnly':
      return {
        id: table.id,
        name: table.name,
        fields: table.fields.map((field: { id: string; name: string; }) => ({
          id: field.id,
          name: field.name,
        })),
        views: table.views.map((view: { id: string; name: string; }) => ({
          id: view.id,
          name: view.name,
        })),
      };
    case 'full':
    default:
      return {
        id: table.id,
        name: table.name,
        description: table.description,
        fields: table.fields,
        views: table.views,
      };
  }
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
        version: '0.1.0',
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
          name: 'list_records',
          description: 'List records from a table',
          inputSchema: getInputSchema(ListRecordsArgsSchema),
        },
        {
          name: 'list_records_for_table',
          description: 'List records from a table (official MCP-aligned format)',
          inputSchema: getInputSchema(ListRecordsForTableArgsSchema),
        },
        {
          name: 'search_records',
          description: 'Search for records containing specific text',
          inputSchema: getInputSchema(SearchRecordsArgsSchema),
        },
        {
          name: 'list_bases',
          description: 'List all accessible Airtable bases',
          inputSchema: {
            type: 'object',
            properties: {},
            required: [],
          },
        },
        {
          name: 'describe_base',
          description: 'Get a complete schema for a specific base, including all its tables, fields, views and information such as colunm descriptions or allowed field types',
          inputSchema: getInputSchema(DescribeBaseArgsSchema),
        },
        {
          name: 'describe_all_bases',
          description: 'Get a complete schema for all accessible bases and their tables. This includes all tables, fields, views, and information such as column descriptions or allowed field types.',
          inputSchema: getInputSchema(DescribeAllBasesArgsSchema),
        },
        {
          name: 'list_tables',
          description: 'List all tables in a specific base',
          inputSchema: getInputSchema(ListTablesArgsSchema),
        },
        {
          name: 'describe_table',
          description: 'Get detailed information about a specific table',
          inputSchema: getInputSchema(DescribeTableArgsSchema),
        },
        {
          name: 'get_table_schema',
          description: 'Get the full schema for a specific table (official MCP-aligned format)',
          inputSchema: getInputSchema(GetTableSchemaArgsSchema),
        },
        {
          name: 'get_record',
          description: 'Get a specific record by ID',
          inputSchema: getInputSchema(GetRecordArgsSchema),
        },
        {
          name: 'create_record',
          description: 'Create a new record in a table',
          inputSchema: getInputSchema(CreateRecordArgsSchema),
        },
        {
          name: 'create_records_for_table',
          description: 'Create up to 50 records in a table (official MCP-aligned format)',
          inputSchema: getInputSchema(CreateRecordsForTableArgsSchema),
        },
        {
          name: 'update_records',
          description: 'Update up to 10 records in a table',
          inputSchema: getInputSchema(UpdateRecordsArgsSchema),
        },
        {
          name: 'delete_records',
          description: 'Delete records from a table',
          inputSchema: getInputSchema(DeleteRecordsArgsSchema),
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
        case 'list_records': {
          const args = ListRecordsArgsSchema.parse(request.params.arguments);
          const records = await this.airtableService.listRecords(
            args.baseId,
            args.tableId,
            {
              view: args.view,
              maxRecords: args.maxRecords,
              filterByFormula: args.filterByFormula,
              sort: args.sort,
            },
          );
          return formatToolResponse(records);
        }

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

        case 'list_bases': {
          const { bases } = await this.airtableService.listBases();
          return formatToolResponse(bases.map((base) => ({
            id: base.id,
            name: base.name,
            permissionLevel: base.permissionLevel,
          })));
        }

        case 'describe_base': {
          const args = DescribeBaseArgsSchema.parse(request.params.arguments);
          const base = await this.airtableService.describeBase(args.baseId);
          return formatToolResponse(base);
        }

        case 'describe_all_bases': {
          const bases = await this.airtableService.describeAllBases();
          return formatToolResponse(bases);
        }

        case 'list_tables': {
          const args = ListTablesArgsSchema.parse(request.params.arguments);
          const schema = await this.airtableService.getBaseSchema(args.baseId);
          return formatToolResponse(schema.tables.map((table) => {
            switch (args.detailLevel) {
              case 'tableIdentifiersOnly':
                return {
                  id: table.id,
                  name: table.name,
                };
              case 'identifiersOnly':
                return {
                  id: table.id,
                  name: table.name,
                  fields: table.fields.map((field) => ({
                    id: field.id,
                    name: field.name,
                  })),
                  views: table.views.map((view) => ({
                    id: view.id,
                    name: view.name,
                  })),
                };
              case 'full':
              default:
                return {
                  id: table.id,
                  name: table.name,
                  description: table.description,
                  fields: table.fields,
                  views: table.views,
                };
            }
          }));
        }

        case 'get_table_schema': {
          const args = GetTableSchemaArgsSchema.parse(request.params.arguments);
          const result = await getTableSchema(this.airtableService, args);
          return formatToolResponse(result);
        }

        case 'describe_table': {
          const args = DescribeTableArgsSchema.parse(request.params.arguments);
          const schema = await this.airtableService.getBaseSchema(args.baseId);
          const table = schema.tables.find((t) => t.id === args.tableId);

          if (!table) {
            return formatToolResponse(`Table ${args.tableId} not found in base ${args.baseId}`, true);
          }

          switch (args.detailLevel) {
            case 'tableIdentifiersOnly':
              return formatToolResponse({
                id: table.id,
                name: table.name,
              });
            case 'identifiersOnly':
              return formatToolResponse({
                id: table.id,
                name: table.name,
                fields: table.fields.map((field) => ({
                  id: field.id,
                  name: field.name,
                })),
                views: table.views.map((view) => ({
                  id: view.id,
                  name: view.name,
                })),
              });
            case 'full':
            default:
              return formatToolResponse({
                id: table.id,
                name: table.name,
                description: table.description,
                fields: table.fields,
                views: table.views,
              });
          }
        }

        case 'get_record': {
          const args = GetRecordArgsSchema.parse(request.params.arguments);
          const record = await this.airtableService.getRecord(args.baseId, args.tableId, args.recordId);
          return formatToolResponse({
            id: record.id,
            fields: record.fields,
          });
        }

        case 'create_record': {
          const args = CreateRecordArgsSchema.parse(request.params.arguments);
          const record = await this.airtableService.createRecord(args.baseId, args.tableId, args.fields);
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

        case 'update_records': {
          const args = UpdateRecordsArgsSchema.parse(request.params.arguments);
          const records = await this.airtableService.updateRecords(args.baseId, args.tableId, args.records);
          return formatToolResponse(records.map((record) => ({
            id: record.id,
            fields: record.fields,
          })));
        }

        case 'delete_records': {
          const args = DeleteRecordsArgsSchema.parse(request.params.arguments);
          const records = await this.airtableService.deleteRecords(args.baseId, args.tableId, args.recordIds);
          return formatToolResponse(records.map((record) => ({
            id: record.id,
          })));
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
