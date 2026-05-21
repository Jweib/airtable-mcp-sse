import { resolveTable } from './listRecordsForTable.js';
import type { BaseSchemaResponse, Table } from '../types.js';

const BASE_ID_PATTERN = /^app[a-zA-Z0-9]{14}$/;

export interface GetTableSchemaInput {
  baseId: string;
  tableId: string;
}

export interface GetTableSchemaField {
  id: string;
  name: string;
  type: string;
  description?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  options?: Record<string, any>;
}

export interface GetTableSchemaView {
  id: string;
  name: string;
  type: string;
}

export interface GetTableSchemaOutput {
  id: string;
  name: string;
  primaryFieldId: string;
  description?: string;
  fields: GetTableSchemaField[];
  views: GetTableSchemaView[];
}

export interface GetTableSchemaService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
}

const validationError = (message: string): never => {
  throw new Error(`Invalid input: ${message}`);
};

export const validateGetTableSchemaInput = (input: GetTableSchemaInput): GetTableSchemaInput => {
  if (!BASE_ID_PATTERN.test(input.baseId)) {
    validationError(`baseId must match app + 14 alphanumeric characters, got '${input.baseId}'`);
  }

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  return input;
};

/**
 * Maps Airtable meta API table schema to the official MCP get_table_schema shape.
 * Includes table/field description when returned by the Airtable API (observed on full schema).
 */
export const mapTableToOfficialSchema = (table: Table): GetTableSchemaOutput => {
  const fields = table.fields.map((field) => {
    const mappedField: GetTableSchemaField = {
      id: field.id,
      name: field.name,
      type: field.type,
    };

    if (field.description) {
      mappedField.description = field.description;
    }

    if ('options' in field && field.options !== undefined) {
      mappedField.options = field.options as Record<string, unknown>;
    }

    return mappedField;
  });

  const output: GetTableSchemaOutput = {
    id: table.id,
    name: table.name,
    primaryFieldId: table.primaryFieldId,
    fields,
    views: table.views.map((view) => ({
      id: view.id,
      name: view.name,
      type: view.type,
    })),
  };

  if (table.description) {
    output.description = table.description;
  }

  return output;
};

export const getTableSchema = async (
  service: GetTableSchemaService,
  rawInput: GetTableSchemaInput,
): Promise<GetTableSchemaOutput> => {
  const validated = validateGetTableSchemaInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);
  return mapTableToOfficialSchema(table);
};
