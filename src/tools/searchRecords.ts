import { escapeStringValue, getFieldReferenceByName } from '../filters/builder.js';
import { fetchAggregatedRecords } from '../internal/paginatedFetch.js';
import { projectRecordToOfficialFormat } from '../internal/recordProjection.js';
import {
  validateBaseId,
  validatePageSize,
} from '../internal/validation.js';
import { decodeCursor } from '../pagination/cursor.js';
import type {
  BaseSchemaResponse,
  ListRecordsPageOptions,
  ListRecordsPageResult,
  Table,
} from '../types.js';
import { resolveTable } from './listRecordsForTable.js';

export const NON_SEARCHABLE_FIELD_TYPES = new Set([
  'date',
  'dateTime',
  'createdTime',
  'lastModifiedTime',
  'checkbox',
  'rating',
  'count',
  'number',
  'percent',
  'currency',
  'button',
  'multipleAttachments',
]);

export const isSearchableFieldType = (fieldType: string): boolean => (
  !NON_SEARCHABLE_FIELD_TYPES.has(fieldType)
);

export interface SearchRecordsInput {
  baseId: string;
  table: string;
  query: string;
  fields: string[] | 'ALL_SEARCHABLE_FIELDS';
  pageSize?: number;
  cursor?: string;
}

interface ValidatedSearchRecordsInput extends Omit<SearchRecordsInput, 'pageSize'> {
  pageSize: number;
}

export interface SearchRecordsRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface SearchRecordsOutput {
  records: SearchRecordsRecord[];
  metadata?: { totalRecordCount: number };
  nextCursor?: string;
}

export interface SearchRecordsService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
  listRecordsPage(
    baseId: string,
    tableId: string,
    options: ListRecordsPageOptions,
  ): Promise<ListRecordsPageResult>;
}

export const tokenizeQuery = (query: string): string[] => {
  const tokens = [...new Set(
    query.trim().toLowerCase().split(/\s+/).filter((token) => token.length > 0),
  )];
  if (tokens.length === 0) {
    throw new Error('query must contain at least one token');
  }
  return tokens;
};

export const buildSearchFilterFormula = (tokens: string[], fieldNames: string[]): string => {
  const tokenClauses = tokens.map((token) => {
    const escapedToken = escapeStringValue(token);
    const fieldFinds = fieldNames.map(
      (fieldName) => `FIND(LOWER("${escapedToken}"), LOWER(${getFieldReferenceByName(fieldName)}))`,
    );
    return `OR(${fieldFinds.join(', ')})`;
  });
  return `AND(${tokenClauses.join(', ')})`;
};

const resolveFieldByIdentifier = (table: Table, fieldIdentifier: string) => {
  const field = table.fields.find(
    (candidate) => candidate.id === fieldIdentifier || candidate.name === fieldIdentifier,
  );
  if (!field) {
    throw new Error(`Unknown field '${fieldIdentifier}' in fields.`);
  }
  return field;
};

export const resolveSearchableFields = (
  table: Table,
  fields: string[] | 'ALL_SEARCHABLE_FIELDS',
): Array<{ id: string; name: string; type: string }> => {
  let candidates: Array<{ id: string; name: string; type: string }>;

  if (fields === 'ALL_SEARCHABLE_FIELDS') {
    candidates = table.fields.filter((field) => isSearchableFieldType(field.type));
  } else {
    candidates = fields.map((fieldIdentifier) => resolveFieldByIdentifier(table, fieldIdentifier))
      .filter((field) => isSearchableFieldType(field.type));
  }

  if (candidates.length === 0) {
    throw new Error('no searchable fields in selection');
  }

  return candidates;
};

export const validateSearchRecordsInput = (input: SearchRecordsInput): ValidatedSearchRecordsInput => {
  validateBaseId(input.baseId);

  if (!input.table || typeof input.table !== 'string') {
    throw new Error('Invalid input: table is required');
  }

  if (typeof input.query !== 'string') {
    throw new Error('Invalid input: query is required');
  }

  if (input.fields !== 'ALL_SEARCHABLE_FIELDS') {
    if (!Array.isArray(input.fields) || input.fields.length === 0) {
      throw new Error('Invalid input: fields must be a non-empty array or ALL_SEARCHABLE_FIELDS');
    }
  }

  const validated: ValidatedSearchRecordsInput = {
    baseId: input.baseId,
    table: input.table,
    query: input.query,
    fields: input.fields,
    pageSize: validatePageSize(input.pageSize),
  };

  if (input.cursor !== undefined) {
    validated.cursor = input.cursor;
  }

  return validated;
};

export const searchRecords = async (
  service: SearchRecordsService,
  rawInput: SearchRecordsInput,
): Promise<SearchRecordsOutput> => {
  const validated = validateSearchRecordsInput(rawInput);
  const tokens = tokenizeQuery(validated.query);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.table);
  const searchableFields = resolveSearchableFields(table, validated.fields);
  const filterByFormula = buildSearchFilterFormula(
    tokens,
    searchableFields.map((field) => field.name),
  );

  const basePageOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'> = {
    filterByFormula,
    fields: searchableFields.map((field) => field.name),
  };

  const initialOffset = validated.cursor ? decodeCursor(validated.cursor) : undefined;

  const { records, nextCursor, tableExhausted } = await fetchAggregatedRecords(
    service,
    validated.baseId,
    table.id,
    validated.pageSize,
    basePageOptions,
    initialOffset,
    'search_records',
  );

  const mappedRecords = records.map((record) => projectRecordToOfficialFormat(record, table));

  const output: SearchRecordsOutput = {
    records: mappedRecords,
  };

  if (nextCursor) {
    output.nextCursor = nextCursor;
  } else if (tableExhausted) {
    output.metadata = { totalRecordCount: mappedRecords.length };
  }

  return output;
};
