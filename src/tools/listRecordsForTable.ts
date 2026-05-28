import { buildFilterFormula } from '../filters/builder.js';
import { fetchAggregatedRecords } from '../internal/paginatedFetch.js';
import { projectRecordToOfficialFormat } from '../internal/recordProjection.js';
import {
  RECORD_ID_PATTERN,
  validateBaseId,
  validatePageSize,
  validationError,
} from '../internal/validation.js';
import { decodeCursor } from '../pagination/cursor.js';
import type {
  BaseSchemaResponse,
  ListRecordsPageOptions,
  ListRecordsPageResult,
  Table,
} from '../types.js';

export { fetchAggregatedRecords } from '../internal/paginatedFetch.js';

export interface ListRecordsForTableInput {
  baseId: string;
  tableId: string;
  fieldIds?: string[];
  pageSize?: number;
  cursor?: string;
  sort?: Array<{ fieldId: string; direction?: 'asc' | 'desc' | undefined }>;
  recordIds?: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  filters?: unknown;
}

interface ValidatedListRecordsForTableInput extends Omit<ListRecordsForTableInput, 'pageSize' | 'sort'> {
  pageSize: number;
  sort?: Array<{ fieldId: string; direction?: 'asc' | 'desc' }>;
}

export interface ListRecordsForTableRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface ListRecordsForTableOutput {
  records: ListRecordsForTableRecord[];
  metadata?: { totalRecordCount: number };
  nextCursor?: string;
}

export interface ListRecordsForTableService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
  listRecordsPage(
    baseId: string,
    tableId: string,
    options: ListRecordsPageOptions,
  ): Promise<ListRecordsPageResult>;
}

export type { ListRecordsPageOptions, ListRecordsPageResult };

const COUNT_REST_PAGE_SIZE = 100;
const MAX_COUNT_REST_CALLS = 80;

export const validateListRecordsForTableInput = (input: ListRecordsForTableInput): ValidatedListRecordsForTableInput => {
  validateBaseId(input.baseId);

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  if (input.recordIds) {
    input.recordIds.forEach((recordId, index) => {
      if (!RECORD_ID_PATTERN.test(recordId)) {
        validationError(
          `recordIds[${index}] must match rec + 14 alphanumeric characters, got '${recordId}'`,
        );
      }
    });
  }

  if (input.sort) {
    input.sort.forEach((sortOption, index) => {
      if (sortOption.direction && sortOption.direction !== 'asc' && sortOption.direction !== 'desc') {
        validationError(`sort[${index}].direction must be 'asc' or 'desc', got '${sortOption.direction}'`);
      }
    });
  }

  const validated: ValidatedListRecordsForTableInput = {
    baseId: input.baseId,
    tableId: input.tableId,
    pageSize: validatePageSize(input.pageSize),
  };

  if (input.fieldIds !== undefined) {
    validated.fieldIds = input.fieldIds;
  }
  if (input.cursor !== undefined) {
    validated.cursor = input.cursor;
  }
  if (input.recordIds !== undefined) {
    validated.recordIds = input.recordIds;
  }
  if (input.filters !== undefined) {
    validated.filters = input.filters;
  }
  if (input.sort !== undefined) {
    validated.sort = input.sort.map((sortOption) => {
      const entry: { fieldId: string; direction?: 'asc' | 'desc' } = { fieldId: sortOption.fieldId };
      if (sortOption.direction !== undefined) {
        entry.direction = sortOption.direction;
      }
      return entry;
    });
  }

  return validated;
};

export const resolveTable = (baseSchema: BaseSchemaResponse, tableId: string): Table => {
  const table = baseSchema.tables.find(
    (candidate) => candidate.id === tableId || candidate.name === tableId,
  );
  if (!table) {
    throw new Error(`Table '${tableId}' not found in base.`);
  }
  return table;
};

export const resolveFieldIdentifiers = (
  table: Table,
  fieldIds?: string[],
): { resolvedFieldIds: string[]; apiFieldNames: string[] } => {
  if (!fieldIds || fieldIds.length === 0) {
    return { resolvedFieldIds: [], apiFieldNames: [] };
  }

  const resolvedFieldIds = fieldIds.map((fieldIdentifier) => {
    const field = table.fields.find(
      (candidate) => candidate.id === fieldIdentifier || candidate.name === fieldIdentifier,
    );
    if (!field) {
      throw new Error(`Unknown field '${fieldIdentifier}' in fieldIds.`);
    }
    return field.id;
  });

  const apiFieldNames = resolvedFieldIds.map((fieldId) => {
    const field = table.fields.find((candidate) => candidate.id === fieldId);
    return field?.name ?? fieldId;
  });

  return { resolvedFieldIds, apiFieldNames };
};

export const buildListRecordsPageOptions = (
  table: Table,
  input: ValidatedListRecordsForTableInput,
): Omit<ListRecordsPageOptions, 'pageSize' | 'offset'> => {
  let filterByFormula: string | undefined;
  if (input.filters) {
    filterByFormula = buildFilterFormula(input.filters, table);
  }

  const sort = input.sort?.map((sortOption) => {
    const field = table.fields.find(
      (candidate) => candidate.id === sortOption.fieldId || candidate.name === sortOption.fieldId,
    );
    if (!field) {
      throw new Error(`Unknown field '${sortOption.fieldId}' in sort.`);
    }
    const entry: { field: string; direction?: 'asc' | 'desc' } = { field: field.name };
    if (sortOption.direction) {
      entry.direction = sortOption.direction;
    }
    return entry;
  });

  const { apiFieldNames } = resolveFieldIdentifiers(table, input.fieldIds);

  const baseOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'> = {};

  if (filterByFormula) {
    baseOptions.filterByFormula = filterByFormula;
  }
  if (apiFieldNames.length > 0) {
    baseOptions.fields = apiFieldNames;
  }
  if (input.recordIds) {
    baseOptions.recordIds = input.recordIds;
  }
  if (sort) {
    baseOptions.sort = sort;
  }

  return baseOptions;
};

const resolvePrimaryFieldName = (table: Table): string | undefined => {
  const primaryField = table.fields.find((f) => f.id === table.primaryFieldId);
  return primaryField?.name;
};

const countTotalRecords = async (
  service: ListRecordsForTableService,
  baseId: string,
  tableId: string,
  basePageOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'>,
  countFieldName?: string,
): Promise<number> => {
  let total = 0;
  let currentOffset: string | undefined;
  let restCalls = 0;

  while (restCalls < MAX_COUNT_REST_CALLS) {
    const fieldsForCount = countFieldName ? [countFieldName] : basePageOptions.fields;
    const pageOptions: ListRecordsPageOptions = {
      ...basePageOptions,
      pageSize: COUNT_REST_PAGE_SIZE,
    };
    if (fieldsForCount) {
      pageOptions.fields = fieldsForCount;
    }
    if (currentOffset) {
      pageOptions.offset = currentOffset;
    }

    restCalls += 1;
    // eslint-disable-next-line no-await-in-loop
    const { records, offset } = await service.listRecordsPage(baseId, tableId, pageOptions);
    total += records.length;

    if (!offset) {
      return total;
    }
    currentOffset = offset;
  }

  throw new Error(
    `list_records_for_table totalRecordCount exceeded maximum REST calls (${MAX_COUNT_REST_CALLS}).`,
  );
};

export const listRecordsForTable = async (
  service: ListRecordsForTableService,
  rawInput: ListRecordsForTableInput,
): Promise<ListRecordsForTableOutput> => {
  const validated = validateListRecordsForTableInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);
  const { resolvedFieldIds } = resolveFieldIdentifiers(table, validated.fieldIds);
  const basePageOptions = buildListRecordsPageOptions(table, validated);
  const initialOffset = validated.cursor ? decodeCursor(validated.cursor) : undefined;

  const { records, nextCursor, tableExhausted } = await fetchAggregatedRecords(
    service,
    validated.baseId,
    table.id,
    validated.pageSize,
    basePageOptions,
    initialOffset,
    'list_records_for_table',
  );

  const mappedRecords = records.map(
    (record) => projectRecordToOfficialFormat(record, table, resolvedFieldIds),
  );

  const output: ListRecordsForTableOutput = {
    records: mappedRecords,
  };

  if (nextCursor) {
    output.nextCursor = nextCursor;
  }

  let totalRecordCount: number;
  if (tableExhausted && !nextCursor && !initialOffset) {
    totalRecordCount = mappedRecords.length;
  } else {
    const countFieldName = resolvePrimaryFieldName(table);
    totalRecordCount = await countTotalRecords(
      service,
      validated.baseId,
      table.id,
      basePageOptions,
      countFieldName,
    );
  }
  output.metadata = { totalRecordCount };

  return output;
};
