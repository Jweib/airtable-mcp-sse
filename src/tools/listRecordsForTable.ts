import { buildFilterFormula } from '../filters/builder.js';
import { fieldsToCellValuesByFieldId } from '../mapping/recordMapper.js';
import type { AirtableApiRecord } from '../mapping/recordMapper.js';
import { decodeCursor, encodeCursor } from '../pagination/cursor.js';
import type {
  BaseSchemaResponse,
  ListRecordsPageOptions,
  ListRecordsPageResult,
  Table,
} from '../types.js';

const BASE_ID_PATTERN = /^app[a-zA-Z0-9]{14}$/;
const RECORD_ID_PATTERN = /^rec[a-zA-Z0-9]{14}$/;
const DEFAULT_PAGE_SIZE = 1000;
const MAX_PAGE_SIZE = 8000;
const AIRTABLE_REST_PAGE_SIZE_MAX = 100;
const MAX_INTERNAL_REST_CALLS = 80;

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

const validationError = (message: string): never => {
  throw new Error(`Invalid input: ${message}`);
};

export const validateListRecordsForTableInput = (input: ListRecordsForTableInput): ValidatedListRecordsForTableInput => {
  if (!BASE_ID_PATTERN.test(input.baseId)) {
    validationError(`baseId must match app + 14 alphanumeric characters, got '${input.baseId}'`);
  }

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  if (input.pageSize !== undefined) {
    if (!Number.isInteger(input.pageSize) || input.pageSize < 1 || input.pageSize > MAX_PAGE_SIZE) {
      validationError(`pageSize must be between 1 and ${MAX_PAGE_SIZE}, got ${input.pageSize}`);
    }
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
    pageSize: input.pageSize ?? DEFAULT_PAGE_SIZE,
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

const projectCellValues = (
  record: AirtableApiRecord,
  table: Table,
  resolvedFieldIds: string[],
): ListRecordsForTableRecord => {
  const mapped = fieldsToCellValuesByFieldId(record, table);
  const createdTime = mapped.createdTime ?? record.createdTime;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const buildRecord = (cellValuesByFieldId: Record<string, any>): ListRecordsForTableRecord => (
    createdTime
      ? { id: mapped.id, createdTime, cellValuesByFieldId }
      : { id: mapped.id, cellValuesByFieldId }
  );

  if (resolvedFieldIds.length === 0) {
    return buildRecord(mapped.cellValuesByFieldId);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cellValuesByFieldId: Record<string, any> = {};
  resolvedFieldIds.forEach((fieldId) => {
    if (fieldId in mapped.cellValuesByFieldId) {
      cellValuesByFieldId[fieldId] = mapped.cellValuesByFieldId[fieldId];
    }
  });

  return buildRecord(cellValuesByFieldId);
};

export const buildListRecordsPageOptions = (
  table: Table,
  input: ValidatedListRecordsForTableInput,
): Omit<ListRecordsPageOptions, 'pageSize' | 'offset'> => {
  const validated = validateListRecordsForTableInput(input);

  let filterByFormula: string | undefined;
  if (validated.filters) {
    filterByFormula = buildFilterFormula(validated.filters, table);
  }

  const sort = validated.sort?.map((sortOption) => {
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

  const { apiFieldNames } = resolveFieldIdentifiers(table, validated.fieldIds);

  const baseOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'> = {};

  if (filterByFormula) {
    baseOptions.filterByFormula = filterByFormula;
  }
  if (apiFieldNames.length > 0) {
    baseOptions.fields = apiFieldNames;
  }
  if (validated.recordIds) {
    baseOptions.recordIds = validated.recordIds;
  }
  if (sort) {
    baseOptions.sort = sort;
  }

  return baseOptions;
};

interface AggregatedPageFetchResult {
  records: ListRecordsPageResult['records'];
  nextCursor?: string;
  tableExhausted: boolean;
}

export const fetchAggregatedRecords = async (
  service: ListRecordsForTableService,
  baseId: string,
  tableId: string,
  targetPageSize: number,
  basePageOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'>,
  initialOffset?: string,
): Promise<AggregatedPageFetchResult> => {
  const aggregatedRecords: ListRecordsPageResult['records'] = [];
  let currentOffset = initialOffset;
  let nextCursor: string | undefined;
  let restCalls = 0;

  while (aggregatedRecords.length < targetPageSize && restCalls < MAX_INTERNAL_REST_CALLS) {
    const remaining = targetPageSize - aggregatedRecords.length;
    const requestPageSize = Math.min(remaining, AIRTABLE_REST_PAGE_SIZE_MAX);

    const pageOptions: ListRecordsPageOptions = {
      ...basePageOptions,
      pageSize: requestPageSize,
    };
    if (currentOffset) {
      pageOptions.offset = currentOffset;
    }

    restCalls += 1;
    // eslint-disable-next-line no-await-in-loop
    const { records, offset } = await service.listRecordsPage(baseId, tableId, pageOptions);
    aggregatedRecords.push(...records);

    if (aggregatedRecords.length >= targetPageSize) {
      const trimmedRecords = aggregatedRecords.slice(0, targetPageSize);
      const result: AggregatedPageFetchResult = {
        records: trimmedRecords,
        tableExhausted: !offset,
      };
      if (offset) {
        const encoded = encodeCursor(offset);
        if (encoded) {
          result.nextCursor = encoded;
        }
      }
      return result;
    }

    if (!offset) {
      return {
        records: aggregatedRecords,
        tableExhausted: true,
      };
    }

    currentOffset = offset;
  }

  if (restCalls >= MAX_INTERNAL_REST_CALLS) {
    throw new Error(
      `list_records_for_table exceeded maximum internal REST calls (${MAX_INTERNAL_REST_CALLS}).`,
    );
  }

  return {
    records: aggregatedRecords,
    tableExhausted: true,
  };
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
  );

  const mappedRecords = records.map((record) => projectCellValues(record, table, resolvedFieldIds));

  const output: ListRecordsForTableOutput = {
    records: mappedRecords,
  };

  if (nextCursor) {
    output.nextCursor = nextCursor;
    // V1: totalRecordCount omitted when more pages remain (nextCursor present).
  } else if (tableExhausted) {
    output.metadata = { totalRecordCount: mappedRecords.length };
  }

  return output;
};
