import { buildFilterFormula } from '../filters/builder.js';
import { fieldsToCellValuesByFieldId } from '../mapping/recordMapper.js';
import type { AirtableApiRecord } from '../mapping/recordMapper.js';
import { decodeCursor, encodeCursor } from '../pagination/cursor.js';
import type { BaseSchemaResponse, Table } from '../types.js';
import type { ListRecordsPageOptions, ListRecordsPageResult } from '../types.js';

const BASE_ID_PATTERN = /^app[a-zA-Z0-9]{14}$/;
const RECORD_ID_PATTERN = /^rec[a-zA-Z0-9]{14}$/;
const DEFAULT_PAGE_SIZE = 1000;
const MAX_PAGE_SIZE = 8000;

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
  createdTime: string;
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
  if (resolvedFieldIds.length === 0) {
    return {
      id: mapped.id,
      createdTime: mapped.createdTime ?? record.createdTime ?? '',
      cellValuesByFieldId: mapped.cellValuesByFieldId,
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cellValuesByFieldId: Record<string, any> = {};
  resolvedFieldIds.forEach((fieldId) => {
    if (fieldId in mapped.cellValuesByFieldId) {
      cellValuesByFieldId[fieldId] = mapped.cellValuesByFieldId[fieldId];
    }
  });

  return {
    id: mapped.id,
    createdTime: mapped.createdTime ?? record.createdTime ?? '',
    cellValuesByFieldId,
  };
};

export const buildListRecordsPageOptions = (
  table: Table,
  input: ValidatedListRecordsForTableInput,
): ListRecordsPageOptions => {
  const validated = validateListRecordsForTableInput(input);
  const { resolvedFieldIds, apiFieldNames } = resolveFieldIdentifiers(table, validated.fieldIds);

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

  const pageOptions: ListRecordsPageOptions = {
    pageSize: validated.pageSize,
  };

  if (filterByFormula) {
    pageOptions.filterByFormula = filterByFormula;
  }
  if (apiFieldNames.length > 0) {
    pageOptions.fields = apiFieldNames;
  }

  const decodedOffset = validated.cursor ? decodeCursor(validated.cursor) : undefined;
  if (decodedOffset) {
    pageOptions.offset = decodedOffset;
  }
  if (validated.recordIds) {
    pageOptions.recordIds = validated.recordIds;
  }
  if (sort) {
    pageOptions.sort = sort;
  }

  return pageOptions;
};

export const listRecordsForTable = async (
  service: ListRecordsForTableService,
  rawInput: ListRecordsForTableInput,
): Promise<ListRecordsForTableOutput> => {
  const validated = validateListRecordsForTableInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);
  const { resolvedFieldIds } = resolveFieldIdentifiers(table, validated.fieldIds);
  const pageOptions = buildListRecordsPageOptions(table, validated);

  const { records, offset } = await service.listRecordsPage(
    validated.baseId,
    table.id,
    pageOptions,
  );

  const mappedRecords = records.map((record) => projectCellValues(record, table, resolvedFieldIds));

  const output: ListRecordsForTableOutput = {
    records: mappedRecords,
  };

  if (offset) {
    const nextCursor = encodeCursor(offset);
    if (nextCursor) {
      output.nextCursor = nextCursor;
    }
    // V1: totalRecordCount is omitted when more pages exist (exact count would require full pagination).
  } else {
    output.metadata = { totalRecordCount: mappedRecords.length };
  }

  return output;
};
