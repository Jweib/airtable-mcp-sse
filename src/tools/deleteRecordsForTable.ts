import {
  RECORD_ID_PATTERN,
  validateBaseId,
  validationError,
} from '../internal/validation.js';
import type { BaseSchemaResponse } from '../types.js';
import { AIRTABLE_REST_CREATE_BATCH_SIZE, MCP_CREATE_RECORDS_MAX } from './createRecordsForTable.js';
import { resolveTable } from './listRecordsForTable.js';

export const MCP_DELETE_RECORDS_MAX = MCP_CREATE_RECORDS_MAX;
export const AIRTABLE_REST_DELETE_BATCH_SIZE = AIRTABLE_REST_CREATE_BATCH_SIZE;

/**
 * DELETE query strings use records[]=recXXX per id. With at most 10 ids per request
 * (~21 chars each), URL length stays well under typical HTTP limits (~8KB+).
 */
export const buildDeleteRecordsQueryString = (recordIds: string[]): string => (
  recordIds.map((id) => `records[]=${encodeURIComponent(id)}`).join('&')
);

export interface DeleteRecordsForTableInput {
  baseId: string;
  tableId: string;
  recordIds: string[];
}

export interface DeleteRecordsForTableRecord {
  id: string;
  deleted: boolean;
}

export interface DeleteRecordsForTableOutput {
  records: DeleteRecordsForTableRecord[];
}

export interface DeleteRecordsForTableService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
  deleteRecordsPage(
    baseId: string,
    tableId: string,
    recordIds: string[],
  ): Promise<DeleteRecordsForTableRecord[]>;
}

export const validateDeleteRecordsForTableInput = (input: DeleteRecordsForTableInput): DeleteRecordsForTableInput => {
  validateBaseId(input.baseId);

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  if (!Array.isArray(input.recordIds)) {
    validationError('recordIds must be an array');
  }

  if (input.recordIds.length < 1 || input.recordIds.length > MCP_DELETE_RECORDS_MAX) {
    validationError(
      `recordIds must contain between 1 and ${MCP_DELETE_RECORDS_MAX} entries, got ${input.recordIds.length}`,
    );
  }

  input.recordIds.forEach((recordId, index) => {
    if (typeof recordId !== 'string' || !RECORD_ID_PATTERN.test(recordId)) {
      validationError(
        `recordIds[${index}] must match rec + 14 alphanumeric characters, got '${recordId}'`,
      );
    }
  });

  return input;
};

const chunkRecordIds = (recordIds: string[], chunkSize: number): string[][] => {
  const chunks: string[][] = [];
  for (let index = 0; index < recordIds.length; index += chunkSize) {
    chunks.push(recordIds.slice(index, index + chunkSize));
  }
  return chunks;
};

export const deleteRecordsForTable = async (
  service: DeleteRecordsForTableService,
  rawInput: DeleteRecordsForTableInput,
): Promise<DeleteRecordsForTableOutput> => {
  const validated = validateDeleteRecordsForTableInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);

  const batches = chunkRecordIds(validated.recordIds, AIRTABLE_REST_DELETE_BATCH_SIZE);
  const deletedRecords: DeleteRecordsForTableRecord[] = [];

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
    const batch = batches[batchIndex]!;
    const startIndex = batchIndex * AIRTABLE_REST_DELETE_BATCH_SIZE;
    try {
      // eslint-disable-next-line no-await-in-loop
      const batchResult = await service.deleteRecordsPage(validated.baseId, table.id, batch);
      deletedRecords.push(...batchResult);
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed at batch ${batchIndex + 1}/${batches.length} starting at record index ${startIndex}: ${cause}`,
      );
    }
  }

  return {
    records: deletedRecords.map((record) => ({
      id: record.id,
      deleted: record.deleted,
    })),
  };
};
