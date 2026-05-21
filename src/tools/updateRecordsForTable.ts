import { cellValuesByFieldIdToFields } from '../mapping/recordMapper.js';
import type { AirtableApiRecord } from '../mapping/recordMapper.js';
import { projectRecordToOfficialFormat } from '../internal/recordProjection.js';
import { resolveCellValuesSelectChoices } from '../internal/selectChoiceResolver.js';
import {
  RECORD_ID_PATTERN,
  validateBaseId,
  validationError,
} from '../internal/validation.js';
import type { BaseSchemaResponse, FieldSet } from '../types.js';
import { AIRTABLE_REST_CREATE_BATCH_SIZE, MCP_CREATE_RECORDS_MAX } from './createRecordsForTable.js';
import { resolveTable } from './listRecordsForTable.js';

export const MCP_UPDATE_RECORDS_MAX = MCP_CREATE_RECORDS_MAX;
export const AIRTABLE_REST_UPDATE_BATCH_SIZE = AIRTABLE_REST_CREATE_BATCH_SIZE;

export interface UpdateRecordsForTableInputRecord {
  id: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface UpdateRecordsForTableInput {
  baseId: string;
  tableId: string;
  records: UpdateRecordsForTableInputRecord[];
}

export interface UpdateRecordsForTableRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface UpdateRecordsForTableOutput {
  records: UpdateRecordsForTableRecord[];
}

export interface UpdateRecordPageEntry {
  id: string;
  fields: FieldSet;
}

export interface UpdateRecordsForTableService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
  updateRecordsPage(
    baseId: string,
    tableId: string,
    records: UpdateRecordPageEntry[],
  ): Promise<AirtableApiRecord[]>;
}

export const validateUpdateRecordsForTableInput = (input: UpdateRecordsForTableInput): UpdateRecordsForTableInput => {
  validateBaseId(input.baseId);

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  if (!Array.isArray(input.records)) {
    validationError('records must be an array');
  }

  if (input.records.length < 1 || input.records.length > MCP_UPDATE_RECORDS_MAX) {
    validationError(
      `records must contain between 1 and ${MCP_UPDATE_RECORDS_MAX} entries, got ${input.records.length}`,
    );
  }

  input.records.forEach((record, index) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      validationError(`record[${index}] must be an object`);
    }
    if (!record.id || typeof record.id !== 'string') {
      validationError(`record[${index}].id is required`);
    }
    if (!RECORD_ID_PATTERN.test(record.id)) {
      validationError(
        `record[${index}].id must match rec + 14 alphanumeric characters, got '${record.id}'`,
      );
    }
    if (!record.cellValuesByFieldId || typeof record.cellValuesByFieldId !== 'object' || Array.isArray(record.cellValuesByFieldId)) {
      validationError(`record[${index}].cellValuesByFieldId is required`);
    }
    if (Object.keys(record.cellValuesByFieldId).length === 0) {
      validationError(`record[${index}].cellValuesByFieldId must not be empty`);
    }
  });

  return input;
};

const chunkRecords = <T>(records: T[], chunkSize: number): T[][] => {
  const chunks: T[][] = [];
  for (let index = 0; index < records.length; index += chunkSize) {
    chunks.push(records.slice(index, index + chunkSize));
  }
  return chunks;
};

export const updateRecordsForTable = async (
  service: UpdateRecordsForTableService,
  rawInput: UpdateRecordsForTableInput,
): Promise<UpdateRecordsForTableOutput> => {
  const validated = validateUpdateRecordsForTableInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);

  const restRecords: UpdateRecordPageEntry[] = validated.records.map((record) => {
    const resolvedCellValues = resolveCellValuesSelectChoices(record.cellValuesByFieldId, table);
    return {
      id: record.id,
      fields: cellValuesByFieldIdToFields(resolvedCellValues, table),
    };
  });

  const batches = chunkRecords(restRecords, AIRTABLE_REST_UPDATE_BATCH_SIZE);
  const updatedRecords: AirtableApiRecord[] = [];

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
    const batch = batches[batchIndex]!;
    const startIndex = batchIndex * AIRTABLE_REST_UPDATE_BATCH_SIZE;
    try {
      // eslint-disable-next-line no-await-in-loop
      const batchResult = await service.updateRecordsPage(validated.baseId, table.id, batch);
      updatedRecords.push(...batchResult);
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed at batch ${batchIndex + 1}/${batches.length} starting at record index ${startIndex}: ${cause}`,
      );
    }
  }

  return {
    records: updatedRecords.map((record) => projectRecordToOfficialFormat(record, table)),
  };
};
