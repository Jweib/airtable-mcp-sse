import { cellValuesByFieldIdToFields } from '../mapping/recordMapper.js';
import type { AirtableApiRecord } from '../mapping/recordMapper.js';
import { projectRecordToOfficialFormat } from '../internal/recordProjection.js';
import { validateBaseId, validationError } from '../internal/validation.js';
import type { BaseSchemaResponse, FieldSet, Table } from '../types.js';
import { resolveTable } from './listRecordsForTable.js';

export const AIRTABLE_REST_CREATE_BATCH_SIZE = 10;
export const MCP_CREATE_RECORDS_MAX = 50;

const CHOICE_ID_PATTERN = /^sel[a-zA-Z0-9]{14}$/;

type SelectChoice = { id?: string; name: string };

const getSelectChoices = (field: Table['fields'][number]): SelectChoice[] | undefined => {
  if (field.type !== 'singleSelect' && field.type !== 'multipleSelects') {
    return undefined;
  }
  const options = field as { options?: { choices?: SelectChoice[] } };
  return options.options?.choices;
};

const resolveChoiceIdToName = (choiceId: string, choices: SelectChoice[]): string => {
  const choice = choices.find((candidate) => candidate.id === choiceId);
  if (!choice) {
    throw new Error(`Unknown select choice id '${choiceId}'.`);
  }
  return choice.name;
};

export const resolveCellValuesSelectChoices = (
  cellValues: Record<string, unknown>,
  table: Table,
): Record<string, unknown> => {
  const resolved: Record<string, unknown> = { ...cellValues };

  Object.entries(cellValues).forEach(([fieldKey, value]) => {
    const field = table.fields.find(
      (candidate) => candidate.id === fieldKey || candidate.name === fieldKey,
    );
    if (!field) {
      return;
    }

    const choices = getSelectChoices(field);
    if (!choices) {
      return;
    }

    if (field.type === 'singleSelect' && typeof value === 'string' && CHOICE_ID_PATTERN.test(value)) {
      resolved[fieldKey] = resolveChoiceIdToName(value, choices);
      return;
    }

    if (field.type === 'multipleSelects' && Array.isArray(value)) {
      resolved[fieldKey] = value.map((entry) => (
        typeof entry === 'string' && CHOICE_ID_PATTERN.test(entry)
          ? resolveChoiceIdToName(entry, choices)
          : entry
      ));
    }
  });

  return resolved;
};

export interface CreateRecordsForTableInputRecord {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface CreateRecordsForTableInput {
  baseId: string;
  tableId: string;
  records: CreateRecordsForTableInputRecord[];
}

export interface CreateRecordsForTableRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export interface CreateRecordsForTableOutput {
  records: CreateRecordsForTableRecord[];
}

export interface CreateRecordsForTableService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
  createRecordsPage(baseId: string, tableId: string, records: FieldSet[]): Promise<AirtableApiRecord[]>;
}

export const validateCreateRecordsForTableInput = (input: CreateRecordsForTableInput): CreateRecordsForTableInput => {
  validateBaseId(input.baseId);

  if (!input.tableId || typeof input.tableId !== 'string') {
    validationError('tableId is required');
  }

  if (!Array.isArray(input.records)) {
    validationError('records must be an array');
  }

  if (input.records.length < 1 || input.records.length > MCP_CREATE_RECORDS_MAX) {
    validationError(
      `records must contain between 1 and ${MCP_CREATE_RECORDS_MAX} entries, got ${input.records.length}`,
    );
  }

  input.records.forEach((record, index) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      validationError(`record[${index}] must be an object`);
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

export const createRecordsForTable = async (
  service: CreateRecordsForTableService,
  rawInput: CreateRecordsForTableInput,
): Promise<CreateRecordsForTableOutput> => {
  const validated = validateCreateRecordsForTableInput(rawInput);
  const baseSchema = await service.getBaseSchema(validated.baseId);
  const table = resolveTable(baseSchema, validated.tableId);

  const restFieldSets = validated.records.map((record) => {
    const resolvedCellValues = resolveCellValuesSelectChoices(record.cellValuesByFieldId, table);
    return cellValuesByFieldIdToFields(resolvedCellValues, table);
  });

  const batches = chunkRecords(restFieldSets, AIRTABLE_REST_CREATE_BATCH_SIZE);
  const createdRecords: AirtableApiRecord[] = [];

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
    const batch = batches[batchIndex]!;
    const startIndex = batchIndex * AIRTABLE_REST_CREATE_BATCH_SIZE;
    try {
      // eslint-disable-next-line no-await-in-loop
      const batchResult = await service.createRecordsPage(validated.baseId, table.id, batch);
      createdRecords.push(...batchResult);
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed at batch ${batchIndex + 1}/${batches.length} starting at record index ${startIndex}: ${cause}`,
      );
    }
  }

  return {
    records: createdRecords.map((record) => projectRecordToOfficialFormat(record, table)),
  };
};
