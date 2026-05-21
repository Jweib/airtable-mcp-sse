import {
  describe, expect, test, vi, beforeEach,
} from 'vitest';
import type { BaseSchemaResponse, Table } from '../types.js';
import { resolveCellValuesSelectChoices } from '../internal/selectChoiceResolver.js';
import {
  AIRTABLE_REST_CREATE_BATCH_SIZE,
  createRecordsForTable,
} from './createRecordsForTable.js';
import type { CreateRecordsForTableService } from './createRecordsForTable.js';
import { cellValuesByFieldIdToFields, fieldsToCellValuesByFieldId } from '../mapping/recordMapper.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';

const tableSchema = {
  id: tableId,
  name: 'Contacts',
  primaryFieldId: 'fldName',
  fields: [
    { id: 'fldName', name: 'Name', type: 'singleLineText' },
    {
      id: 'fldStatus',
      name: 'Status',
      type: 'singleSelect',
      options: {
        choices: [
          { id: 'selAAAAAAAAAAAAAA', name: 'Todo' },
          { id: 'selBBBBBBBBBBBBBB', name: 'Done' },
        ],
      },
    },
  ],
  views: [],
} as unknown as Table;

const baseSchema: BaseSchemaResponse = { tables: [tableSchema] };

const apiRecord = (
  id: string,
  fields: Record<string, unknown>,
  createdTime = '2026-04-20T19:34:18.000Z',
) => ({
  id,
  createdTime,
  fields,
});

describe('createRecordsForTable', () => {
  let mockService: CreateRecordsForTableService;
  let createCalls: Array<{ tableId: string; batchSize: number; fields: Record<string, unknown>[] }>;

  beforeEach(() => {
    createCalls = [];
    let recordCounter = 0;

    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
      createRecordsPage: vi.fn().mockImplementation(async (_base, tbl, fieldSets) => {
        createCalls.push({
          tableId: tbl,
          batchSize: fieldSets.length,
          fields: fieldSets,
        });
        return fieldSets.map((fields) => {
          recordCounter += 1;
          const index = recordCounter;
          return apiRecord(
            `rec${index.toString().padStart(14, '0')}`,
            fields,
          );
        });
      }),
    };
  });

  test('T1. single record creation returns official format', async () => {
    const result = await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ cellValuesByFieldId: { fldName: 'Alice' } }],
    });

    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toEqual({
      id: 'rec00000000000001',
      createdTime: '2026-04-20T19:34:18.000Z',
      cellValuesByFieldId: { fldName: 'Alice' },
    });
    expect(createCalls).toHaveLength(1);
    expect(createCalls[0]?.batchSize).toBe(1);
  });

  test('T2. 23 records trigger 3 REST batches (10+10+3)', async () => {
    const records = Array.from({ length: 23 }, (_, index) => ({
      cellValuesByFieldId: { fldName: `User ${index}` },
    }));

    const result = await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    });

    expect(result.records).toHaveLength(23);
    expect(createCalls).toHaveLength(3);
    expect(createCalls.map((call) => call.batchSize)).toEqual([10, 10, 3]);
    expect(mockService.createRecordsPage).toHaveBeenCalledTimes(3);
  });

  test('T3. cellValuesByFieldId ↔ fields mapping round-trip', async () => {
    const input = { fldName: 'Bob', fldStatus: 'Todo' };
    const fields = cellValuesByFieldIdToFields(input, tableSchema);
    expect(fields).toEqual({ Name: 'Bob', Status: 'Todo' });

    const mapped = fieldsToCellValuesByFieldId(
      apiRecord('recAAAAAAAAAAAAAA', fields),
      tableSchema,
    );
    expect(mapped.cellValuesByFieldId).toEqual(input);
  });

  test('T4. createdTime present on each returned record', async () => {
    const result = await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [
        { cellValuesByFieldId: { fldName: 'A' } },
        { cellValuesByFieldId: { fldName: 'B' } },
      ],
    });

    result.records.forEach((record) => {
      expect(record.createdTime).toBe('2026-04-20T19:34:18.000Z');
    });
  });

  test('T5. empty records array throws validation', async () => {
    await expect(createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [],
    })).rejects.toThrow(
      'Invalid input: records must contain between 1 and 50 entries, got 0',
    );
  });

  test('T6. more than 50 records throws validation', async () => {
    const records = Array.from({ length: 51 }, () => ({
      cellValuesByFieldId: { fldName: 'x' },
    }));

    await expect(createRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    })).rejects.toThrow(
      'Invalid input: records must contain between 1 and 50 entries, got 51',
    );
  });

  test('T7. empty cellValuesByFieldId throws validation', async () => {
    await expect(createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ cellValuesByFieldId: {} }],
    })).rejects.toThrow(
      'Invalid input: record[0].cellValuesByFieldId must not be empty',
    );
  });

  test('T8. singleSelect choice ID resolved to name before REST call', async () => {
    await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ cellValuesByFieldId: { fldStatus: 'selAAAAAAAAAAAAAA' } }],
    });

    expect(createCalls[0]?.fields[0]).toEqual({ Status: 'Todo' });
  });

  test('T9. singleSelect choice name passed through unchanged', async () => {
    await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ cellValuesByFieldId: { fldStatus: 'Done' } }],
    });

    expect(createCalls[0]?.fields[0]).toEqual({ Status: 'Done' });
  });

  test('T10. order preserved across 3 batches', async () => {
    const records = Array.from({ length: 25 }, (_, index) => ({
      cellValuesByFieldId: { fldName: `Order-${index}` },
    }));

    const result = await createRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    });

    expect(result.records.map((record) => record.cellValuesByFieldId.fldName)).toEqual(
      records.map((_, index) => `Order-${index}`),
    );
    expect(createCalls).toHaveLength(3);
    expect(createCalls.map((call) => call.batchSize)).toEqual([
      AIRTABLE_REST_CREATE_BATCH_SIZE,
      AIRTABLE_REST_CREATE_BATCH_SIZE,
      5,
    ]);
  });

  test('T11. API error on 2nd batch propagates with batch context', async () => {
    let callCount = 0;
    vi.mocked(mockService.createRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return [apiRecord('rec00000000000001', { Name: 'ok' })];
      }
      throw new Error('Rate limit exceeded');
    });

    const records = Array.from({ length: 15 }, (_, index) => ({
      cellValuesByFieldId: { fldName: `User ${index}` },
    }));

    await expect(createRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    })).rejects.toThrow(
      'Failed at batch 2/2 starting at record index 10: Rate limit exceeded',
    );

    expect(callCount).toBe(2);
  });
});

describe('resolveCellValuesSelectChoices', () => {
  test('resolves choice id via helper', () => {
    const resolved = resolveCellValuesSelectChoices(
      { fldStatus: 'selBBBBBBBBBBBBBB' },
      tableSchema,
    );
    expect(resolved).toEqual({ fldStatus: 'Done' });
  });
});
