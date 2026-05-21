import {
  describe, expect, test, vi, beforeEach,
} from 'vitest';
import type { BaseSchemaResponse, Table } from '../types.js';
import {
  AIRTABLE_REST_UPDATE_BATCH_SIZE,
  updateRecordsForTable,
} from './updateRecordsForTable.js';
import type { UpdateRecordsForTableService } from './updateRecordsForTable.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';
const rec = (suffix: string): string => `rec${suffix.padStart(14, '0')}`;

const tableSchema = {
  id: tableId,
  name: 'Contacts',
  primaryFieldId: 'fldName',
  fields: [
    { id: 'fldName', name: 'Name', type: 'singleLineText' },
    { id: 'fldNotes', name: 'Notes', type: 'multilineText' },
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

describe('updateRecordsForTable', () => {
  let mockService: UpdateRecordsForTableService;
  let updateCalls: Array<{ batchSize: number; records: Array<{ id: string; fields: Record<string, unknown> }> }>;

  beforeEach(() => {
    updateCalls = [];

    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
      updateRecordsPage: vi.fn().mockImplementation(async (_base, _table, records) => {
        updateCalls.push({
          batchSize: records.length,
          records: records.map((entry: { id: string; fields: Record<string, unknown> }) => ({
            id: entry.id,
            fields: entry.fields,
          })),
        });
        return records.map((entry: { id: string; fields: Record<string, unknown> }) => apiRecord(
          entry.id,
          entry.fields,
        ));
      }),
    };
  });

  test('T1. single record update returns official format', async () => {
    const recordId = rec('1');
    const result = await updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ id: recordId, cellValuesByFieldId: { fldName: 'Alice Updated' } }],
    });

    expect(result.records).toEqual([{
      id: recordId,
      createdTime: '2026-04-20T19:34:18.000Z',
      cellValuesByFieldId: { fldName: 'Alice Updated' },
    }]);
    expect(updateCalls).toHaveLength(1);
    expect(updateCalls[0]?.batchSize).toBe(1);
  });

  test('T2. 23 records trigger 3 PATCH batches (10+10+3)', async () => {
    const records = Array.from({ length: 23 }, (_, index) => ({
      id: rec(String(index + 1)),
      cellValuesByFieldId: { fldName: `User ${index}` },
    }));

    const result = await updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    });

    expect(result.records).toHaveLength(23);
    expect(updateCalls).toHaveLength(3);
    expect(updateCalls.map((call) => call.batchSize)).toEqual([10, 10, 3]);
    expect(mockService.updateRecordsPage).toHaveBeenCalledTimes(3);
  });

  test('T3. record without id throws validation', async () => {
    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ cellValuesByFieldId: { fldName: 'x' } } as { id: string; cellValuesByFieldId: Record<string, string> }],
    })).rejects.toThrow('Invalid input: record[0].id is required');
  });

  test('T4. invalid record id format throws validation', async () => {
    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ id: 'bad-id', cellValuesByFieldId: { fldName: 'x' } }],
    })).rejects.toThrow(
      "Invalid input: record[0].id must match rec + 14 alphanumeric characters, got 'bad-id'",
    );
  });

  test('T5. partial update sends only provided fields in PATCH body', async () => {
    const recordId = rec('5');
    await updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ id: recordId, cellValuesByFieldId: { fldNotes: 'Only notes' } }],
    });

    expect(updateCalls[0]?.records[0]).toEqual({
      id: recordId,
      fields: { Notes: 'Only notes' },
    });
    expect(Object.keys(updateCalls[0]?.records[0]?.fields ?? {})).toEqual(['Notes']);
  });

  test('T6. singleSelect choice ID resolved to name before REST call', async () => {
    await updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ id: rec('6'), cellValuesByFieldId: { fldStatus: 'selAAAAAAAAAAAAAA' } }],
    });

    expect(updateCalls[0]?.records[0]?.fields).toEqual({ Status: 'Todo' });
  });

  test('T7. empty records array throws validation', async () => {
    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [],
    })).rejects.toThrow(
      'Invalid input: records must contain between 1 and 50 entries, got 0',
    );
  });

  test('T8. more than 50 records throws validation', async () => {
    const records = Array.from({ length: 51 }, (_, index) => ({
      id: rec(String(index + 1)),
      cellValuesByFieldId: { fldName: 'x' },
    }));

    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    })).rejects.toThrow(
      'Invalid input: records must contain between 1 and 50 entries, got 51',
    );
  });

  test('T9. empty cellValuesByFieldId throws validation', async () => {
    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records: [{ id: rec('9'), cellValuesByFieldId: {} }],
    })).rejects.toThrow(
      'Invalid input: record[0].cellValuesByFieldId must not be empty',
    );
  });

  test('T10. order preserved across 3 batches', async () => {
    const records = Array.from({ length: 25 }, (_, index) => ({
      id: rec(String(index + 1)),
      cellValuesByFieldId: { fldName: `Order-${index}` },
    }));

    const result = await updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    });

    expect(result.records.map((record) => record.id)).toEqual(records.map((record) => record.id));
    expect(result.records.map((record) => record.cellValuesByFieldId.fldName)).toEqual(
      records.map((_, index) => `Order-${index}`),
    );
    expect(updateCalls.map((call) => call.batchSize)).toEqual([
      AIRTABLE_REST_UPDATE_BATCH_SIZE,
      AIRTABLE_REST_UPDATE_BATCH_SIZE,
      5,
    ]);
  });

  test('T11. API error on 2nd batch propagates with batch context', async () => {
    let callCount = 0;
    vi.mocked(mockService.updateRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return [apiRecord(rec('1'), { Name: 'ok' })];
      }
      throw new Error('Rate limit exceeded');
    });

    const records = Array.from({ length: 15 }, (_, index) => ({
      id: rec(String(index + 1)),
      cellValuesByFieldId: { fldName: `User ${index}` },
    }));

    await expect(updateRecordsForTable(mockService, {
      baseId,
      tableId,
      records,
    })).rejects.toThrow(
      'Failed at batch 2/2 starting at record index 10: Rate limit exceeded',
    );

    expect(callCount).toBe(2);
  });
});
