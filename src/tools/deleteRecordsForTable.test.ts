import {
  describe, expect, test, vi, beforeEach,
} from 'vitest';
import type { BaseSchemaResponse, Table } from '../types.js';
import {
  AIRTABLE_REST_DELETE_BATCH_SIZE,
  buildDeleteRecordsQueryString,
  deleteRecordsForTable,
} from './deleteRecordsForTable.js';
import type { DeleteRecordsForTableService } from './deleteRecordsForTable.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';

const rec = (suffix: string): string => `rec${suffix.padStart(14, '0')}`;

const tableSchema = {
  id: tableId,
  name: 'Contacts',
  primaryFieldId: 'fldName',
  fields: [{ id: 'fldName', name: 'Name', type: 'singleLineText' }],
  views: [],
} as unknown as Table;

const baseSchema: BaseSchemaResponse = { tables: [tableSchema] };

describe('deleteRecordsForTable', () => {
  let mockService: DeleteRecordsForTableService;
  let deleteCalls: Array<{ tableId: string; recordIds: string[] }>;

  beforeEach(() => {
    deleteCalls = [];

    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
      deleteRecordsPage: vi.fn().mockImplementation(async (_base, tbl, recordIds) => {
        deleteCalls.push({ tableId: tbl, recordIds });
        return recordIds.map((id) => ({ id, deleted: true }));
      }),
    };
  });

  test('T1. delete single record returns official output shape', async () => {
    const recordId = rec('1');
    const result = await deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds: [recordId],
    });

    expect(result).toEqual({
      records: [{ id: recordId, deleted: true }],
    });
    expect(deleteCalls).toHaveLength(1);
    expect(deleteCalls[0]?.recordIds).toEqual([recordId]);
  });

  test('T2. 23 recordIds trigger 3 DELETE batches (10+10+3)', async () => {
    const recordIds = Array.from({ length: 23 }, (_, index) => rec(String(index + 1)));

    const result = await deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds,
    });

    expect(result.records).toHaveLength(23);
    expect(deleteCalls).toHaveLength(3);
    expect(deleteCalls.map((call) => call.recordIds.length)).toEqual([10, 10, 3]);
    expect(mockService.deleteRecordsPage).toHaveBeenCalledTimes(3);
  });

  test('T3. empty recordIds throws validation', async () => {
    await expect(deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds: [],
    })).rejects.toThrow(
      'Invalid input: recordIds must contain between 1 and 50 entries, got 0',
    );
  });

  test('T4. more than 50 recordIds throws validation', async () => {
    const recordIds = Array.from({ length: 51 }, (_, index) => rec(String(index + 1)));

    await expect(deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds,
    })).rejects.toThrow(
      'Invalid input: recordIds must contain between 1 and 50 entries, got 51',
    );
  });

  test('T5. invalid recordId format throws validation', async () => {
    await expect(deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds: ['bad-id'],
    })).rejects.toThrow(
      "Invalid input: recordIds[0] must match rec + 14 alphanumeric characters, got 'bad-id'",
    );
  });

  test('T6. order preserved across 3 batches', async () => {
    const recordIds = Array.from({ length: 25 }, (_, index) => rec(String(index + 1)));

    const result = await deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds,
    });

    expect(result.records.map((record) => record.id)).toEqual(recordIds);
    expect(deleteCalls.map((call) => call.recordIds.length)).toEqual([
      AIRTABLE_REST_DELETE_BATCH_SIZE,
      AIRTABLE_REST_DELETE_BATCH_SIZE,
      5,
    ]);
  });

  test('T7. API error on 2nd batch propagates with batch context', async () => {
    let callCount = 0;
    vi.mocked(mockService.deleteRecordsPage).mockImplementation(async (_base, _table, recordIds) => {
      callCount += 1;
      if (callCount === 1) {
        return recordIds.map((id) => ({ id, deleted: true }));
      }
      throw new Error('Rate limit exceeded');
    });

    const recordIds = Array.from({ length: 15 }, (_, index) => rec(String(index + 1)));

    await expect(deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds,
    })).rejects.toThrow(
      'Failed at batch 2/2 starting at record index 10: Rate limit exceeded',
    );

    expect(callCount).toBe(2);
  });

  test('T8. output format matches official schema with deleted flag from API', async () => {
    vi.mocked(mockService.deleteRecordsPage).mockResolvedValueOnce([
      { id: rec('8'), deleted: true },
    ]);

    const result = await deleteRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds: [rec('8')],
    });

    expect(result).toEqual({
      records: [{ id: rec('8'), deleted: true }],
    });
    expect(result.records[0]).toHaveProperty('deleted', true);
    expect(Object.keys(result.records[0] ?? {})).toEqual(['id', 'deleted']);
  });
});

describe('buildDeleteRecordsQueryString', () => {
  test('builds records[] query parameters', () => {
    expect(buildDeleteRecordsQueryString([rec('1'), rec('2')])).toBe(
      `records[]=${rec('1')}&records[]=${rec('2')}`,
    );
  });
});
