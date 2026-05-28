import {
  describe, expect, test, vi, beforeEach,
} from 'vitest';
import type { BaseSchemaResponse, Table } from '../types.js';
import { listRecordsForTable } from './listRecordsForTable.js';
import type { ListRecordsForTableService, ListRecordsPageResult } from './listRecordsForTable.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';

const tableSchema = {
  id: tableId,
  name: 'Contacts',
  primaryFieldId: 'fldText',
  fields: [
    { id: 'fldText', name: 'Name', type: 'singleLineText' },
    { id: 'fldA', name: 'Field A', type: 'singleLineText' },
    { id: 'fldB', name: 'Field B', type: 'singleLineText' },
    { id: 'fldAdresse', name: 'Adresse', type: 'singleLineText' },
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

const recId = (index: number): string => `rec${index.toString().padStart(14, '0')}`;

const makeRecords = (count: number, startIndex = 0) => Array.from({ length: count }, (_, index) => (
  apiRecord(recId(startIndex + index), { Name: `User ${startIndex + index}` })
));

describe('listRecordsForTable', () => {
  let mockService: ListRecordsForTableService;
  let pageResult: ListRecordsPageResult;

  beforeEach(() => {
    pageResult = {
      records: [
        apiRecord('recAAAAAAAAAAAAAA', { Name: 'Alice', 'Field A': 'a1', 'Field B': 'b1' }),
      ],
      offset: undefined,
    };

    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
      listRecordsPage: vi.fn().mockResolvedValue(pageResult),
    };
  });

  test('minimal call returns official record format', async () => {
    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
    });

    expect(result.records).toEqual([{
      id: 'recAAAAAAAAAAAAAA',
      createdTime: '2026-04-20T19:34:18.000Z',
      cellValuesByFieldId: {
        fldText: 'Alice',
        fldA: 'a1',
        fldB: 'b1',
      },
    }]);
    expect(result.metadata).toEqual({ totalRecordCount: 1 });
    expect(result.nextCursor).toBeUndefined();
  });

  test('fieldIds limits cellValuesByFieldId to requested field IDs', async () => {
    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      fieldIds: ['fldA', 'fldB'],
    });

    expect(result.records[0]?.cellValuesByFieldId).toEqual({
      fldA: 'a1',
      fldB: 'b1',
    });
    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({
        fields: ['Field A', 'Field B'],
      }),
    );
  });

  test('fieldIds by names are resolved to field IDs internally', async () => {
    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      fieldIds: ['Field A'],
    });

    expect(result.records[0]?.cellValuesByFieldId).toEqual({ fldA: 'a1' });
    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({ fields: ['Field A'] }),
    );
  });

  test('pageSize=20 is passed to the API', async () => {
    await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 20,
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({ pageSize: 20 }),
    );
  });

  test('pageSize=9999 throws validation error', async () => {
    await expect(listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 9999,
    })).rejects.toThrow('Invalid input: pageSize must be between 1 and 8000, got 9999');
  });

  test('cursor is decoded and passed as offset to the API', async () => {
    await listRecordsForTable(mockService, {
      baseId,
      tableId,
      cursor: 'itrABC/rec123',
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({ offset: 'itrABC/rec123' }),
    );
  });

  test('API offset is encoded as nextCursor', async () => {
    vi.mocked(mockService.listRecordsPage).mockResolvedValueOnce({
      records: [apiRecord('recAAAAAAAAAAAAAA', { Name: 'Alice' })],
      offset: 'itrNEXT/page',
    });
    vi.mocked(mockService.listRecordsPage).mockResolvedValueOnce({
      records: makeRecords(1),
      offset: undefined,
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 1,
    });

    expect(result.nextCursor).toBe('itrNEXT/page');
    expect(result.metadata).toEqual({ totalRecordCount: 1 });
    expect(mockService.listRecordsPage).toHaveBeenCalledTimes(2);
  });

  test('pageSize=1 on 130 records returns totalRecordCount=130 and nextCursor in one MCP call', async () => {
    let callCount = 0;
    vi.mocked(mockService.listRecordsPage).mockImplementation(async (_baseId, _tableId, options) => {
      callCount += 1;

      // First call: the requested page (pageSize=1, no offset)
      if (callCount === 1) {
        expect(options.pageSize).toBe(1);
        expect(options.offset).toBeUndefined();
        return { records: makeRecords(1, 0), offset: 'itrPage2' };
      }

      // Count pass: 100 + 30 records, from the start (no offset)
      if (callCount === 2) {
        expect(options.pageSize).toBe(100);
        expect(options.offset).toBeUndefined();
        return { records: makeRecords(100, 0), offset: 'itrCount2' };
      }
      if (callCount === 3) {
        expect(options.pageSize).toBe(100);
        expect(options.offset).toBe('itrCount2');
        return { records: makeRecords(30, 100), offset: undefined };
      }

      throw new Error('Unexpected extra REST call');
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 1,
    });

    expect(result.records).toHaveLength(1);
    expect(result.nextCursor).toBe('itrPage2');
    expect(result.metadata).toEqual({ totalRecordCount: 130 });
    expect(callCount).toBe(3);
  });

  test('no API offset includes totalRecordCount and omits nextCursor', async () => {
    vi.mocked(mockService.listRecordsPage).mockResolvedValueOnce({
      records: [
        apiRecord('recAAAAAAAAAAAAAA', { Name: 'A' }),
        apiRecord('recBBBBBBBBBBBBBB', { Name: 'B' }),
      ],
      offset: undefined,
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 1000,
    });

    expect(result.nextCursor).toBeUndefined();
    expect(result.metadata).toEqual({ totalRecordCount: 2 });
  });

  test('filters contains generates expected filterByFormula', async () => {
    await listRecordsForTable(mockService, {
      baseId,
      tableId,
      filters: {
        operator: 'and',
        operands: [{
          operator: 'contains',
          operands: ['fldAdresse', 'Zink'],
        }],
      },
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({
        filterByFormula: 'AND(FIND(LOWER("Zink"), LOWER({Adresse}))>0)',
      }),
    );
  });

  test('invalid filters operator propagates builder error', async () => {
    await expect(listRecordsForTable(mockService, {
      baseId,
      tableId,
      filters: {
        operator: 'and',
        operands: [{ operator: 'startsWith', operands: ['fldText', 'foo'] }],
      },
    })).rejects.toThrow("Unsupported filter operator 'startsWith'.");
  });

  test('recordIds are passed to the API layer', async () => {
    await listRecordsForTable(mockService, {
      baseId,
      tableId,
      recordIds: ['recAAAAAAAAAAAAAA'],
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({
        recordIds: ['recAAAAAAAAAAAAAA'],
      }),
    );
  });

  test('sort builds REST sort parameters using resolved field name', async () => {
    await listRecordsForTable(mockService, {
      baseId,
      tableId,
      sort: [{ fieldId: 'Name', direction: 'desc' }],
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({
        sort: [{ field: 'Name', direction: 'desc' }],
      }),
    );
  });

  test('invalid sort direction throws validation error', async () => {
    await expect(listRecordsForTable(mockService, {
      baseId,
      tableId,
      sort: [{ fieldId: 'Name', direction: 'invalid' as 'asc' }],
    })).rejects.toThrow("Invalid input: sort[0].direction must be 'asc' or 'desc', got 'invalid'");
  });

  test('pageSize=150 with offset on second page makes 2 REST calls and exposes nextCursor', async () => {
    let callCount = 0;
    vi.mocked(mockService.listRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return { records: makeRecords(100), offset: 'itrPage2' };
      }
      if (callCount === 2) {
        return { records: makeRecords(50, 100), offset: 'itrPage3' };
      }
      if (callCount === 3) {
        return { records: makeRecords(100), offset: 'itrCount2' };
      }
      if (callCount === 4) {
        return { records: makeRecords(50, 100), offset: undefined };
      }
      throw new Error('Unexpected extra REST call');
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 150,
    });

    expect(callCount).toBe(4);
    expect(result.records).toHaveLength(150);
    expect(result.nextCursor).toBe('itrPage3');
    expect(result.metadata).toEqual({ totalRecordCount: 150 });
    expect(mockService.listRecordsPage).toHaveBeenNthCalledWith(
      1,
      baseId,
      tableId,
      expect.objectContaining({ pageSize: 100 }),
    );
    expect(mockService.listRecordsPage).toHaveBeenNthCalledWith(
      2,
      baseId,
      tableId,
      expect.objectContaining({ pageSize: 50, offset: 'itrPage2' }),
    );
  });

  test('pageSize=150 without offset on second page returns 150 records and totalRecordCount', async () => {
    let callCount = 0;
    vi.mocked(mockService.listRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return { records: makeRecords(100), offset: 'itrPage2' };
      }
      if (callCount === 2) {
        return { records: makeRecords(50, 100), offset: undefined };
      }
      throw new Error('Unexpected extra REST call');
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 150,
    });

    expect(callCount).toBe(2);
    expect(result.records).toHaveLength(150);
    expect(result.nextCursor).toBeUndefined();
    expect(result.metadata).toEqual({ totalRecordCount: 150 });
  });

  test('pageSize=250 aggregates three REST pages and exposes nextCursor', async () => {
    let callCount = 0;
    vi.mocked(mockService.listRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return { records: makeRecords(100), offset: 'itrPage2' };
      }
      if (callCount === 2) {
        return { records: makeRecords(100, 100), offset: 'itrPage3' };
      }
      if (callCount === 3) {
        return { records: makeRecords(50, 200), offset: 'itrPage4' };
      }
      if (callCount === 4) {
        return { records: makeRecords(100), offset: 'itrCount2' };
      }
      if (callCount === 5) {
        return { records: makeRecords(100, 100), offset: 'itrCount3' };
      }
      if (callCount === 6) {
        return { records: makeRecords(50, 200), offset: undefined };
      }
      throw new Error('Unexpected extra REST call');
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 250,
    });

    expect(callCount).toBe(6);
    expect(result.records).toHaveLength(250);
    expect(result.nextCursor).toBe('itrPage4');
    expect(result.metadata).toEqual({ totalRecordCount: 250 });
    expect(mockService.listRecordsPage).toHaveBeenCalledTimes(6);
  });

  test('pageSize=50 uses a single REST call', async () => {
    vi.mocked(mockService.listRecordsPage).mockResolvedValueOnce({
      records: makeRecords(50),
      offset: undefined,
    });

    const result = await listRecordsForTable(mockService, {
      baseId,
      tableId,
      pageSize: 50,
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledTimes(1);
    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({ pageSize: 50 }),
    );
    expect(result.records).toHaveLength(50);
    expect(result.nextCursor).toBeUndefined();
    expect(result.metadata).toEqual({ totalRecordCount: 50 });
  });
});
