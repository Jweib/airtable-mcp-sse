import {
  describe, expect, test, vi, beforeEach,
} from 'vitest';
import type { BaseSchemaResponse, Table } from '../types.js';
import {
  buildSearchFilterFormula,
  resolveSearchableFields,
  searchRecords,
  tokenizeQuery,
} from './searchRecords.js';
import type { SearchRecordsService } from './searchRecords.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';

const tableSchema = {
  id: tableId,
  name: 'Contacts',
  primaryFieldId: 'fldText',
  fields: [
    { id: 'fldAdresse', name: 'Adresse', type: 'singleLineText' },
    { id: 'fldTitre', name: 'Titre', type: 'singleLineText' },
    { id: 'fldDate', name: 'Event Date', type: 'date' },
    { id: 'fldNumber', name: 'Amount', type: 'number' },
    { id: 'fldRating', name: 'Score', type: 'rating' },
    { id: 'fldCheckbox', name: 'Done', type: 'checkbox' },
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
  apiRecord(recId(startIndex + index), { Adresse: `Match ${startIndex + index}` })
));

describe('searchRecords formula building', () => {
  test('T1. simple search "Zink" on Adresse', () => {
    const formula = buildSearchFilterFormula(['zink'], ['Adresse']);
    expect(formula).toBe('AND(OR(FIND(LOWER("zink"), LOWER({Adresse}))))');
  });

  test('T2. multiple tokens "rue zink" on Adresse', () => {
    const formula = buildSearchFilterFormula(['rue', 'zink'], ['Adresse']);
    expect(formula).toBe(
      'AND(OR(FIND(LOWER("rue"), LOWER({Adresse}))), OR(FIND(LOWER("zink"), LOWER({Adresse}))))',
    );
  });

  test('T3. token-order independent: "zink rue" vs "rue zink"', () => {
    const formulaZinkRue = buildSearchFilterFormula(tokenizeQuery('zink rue'), ['Adresse']);
    const formulaRueZink = buildSearchFilterFormula(tokenizeQuery('rue zink'), ['Adresse']);
    expect(formulaZinkRue).toBe(
      'AND(OR(FIND(LOWER("zink"), LOWER({Adresse}))), OR(FIND(LOWER("rue"), LOWER({Adresse}))))',
    );
    expect(formulaRueZink).toBe(
      'AND(OR(FIND(LOWER("rue"), LOWER({Adresse}))), OR(FIND(LOWER("zink"), LOWER({Adresse}))))',
    );
  });

  test('T4. case-insensitive: "ZINK" and "zink" tokenize to the same formula', () => {
    const upper = buildSearchFilterFormula(tokenizeQuery('ZINK'), ['Adresse']);
    const lower = buildSearchFilterFormula(tokenizeQuery('zink'), ['Adresse']);
    expect(upper).toBe(lower);
    expect(upper).toContain('LOWER("zink")');
  });

  test('T5. multi-field search for "alice"', () => {
    const formula = buildSearchFilterFormula(['alice'], ['Adresse', 'Titre']);
    expect(formula).toBe(
      'AND(OR(FIND(LOWER("alice"), LOWER({Adresse})), FIND(LOWER("alice"), LOWER({Titre}))))',
    );
  });

  test('T9. escaping quotes in token value', () => {
    const formula = buildSearchFilterFormula(['say "hi"'], ['Adresse']);
    expect(formula).toContain('LOWER("say \\"hi\\"")');
  });

  test('T11. duplicate tokens deduplicated', () => {
    const tokens = tokenizeQuery('rue rue zink');
    expect(tokens).toEqual(['rue', 'zink']);
    const formula = buildSearchFilterFormula(tokens, ['Adresse']);
    expect(formula).toBe(
      'AND(OR(FIND(LOWER("rue"), LOWER({Adresse}))), OR(FIND(LOWER("zink"), LOWER({Adresse}))))',
    );
  });
});

describe('searchRecords field resolution', () => {
  test('T6. ALL_SEARCHABLE_FIELDS excludes non-text types', () => {
    const resolved = resolveSearchableFields(tableSchema, 'ALL_SEARCHABLE_FIELDS');
    expect(resolved.map((field) => field.name)).toEqual(['Adresse', 'Titre']);
  });

  test('T8. no searchable fields in selection throws', () => {
    expect(() => resolveSearchableFields(tableSchema, ['Event Date', 'Amount'])).toThrow(
      'no searchable fields in selection',
    );
  });
});

describe('searchRecords handler', () => {
  let mockService: SearchRecordsService;

  beforeEach(() => {
    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
      listRecordsPage: vi.fn().mockResolvedValue({
        records: [apiRecord('recAAAAAAAAAAAAAA', { Adresse: '12 rue Zink' })],
        offset: undefined,
      }),
    };
  });

  test('T7. empty or whitespace query throws', async () => {
    await expect(searchRecords(mockService, {
      baseId,
      table: tableId,
      query: '   ',
      fields: ['Adresse'],
    })).rejects.toThrow('query must contain at least one token');

    await expect(searchRecords(mockService, {
      baseId,
      table: tableId,
      query: '',
      fields: ['Adresse'],
    })).rejects.toThrow('query must contain at least one token');
  });

  test('T8. empty fields array throws at validation', async () => {
    await expect(searchRecords(mockService, {
      baseId,
      table: tableId,
      query: 'zink',
      fields: [],
    })).rejects.toThrow('fields must be a non-empty array or ALL_SEARCHABLE_FIELDS');
  });

  test('T10. pageSize=150 uses internal pagination like list_records_for_table', async () => {
    let callCount = 0;
    vi.mocked(mockService.listRecordsPage).mockImplementation(async () => {
      callCount += 1;
      if (callCount === 1) {
        return { records: makeRecords(100), offset: 'itrPage2' };
      }
      if (callCount === 2) {
        return { records: makeRecords(50, 100), offset: 'itrPage3' };
      }
      throw new Error('Unexpected extra REST call');
    });

    const result = await searchRecords(mockService, {
      baseId,
      table: tableId,
      query: 'match',
      fields: ['Adresse'],
      pageSize: 150,
    });

    expect(callCount).toBe(2);
    expect(result.records).toHaveLength(150);
    expect(result.nextCursor).toBe('itrPage3');
    expect(result.metadata).toBeUndefined();
    expect(mockService.listRecordsPage).toHaveBeenNthCalledWith(
      1,
      baseId,
      tableId,
      expect.objectContaining({
        pageSize: 100,
        filterByFormula: 'AND(OR(FIND(LOWER("match"), LOWER({Adresse}))))',
      }),
    );
    expect(mockService.listRecordsPage).toHaveBeenNthCalledWith(
      2,
      baseId,
      tableId,
      expect.objectContaining({ pageSize: 50, offset: 'itrPage2' }),
    );
  });

  test('T12. output format matches list_records_for_table', async () => {
    const result = await searchRecords(mockService, {
      baseId,
      table: tableId,
      query: 'zink',
      fields: ['Adresse'],
    });

    expect(result.records).toEqual([{
      id: 'recAAAAAAAAAAAAAA',
      createdTime: '2026-04-20T19:34:18.000Z',
      cellValuesByFieldId: {
        fldAdresse: '12 rue Zink',
      },
    }]);
    expect(result.metadata).toEqual({ totalRecordCount: 1 });
    expect(result.nextCursor).toBeUndefined();
  });

  test('passes filterByFormula for simple search', async () => {
    await searchRecords(mockService, {
      baseId,
      table: tableId,
      query: 'Zink',
      fields: ['Adresse'],
    });

    expect(mockService.listRecordsPage).toHaveBeenCalledWith(
      baseId,
      tableId,
      expect.objectContaining({
        filterByFormula: 'AND(OR(FIND(LOWER("zink"), LOWER({Adresse}))))',
        fields: ['Adresse'],
      }),
    );
  });
});
