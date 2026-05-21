import { describe, expect, test } from 'vitest';
import type { Table } from '../types.js';
import {
  cellValuesByFieldIdToFields,
  fieldsToCellValuesByFieldId,
} from './recordMapper.js';

const tableSchema = {
  id: 'tbl1',
  name: 'Contacts',
  primaryFieldId: 'fldName',
  fields: [
    { id: 'fldName', name: 'Name', type: 'singleLineText' },
    { id: 'fldScore', name: 'Score', type: 'number', options: { precision: 0 } },
  ],
  views: [],
} as unknown as Table;

describe('recordMapper', () => {
  test('maps fields keyed by field names to cellValuesByFieldId', () => {
    const mapped = fieldsToCellValuesByFieldId({
      id: 'rec1',
      createdTime: '2026-01-01T00:00:00.000Z',
      fields: { Name: 'Alice', Score: 42 },
    }, tableSchema);

    expect(mapped).toEqual({
      id: 'rec1',
      createdTime: '2026-01-01T00:00:00.000Z',
      cellValuesByFieldId: { fldName: 'Alice', fldScore: 42 },
    });
  });

  test('keeps keys already provided as field ids', () => {
    const mapped = fieldsToCellValuesByFieldId({
      id: 'rec1',
      fields: { fldName: 'Bob' },
    }, tableSchema);

    expect(mapped).toEqual({
      id: 'rec1',
      cellValuesByFieldId: { fldName: 'Bob' },
    });
  });

  test('maps cellValuesByFieldId to Airtable fields payload (field names)', () => {
    const fields = cellValuesByFieldIdToFields(
      { fldName: 'Alice', fldScore: 10 },
      tableSchema,
    );

    expect(fields).toEqual({ Name: 'Alice', Score: 10 });
  });

  test('keeps unknown field ids untouched when reverse mapping', () => {
    const fields = cellValuesByFieldIdToFields(
      { fldUnknown: 'mystery' },
      tableSchema,
    );

    expect(fields).toEqual({ fldUnknown: 'mystery' });
  });
});
