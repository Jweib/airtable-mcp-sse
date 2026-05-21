import { describe, expect, test, vi, beforeEach } from 'vitest';
import { GetTableSchemaArgsSchema } from '../types.js';
import type { BaseSchemaResponse, Table } from '../types.js';
import { getTableSchema } from './getTableSchema.js';
import type { GetTableSchemaService } from './getTableSchema.js';

const baseId = 'appAAAAAAAAAAAAAA';
const tableId = 'tblAAAAAAAAAAAAAA';

const fullTable = {
  id: tableId,
  name: 'Contacts',
  description: 'Contact directory',
  primaryFieldId: 'fldText',
  fields: [
    {
      id: 'fldText',
      name: 'Name',
      type: 'singleLineText',
      description: 'Primary name',
    },
    {
      id: 'fldStatus',
      name: 'Status',
      type: 'singleSelect',
      options: {
        choices: [{ id: 'selA', name: 'Active' }],
      },
    },
  ],
  views: [
    { id: 'viwGrid', name: 'Grid view', type: 'grid' },
  ],
} as unknown as Table;

const baseSchema: BaseSchemaResponse = { tables: [fullTable] };

describe('getTableSchema', () => {
  let mockService: GetTableSchemaService;

  beforeEach(() => {
    mockService = {
      getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
    };
  });

  test('T1. tableId by ID returns the correct table schema', async () => {
    const result = await getTableSchema(mockService, {
      baseId,
      tableId,
    });

    expect(result.id).toBe(tableId);
    expect(result.name).toBe('Contacts');
    expect(mockService.getBaseSchema).toHaveBeenCalledWith(baseId);
  });

  test('T2. tableId by name resolves to the same table', async () => {
    const result = await getTableSchema(mockService, {
      baseId,
      tableId: 'Contacts',
    });

    expect(result).toEqual(await getTableSchema(mockService, { baseId, tableId }));
  });

  test('T3. unknown tableId throws a clear error', async () => {
    await expect(getTableSchema(mockService, {
      baseId,
      tableId: 'Unknown Table',
    })).rejects.toThrow("Table 'Unknown Table' not found in base.");
  });

  test('T4. invalid baseId format throws validation error', async () => {
    await expect(getTableSchema(mockService, {
      baseId: 'invalid-base',
      tableId,
    })).rejects.toThrow("Invalid input: baseId must match app + 14 alphanumeric characters, got 'invalid-base'");
  });

  test('T5. output contains id, name, fields, views and primaryFieldId', async () => {
    const result = await getTableSchema(mockService, { baseId, tableId });

    expect(result).toMatchObject({
      id: tableId,
      name: 'Contacts',
      primaryFieldId: 'fldText',
      fields: expect.any(Array),
      views: expect.any(Array),
    });
    expect(result.fields).toHaveLength(2);
    expect(result.views).toHaveLength(1);
  });

  test('T6. fields contain id, name, type and options when applicable', async () => {
    const result = await getTableSchema(mockService, { baseId, tableId });

    expect(result.fields[0]).toEqual({
      id: 'fldText',
      name: 'Name',
      type: 'singleLineText',
      description: 'Primary name',
    });
    expect(result.fields[1]).toEqual({
      id: 'fldStatus',
      name: 'Status',
      type: 'singleSelect',
      options: {
        choices: [{ id: 'selA', name: 'Active' }],
      },
    });
  });

  test('T7. detailLevel is rejected by the Zod input schema', () => {
    expect(() => GetTableSchemaArgsSchema.parse({
      baseId,
      tableId,
      detailLevel: 'full',
    })).toThrow();
  });
});
