import { describe, expect, test, vi } from 'vitest';
import type { BaseSchemaResponse } from '../types.js';
import { listTablesForBase } from './listTablesForBase.js';
import type { ListTablesForBaseService } from './listTablesForBase.js';

const baseId = 'appAAAAAAAAAAAAAA';

const baseSchema: BaseSchemaResponse = {
  tables: [
    {
      id: 'tblAAAAAAAAAAAAAA',
      name: 'Contacts',
      primaryFieldId: 'fldName',
      fields: [
        { id: 'fldName', name: 'Name', type: 'singleLineText' },
      ],
      views: [{ id: 'viw1', name: 'Grid', type: 'grid' }],
    },
    {
      id: 'tblBBBBBBBBBBBBBB',
      name: 'Orders',
      primaryFieldId: 'fldOrder',
      fields: [
        { id: 'fldOrder', name: 'Order ID', type: 'singleLineText' },
      ],
      views: [],
      description: 'Order table',
    },
  ],
};

describe('listTablesForBase', () => {
  const mockService: ListTablesForBaseService = {
    getBaseSchema: vi.fn().mockResolvedValue(baseSchema),
  };

  test('returns compact table identifiers', async () => {
    const result = await listTablesForBase(mockService, { baseId });

    expect(result).toEqual({
      tables: [
        {
          id: 'tblAAAAAAAAAAAAAA',
          name: 'Contacts',
          primaryFieldId: 'fldName',
        },
        {
          id: 'tblBBBBBBBBBBBBBB',
          name: 'Orders',
          primaryFieldId: 'fldOrder',
        },
      ],
    });
    expect(mockService.getBaseSchema).toHaveBeenCalledWith(baseId);
  });

  test('does not include fields or views in output', async () => {
    const result = await listTablesForBase(mockService, { baseId });

    result.tables.forEach((table) => {
      expect(table).not.toHaveProperty('fields');
      expect(table).not.toHaveProperty('views');
      expect(table).not.toHaveProperty('description');
    });
  });

  test('invalid baseId throws validation error', async () => {
    await expect(listTablesForBase(mockService, { baseId: 'invalid' })).rejects.toThrow(
      "Invalid input: baseId must match app + 14 alphanumeric characters, got 'invalid'",
    );
  });

  test('returns empty tables array for base with no tables', async () => {
    vi.mocked(mockService.getBaseSchema).mockResolvedValueOnce({ tables: [] });

    const result = await listTablesForBase(mockService, { baseId });

    expect(result).toEqual({ tables: [] });
  });
});
