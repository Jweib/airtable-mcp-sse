import { describe, expect, test, vi } from 'vitest';
import { searchBases } from './searchBases.js';
import type { SearchBasesService } from './searchBases.js';

const mockBases = {
  bases: [
    { id: 'appAAAAAAAAAAAAAA', name: 'CRM Alpha', permissionLevel: 'owner' },
    { id: 'appBBBBBBBBBBBBBB', name: 'Inventory Beta', permissionLevel: 'edit' },
    { id: 'appCCCCCCCCCCCCCC', name: 'alpha archive', permissionLevel: 'read' },
  ],
};

describe('searchBases', () => {
  const mockService: SearchBasesService = {
    listBases: vi.fn().mockResolvedValue(mockBases),
  };

  test('matches bases whose name contains the query', async () => {
    const result = await searchBases(mockService, { query: 'CRM' });

    expect(result.bases).toEqual([
      { id: 'appAAAAAAAAAAAAAA', name: 'CRM Alpha', permissionLevel: 'owner' },
    ]);
  });

  test('is case-insensitive', async () => {
    const result = await searchBases(mockService, { query: 'ALPHA' });

    expect(result.bases).toHaveLength(2);
    expect(result.bases.map((base) => base.name)).toEqual(['CRM Alpha', 'alpha archive']);
  });

  test('empty or whitespace query throws validation error', async () => {
    await expect(searchBases(mockService, { query: '' })).rejects.toThrow(
      'Invalid input: query must not be empty',
    );
    await expect(searchBases(mockService, { query: '   ' })).rejects.toThrow(
      'Invalid input: query must not be empty',
    );
  });

  test('returns empty bases array when no name matches', async () => {
    const result = await searchBases(mockService, { query: 'nonexistent' });

    expect(result).toEqual({ bases: [] });
  });

  test('output uses official base entry shape', async () => {
    const result = await searchBases(mockService, { query: 'Inventory' });

    expect(result).toEqual({
      bases: [
        { id: 'appBBBBBBBBBBBBBB', name: 'Inventory Beta', permissionLevel: 'edit' },
      ],
    });
  });
});
