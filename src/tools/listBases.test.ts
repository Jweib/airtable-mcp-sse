import { describe, expect, test, vi } from 'vitest';
import { listBases } from './listBases.js';
import type { ListBasesService } from './listBases.js';

describe('listBases', () => {
  test('returns bases wrapped in official output shape', async () => {
    const mockService: ListBasesService = {
      listBases: vi.fn().mockResolvedValue({
        bases: [
          { id: 'appAAAAAAAAAAAAAA', name: 'CRM', permissionLevel: 'owner' },
          { id: 'appBBBBBBBBBBBBBB', name: 'Inventory', permissionLevel: 'edit' },
        ],
      }),
    };

    const result = await listBases(mockService);

    expect(result).toEqual({
      bases: [
        { id: 'appAAAAAAAAAAAAAA', name: 'CRM', permissionLevel: 'owner' },
        { id: 'appBBBBBBBBBBBBBB', name: 'Inventory', permissionLevel: 'edit' },
      ],
    });
    expect(mockService.listBases).toHaveBeenCalledOnce();
  });

  test('returns empty bases array when none accessible', async () => {
    const mockService: ListBasesService = {
      listBases: vi.fn().mockResolvedValue({ bases: [] }),
    };

    const result = await listBases(mockService);

    expect(result).toEqual({ bases: [] });
  });
});
