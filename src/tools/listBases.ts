import type { ListBasesResponse } from '../types.js';

export interface ListBasesBaseEntry {
  id: string;
  name: string;
  permissionLevel: string;
}

export interface ListBasesOutput {
  bases: ListBasesBaseEntry[];
}

export interface ListBasesService {
  listBases(): Promise<ListBasesResponse>;
}

export const listBases = async (service: ListBasesService): Promise<ListBasesOutput> => {
  const { bases } = await service.listBases();

  return {
    bases: bases.map((base) => ({
      id: base.id,
      name: base.name,
      permissionLevel: base.permissionLevel,
    })),
  };
};
