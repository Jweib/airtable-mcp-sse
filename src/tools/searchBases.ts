import { validationError } from '../internal/validation.js';
import type { ListBasesResponse } from '../types.js';
import type { ListBasesBaseEntry } from './listBases.js';

export interface SearchBasesInput {
  query: string;
}

export interface SearchBasesOutput {
  bases: ListBasesBaseEntry[];
}

export interface SearchBasesService {
  listBases(): Promise<ListBasesResponse>;
}

export const validateSearchBasesInput = (input: SearchBasesInput): SearchBasesInput => {
  if (typeof input.query !== 'string') {
    validationError('query is required');
  }

  const trimmed = input.query.trim();
  if (trimmed.length === 0) {
    validationError('query must not be empty');
  }

  return { query: trimmed };
};

export const searchBases = async (
  service: SearchBasesService,
  rawInput: SearchBasesInput,
): Promise<SearchBasesOutput> => {
  const { query } = validateSearchBasesInput(rawInput);
  const { bases } = await service.listBases();
  const needle = query.toLowerCase();

  const matched = bases
    .filter((base) => base.name.toLowerCase().includes(needle))
    .map((base) => ({
      id: base.id,
      name: base.name,
      permissionLevel: base.permissionLevel,
    }));

  return { bases: matched };
};
