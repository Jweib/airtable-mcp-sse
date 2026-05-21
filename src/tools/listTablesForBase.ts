import { validateBaseId } from '../internal/validation.js';
import type { BaseSchemaResponse } from '../types.js';

export interface ListTablesForBaseInput {
  baseId: string;
}

export interface ListTablesForBaseTableEntry {
  id: string;
  name: string;
  primaryFieldId: string;
}

export interface ListTablesForBaseOutput {
  tables: ListTablesForBaseTableEntry[];
}

export interface ListTablesForBaseService {
  getBaseSchema(baseId: string): Promise<BaseSchemaResponse>;
}

export const validateListTablesForBaseInput = (input: ListTablesForBaseInput): ListTablesForBaseInput => {
  validateBaseId(input.baseId);
  return input;
};

export const listTablesForBase = async (
  service: ListTablesForBaseService,
  rawInput: ListTablesForBaseInput,
): Promise<ListTablesForBaseOutput> => {
  const validated = validateListTablesForBaseInput(rawInput);
  const schema = await service.getBaseSchema(validated.baseId);

  return {
    tables: schema.tables.map((table) => ({
      id: table.id,
      name: table.name,
      primaryFieldId: table.primaryFieldId,
    })),
  };
};
