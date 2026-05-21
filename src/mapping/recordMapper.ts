import type { Table } from '../types.js';

export interface AirtableApiRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fields: Record<string, any>;
}

export interface OfficialMcpRecord {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

const createFieldLookupMaps = (tableSchema: Table) => {
  const byId = new Map<string, string>();
  const byName = new Map<string, string>();

  tableSchema.fields.forEach((field) => {
    byId.set(field.id, field.name);
    byName.set(field.name, field.id);
  });

  return { byId, byName };
};

export const fieldsToCellValuesByFieldId = (
  record: AirtableApiRecord,
  tableSchema: Table,
): OfficialMcpRecord => {
  const { byName } = createFieldLookupMaps(tableSchema);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cellValuesByFieldId: Record<string, any> = {};

  Object.entries(record.fields).forEach(([key, value]) => {
    const mappedKey = byName.get(key) ?? key;
    cellValuesByFieldId[mappedKey] = value;
  });

  return record.createdTime
    ? {
      id: record.id,
      createdTime: record.createdTime,
      cellValuesByFieldId,
    }
    : {
      id: record.id,
      cellValuesByFieldId,
    };
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const cellValuesByFieldIdToFields = (cellValues: Record<string, any>, tableSchema: Table): Record<string, any> => {
  const { byId } = createFieldLookupMaps(tableSchema);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fields: Record<string, any> = {};

  Object.entries(cellValues).forEach(([fieldId, value]) => {
    const mappedKey = byId.get(fieldId) ?? fieldId;
    fields[mappedKey] = value;
  });

  return fields;
};
