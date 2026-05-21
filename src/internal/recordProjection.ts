import { fieldsToCellValuesByFieldId } from '../mapping/recordMapper.js';
import type { AirtableApiRecord } from '../mapping/recordMapper.js';
import type { Table } from '../types.js';

export interface OfficialMcpRecordOutput {
  id: string;
  createdTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cellValuesByFieldId: Record<string, any>;
}

export const projectRecordToOfficialFormat = (
  record: AirtableApiRecord,
  table: Table,
  fieldIds?: string[],
): OfficialMcpRecordOutput => {
  const mapped = fieldsToCellValuesByFieldId(record, table);
  const createdTime = mapped.createdTime ?? record.createdTime;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const buildRecord = (cellValuesByFieldId: Record<string, any>): OfficialMcpRecordOutput => (
    createdTime
      ? { id: mapped.id, createdTime, cellValuesByFieldId }
      : { id: mapped.id, cellValuesByFieldId }
  );

  if (!fieldIds || fieldIds.length === 0) {
    return buildRecord(mapped.cellValuesByFieldId);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cellValuesByFieldId: Record<string, any> = {};
  fieldIds.forEach((fieldId) => {
    if (fieldId in mapped.cellValuesByFieldId) {
      cellValuesByFieldId[fieldId] = mapped.cellValuesByFieldId[fieldId];
    }
  });

  return buildRecord(cellValuesByFieldId);
};
