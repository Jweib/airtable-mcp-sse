import { encodeCursor } from '../pagination/cursor.js';
import type { ListRecordsPageOptions, ListRecordsPageResult } from '../types.js';

export const AIRTABLE_REST_PAGE_SIZE_MAX = 100;
export const MAX_INTERNAL_REST_CALLS = 80;

export interface PaginatedRecordsService {
  listRecordsPage(
    baseId: string,
    tableId: string,
    options: ListRecordsPageOptions,
  ): Promise<ListRecordsPageResult>;
}

export interface AggregatedPageFetchResult {
  records: ListRecordsPageResult['records'];
  nextCursor?: string;
  tableExhausted: boolean;
}

export const fetchAggregatedRecords = async (
  service: PaginatedRecordsService,
  baseId: string,
  tableId: string,
  targetPageSize: number,
  basePageOptions: Omit<ListRecordsPageOptions, 'pageSize' | 'offset'>,
  initialOffset?: string,
  errorContext = 'paginated records fetch',
): Promise<AggregatedPageFetchResult> => {
  const aggregatedRecords: ListRecordsPageResult['records'] = [];
  let currentOffset = initialOffset;
  let nextCursor: string | undefined;
  let restCalls = 0;

  while (aggregatedRecords.length < targetPageSize && restCalls < MAX_INTERNAL_REST_CALLS) {
    const remaining = targetPageSize - aggregatedRecords.length;
    const requestPageSize = Math.min(remaining, AIRTABLE_REST_PAGE_SIZE_MAX);

    const pageOptions: ListRecordsPageOptions = {
      ...basePageOptions,
      pageSize: requestPageSize,
    };
    if (currentOffset) {
      pageOptions.offset = currentOffset;
    }

    restCalls += 1;
    // eslint-disable-next-line no-await-in-loop
    const { records, offset } = await service.listRecordsPage(baseId, tableId, pageOptions);
    aggregatedRecords.push(...records);

    if (aggregatedRecords.length >= targetPageSize) {
      const trimmedRecords = aggregatedRecords.slice(0, targetPageSize);
      const result: AggregatedPageFetchResult = {
        records: trimmedRecords,
        tableExhausted: !offset,
      };
      if (offset) {
        const encoded = encodeCursor(offset);
        if (encoded) {
          result.nextCursor = encoded;
        }
      }
      return result;
    }

    if (!offset) {
      return {
        records: aggregatedRecords,
        tableExhausted: true,
      };
    }

    currentOffset = offset;
  }

  if (restCalls >= MAX_INTERNAL_REST_CALLS) {
    throw new Error(
      `${errorContext} exceeded maximum internal REST calls (${MAX_INTERNAL_REST_CALLS}).`,
    );
  }

  return {
    records: aggregatedRecords,
    tableExhausted: true,
  };
};
