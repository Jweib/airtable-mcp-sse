import nodeFetch, { RequestInit } from 'node-fetch';
import { z } from 'zod';
import {
  IAirtableService,
  ListBasesResponse,
  BaseSchemaResponse,
  ListRecordsPageOptions,
  ListRecordsPageResult,
  Field,
  Table,
  AirtableRecord,
  ListBasesResponseSchema,
  BaseSchemaResponseSchema,
  TableSchema,
  FieldSchema,
  FieldSet,
} from './types.js';

export class AirtableService implements IAirtableService {
  private readonly apiKey: string;

  private readonly baseUrl: string;

  private readonly fetch: typeof nodeFetch;

  constructor(
    apiKey: string,
    baseUrl: string = 'https://api.airtable.com',
    fetch: typeof nodeFetch = nodeFetch,
  ) {
    if (!apiKey) {
      throw new Error('airtable-mcp-server: No API key provided. An API key must be passed to the AirtableService constructor.');
    }

    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
    this.fetch = fetch;
  }

  private async fetchFromAPI<T>(endpoint: string, schema: z.ZodSchema<T>, options: RequestInit = {}): Promise<T> {
    const response = await this.fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    const responseText = await response.text();

    if (!response.ok) {
      throw new Error(`Airtable API Error: ${response.statusText}. Response: ${responseText}`);
    }

    try {
      const data = JSON.parse(responseText);
      return schema.parse(data);
    } catch (parseError) {
      throw new Error(`Failed to parse API response: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
    }
  }

  async listBases(): Promise<ListBasesResponse> {
    return this.fetchFromAPI('/v0/meta/bases', ListBasesResponseSchema);
  }

  async getBaseSchema(baseId: string): Promise<BaseSchemaResponse> {
    return this.fetchFromAPI(`/v0/meta/bases/${baseId}/tables`, BaseSchemaResponseSchema);
  }

  private static buildRecordIdsFilterFormula(recordIds: string[]): string {
    return `OR(${recordIds.map((recordId) => `RECORD_ID()="${recordId.replace(/"/g, '\\"')}"`).join(', ')})`;
  }

  private static mergeFilterFormulas(...formulas: Array<string | undefined>): string | undefined {
    const parts = formulas.filter((formula): formula is string => Boolean(formula));
    if (parts.length === 0) {
      return undefined;
    }
    if (parts.length === 1) {
      return parts[0];
    }
    return `AND(${parts.join(', ')})`;
  }

  async listRecordsPage(
    baseId: string,
    tableId: string,
    options: ListRecordsPageOptions = {},
  ): Promise<ListRecordsPageResult> {
    const queryParams = new URLSearchParams();

    if (options.pageSize) {
      queryParams.append('pageSize', options.pageSize.toString());
    }
    if (options.offset) {
      queryParams.append('offset', options.offset);
    }
    if (options.fields && options.fields.length > 0) {
      options.fields.forEach((fieldName) => {
        queryParams.append('fields[]', fieldName);
      });
    }
    if (options.sort && options.sort.length > 0) {
      options.sort.forEach((sortOption, index) => {
        queryParams.append(`sort[${index}][field]`, sortOption.field);
        if (sortOption.direction) {
          queryParams.append(`sort[${index}][direction]`, sortOption.direction);
        }
      });
    }

    const recordIdsFormula = options.recordIds && options.recordIds.length > 0
      ? AirtableService.buildRecordIdsFilterFormula(options.recordIds)
      : undefined;
    const filterByFormula = AirtableService.mergeFilterFormulas(
      options.filterByFormula,
      recordIdsFormula,
    );
    if (filterByFormula) {
      queryParams.append('filterByFormula', filterByFormula);
    }

    const response = await this.fetchFromAPI(
      `/v0/${baseId}/${tableId}?${queryParams.toString()}`,
      z.object({
        records: z.array(z.object({
          id: z.string(),
          createdTime: z.string(),
          fields: z.record(z.any()),
        })),
        offset: z.string().optional(),
      }),
    );

    const result: ListRecordsPageResult = {
      records: response.records,
    };
    if (response.offset) {
      result.offset = response.offset;
    }
    return result;
  }

  async getRecord(baseId: string, tableId: string, recordId: string): Promise<AirtableRecord> {
    return this.fetchFromAPI(
      `/v0/${baseId}/${tableId}/${recordId}`,
      z.object({ id: z.string(), fields: z.record(z.any()) }),
    );
  }

  async createRecordsPage(
    baseId: string,
    tableId: string,
    records: FieldSet[],
  ): Promise<Array<AirtableRecord & { createdTime?: string }>> {
    const response = await this.fetchFromAPI(
      `/v0/${baseId}/${tableId}`,
      z.object({
        records: z.array(z.object({
          id: z.string(),
          createdTime: z.string().optional(),
          fields: z.record(z.any()),
        })),
      }),
      {
        method: 'POST',
        body: JSON.stringify({
          records: records.map((fields) => ({ fields })),
        }),
      },
    );

    return response.records.map((record) => {
      const mapped: AirtableRecord & { createdTime?: string } = {
        id: record.id,
        fields: record.fields,
      };
      if (record.createdTime) {
        mapped.createdTime = record.createdTime;
      }
      return mapped;
    });
  }

  async updateRecordsPage(
    baseId: string,
    tableId: string,
    records: { id: string; fields: FieldSet }[],
  ): Promise<Array<AirtableRecord & { createdTime?: string }>> {
    const response = await this.fetchFromAPI(
      `/v0/${baseId}/${tableId}`,
      z.object({
        records: z.array(z.object({
          id: z.string(),
          createdTime: z.string().optional(),
          fields: z.record(z.any()),
        })),
      }),
      {
        method: 'PATCH',
        body: JSON.stringify({ records }),
      },
    );

    return response.records.map((record) => {
      const mapped: AirtableRecord & { createdTime?: string } = {
        id: record.id,
        fields: record.fields,
      };
      if (record.createdTime) {
        mapped.createdTime = record.createdTime;
      }
      return mapped;
    });
  }

  async deleteRecordsPage(
    baseId: string,
    tableId: string,
    recordIds: string[],
  ): Promise<Array<{ id: string; deleted: boolean }>> {
    const queryString = recordIds.map((id) => `records[]=${encodeURIComponent(id)}`).join('&');
    const response = await this.fetchFromAPI(
      `/v0/${baseId}/${tableId}?${queryString}`,
      z.object({ records: z.array(z.object({ id: z.string(), deleted: z.boolean() })) }),
      {
        method: 'DELETE',
      },
    );
    return response.records;
  }

  async createTable(baseId: string, name: string, fields: Field[], description?: string): Promise<Table> {
    return this.fetchFromAPI(
      `/v0/meta/bases/${baseId}/tables`,
      TableSchema,
      {
        method: 'POST',
        body: JSON.stringify({ name, description, fields }),
      },
    );
  }

  async updateTable(
    baseId: string,
    tableId: string,
    updates: { name?: string; description?: string },
  ): Promise<Table> {
    return this.fetchFromAPI(
      `/v0/meta/bases/${baseId}/tables/${tableId}`,
      TableSchema,
      {
        method: 'PATCH',
        body: JSON.stringify(updates),
      },
    );
  }

  async createField(baseId: string, tableId: string, field: Omit<Field, 'id'>): Promise<Field> {
    return this.fetchFromAPI(
      `/v0/meta/bases/${baseId}/tables/${tableId}/fields`,
      FieldSchema,
      {
        method: 'POST',
        body: JSON.stringify(field),
      },
    );
  }

  async updateField(
    baseId: string,
    tableId: string,
    fieldId: string,
    updates: { name?: string; description?: string },
  ): Promise<Field> {
    return this.fetchFromAPI(
      `/v0/meta/bases/${baseId}/tables/${tableId}/fields/${fieldId}`,
      FieldSchema,
      {
        method: 'PATCH',
        body: JSON.stringify(updates),
      },
    );
  }

}
