# Migration guide — v1.x → v2.0

This server now exposes only official-aligned data tools plus a small set of schema-admin helpers. Update agent prompts and automations to use the new tool names and response shapes.

## Tool rename map

| v1 tool | v2 tool |
|---------|---------|
| `list_records` | `list_records_for_table` |
| `search_records` | `search_records` (same name, new contract) |
| `describe_table` | `get_table_schema` |
| `describe_base` | `list_tables_for_base` then `get_table_schema` per table |
| `describe_all_bases` | `list_bases` then loop `list_tables_for_base` |
| `list_tables` | `list_tables_for_base` |
| `create_record` | `create_records_for_table` |
| `update_records` | `update_records_for_table` |
| `delete_records` | `delete_records_for_table` |

Unchanged: `get_record`, `create_table`, `update_table`, `create_field`, `update_field`, `list_bases` (name only; output shape changed).

## Parameter changes

### `list_records` → `list_records_for_table`

| v1 | v2 |
|----|-----|
| `tableId` | `tableId` (ID or name) |
| `maxRecords` | `pageSize` (default 1000, max 8000) |
| `filterByFormula` (string) | `filters` (structured object → formula) |
| `sort[].field` (name) | `sort[].fieldId` (ID or name) |
| `view` | *removed* — use `filters` or list in Airtable UI |
| — | `cursor` from previous `nextCursor` |
| — | `fieldIds` to limit returned columns |
| — | `recordIds` to fetch specific records |

### `search_records`

| v1 | v2 |
|----|-----|
| `tableId` | `table` (ID or name) |
| `searchTerm` | `query` |
| `fieldIds` (optional) | `fields` (required): array of field IDs/names or `"ALL_SEARCHABLE_FIELDS"` |
| `maxRecords` | `pageSize` |
| `view` | *removed* |
| — | `cursor` |

### `create_record` → `create_records_for_table`

| v1 | v2 |
|----|-----|
| `fields: { "Name": "x" }` (names) | `records: [{ cellValuesByFieldId: { "fldXXX": "x" } }]` |
| single record | 1–50 records per call |

### `update_records` → `update_records_for_table`

| v1 | v2 |
|----|-----|
| `records[].fields` (names) | `records[].cellValuesByFieldId` (field IDs) |
| up to 10 per REST call | up to 50 per MCP call (batched internally) |

### `delete_records` → `delete_records_for_table`

| v1 | v2 |
|----|-----|
| `recordIds` | `recordIds` (1–50, validated `rec` + 14 chars) |
| response: `[{ id }]` | `{ records: [{ id, deleted: true }] }` |

### `list_bases`

| v1 output | v2 output |
|-----------|-----------|
| `[{ id, name, permissionLevel }]` | `{ bases: [{ id, name, permissionLevel }] }` |

### `list_tables` → `list_tables_for_base`

| v1 | v2 |
|----|-----|
| `detailLevel` (`full`, etc.) | *removed* — always compact |
| fields/views in response | use `get_table_schema` for full schema |

Output:

```json
{
  "tables": [
    { "id": "tblXXX", "name": "...", "primaryFieldId": "fldXXX" }
  ]
}
```

## Output format: `fields` vs `cellValuesByFieldId`

| Context | v1 | v2 |
|---------|----|-----|
| MCP record tools | Airtable field **names** in `fields` | Field **IDs** (`fld...`) in `cellValuesByFieldId` |
| REST layer (internal) | names | names (converted inside the server) |
| `get_record` (P4) | still `{ id, fields }` with names | unchanged |

Example v2 list response:

```json
{
  "records": [{
    "id": "recXXX",
    "createdTime": "2026-04-20T19:34:18.000Z",
    "cellValuesByFieldId": {
      "fldName": "Alice",
      "fldStatus": "Done"
    }
  }],
  "nextCursor": "opaque-token"
}
```

## Pagination: offset vs cursor

- v1 `list_records` followed Airtable REST `offset` internally but did not expose it; it returned all pages merged up to `maxRecords`.
- v2 `list_records_for_table` and `search_records` expose an opaque **`nextCursor`** in the MCP response. Pass it back as `cursor` for the next page.
- `list_records_for_table` always includes `metadata.totalRecordCount` (the total number of matching records), even when `nextCursor` is present.
  - This may require extra internal REST calls to compute the count.
  - The server enforces a safety cap on count pagination (currently 80 REST calls). If exceeded, it returns an error instead of an incorrect partial count.

There is no `offset` parameter on MCP tools.

## Replacing `describe_all_bases`

```text
1. list_bases → bases[]
2. For each base: list_tables_for_base
3. For each table needing detail: get_table_schema
```

## Select fields (singleSelect / multipleSelects)

When writing via `create_records_for_table` or `update_records_for_table`, you may pass either:

- choice **name** (string), or
- choice **ID** (`sel` + 14 characters) — resolved to name before the REST call.

## Questions

Open an issue on the project repository if a v1 workflow has no clear v2 equivalent.
