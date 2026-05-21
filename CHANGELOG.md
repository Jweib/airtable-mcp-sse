# Changelog

## 2.0.0 — 2026-05-21

### Breaking changes

Legacy MCP tools removed. Use the official-aligned replacements (see [MIGRATION.md](./MIGRATION.md)).

| Removed | Replacement |
|---------|-------------|
| `list_records` | `list_records_for_table` |
| `search_records` (legacy API) | `search_records` (new input/output) |
| `describe_table` | `get_table_schema` |
| `describe_base` | `list_tables_for_base` + `get_table_schema` |
| `describe_all_bases` | `list_bases` + per-base `list_tables_for_base` |
| `list_tables` | `list_tables_for_base` |
| `create_record` | `create_records_for_table` |
| `update_records` | `update_records_for_table` |
| `delete_records` | `delete_records_for_table` |

### Added

- Official-aligned record I/O with `cellValuesByFieldId` and cursor pagination (`nextCursor`).
- Structured filters for `list_records_for_table` (translated to `filterByFormula`).
- `search_bases` for base discovery by name.
- Internal batching for create/update/delete (up to 50 records per MCP call, 10 per REST request).

### Changed

- `list_bases` now returns `{ bases: [...] }` instead of a bare array.
- Server version reported as `2.0.0`.

### Removed (service layer)

- `AirtableService.listRecords`, `searchRecords`, `createRecord`, `updateRecords`, `deleteRecords`, `describeBase`, `describeAllBases`.

### Unchanged (P4)

- `get_record`, `create_table`, `update_table`, `create_field`, `update_field`
- MCP resources (`airtable://.../schema`)

## 1.5.x and earlier

See git history for the pre-alignment tool surface.
