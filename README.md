# airtable-mcp-server

[![smithery badge](https://smithery.ai/badge/airtable-mcp-server)](https://smithery.ai/server/airtable-mcp-server)

A Model Context Protocol server that provides read and write access to Airtable databases, aligned with the official Airtable MCP tool contracts.

https://github.com/user-attachments/assets/c8285e76-d0ed-4018-94c7-20535db6c944

## Usage

1. **Start the server**:
   ```bash
   npm start
   ```
   The server listens on port 8080.

2. **Configure your client**:
   Add this to the `mcpServers` section of your MCP client configuration. Provide your [Airtable personal access token](https://airtable.com/create/tokens) as a Bearer token.

   ```json
   {
     "mcpServers": {
       "airtable": {
         "url": "http://localhost:8080/sse",
         "headers": {
           "Authorization": "Bearer pat123.abc123"
         }
       }
     }
   }
   ```

   Required scopes: at least `schema.bases:read` and `data.records:read`, plus write scopes if you create or update data.

## MCP tools (v2)

### Records and tables

| Tool | Description |
|------|-------------|
| `list_records_for_table` | List records with `cellValuesByFieldId`, filters, sort, cursor pagination |
| `search_records` | Tokenized text search across selected fields |
| `get_table_schema` | Full table schema (fields, views, types) |
| `create_records_for_table` | Create up to 50 records per call (batched to REST) |
| `update_records_for_table` | Update up to 50 records per call (PATCH, batched) |
| `delete_records_for_table` | Delete up to 50 records per call (batched) |

**Example — list records:**

```json
{
  "name": "list_records_for_table",
  "arguments": {
    "baseId": "appXXXXXXXXXXXXXX",
    "tableId": "Contacts",
    "pageSize": 100,
    "fieldIds": ["fldName", "fldEmail"]
  }
}
```

**Response shape:**

```json
{
  "records": [
    {
      "id": "recXXXXXXXXXXXXXX",
      "createdTime": "2026-04-20T19:34:18.000Z",
      "cellValuesByFieldId": { "fldName": "Alice" }
    }
  ],
  "metadata": { "totalRecordCount": 1 }
}
```

**Example — search:**

```json
{
  "name": "search_records",
  "arguments": {
    "baseId": "appXXXXXXXXXXXXXX",
    "table": "Contacts",
    "query": "acme paris",
    "fields": "ALL_SEARCHABLE_FIELDS",
    "pageSize": 50
  }
}
```

**Example — create records:**

```json
{
  "name": "create_records_for_table",
  "arguments": {
    "baseId": "appXXXXXXXXXXXXXX",
    "tableId": "tblXXXXXXXXXXXXXX",
    "records": [
      { "cellValuesByFieldId": { "fldName": "New row" } }
    ]
  }
}
```

### Discovery

| Tool | Description |
|------|-------------|
| `list_bases` | All accessible bases |
| `search_bases` | Filter bases by name (case-insensitive) |
| `list_tables_for_base` | Compact table list (`id`, `name`, `primaryFieldId`) |

**Example — list bases:**

```json
{ "name": "list_bases", "arguments": {} }
```

```json
{
  "bases": [
    { "id": "appXXX", "name": "CRM", "permissionLevel": "owner" }
  ]
}
```

### Schema admin (non-official, retained)

These tools use the Airtable Metadata API and legacy `{ fields }` payloads. They are convenient for bootstrapping bases but are not part of the official record-oriented MCP contract.

| Tool | Description |
|------|-------------|
| `get_record` | Fetch one record by ID (`{ id, fields }`) |
| `create_table` | Create a table |
| `update_table` | Rename or describe a table |
| `create_field` | Add a field |
| `update_field` | Rename or describe a field |

## Resources

Table schemas are exposed as MCP resources:

- URI: `airtable://<baseId>/<tableId>/schema`
- JSON includes field types, options, and views (same detail as a full schema read).

## Migration from v1

See [MIGRATION.md](./MIGRATION.md) for renamed tools, parameter changes, and output format differences.

## Hosting with Docker

```bash
docker build -t airtable-mcp-server .
docker run -p 8080:8080 -e AIRTABLE_API_KEY=pat... airtable-mcp-server
```

Use HTTPS in production (reverse proxy in front of port 8080).

## Contributing

```bash
npm install
npm test
npm run build
```

## Releases

Versions follow [semantic versioning](https://semver.org/). See [CHANGELOG.md](./CHANGELOG.md).
