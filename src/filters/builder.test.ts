import { describe, expect, test, vi } from 'vitest';
import type { Table } from '../types.js';
import { buildFilterFormula } from './builder.js';

const tableSchema = {
  id: 'tbl1',
  name: 'Contacts',
  primaryFieldId: 'fldText',
  fields: [
    { id: 'fldText', name: 'Name', type: 'singleLineText' },
    { id: 'fldNumber', name: 'Score', type: 'number', options: { precision: 0 } },
    {
      id: 'fldSelect',
      name: 'Status',
      type: 'singleSelect',
      options: { choices: [{ id: 'selA', name: 'Active' }] },
    },
    {
      id: 'fldMulti',
      name: 'Tags',
      type: 'multipleSelects',
      options: { choices: [{ id: 'selT', name: 'Tag' }] },
    },
    {
      id: 'fldDate',
      name: 'Due Date',
      type: 'date',
      options: { dateFormat: { name: 'iso', format: 'YYYY-MM-DD' } },
    },
    {
      id: 'fldAttach',
      name: 'Attachments',
      type: 'multipleAttachments',
      options: { isReversed: false },
    },
  ],
  views: [],
} as unknown as Table;

const tableSchemaWithBraceField = {
  ...tableSchema,
  fields: [
    ...tableSchema.fields,
    { id: 'fldBrace', name: 'Score}', type: 'singleLineText' },
  ],
} as unknown as Table;

describe('buildFilterFormula', () => {
  test('builds equals filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldText', 'Alice'] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}="Alice")');
  });

  test('builds not equals filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '!=', operands: ['fldText', 'Alice'] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}!="Alice")');
  });

  test('builds numeric comparisons', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '>=', operands: ['fldNumber', 10] }],
    }, tableSchema);

    expect(formula).toBe('AND({Score}>=10)');
  });

  test('builds contains filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'contains', operands: ['fldText', 'bob'] }],
    }, tableSchema);

    expect(formula).toBe('AND(FIND(LOWER("bob"), LOWER({Name}))>0)');
  });

  test('builds doesNotContain filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'doesNotContain', operands: ['fldText', 'bob'] }],
    }, tableSchema);

    expect(formula).toBe('AND(OR({Name}=BLANK(), FIND(LOWER("bob"), LOWER({Name}))=0))');
  });

  test('builds isEmpty filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isEmpty', operands: ['fldText'] }],
    }, tableSchema);

    expect(formula).toBe('AND(OR({Name}=BLANK(), {Name}=""))');
  });

  test('builds isNotEmpty filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isNotEmpty', operands: ['fldText'] }],
    }, tableSchema);

    expect(formula).toBe('AND(AND({Name}!=BLANK(), {Name}!=""))');
  });

  test('builds isAnyOf filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isAnyOf', operands: ['fldSelect', ['selA', 'selB']] }],
    }, tableSchema);

    expect(formula).toBe('AND(OR({Status}="selA", {Status}="selB"))');
  });

  test('builds isNoneOf filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isNoneOf', operands: ['fldSelect', ['selA', 'selB']] }],
    }, tableSchema);

    expect(formula).toBe('AND(AND({Status}!="selA", {Status}!="selB"))');
  });

  test('builds hasAnyOf filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'hasAnyOf', operands: ['fldMulti', ['selA', 'selB']] }],
    }, tableSchema);

    expect(formula).toBe('AND(OR(FIND(LOWER("selA"), LOWER(ARRAYJOIN({Tags}, ",")))>0, FIND(LOWER("selB"), LOWER(ARRAYJOIN({Tags}, ",")))>0))');
  });

  test('builds hasAllOf filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'hasAllOf', operands: ['fldMulti', ['selA', 'selB']] }],
    }, tableSchema);

    expect(formula).toBe('AND(AND(FIND(LOWER("selA"), LOWER(ARRAYJOIN({Tags}, ",")))>0, FIND(LOWER("selB"), LOWER(ARRAYJOIN({Tags}, ",")))>0))');
  });

  test('builds isWithin date mode today', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isWithin', operands: ['fldDate', { mode: 'today' }] }],
    }, tableSchema);

    expect(formula).toBe('AND(IS_SAME({Due Date}, TODAY(), "day"))');
  });

  test('builds filename filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'filename', operands: ['fldAttach', 'invoice'] }],
    }, tableSchema);

    expect(formula).toBe('AND(FIND(LOWER("invoice"), LOWER(ARRAYJOIN({Attachments}, ",")))>0)');
  });

  test('builds fileType filter', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'fileType', operands: ['fldAttach', 'pdf'] }],
    }, tableSchema);

    expect(formula).toBe('AND(FIND(LOWER(".pdf"), LOWER(ARRAYJOIN({Attachments}, ",")))>0)');
  });

  test('supports nested and/or expressions', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [
        { operator: 'contains', operands: ['fldText', 'alice'] },
        {
          operator: 'or',
          operands: [
            { operator: '>=', operands: ['fldNumber', 10] },
            { operator: 'isAnyOf', operands: ['fldSelect', ['selA']] },
          ],
        },
      ],
    }, tableSchema);

    expect(formula).toBe('AND(FIND(LOWER("alice"), LOWER({Name}))>0, OR({Score}>=10, OR({Status}="selA")))');
  });

  test('throws explicit error for unsupported date modes', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isWithin', operands: ['fldDate', { mode: 'thisCalendarWeek' }] }],
    }, tableSchema)).toThrow(
      "Date mode 'thisCalendarWeek' not yet supported. Supported modes: [today, tomorrow, yesterday, exactDate, daysAgo, daysFromNow, pastWeek, pastMonth, pastYear, pastNumberOfDays, nextNumberOfDays]",
    );
  });

  test('escapes string value with apostrophe', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldText', "L'appartement"] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}="L\'appartement")');
  });

  test('escapes string value with double quotes', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldText', 'Say "hi"'] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}="Say \\"hi\\"")');
  });

  test('escapes string value with backslash', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldText', 'C:\\path'] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}="C:\\\\path")');
  });

  test('escapes string value with newline', () => {
    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldText', 'line1\nline2'] }],
    }, tableSchema);

    expect(formula).toBe('AND({Name}="line1\\nline2")');
  });

  test('throws for unknown comparison operator', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'startsWith', operands: ['fldText', 'foo'] }],
    }, tableSchema)).toThrow("Unsupported filter operator 'startsWith'.");
  });

  test('throws for unknown root logical operator', () => {
    expect(() => buildFilterFormula({
      operator: 'xor',
      operands: [{ operator: '=', operands: ['fldText', 'foo'] }],
    }, tableSchema)).toThrow("Root filters operator must be 'and' or 'or'.");
  });

  test('throws for empty logical operands array', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [],
    }, tableSchema)).toThrow("Root filters must contain a non-empty 'operands' array.");
  });

  test('throws when using contains on number field', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'contains', operands: ['fldNumber', '10'] }],
    }, tableSchema)).toThrow(
      "Operator 'contains' is not supported on field type 'number' (field: Score). Allowed operators for 'number' fields:",
    );
  });

  test('throws when using < on singleLineText field', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '<', operands: ['fldText', 1] }],
    }, tableSchema)).toThrow(
      "Operator '<' is not supported on field type 'singleLineText' (field: Name). Allowed operators for 'singleLineText' fields:",
    );
  });

  test('throws when using isWithin on singleLineText field', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'isWithin', operands: ['fldText', { mode: 'today' }] }],
    }, tableSchema)).toThrow(
      "Operator 'isWithin' is not supported on field type 'singleLineText' (field: Name). Allowed operators for 'singleLineText' fields:",
    );
  });

  test('throws when using hasAnyOf on singleSelect and suggests isAnyOf', () => {
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'hasAnyOf', operands: ['fldSelect', ['selA']] }],
    }, tableSchema)).toThrow(
      "Operator 'hasAnyOf' is not supported on field type 'singleSelect' (field: Status). Allowed operators for 'singleSelect' fields:",
    );
    expect(() => buildFilterFormula({
      operator: 'and',
      operands: [{ operator: 'hasAnyOf', operands: ['fldSelect', ['selA']] }],
    }, tableSchema)).toThrow("Use 'isAnyOf' or 'isNoneOf' instead of 'hasAnyOf'/'hasAllOf' for singleSelect fields.");
  });

  test('escapes field name containing } in formula reference', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const formula = buildFilterFormula({
      operator: 'and',
      operands: [{ operator: '=', operands: ['fldBrace', 'x'] }],
    }, tableSchemaWithBraceField);

    expect(formula).toBe('AND({Score\\}}="x")');
    expect(warnSpy).toHaveBeenCalledWith(
      "Field name 'Score}' contains '}' which was escaped for formula.",
    );

    warnSpy.mockRestore();
  });
});
