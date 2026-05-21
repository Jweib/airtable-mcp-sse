import { describe, expect, test } from 'vitest';
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
});
