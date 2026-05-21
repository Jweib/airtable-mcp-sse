import type { Field, Table } from '../types.js';

const SUPPORTED_DATE_MODES = [
  'today',
  'tomorrow',
  'yesterday',
  'exactDate',
  'daysAgo',
  'daysFromNow',
  'pastWeek',
  'pastMonth',
  'pastYear',
  'pastNumberOfDays',
  'nextNumberOfDays',
] as const;

type SupportedDateMode = (typeof SUPPORTED_DATE_MODES)[number];
type LogicalOperator = 'and' | 'or';
type ComparisonOperator =
  | '='
  | '!='
  | '<'
  | '>'
  | '<='
  | '>='
  | 'contains'
  | 'doesNotContain'
  | 'isEmpty'
  | 'isNotEmpty'
  | 'isAnyOf'
  | 'isNoneOf'
  | 'hasAnyOf'
  | 'hasAllOf'
  | 'isWithin'
  | 'filename'
  | 'fileType';

const TEXT_SEARCH_OPERATORS: ComparisonOperator[] = ['contains', 'doesNotContain'];
const NUMERIC_COMPARE_OPERATORS: ComparisonOperator[] = ['<', '>', '<=', '>='];
const HAS_ANY_ALL_OPERATORS: ComparisonOperator[] = ['hasAnyOf', 'hasAllOf'];
const IS_ANY_NONE_OPERATORS: ComparisonOperator[] = ['isAnyOf', 'isNoneOf'];
const DATE_OPERATORS: ComparisonOperator[] = ['isWithin'];
const ATTACHMENT_OPERATORS: ComparisonOperator[] = ['filename', 'fileType'];
const UNIVERSAL_OPERATORS: ComparisonOperator[] = ['=', '!=', 'isEmpty', 'isNotEmpty'];

const TEXT_FIELD_TYPES = new Set([
  'singleLineText',
  'multilineText',
  'richText',
  'email',
  'url',
  'phoneNumber',
  'autoNumber',
  'barcode',
]);

const NUMERIC_FIELD_TYPES = new Set([
  'number',
  'currency',
  'percent',
  'rating',
  'count',
  'duration',
  'autoNumber',
]);

const HAS_ANY_ALL_FIELD_TYPES = new Set([
  'multipleSelects',
  'multipleAttachments',
  'multipleRecordLinks',
  'multipleCollaborators',
]);

const IS_ANY_NONE_FIELD_TYPES = new Set(['singleSelect', 'singleCollaborator']);

const DATE_FIELD_TYPES = new Set(['date', 'dateTime', 'createdTime', 'lastModifiedTime']);

const ATTACHMENT_FIELD_TYPES = new Set(['multipleAttachments']);

interface LogicalFilterNode {
  operator: LogicalOperator;
  operands: FilterNode[];
}

interface ComparisonFilterNode {
  operator: ComparisonOperator;
  operands: unknown[];
}

type FilterNode = LogicalFilterNode | ComparisonFilterNode;

interface DateModeValue {
  mode: string;
  date?: string;
  amount?: number;
}

type SchemaField = Field & { id: string };

const assertIsObject = (value: unknown, errorMessage: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(errorMessage);
  }
  return value as Record<string, unknown>;
};

export const escapeStringValue = (value: string): string => value
  .replace(/\\/g, '\\\\')
  .replace(/"/g, '\\"')
  .replace(/\n/g, '\\n')
  .replace(/\r/g, '\\r')
  .replace(/\t/g, '\\t');

const escapeFieldNameForFormula = (fieldName: string): string => {
  let escaped = fieldName;
  if (fieldName.includes('}')) {
    // eslint-disable-next-line no-console
    console.warn(`Field name '${fieldName}' contains '}' which was escaped for formula.`);
    escaped = escaped.replace(/}/g, '\\}');
  }
  if (fieldName.includes('"')) {
    // eslint-disable-next-line no-console
    console.warn(`Field name '${fieldName}' contains '"' which was escaped for formula.`);
    escaped = escaped.replace(/"/g, '\\"');
  }
  return escaped;
};

const asFormulaValue = (value: unknown): string => {
  if (typeof value === 'string') return `"${escapeStringValue(value)}"`;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? 'TRUE()' : 'FALSE()';
  throw new Error(`Unsupported filter value type: ${typeof value}`);
};

const resolveField = (fieldIdentifier: unknown, tableSchema: Table): SchemaField => {
  if (typeof fieldIdentifier !== 'string') {
    throw new Error('Expected first operand to be a field identifier string.');
  }

  const field = tableSchema.fields.find(
    (candidate): candidate is SchemaField => (
      candidate.id === fieldIdentifier || candidate.name === fieldIdentifier
    ),
  );
  if (!field) {
    throw new Error(`Unknown field '${fieldIdentifier}' in filters.`);
  }

  return field;
};

/**
 * Airtable filterByFormula resolves fields by display name inside curly braces (e.g. {Name}),
 * not by field id ({fldXXX}). The REST API does not accept {fld...} as a field reference in
 * formulas (see Airtable support docs on filterByFormula). MCP filter operands use field IDs
 * or names; we resolve to the schema field and emit an escaped *name* reference for the API.
 */
const getFieldReference = (field: SchemaField): string => `{${escapeFieldNameForFormula(field.name)}}`;

const getAllowedOperatorsForFieldType = (fieldType: string): string[] => {
  const allowed = new Set<string>(UNIVERSAL_OPERATORS);

  if (TEXT_FIELD_TYPES.has(fieldType) || fieldType === 'formula') {
    TEXT_SEARCH_OPERATORS.forEach((operator) => allowed.add(operator));
  }
  if (NUMERIC_FIELD_TYPES.has(fieldType) || fieldType === 'formula') {
    NUMERIC_COMPARE_OPERATORS.forEach((operator) => allowed.add(operator));
  }
  if (HAS_ANY_ALL_FIELD_TYPES.has(fieldType)) {
    HAS_ANY_ALL_OPERATORS.forEach((operator) => allowed.add(operator));
  }
  if (IS_ANY_NONE_FIELD_TYPES.has(fieldType)) {
    IS_ANY_NONE_OPERATORS.forEach((operator) => allowed.add(operator));
  }
  if (DATE_FIELD_TYPES.has(fieldType)) {
    DATE_OPERATORS.forEach((operator) => allowed.add(operator));
  }
  if (ATTACHMENT_FIELD_TYPES.has(fieldType)) {
    ATTACHMENT_OPERATORS.forEach((operator) => allowed.add(operator));
  }

  return Array.from(allowed).sort();
};

const validateOperatorForField = (operator: string, field: SchemaField): void => {
  const fieldType = field.type;
  const allowedForField = getAllowedOperatorsForFieldType(fieldType);
  const formatError = (hint?: string) => {
    const suffix = hint ? ` ${hint}` : '';
    throw new Error(
      `Operator '${operator}' is not supported on field type '${fieldType}' (field: ${field.name}). `
      + `Allowed operators for '${fieldType}' fields: [${allowedForField.join(', ')}].${suffix}`,
    );
  };

  if (TEXT_SEARCH_OPERATORS.includes(operator as ComparisonOperator)) {
    if (fieldType === 'formula') {
      // eslint-disable-next-line no-console
      console.warn(
        `Operator '${operator}' used on formula field '${field.name}': return type is unknown, allowing with warning.`,
      );
      return;
    }
    if (!TEXT_FIELD_TYPES.has(fieldType)) {
      formatError();
    }
    return;
  }

  if (NUMERIC_COMPARE_OPERATORS.includes(operator as ComparisonOperator)) {
    if (fieldType === 'formula') {
      // eslint-disable-next-line no-console
      console.warn(
        `Operator '${operator}' used on formula field '${field.name}': return type is unknown, allowing with warning.`,
      );
      return;
    }
    if (!NUMERIC_FIELD_TYPES.has(fieldType)) {
      formatError();
    }
    return;
  }

  if (HAS_ANY_ALL_OPERATORS.includes(operator as ComparisonOperator)) {
    if (!HAS_ANY_ALL_FIELD_TYPES.has(fieldType)) {
      const hint = fieldType === 'singleSelect'
        ? "Use 'isAnyOf' or 'isNoneOf' instead of 'hasAnyOf'/'hasAllOf' for singleSelect fields."
        : undefined;
      formatError(hint);
    }
    return;
  }

  if (IS_ANY_NONE_OPERATORS.includes(operator as ComparisonOperator)) {
    if (!IS_ANY_NONE_FIELD_TYPES.has(fieldType)) {
      formatError();
    }
    return;
  }

  if (DATE_OPERATORS.includes(operator as ComparisonOperator)) {
    if (!DATE_FIELD_TYPES.has(fieldType)) {
      formatError();
    }
    return;
  }

  if (ATTACHMENT_OPERATORS.includes(operator as ComparisonOperator)) {
    if (!ATTACHMENT_FIELD_TYPES.has(fieldType)) {
      formatError();
    }
  }
};

const requireArrayValue = (value: unknown, operator: string): unknown[] => {
  if (!Array.isArray(value)) {
    throw new Error(`Operator '${operator}' expects an array as second operand.`);
  }
  return value;
};

const requireNonEmptyArrayValue = (value: unknown, operator: string): unknown[] => {
  const arrayValue = requireArrayValue(value, operator);
  if (arrayValue.length === 0) {
    throw new Error(`Operator '${operator}' expects a non-empty array as second operand.`);
  }
  return arrayValue;
};

const buildDateFormula = (fieldRef: string, rawDateValue: unknown): string => {
  const dateValue = assertIsObject(
    rawDateValue,
    "Operator 'isWithin' expects an object with at least a 'mode' property as second operand.",
  );
  const mode = dateValue.mode;
  if (typeof mode !== 'string') {
    throw new Error("Operator 'isWithin' expects a string 'mode' value.");
  }

  const typedDateValue = dateValue as unknown as DateModeValue;
  if (!SUPPORTED_DATE_MODES.includes(mode as SupportedDateMode)) {
    throw new Error(
      `Date mode '${mode}' not yet supported. Supported modes: [${SUPPORTED_DATE_MODES.join(', ')}]`,
    );
  }

  switch (mode as SupportedDateMode) {
    case 'today':
      return `IS_SAME(${fieldRef}, TODAY(), "day")`;
    case 'tomorrow':
      return `IS_SAME(${fieldRef}, DATEADD(TODAY(), 1, "day"), "day")`;
    case 'yesterday':
      return `IS_SAME(${fieldRef}, DATEADD(TODAY(), -1, "day"), "day")`;
    case 'exactDate': {
      if (typeof typedDateValue.date !== 'string') {
        throw new Error("Date mode 'exactDate' expects a 'date' string.");
      }
      return `IS_SAME(${fieldRef}, DATETIME_PARSE("${escapeStringValue(typedDateValue.date)}"), "day")`;
    }
    case 'daysAgo': {
      if (typeof typedDateValue.amount !== 'number') {
        throw new Error("Date mode 'daysAgo' expects an 'amount' number.");
      }
      return `IS_SAME(${fieldRef}, DATEADD(TODAY(), -${typedDateValue.amount}, "day"), "day")`;
    }
    case 'daysFromNow': {
      if (typeof typedDateValue.amount !== 'number') {
        throw new Error("Date mode 'daysFromNow' expects an 'amount' number.");
      }
      return `IS_SAME(${fieldRef}, DATEADD(TODAY(), ${typedDateValue.amount}, "day"), "day")`;
    }
    case 'pastWeek':
      return `IS_AFTER(${fieldRef}, DATEADD(TODAY(), -1, "week"))`;
    case 'pastMonth':
      return `IS_AFTER(${fieldRef}, DATEADD(TODAY(), -1, "month"))`;
    case 'pastYear':
      return `IS_AFTER(${fieldRef}, DATEADD(TODAY(), -1, "year"))`;
    case 'pastNumberOfDays': {
      if (typeof typedDateValue.amount !== 'number') {
        throw new Error("Date mode 'pastNumberOfDays' expects an 'amount' number.");
      }
      return `IS_AFTER(${fieldRef}, DATEADD(TODAY(), -${typedDateValue.amount}, "day"))`;
    }
    case 'nextNumberOfDays': {
      if (typeof typedDateValue.amount !== 'number') {
        throw new Error("Date mode 'nextNumberOfDays' expects an 'amount' number.");
      }
      return `IS_BEFORE(${fieldRef}, DATEADD(TODAY(), ${typedDateValue.amount}, "day"))`;
    }
    default:
      throw new Error(`Unexpected date mode '${mode}'.`);
  }
};

const buildComparisonFormula = (
  operator: ComparisonOperator,
  operands: unknown[],
  tableSchema: Table,
): string => {
  const field = resolveField(operands[0], tableSchema);
  validateOperatorForField(operator, field);
  const fieldRef = getFieldReference(field);

  switch (operator) {
    case '=':
    case '!=':
    case '<':
    case '>':
    case '<=':
    case '>=':
      return `${fieldRef}${operator}${asFormulaValue(operands[1])}`;
    case 'contains':
      return `FIND(LOWER(${asFormulaValue(operands[1])}), LOWER(${fieldRef}))>0`;
    case 'doesNotContain':
      return `OR(${fieldRef}=BLANK(), FIND(LOWER(${asFormulaValue(operands[1])}), LOWER(${fieldRef}))=0)`;
    case 'isEmpty':
      return `OR(${fieldRef}=BLANK(), ${fieldRef}="")`;
    case 'isNotEmpty':
      return `AND(${fieldRef}!=BLANK(), ${fieldRef}!="")`;
    case 'isAnyOf': {
      const values = requireNonEmptyArrayValue(operands[1], operator);
      return `OR(${values.map((value) => `${fieldRef}=${asFormulaValue(value)}`).join(', ')})`;
    }
    case 'isNoneOf': {
      const values = requireNonEmptyArrayValue(operands[1], operator);
      return `AND(${values.map((value) => `${fieldRef}!=${asFormulaValue(value)}`).join(', ')})`;
    }
    case 'hasAnyOf': {
      const values = requireNonEmptyArrayValue(operands[1], operator);
      return `OR(${values.map((value) => `FIND(LOWER(${asFormulaValue(value)}), LOWER(ARRAYJOIN(${fieldRef}, ",")))>0`).join(', ')})`;
    }
    case 'hasAllOf': {
      const values = requireNonEmptyArrayValue(operands[1], operator);
      return `AND(${values.map((value) => `FIND(LOWER(${asFormulaValue(value)}), LOWER(ARRAYJOIN(${fieldRef}, ",")))>0`).join(', ')})`;
    }
    case 'isWithin':
      return buildDateFormula(fieldRef, operands[1]);
    case 'filename':
      return `FIND(LOWER(${asFormulaValue(operands[1])}), LOWER(ARRAYJOIN(${fieldRef}, ",")))>0`;
    case 'fileType':
      return `FIND(LOWER(${asFormulaValue(`.${String(operands[1])}`)}), LOWER(ARRAYJOIN(${fieldRef}, ",")))>0`;
    default:
      throw new Error(`Unsupported filter operator '${operator}'.`);
  }
};

const buildNodeFormula = (node: FilterNode, tableSchema: Table): string => {
  if (node.operator === 'and' || node.operator === 'or') {
    if (!Array.isArray(node.operands) || node.operands.length === 0) {
      throw new Error(`Logical operator '${node.operator}' expects a non-empty operands array.`);
    }
    const logicalKeyword = node.operator.toUpperCase();
    return `${logicalKeyword}(${node.operands.map((childNode) => buildNodeFormula(childNode, tableSchema)).join(', ')})`;
  }

  const comparisonNode = node as ComparisonFilterNode;
  if (!Array.isArray(comparisonNode.operands)) {
    throw new Error(`Operator '${comparisonNode.operator}' expects an operands array.`);
  }
  if (comparisonNode.operands.length === 0) {
    throw new Error(`Operator '${comparisonNode.operator}' expects at least one operand.`);
  }

  return buildUnknownComparisonFormula(String(comparisonNode.operator), comparisonNode.operands, tableSchema);
};

const buildUnknownComparisonFormula = (
  operator: string,
  operands: unknown[],
  tableSchema: Table,
): string => {
  const supportedOperators: ComparisonOperator[] = [
    '=', '!=', '<', '>', '<=', '>=',
    'contains', 'doesNotContain', 'isEmpty', 'isNotEmpty',
    'isAnyOf', 'isNoneOf', 'hasAnyOf', 'hasAllOf',
    'isWithin', 'filename', 'fileType',
  ];

  if (!supportedOperators.includes(operator as ComparisonOperator)) {
    throw new Error(`Unsupported filter operator '${operator}'.`);
  }

  return buildComparisonFormula(operator as ComparisonOperator, operands, tableSchema);
};

export const buildFilterFormula = (filters: unknown, tableSchema: Table): string => {
  const root = assertIsObject(filters, "Filters must be an object with 'operator' and 'operands'.");
  const operator = root.operator;
  const operands = root.operands;

  if (operator !== 'and' && operator !== 'or') {
    throw new Error("Root filters operator must be 'and' or 'or'.");
  }
  if (!Array.isArray(operands) || operands.length === 0) {
    throw new Error("Root filters must contain a non-empty 'operands' array.");
  }

  return buildNodeFormula({ operator, operands } as LogicalFilterNode, tableSchema);
};

export const buildComparisonFilterFormula = (
  operator: string,
  operands: unknown[],
  tableSchema: Table,
): string => buildUnknownComparisonFormula(operator, operands, tableSchema);
