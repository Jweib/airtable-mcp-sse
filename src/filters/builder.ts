import type { Table } from '../types.js';

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

const assertIsObject = (value: unknown, errorMessage: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(errorMessage);
  }
  return value as Record<string, unknown>;
};

const escapeStringValue = (value: string): string => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

const asFormulaValue = (value: unknown): string => {
  if (typeof value === 'string') return `"${escapeStringValue(value)}"`;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? 'TRUE()' : 'FALSE()';
  throw new Error(`Unsupported filter value type: ${typeof value}`);
};

const getFieldReference = (fieldIdentifier: unknown, tableSchema: Table): string => {
  if (typeof fieldIdentifier !== 'string') {
    throw new Error('Expected first operand to be a field identifier string.');
  }

  const field = tableSchema.fields.find(
    (candidate) => candidate.id === fieldIdentifier || candidate.name === fieldIdentifier,
  );
  if (!field) {
    throw new Error(`Unknown field '${fieldIdentifier}' in filters.`);
  }

  return `{${field.name}}`;
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

const buildComparisonFormula = (operator: ComparisonOperator, operands: unknown[], tableSchema: Table): string => {
  const fieldRef = getFieldReference(operands[0], tableSchema);

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

  return buildComparisonFormula(comparisonNode.operator, comparisonNode.operands, tableSchema);
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
