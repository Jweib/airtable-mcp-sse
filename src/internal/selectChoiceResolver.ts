import type { Table } from '../types.js';

const CHOICE_ID_PATTERN = /^sel[a-zA-Z0-9]{14}$/;

type SelectChoice = { id?: string; name: string };

const getSelectChoices = (field: Table['fields'][number]): SelectChoice[] | undefined => {
  if (field.type !== 'singleSelect' && field.type !== 'multipleSelects') {
    return undefined;
  }
  const options = field as { options?: { choices?: SelectChoice[] } };
  return options.options?.choices;
};

const resolveChoiceIdToName = (choiceId: string, choices: SelectChoice[]): string => {
  const choice = choices.find((candidate) => candidate.id === choiceId);
  if (!choice) {
    throw new Error(`Unknown select choice id '${choiceId}'.`);
  }
  return choice.name;
};

export const resolveCellValuesSelectChoices = (
  cellValues: Record<string, unknown>,
  table: Table,
): Record<string, unknown> => {
  const resolved: Record<string, unknown> = { ...cellValues };

  Object.entries(cellValues).forEach(([fieldKey, value]) => {
    const field = table.fields.find(
      (candidate) => candidate.id === fieldKey || candidate.name === fieldKey,
    );
    if (!field) {
      return;
    }

    const choices = getSelectChoices(field);
    if (!choices) {
      return;
    }

    if (field.type === 'singleSelect' && typeof value === 'string' && CHOICE_ID_PATTERN.test(value)) {
      resolved[fieldKey] = resolveChoiceIdToName(value, choices);
      return;
    }

    if (field.type === 'multipleSelects' && Array.isArray(value)) {
      resolved[fieldKey] = value.map((entry) => (
        typeof entry === 'string' && CHOICE_ID_PATTERN.test(entry)
          ? resolveChoiceIdToName(entry, choices)
          : entry
      ));
    }
  });

  return resolved;
};
