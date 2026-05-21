export const BASE_ID_PATTERN = /^app[a-zA-Z0-9]{14}$/;
export const RECORD_ID_PATTERN = /^rec[a-zA-Z0-9]{14}$/;
export const DEFAULT_PAGE_SIZE = 1000;
export const MAX_PAGE_SIZE = 8000;

export const validationError = (message: string): never => {
  throw new Error(`Invalid input: ${message}`);
};

export const validateBaseId = (baseId: string): void => {
  if (!BASE_ID_PATTERN.test(baseId)) {
    validationError(`baseId must match app + 14 alphanumeric characters, got '${baseId}'`);
  }
};

export const validatePageSize = (pageSize: number | undefined): number => {
  if (pageSize !== undefined) {
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
      validationError(`pageSize must be between 1 and ${MAX_PAGE_SIZE}, got ${pageSize}`);
    }
  }
  return pageSize ?? DEFAULT_PAGE_SIZE;
};
