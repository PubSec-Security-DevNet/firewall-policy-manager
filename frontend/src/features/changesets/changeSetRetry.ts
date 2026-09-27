import type { ChangeSet } from '../../api/client';

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function retryableChangeSet(item: ChangeSet) {
  const operationKinds = new Map(
    item.operations.map((operation) => [operation.id, operation.kind]),
  );
  const partialCategoryRecovery =
    item.state === 'PARTIALLY_SUCCEEDED' &&
    item.transactions.length > 0 &&
    item.transactions.every(
      (transaction) =>
        !transaction.reconciliation_required &&
        transaction.operation_results.length > 0 &&
        transaction.operation_results.every(
          (result) =>
            (result.status === 'SUCCEEDED' &&
              result.mutated === true &&
              ['ENSURE_RULE_CATEGORY', 'CREATE_OBJECT'].includes(
                operationKinds.get(stringValue(result.operation_id)) ?? '',
              )) ||
            (result.mutated === false &&
              ['FAILED', 'CONFLICT', 'NOT_ATTEMPTED'].includes(stringValue(result.status))),
        ),
    );
  const safeTransactions = item.transactions.every(
    (transaction) =>
      !transaction.reconciliation_required &&
      transaction.operation_results.length > 0 &&
      transaction.operation_results.every(
        (result) =>
          result.mutated === false &&
          ['SUCCEEDED', 'FAILED', 'CONFLICT', 'NOT_ATTEMPTED'].includes(stringValue(result.status)),
      ),
  );
  const interruptedIdempotentCreate =
    item.state === 'FAILED' &&
    stringValue(record(item.failure_info).code) === 'CHANGE_SET_EXECUTION_ERROR' &&
    item.transactions.length > 0 &&
    item.operations.every((operation) =>
      ['CREATE_OBJECT', 'ENSURE_RULE_CATEGORY', 'CREATE_RULE'].includes(operation.kind),
    ) &&
    item.transactions.every(
      (transaction) =>
        transaction.state === 'EXECUTING' && transaction.operation_results.length === 0,
    );
  return (
    (['FAILED', 'CONFLICT'].includes(item.state) && safeTransactions) ||
    partialCategoryRecovery ||
    interruptedIdempotentCreate
  );
}
