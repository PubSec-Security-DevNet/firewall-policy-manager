// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';

import { AppButton, AppGroup as Group, AppText as Text } from '../../ui';

const MIN_PAGE_SIZE = 100;
const ROW_HEIGHT = 42;
const RESERVED_HEIGHT = 360;

function rowsForViewport() {
  if (typeof window === 'undefined') return MIN_PAGE_SIZE;
  return Math.max(MIN_PAGE_SIZE, Math.floor((window.innerHeight - RESERVED_HEIGHT) / ROW_HEIGHT));
}

// The hook and component intentionally share this small pagination module.
export function useAdaptivePageSize() {
  const [pageSize, setPageSize] = useState(rowsForViewport);

  useEffect(() => {
    const update = () => setPageSize(rowsForViewport());
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  return pageSize;
}

export function AdaptivePagination({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);

  return (
    <Group justify="space-between" align="center" mt="md" wrap="wrap">
      <Text size="sm" c="dimmed">
        Showing {first}–{last} of {total}
      </Text>
      {pageCount > 1 && (
        <Group gap="xs">
          <AppButton
            size="xs"
            variant="subtle"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
          >
            Previous
          </AppButton>
          <Text size="sm" c="dimmed">
            Page {page} of {pageCount}
          </Text>
          <AppButton
            size="xs"
            variant="subtle"
            disabled={page >= pageCount}
            onClick={() => onPageChange(page + 1)}
          >
            Next
          </AppButton>
        </Group>
      )}
    </Group>
  );
}
