<template>
  <div class="aira-table-wrapper">
    <slot name="header" />
    <table class="aira-table" :data-testid="testId">
      <thead v-if="data.length > 0">
        <tr>
          <th
            v-for="column in columns"
            :key="column.key"
            class="aira-table__th"
            :class="column.thClass"
          >
            {{ column.label }}
          </th>
        </tr>
      </thead>
      <tbody v-if="data.length > 0">
        <tr
          v-for="(row, index) in data"
          :key="getRowKey(row, index)"
          class="aira-table__row"
          :data-row-id="getRowKey(row, index)"
          data-testid="table-row"
        >
          <td
            v-for="column in columns"
            :key="column.key"
            class="aira-table__td"
            :class="column.tdClass"
          >
            <slot
              :name="`cell-${column.key}`"
              :row="row"
              :column="column"
              :index="index"
            >
              {{ getCellValue(row, column.key) }}
            </slot>
          </td>
        </tr>
      </tbody>
      <tbody v-else>
        <tr>
          <td :colspan="columns.length" class="aira-table__empty">
            <slot name="empty">
              No data
            </slot>
          </td>
        </tr>
      </tbody>
    </table>
    <slot name="footer" />
  </div>
</template>

<script setup lang="ts" generic="T extends Record<string, any>">
export interface Column {
  key: string
  label: string
  thClass?: string
  tdClass?: string
}

export interface TableProps<T extends Record<string, any> = Record<string, any>> {
  columns: Column[]
  data: T[]
  rowKey?: string | ((row: T) => string)
  testId?: string
}

const props = defineProps<TableProps<T>>()

const getRowKey = (row: T, index: number): string => {
  if (!props.rowKey) return String(index)
  if (typeof props.rowKey === 'function') return props.rowKey(row)
  return String(row[props.rowKey])
}

const getCellValue = (row: T, key: string): any => {
  return row[key]
}
</script>

<style scoped>
.aira-table-wrapper {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
}

.aira-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.aira-table__th {
  padding: 0.75rem 1rem;
  text-align: left;
  font-weight: 600;
  color: var(--auth-ui-text-tertiary);
  border-bottom: 1px solid var(--auth-ui-border);
  white-space: nowrap;
}

.aira-table__row {
  transition: background-color 0.15s ease;
}

.aira-table__row:hover {
  background-color: var(--auth-ui-hover-bg, rgba(0, 0, 0, 0.02));
}

.aira-table__td {
  padding: 0.75rem 1rem;
  color: var(--auth-ui-text);
  border-bottom: 1px solid var(--auth-ui-border);
  vertical-align: middle;
}

.aira-table__row:last-child .aira-table__td {
  border-bottom: none;
}

.aira-table__empty {
  padding: 2rem 1rem;
  text-align: center;
  color: var(--auth-ui-text-tertiary);
  font-size: 0.875rem;
}
</style>

