---
description: 'Calculates the total length of union of all ranges (segments on numeric
  axis).'
sidebar_label: 'intervalLengthSum'
sidebar_position: 155
slug: /sql-reference/aggregate-functions/reference/intervalLengthSum
title: 'intervalLengthSum'
---

Calculates the total length of union of all ranges (segments on numeric axis).

**Syntax**

```sql
intervalLengthSum(start, end)
```

**Arguments**

- `start` — The starting value of the interval. [Int32](/sql-reference/data-types/int-uint#integer-ranges), [Int64](/sql-reference/data-types/int-uint#integer-ranges), [UInt32](/sql-reference/data-types/int-uint#integer-ranges), [UInt64](/sql-reference/data-types/int-uint#integer-ranges), [Float32](/sql-reference/data-types/float), [Float64](/sql-reference/data-types/float), [DateTime](/sql-reference/data-types/datetime) or [Date](/sql-reference/data-types/date).
- `end` — The ending value of the interval. [Int32](/sql-reference/data-types/int-uint#integer-ranges), [Int64](/sql-reference/data-types/int-uint#integer-ranges), [UInt32](/sql-reference/data-types/int-uint#integer-ranges), [UInt64](/sql-reference/data-types/int-uint#integer-ranges), [Float32](/sql-reference/data-types/float), [Float64](/sql-reference/data-types/float), [DateTime](/sql-reference/data-types/datetime) or [Date](/sql-reference/data-types/date).

:::note
Arguments must be of the same data type. Otherwise, an exception will be thrown.
:::

**Returned value**

- Total length of union of all ranges (segments on numeric axis). Depending on the type of the argument, the return value may be [UInt64](/sql-reference/data-types/int-uint#integer-ranges) or [Float64](/sql-reference/data-types/float) type.

**Examples**

1. Input table:

```text
┌─id─┬─start─┬─end─┐
│ a  │   1.1 │ 2.9 │
│ a  │   2.5 │ 3.2 │
│ a  │     4 │   5 │
└────┴───────┴─────┘
```

In this example, the arguments of the Float32 type are used. The function returns a value of the Float64 type.

Result is the sum of lengths of intervals `[1.1, 3.2]` (union of `[1.1, 2.9]` and `[2.5, 3.2]`) and `[4, 5]`

Query:

```sql
SELECT id, intervalLengthSum(start, end), toTypeName(intervalLengthSum(start, end)) FROM fl_interval GROUP BY id ORDER BY id;
```

Result:

```text
┌─id─┬─intervalLengthSum(start, end)─┬─toTypeName(intervalLengthSum(start, end))─┐
│ a  │                           3.1 │ Float64                                   │
└────┴───────────────────────────────┴───────────────────────────────────────────┘
```

2. Input table:

```text
┌─id─┬───────────────start─┬─────────────────end─┐
│ a  │ 2020-01-01 01:12:30 │ 2020-01-01 02:10:10 │
│ a  │ 2020-01-01 02:05:30 │ 2020-01-01 02:50:31 │
│ a  │ 2020-01-01 03:11:22 │ 2020-01-01 03:23:31 │
└────┴─────────────────────┴─────────────────────┘
```

In this example, the arguments of the DateTime type are used. The function returns a value in seconds.

Query:

```sql
SELECT id, intervalLengthSum(start, end), toTypeName(intervalLengthSum(start, end)) FROM dt_interval GROUP BY id ORDER BY id;
```

Result:

```text
┌─id─┬─intervalLengthSum(start, end)─┬─toTypeName(intervalLengthSum(start, end))─┐
│ a  │                          6610 │ UInt64                                    │
└────┴───────────────────────────────┴───────────────────────────────────────────┘
```

3. Input table:

```text
┌─id─┬──────start─┬────────end─┐
│ a  │ 2020-01-01 │ 2020-01-04 │
│ a  │ 2020-01-12 │ 2020-01-18 │
└────┴────────────┴────────────┘
```

In this example, the arguments of the Date type are used. The function returns a value in days.

Query:

```sql
SELECT id, intervalLengthSum(start, end), toTypeName(intervalLengthSum(start, end)) FROM date_interval GROUP BY id ORDER BY id;
```

Result:

```text
┌─id─┬─intervalLengthSum(start, end)─┬─toTypeName(intervalLengthSum(start, end))─┐
│ a  │                             9 │ UInt64                                    │
└────┴───────────────────────────────┴───────────────────────────────────────────┘
```
