# Active Rules Set

## Implementation Overview

The `activeRulesSet` ensures that rule evaluation during transaction processing always uses the latest rules without requiring a database hit on every transaction. It uses atomics and mutexes for safe concurrent access. The previous implementation hit the database for every transaction to get the active rules, despite the likelihood of the rules having not changed. See benchmark comparisons here(#benchmark-results)

`globalActiveRulesSet` is created by `newActiveRulesSet`. `newActiveRulesSet`
sets `invalidatedCount = 1` and `level = 0`. This marks the
`globalActiveRulesSet` as invalid on initialization. When 
`globalActiveRulesSet.populate` is called for the first time. It sees that the
`globalActiveRulesSet` is invalid and it populates the rules set under a mutex
lock and marks the `globalActiveRulesSet` as valid by setting 
`level = invalidatedCount`.

`startRiskEvaluationWorker` which spins off a goroutine to periodically process transaction batches will ensure `globalActiveRulesSet` is populated before spinning off the goroutine. It will return an error if the populate operation fails.

## Implementation Details

### Data Structure

```go
type activeRulesSet struct {
    rules            []Rule              // Slice of active rules from the database
    aggrConds        []AggregateCond     // Aggregate conditions derived from rules
    invalidatedCount atomic.Uint64       // Counter tracking invalidation requests
    level            atomic.Uint64       // Current validity level
    lock             sync.Mutex          // Protects rules and aggrConds during updates
}
```

### Validity Mechanism

Whenever an operation modifies the rules in the DB, it invalidates the 
`globalActiveRulesSet` by increasing `invalidatedCount` by 1. Since `invalidatedCount` is an `atomic.Uint64`, concurrent DB modifications can 
increment the `invalidatedCount` safely. Since `invalidatedCount != level`,
another call to populate the rules set will see the rules set is invalid,
it will repopulate the rules set (and rebuild aggregate conditions) and
then set `level` to equal `invalidatedCount`.

### Key Methods

#### `newActiveRulesSet()`
Creates a new, initially-invalid rules set instance.

```go
func newActiveRulesSet() *activeRulesSet {
    rc := &activeRulesSet{
        rules:     make([]Rule, 0),
        aggrConds: make([]AggregateCond, 0),
    }
    rc.invalidatedCount.Add(1)  // Start as invalid
    rc.level.Store(0)           // No level loaded yet
    return rc
}
```

#### `populate()`
Fetches active rules from the database and rebuilds aggregate conditions. This is the main entry point for loading or reloading rules.

**Behavior**:
1. Checks if the cache is valid (non-blocking, using `isValid()`)
2. If valid, returns early with no database access
3. If invalid:
   - Acquires the mutex lock
   - Fetches active rules via `getActiveRules()`
   - Rebuilds aggregate conditions via `buildAggregateConds()`
   - Updates `level` to match current `invalidatedCount`
   - Releases the lock

**Error Handling**: Returns an error if database fetch fails.

**Thread Safety**: 
- Read path (`isValid()`) requires no lock
- Write path (`populate()`) holds a lock during database operations and updates

#### `isValid()`
Non-blocking check for whether the cache is current.

```go
func (rc *activeRulesSet) isValid() bool {
    return rc.level.Load() == rc.invalidatedCount.Load()
}
```

**Thread Safety**: Lock-free; uses atomic loads to read two uint64 values

#### `invalidate()`
Increments the invalidation counter, marking the cache as stale.

```go
func (rc *activeRulesSet) invalidate() {
    rc.invalidatedCount.Add(1)
    log.Info().Msg("Rules set invalidated")
}
```

**Called When**:
New rule is created or existing rule is updated or deleted, via direct programmatic modification or API calls.

#### `clear()`
Resets the rules set to a pristine state. Primarily used in tests.

```go
func (rc *activeRulesSet) clear() {
    rc.lock.Lock()
    defer rc.lock.Unlock()
    rc.rules = make([]Rule, 0)
    rc.aggrConds = make([]AggregateCond, 0)
    rc.level.Store(0)
    rc.invalidatedCount.Store(1)
}
```

### Global Instance

```go
var globalActiveRulesSet = newActiveRulesSet()
```

`globalActiveRulesSet` is a single global instance of `activeRulesSet` that is
shared across the application

## Integration Points

### Transaction Processing

**File**: `transaction.go`

The primary integration point is in the `evaluateTransaction()` function:

```go
func evaluateTransaction(t Transaction) error {
    // ...
    
    if err = globalActiveRulesSet.populate(); err != nil {
        return fmt.Errorf("failed to populate rules cache: %w", err)
    }
    
    // Build aggregate context using aggrConds
    aggCtx, err := BuildAggContext(context.Background(), db, transactionMap, globalActiveRulesSet.aggrConds)
    if err != nil {
        return fmt.Errorf("failed to build aggregate context: %w", err)
    }

    // ...
}
```

**Flow**:
1. Before evaluating any transaction, `populate()` is called
2. If the cache is valid (common case), this returns immediately
3. If invalid, rules are fetched and aggregate conditions are rebuilt

This prevents the behaviour of calling `getActiveRules` repeatedly for
every transaction. `evaluateTransaction` is called for each transaction during batch processing. By caching the active rules set, we avoid calling `getActiveRules` for every transaction in the batch, despite the rules likely not having changed, which would be costly as already mentioned.

### Rule Creation/Update/Deletion

**File**: `watch-scripts.go`

Rule mutations trigger invalidation of `globalActiveRulesSet`:

**Creating an Active Rule**:
```go
// In CreateInstructionWithPrecompiledDSL
globalActiveRulesSet.invalidate()  // Mark cache as stale
```

**Updating a Rule**:
```go
func updateInstructionDSL(db *sql.DB, id int64, dslJSON string) error {
    // ... execute update ...
    globalActiveRulesSet.invalidate()  // Mark cache as stale
    return nil
}
```

**Deleting a Rule**:
```go
// Deletion handlers also call:
globalActiveRulesSet.invalidate()  // Mark cache as stale
```

**API Endpoints that Trigger Invalidation**:
- `POST /compile-and-save-instruction` - Create new rule
- `PUT /instructions/{id}` - Update rule
- `DELETE /instructions/{id}` - Delete rule
- Internal functions: `CreateInstructionWithPrecompiledDSL()`, `UpdateInstructionWithPrecompiledDSL()`

### Aggregate Conditions

Aggregate conditions are constant per rule set.

**Aggregate Condition Caching**
- Pre-computed once per rule set
- Reused for every transaction until rules change
- Avoids parsing aggregate conditions for every transaction

```go
// In populate()
rc.aggrConds = buildAggregateConds(rc.rules)

// In transaction processing
aggCtx, err := BuildAggContext(context.Background(), db, transactionMap, globalActiveRulesSet.aggrConds)
```

These are expressions like:
- `count(when source == $current.source, "PT24H")` - Count transactions in 24-hour window
- `sum(amount when source == $current.source, "PT24H")` - Sum amounts in 24-hour window

They represent aggregate operations that need additional database context to evaluate.

## Testing Strategy

### Test Files

- **Main Tests**: `active-rules-set_test.go`
- **Integration Tests**: Embedded in transaction and API handler tests

### Test Organization

The tests are as follows:

#### 1. End-to-End Behavior (`TestActiveRulesSet_EndToEnd`)

**Purpose**: Verify that rule modifications during transaction processing are correctly reflected in the active rules set.
This verifies that when rule modifications occur while processing a transaction batch, it is detected, and the active rules set (and aggregate conditions) is repopulated.

#### 2. Rule Creation Invalidation (`TestActiveRulesSet_CreateRuleInvalidates`)

**Purpose**: Verify that creating a new rule properly invalidates the in-memory rules set.

**Test Cases**:
1. **Direct API with pre-compiled DSL**: `CreateInstructionWithPrecompiledDSL()`
2. **HTTP API endpoint**: `POST /compile-and-save-instruction`

#### 3. Rule Update Invalidation (`TestActiveRulesSet_UpdateRuleInvalidates`)

**Purpose**: Verify that updating a rule properly invalidates and rebuilds the cache.

**Test Cases**:
1. **Direct database update**: `updateInstructionDSL()`
2. **API function**: `UpdateInstructionWithPrecompiledDSL()`

#### 4. Rule Deletion Invalidation (`TestActiveRulesSet_DeleteRuleInvalidates`)

**Purpose**: Verify that deleting a rule properly invalidates and removes it from the cache.

**Test Cases**:
1. **Direct database deletion**
2. **HTTP DELETE endpoint**: `DELETE /instructions/{id}`

#### 5. Instruction Record Creation Does Not Invalidate (`TestActiveRulesSet_CreateInstructionRecordDoesNotInvalidate`)

**Purpose**: Verify that `createInstructionRecord` which creating an instruction record without a dsl_json field (i.e. an inactive rule) does not trigger invalidation of the rules set.

#### 6. Concurrent Modification (`TestActiveRulesSet_ConcurrentModification`)

**Purpose**: Verify that concurrent modifications to the active rules set correctly update the invalidation counter and that the cache can be successfully repopulated with all concurrent changes.

**Scenario**:
1. Compile two different rule scripts
2. Launch multiple goroutines that concurrently create instructions via `CreateInstructionWithPrecompiledDSL()`
3. Each goroutine creates one rule concurrently
4. Verify invalidation counter is incremented correctly for all concurrent operations
5. Verify cache can be repopulated to include all concurrently-created rules

#### 7. Return error on Database Failure (`TestActiveRulesSet_PopulateReturnsErrorOnDatabaseFailure`)

**Purpose**: Verify that `populate()` returns an error when database operations fail and that the rules set remains invalid.

### Helper Test Functions

#### `testPopulateActiveRulesSet(t *testing.T)`
Verifies that the global active rules set is correctly populated via `getActiveRules` and `buildAggregateConds`

#### `testExpectedRulesSet(t *testing.T, exp *activeRulesSet)`
Compares the global active rules set with an expected rules set, verifying:
- Rule count and content match
- Aggregate conditions match
- Validity status is correct

#### 8. Aggregate Condition Building Test (`TestBuildAggregateConds`)

**Purpose**: Test the aggregate condition building logic in `buildAggregateConds()`
### Benchmark Test

`BenchmarkEvaluateTransaction` measures the performance of the `evaluateTransaction()` function.

## Benchmark Results

Benchmark runs were executed on Intel(R) Core(TM) i3-1005561 CPU @ 1.20GHz running Linux AMD64.

#### Previous Implementation (Database Query Per Transaction)

| Run | Iterations | ns/op | B/op | Allocs/op |
|-----|------------|------------------|-------------------|-------------|
| 1 | 1134 | 974,706 | 20,568 | 433 |
| 2 | 1154 | 940,815 | 20,567 | 433 |
| 3 | 1194 | 924,216 | 20,571 | 433 |

**Average**: 
- Time: 946,579 ns/op
- Memory: 20,569 B/op
- Allocations: 433 allocs/op

#### New Implementation (In-Memory Set)

| Run | Iterations | ns/op | B/op | Allocs/op |
|-----|------------|------------------|-------------------|-------------|
| 1 | 18,537 | 64,085 | 5,226 | 140 |
| 2 | 15,316 | 71,766 | 5,226 | 140 |
| 3 | 16,850 | 61,441 | 5,226 | 140 |

**Average**: 
- Time: 65,764 ns/op
- Memory: 5,226 B/op
- Allocations: 140 allocs/op

### Performance Improvements

#### Summary Comparison

| Metric | Previous | New | Improvement |
|--------|----------|-----|-------------|
| **Execution Time** | 946,579 ns/op | 65,764 ns/op | **~14.4x faster** |
| **Memory per Op** | 20,569 B/op | 5,226 B/op | **~3.9x less memory** |
| **Allocations** | 433 | 140 | **~3.1x fewer allocations** |
| **Iterations (sample size)** | 1,134-1,194 | 15,316-18,537 | **~13-16x more runs possible** |
