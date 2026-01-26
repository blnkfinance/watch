---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Quick Start: Evaluating Transactions](#quick-start-evaluating-transactions)
4. [Related Documentation](#related-documentation)
5. [Core Concepts](#core-concepts)
6. [Basic Syntax](#basic-syntax)
7. [Rule Structure](#rule-structure)
8. [Condition Types](#condition-types)
9. [Actions and Verdicts](#actions-and-verdicts)
10. [Practical Examples](#practical-examples)
11. [Advanced Patterns](#advanced-patterns)
12. [Best Practices](#best-practices)
13. [Common Patterns](#common-patterns)
14. [Troubleshooting](#troubleshooting)
15. [Field Reference](#field-reference)
16. [Conclusion](#conclusion)

---

## Introduction

**Blnk Watch** is a domain-specific language (DSL) for creating **real-time transaction monitoring rules**.

It enables you to define conditions and automated actions for detecting fraud, enforcing limits, and staying compliant.

A Watch script is declarative: you describe *what* to detect and *what action to take*—the engine handles evaluation at runtime.

> **Note:** This project is community-maintained. We welcome contributions and new maintainers!

---

## Getting Started

### Building

#### Using Make (Recommended)

```bash
# Build the binary
make build

# Build and install to GOPATH/bin
make install
```

#### Using Go directly

```bash
# From the project root
cd cmd/blnk-watch && go build -o ../../blnk-watch .
```

### Running

#### Watch Service (Default)

Starts the main watch service with HTTP API on port 8081:

```bash
# Using the binary
./blnk-watch -command=watch

# Or using make
make watch

# With custom port
./blnk-watch -command=watch -port=9090

# With custom .env file
./blnk-watch -command=watch -env=.env.production
```

#### Watermark Sync Service

Runs continuous watermark synchronization from PostgreSQL to DuckDB:

```bash
# Using the binary
./blnk-watch -command=sync

# Or using make
make sync

# With custom sync interval and batch size
./blnk-watch -command=sync -sync-interval=5s -batch-size=500
```

#### One-Time Watermark Sync

Performs a single watermark sync operation:

```bash
# Using the binary
./blnk-watch -command=sync-once

# Or using make
make sync-once

# With custom batch size
./blnk-watch -command=sync-once -batch-size=2000
```

### Command-Line Options

| Flag | Description | Default | Commands |
|------|-------------|---------|----------|
| `-command` | Command to run: `watch`, `sync`, or `sync-once` | `watch` | All |
| `-env` | Path to .env file | `.env` | All |
| `-port` | Port for watch service HTTP server | `8081` | `watch` |
| `-sync-interval` | Interval for watermark sync | `1s` | `sync` |
| `-batch-size` | Batch size for watermark sync | `1000` | `sync`, `sync-once` |

### Environment Variables

Configure your `.env` file (see `env.example`) with:

- `DB_URL`: PostgreSQL connection URL
- `WATCH_SCRIPT_DIR`: Directory for watch scripts (default: `watch_scripts`)
- `WATCH_SCRIPT_GIT_REPO`: Optional Git repository URL for watch scripts
- `WATCH_SCRIPT_GIT_BRANCH`: Git branch to use (default: `main`)
- `ALERT_WEBHOOK_*`: Webhook alerting configuration (see below)

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build the binary |
| `make install` | Build and install to GOPATH/bin |
| `make watch` | Run the watch service |
| `make sync` | Run continuous watermark sync |
| `make sync-once` | Run one-time watermark sync |
| `make clean` | Remove built binaries |
| `make test` | Run tests |
| `make help` | Show help message |

---

## Quick Start: Evaluating Transactions

### 1. Inject Your First Transaction

Send a transaction to the `/inject` endpoint for evaluation against your watch rules:

```bash
curl -X POST http://localhost:8081/inject \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "txn_001",
    "amount": 15000,
    "currency": "USD",
    "source": "acct_sender_123",
    "destination": "acct_receiver_456",
    "reference": "payment_ref_001",
    "description": "Wire transfer",
    "status": "pending",
    "metadata": {
      "kyc_tier": 1,
      "source_country": "US",
      "destination_country": "NG"
    }
  }'
```

**Response:**
```json
{
  "transaction_id": "txn_001",
  "message": "Call GET /transactions/{id} to fetch the processed transaction or set ALERT_WEBHOOK_URL to get webhooks when the transaction is flagged."
}
```

### 2. Get Transaction Verdict

After injecting a transaction, retrieve the full evaluation results:

```bash
curl http://localhost:8081/transactions/txn_001
```

**Response:**
```json
{
  "transaction_id": "txn_001",
  "amount": 15000,
  "currency": "USD",
  "source": "acct_sender_123",
  "destination": "acct_receiver_456",
  "reference": "payment_ref_001",
  "description": "Wire transfer",
  "status": "pending",
  "metadata": {
    "kyc_tier": 1,
    "source_country": "US",
    "destination_country": "NG",
    "dsl_verdicts": [
      {
        "rule_id": 1,
        "verdict": "review",
        "score": 0.5,
        "reason": "Amount exceeds $10,000"
      }
    ],
    "consolidated_risk_assessment": {
      "final_risk_score": 0.5,
      "final_verdict": "review",
      "final_reason": "Amount exceeds $10,000",
      "source_count": 1
    }
  }
}
```

The `metadata` field contains:
- **`dsl_verdicts`**: Array of individual rule evaluations with `rule_id`, `verdict`, `score`, and `reason`
- **`consolidated_risk_assessment`**: Aggregated risk assessment with `final_risk_score`, `final_verdict`, `final_reason`, and `source_count`

### 3. Configure Alert Webhooks

To receive real-time alerts when transactions are flagged, configure webhooks in your `.env` file:

```bash
# Primary webhook URL for risk alerts
ALERT_WEBHOOK_URL=https://your-server.com/alerts

# Secondary webhook URL (fallback)
ALERT_WEBHOOK_SECONDARY_URL=https://backup.your-server.com/alerts

# Backup webhook URL (fallback)
ALERT_WEBHOOK_BACKUP_URL=https://another-backup.com/alerts

# API key for webhook authentication (sent as Bearer token)
ALERT_WEBHOOK_API_KEY=your_api_key_here

# Risk threshold for alerting (default: 0.5)
# Transactions with risk score >= this threshold trigger alerts
ALERT_WEBHOOK_RISK_THRESHOLD=0.5

# Enable/disable webhook alerting (set to "false" to disable)
ALERT_WEBHOOK_ENABLED=true
```

**Webhook Payload:**

When a transaction triggers an alert, the webhook receives:

```json
{
  "transaction_id": "txn_001",
  "description": "Amount exceeds $10,000",
  "risk_level": "medium",
  "risk_score": 0.5,
  "verdict": "review",
  "source_count": 1,
  "evaluation_data": {
    "final_risk_score": 0.5,
    "final_verdict": "review",
    "final_reason": "Amount exceeds $10,000",
    "source_count": 1,
    "dsl_verdicts": [...],
    "transaction_amount": 15000,
    "transaction_reference": "payment_ref_001"
  }
}
```

**Risk Levels:**
- `high`: Risk score >= 0.8
- `medium`: Risk score >= 0.6
- `low`: Risk score >= 0.3
- `very_low`: Risk score < 0.3

---

## Related Documentation

For more detailed technical documentation, see:

| Document | Description |
|----------|-------------|
| [API Documentation](API_DOCUMENTATION.md) | Complete API reference for all endpoints |
| [Watermark Sync](WATERMARK_SYNC_DOCUMENTATION.md) | Transaction synchronization from PostgreSQL to DuckDB |
| [Git Manager](GIT_MANAGER_README.md) | Managing watch scripts via Git repositories |
| [Parser Reference](PARSER_README.md) | DSL parser internals and grammar specification |

---

## Core Concepts

| Concept | Purpose |
| --- | --- |
| **Rule** | Named container that evaluates transactions |
| **Condition** | Logical test applied to transaction data |
| **Action** | Operation performed when a condition is true (block, review, alert, approve) |
| **Aggregate** | Time-window calculations such as `sum`, `count`, `avg` |
| **Placeholder** | Dynamic references like `$current.source` pointing to live transaction data |

---

## Basic Syntax

### File and Rule Basics

- File extension: `.ws` (Watch Script)
- One rule per file
- Rules are compiled and hot-loaded automatically

```elixir
rule RuleName {
    description "What this rule checks"

    when [conditions]

    then [action]
         score   [0.0–1.0]
         reason  "Why the rule triggered"
}

```

Key sections:

- **rule … { }**: Declares the rule
- **description**: Optional, but highly recommended
- **when**: Logical conditions joined by `and` / `or`
- **then**: Action block

---

## Rule Structure

```elixir
rule HighValueTxn {
    description "Flag transactions over $10,000"

    when amount > 10000

    then review
         score   0.5
         reason  "Amount exceeds $10,000"
}

```

*Use PascalCase for rule names* (`HighValueTxn`, `VelocityDetection`) to keep scripts readable.

---

## Condition Types

Conditions are the heart of a rule.

Combine multiple tests with `and`/`or` and group with parentheses for clarity.

### 1. Field Comparisons

```elixir
// Numeric
when amount > 10000
when amount <= 500

// String
when currency == "USD"
when status != "settled"

```

### 2. Nested Field Access

```elixir
when metadata.kyc_tier == 1
when metadata.merchant_category == "gambling"

```

### 3. Lists and Sets

```elixir
// Static
when destination in ("acct1", "acct2")

// Dynamic lists (system-provided)
when metadata.country in $high_risk_countries

```

### 4. Regex Matching

```elixir
when description regex "regex:(?i)(btc|bitcoin|crypto)"
when description not_regex "regex:^legit"

```

### 5. Time Functions

```elixir
when hour_of_day(timestamp) >= 21
when day_of_week(timestamp) in (0,6)
when month_of_year(timestamp) == 12

```

### 6. Aggregates (Time-Window Analytics)

Use `sum`, `count`, `avg`, `min`, `max` over time windows.

```elixir
when sum(amount when source == $current.source, "PT24H") > 5000
when count(when destination == $current.destination, "PT1H") > 10

```

Time window format:

- `PT1H` = 1 hour
- `PT30M` = 30 minutes
- `P1D` = 1 day
- `P7D` = 7 days

### 7. Previous Transaction Matching

Detect sequences or repeated behavior.

```elixir
when previous_transaction(
    within: "PT1H",
    match: { source: "$current.source", status: "failed" }
)

```

### 8. Dynamic References

Access current transaction context:

```elixir
when sum(amount when source == $current.source, "PT24H") > 5000

```

---

## Actions and Verdicts

**Actions** determine what happens when a rule triggers.

| Action | Effect |
| --- | --- |
| `block` | Reject immediately |
| `review` | Hold for manual review |
| `alert` | Notify but allow |
| `approve` | Force approval |

**Score** (0.0–1.0) reflects risk level.

```elixir
then block
     score   1.0
     reason  "Account on sanctions list"

```

Use scores consistently:

- **0.8–1.0**: High confidence (block)
- **0.5–0.7**: Suspicious (review)
- **0.1–0.4**: Mild anomaly (alert only)

---

## Practical Examples

### High-Value Check

```elixir
rule HighValueTransaction {
    description "Review any transaction above $10,000"
    when amount > 10000
    then review
         score   0.5
         reason  "Amount exceeds threshold"
}

```

### Velocity Detection

```elixir
rule HighVelocitySpending {
    description "Detect rapid spending from a single account"
    when sum(amount where source == $current.source, "PT1H") > 5000
    then review
         score   0.7
         reason  "Spending velocity exceeded"
}

```

### Blacklist Block

```elixir
rule BlockBlacklistedAccounts {
    description "Stop transactions from blacklisted accounts"
    when source in ("blocked_account1", "blocked_account2")
    then block
         score   1.0
         reason  "Source is blacklisted"
}

```

---

## Advanced Patterns

### Structuring (Smurfing)

```elixir
rule StructuringDetection {
    description "Detect multiple small deposits intended to evade limits"
    when amount < 10000
    and count(where source == $current.source, "PT24H") >= 3
    and sum(amount where source == $current.source, "PT24H") > 25000
    then review
         score   0.8
         reason  "Possible structuring"
}

```

### Account Takeover

```elixir
rule AccountTakeoverPattern {
    description "Detect suspicious access at odd hours"
    when previous_transaction(
        within: "P30D",
        match: { source: "$current.source" }
    )
    and hour_of_day(timestamp) between 2 and 5
    and amount > 5000
    then review
         score   0.9
         reason  "Potential account compromise"
}

```

### Cross-Border High Risk

```elixir
rule CrossBorderCompliance {
    description "Enhanced checks for cross-border to high-risk jurisdictions"
    when metadata.source_country != metadata.destination_country
    and metadata.destination_country in $high_risk_countries
    and amount > 1000
    then review
         score   0.6
         reason  "Cross-border transaction to high-risk country"
}

```

---

## Best Practices

1. **Naming**
    
    Use PascalCase with purpose (`HighValueCheck`, not `Rule1`).
    
2. **Descriptive Comments**
    
    Always explain thresholds and intent in `description`.
    
3. **Score Discipline**
    
    Reserve 1.0 for guaranteed fraud (e.g., sanction lists).
    
4. **Threshold Setting**
    
    Start conservative and tune with live/ historical data.
    
5. **Performance**
    - Keep aggregates narrow (avoid `P30D` without filters).
    - Filter inside aggregates (e.g., `where source == $current.source`).
    - Avoid complex regex where possible.
6. **Testing**
    
    Test on historical data and monitor false positives.
    

---

## Common Patterns

| Category | Sample Condition |
| --- | --- |
| **Amount** | `amount > 50000` |
| **Frequency** | `count(where source == $current.source, "PT15M") > 5` |
| **Time-based** | `day_of_week(timestamp) in (0,6)` |
| **Geographic** | `metadata.destination_country in $sanctioned_countries` |
| **Account Type** | `metadata.account_age_days < 30 and amount > 5000` |

---

## Troubleshooting

### Frequent Issues

| Issue | Fix |
| --- | --- |
| Rule not firing | Check field names, types, and time window |
| Syntax error | Verify quotes, operators (`==`), and parentheses |
| Slow evaluation | Narrow windows, add filters, simplify regex |
| High false positives | Adjust thresholds and add qualifying conditions |

### Debugging Steps

1. Start simple and expand incrementally
2. Check compilation logs
3. Replay historical transactions for testing
4. Track false positive/negative rates in monitoring

---

## Field Reference
Common transaction fields:

- `transaction_id`
- `amount`
- `currency`
- `source` / `destination`
- `description`
- `timestamp`
- `status`
- `metadata.*` (nested business fields like KYC tier, country, account age)

*All field names are case-sensitive.*

---

## Maintainers Wanted

This project is **community-maintained** and we're actively looking for maintainers to help guide its development.

If you're interested in contributing as a maintainer, we'd love to have you! Areas where help is especially welcome:

- **Code contributions**: Bug fixes, feature additions, and improvements
- **Documentation**: Improving guides, examples, and API documentation
- **Community support**: Helping answer questions and review pull requests
- **Testing**: Writing tests, improving test coverage, and validating changes
- **Project governance**: Helping set direction, triage issues, and manage releases

To get started, check out open issues, submit a pull request, or reach out to discuss how you'd like to contribute.