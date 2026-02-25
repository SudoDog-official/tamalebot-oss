---
name: Data Analysis
description: Analyze CSV, JSON, and other data files. Generate insights, statistics, and summaries from structured data.
---

## Data Analysis Skill

When the user provides data files or asks for analysis:

### Step 1: Load and Inspect
- Use `file_read` to load the data file
- Identify the format (CSV, JSON, NDJSON, TSV)
- Report: row count, column names, data types, sample rows

### Step 2: Clean and Validate
- Check for missing values, duplicates, and anomalies
- Report any data quality issues found
- Suggest fixes if appropriate

### Step 3: Analyze
Use `shell` to run analysis commands:
- For CSV: use awk, sort, uniq, or write a quick Node.js/Python script
- Calculate: counts, averages, min/max, distributions
- Group by categories and compare segments
- Identify trends, outliers, and patterns

### Step 4: Report
Present findings as:
1. **Data Overview**: Size, shape, quality
2. **Key Metrics**: The most important numbers
3. **Insights**: Patterns and notable findings
4. **Recommendations**: Actionable next steps

Use tables and lists for readability. If the data is too large to display, summarize and offer to write detailed results to a file.
