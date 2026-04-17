# PyPI-SCADA Code Review Method

This project is too large to review linearly. Do not try to hold the whole repo in your head at once. Review one vertical slice at a time, using the debugger for Python behavior and logs/SQLite for full pipeline behavior.

## Review Strategy

Review the project in this order:

1. Analyzer dry-run resolution
2. One tiny real analyzer run
3. Specific pytest tests with debugger support
4. SQLite post-mortem inspection
5. Full deployment logs only after the small slices make sense

Do not start by stepping through `deployment.sh` or reading every line of `evaluate.py`. That is inefficient and will make the project feel more monolithic than it is.

## Use `pytest --pdb` For Isolated Behavior

This is the cleanest way to understand specific modules.

```bash
python -m pytest tests/test_simulator_resolver.py -q --pdb
python -m pytest tests/test_evaluation_profiles.py -q --pdb
python -m pytest tests/test_guarddog_adapter.py -q --pdb
python -m pytest tests/test_financial_validation.py -q --pdb
```

If a test fails, Python drops directly into the failing frame.

Useful debugger commands:

```text
l      # list source around current line
n      # next line
s      # step into function
r      # run until current function returns
p var  # print variable
pp var # pretty-print variable
bt     # backtrace/call stack
q      # quit
```

## Use `pdb` Directly On The Analyzer

For understanding the real analyzer pipeline:

```bash
python -m pdb src/analyzer/evaluate.py --profile test_no_gemini --dry-run-resolution --skip-validation
```

Good breakpoint locations:

```text
b src/analyzer/evaluate.py:524
b src/analyzer/evaluate.py:696
b src/analyzer/evaluate.py:940
b src/analyzer/detection_controller.py:244
b src/analyzer/adapters.py:198
```

Then continue:

```text
c
```

Useful values to inspect:

```text
p samples
p packages
p sample.package_name
p sample.artifact_filename
p sample.resolver_policy
```

The most important analyzer questions are:

- Which packages did the resolver select?
- Which version did it select?
- Which artifacts will be scanned?
- What ground-truth label is attached?
- What resolver policy is stored in the DB?
- Do detector failures become `experiment_mode="error"` instead of benign verdicts?

## Use Tiny Profiles For Real End-To-End Debugging

Do not debug using the full budget profile first. Use the small test profile:

```bash
python src/analyzer/evaluate.py --profile test_no_gemini --run-id-prefix debug --progress never
```

To debug it interactively:

```bash
python -m pdb src/analyzer/evaluate.py --profile test_no_gemini --run-id-prefix debug --progress never
```

This keeps the run small enough to reason about without burning unnecessary API budget.

## Use SQLite As A Post-Mortem Debugger

After a run, inspect what actually happened:

```bash
sqlite3 'file:src/data/eval_results.db?mode=ro&immutable=1' "
select
  run_id,
  package_name,
  version,
  artifact_filename,
  detector,
  experiment_mode,
  prompt_strategy,
  verdict,
  ground_truth,
  substr(details, 1, 300) as details
from eval_result
order by id desc
limit 30;
"
```

For errors only:

```bash
sqlite3 'file:src/data/eval_results.db?mode=ro&immutable=1' "
select
  package_name,
  version,
  artifact_filename,
  detector,
  prompt_strategy,
  substr(details, 1, 500) as details
from eval_result
where experiment_mode = 'error'
order by id desc;
"
```

SQLite is often a better debugger than stepping through every detector call, because the DB shows the actual persisted evidence used for metrics.

## Archive The DB Between Review Runs

If you want a clean database before a new review run:

```bash
python scripts/archive_eval_db.py --dry-run
python scripts/archive_eval_db.py
```

This archives the old `src/data/eval_results.db` and SQLite sidecars, then creates a fresh empty eval DB schema.

## Use Logs For Long Runs

For full deployment or long evaluations, do not use `pdb`. Use logs and SQLite.

Find recent logs:

```bash
ls -lt logs src/injector/logs src/analyzer/logs 2>/dev/null
```

Run small deployment-style checks first:

```bash
MODEL_PROFILE=test_no_gemini UPLOAD_CATEGORIES="controls malicious" bash deployment.sh
```

Use full deployment only after the resolver, DB, and detector slices make sense.

## Recommended Review Session

A practical review session should look like this:

```bash
git status --short
python scripts/archive_eval_db.py --dry-run
python scripts/archive_eval_db.py
python src/analyzer/evaluate.py --profile test_no_gemini --dry-run-resolution --skip-validation
python -m pdb src/analyzer/evaluate.py --profile test_no_gemini --dry-run-resolution --skip-validation
python src/analyzer/evaluate.py --profile test_no_gemini --run-id-prefix debug --progress never
```

Then inspect SQLite rows:

```bash
sqlite3 'file:src/data/eval_results.db?mode=ro&immutable=1' "
select package_name, version, artifact_filename, detector, experiment_mode, verdict, ground_truth
from eval_result
order by id desc
limit 50;
"
```

Only after this should you run a larger profile.

## What Not To Do

Do not:

- Read `evaluate.py` top-to-bottom as the first step.
- Debug the full deployment with `pdb`.
- Run the full budget/frontier profile just to understand control flow.
- Mix old run IDs with canonical runs when reviewing metrics.
- Refactor while reviewing unless the review has already identified a specific bug.

Record refactor ideas separately. Review first, change second.

## Mental Model

Use this split:

- Debugger: small Python slices.
- Tests: module-level behavior.
- SQLite: persisted truth and metric inputs.
- Logs: long-running operational behavior.
- Deployment script: final integration check.

The point is to make the project inspectable without pretending it is small.
