# MoatOS PR0-PR4 Branch Proof - 2026-06-13

Branch: `feature/moatos-pr0-pr4-clean-2026-06-13`

This is freeze/QA branch evidence only. Nothing from this branch has been merged to `main`.

## Scope Verified

- Community report signal wired as soft evidence in `verdict_gate`.
- Brand golden cases added for Orange, OLX, Sameday.
- Radar hot-cache data endpoint and one-tap report package endpoint added.
- Urechea RSS workflow added with comma-separated source parsing.
- Evaluation dataset builder added with deterministic evidence-first cases.
- Exact gate evaluation test added: 350 cases total.

## Why We Did Not Reuse The OSINT Branch Test Directly

`origin/feature/osint-intel-pipeline` contained a useful evaluation direction, but its metric test built `semantic_review` directly from `expected_label`. That made the test partially self-confirming. This branch keeps the idea, but rewrites it so expected labels never feed the gate inputs directly.

## Verification Commands

```bash
python3 -m pytest backend/test_evaluation_metrics.py -q
```

Result:

```text
2 passed in 0.05s
```

```bash
python3 -m pytest backend/test_evidence_gate_golden.py backend/test_radar_report.py backend/test_urechea_workflow.py backend/test_evaluation_metrics.py backend/test_verdict_gate.py backend/test_offer_corpus_recall.py -q
```

Result:

```text
100 passed, 1 warning in 2.02s
```

```bash
python3 -m pytest backend -q
```

Result:

```text
802 passed, 1 warning in 5.16s
```

```bash
ANDROID_HOME="$HOME/Library/Android/sdk" JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:assembleDebug -q
```

Result: command exited `0`.

```bash
ANDROID_HOME="$HOME/Library/Android/sdk" JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleRelease -q
```

Result: command exited `0`.

```bash
git diff --check
```

Result: no output.

## Known Local Environment Note

The isolated worktree has no `local.properties`, so Gradle needs `ANDROID_HOME` set explicitly. Without it, Gradle fails before compiling app code with:

```text
SDK location not found.
```

## Remaining Before Main

- Review this branch diff once more.
- Commit locally on this feature branch.
- Do not merge into `main` until the broader freeze checklist says PR0-PR4 are accepted.
