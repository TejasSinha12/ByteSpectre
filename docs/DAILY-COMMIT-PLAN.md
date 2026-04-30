# Daily Commit Plan

ByteSpectre should grow through small, reviewable commits. A good daily batch has a mix of backend, frontend, tests, docs, and polish.

## Example 10-Commit Day

1. Add one detector rule.
2. Add a fixture or unit test for that detector.
3. Surface a new indicator field in the API.
4. Render that field in the workbench.
5. Add one descriptor parser improvement.
6. Improve graph or search ergonomics.
7. Add sandbox telemetry for one runtime signal.
8. Update architecture or roadmap docs.
9. Add CI or developer workflow polish.
10. Fix one small bug found during verification.

## Guardrails

- Every commit should compile on its own when practical.
- Avoid fake commits that only churn formatting.
- Prefer feature slices that are easy to demo.
- Keep detector logic separate from artifact classification.
- Keep runtime sandbox code isolated from static analysis code.

