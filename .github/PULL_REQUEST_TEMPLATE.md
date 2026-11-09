## Summary of Changes

A clear description of what this PR introduces.

## Related Issues
Closes #(issue number)

## Safety & Invariant Checklist
- [ ] **Strict Read-Only**: This PR does not write to, delete, or modify any Windows system state, registry keys, or filesystem paths.
- [ ] **Synthetic Tests**: New logic is validated with synthetic mock fixtures in `tests/`.
- [ ] **Test Suite Passes**: `python -m unittest discover -s tests -v` executed with 100% green output.
- [ ] **No Unvetted Dependencies**: Preserves the lightweight / stdlib-first architecture.
