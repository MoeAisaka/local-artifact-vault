# Release checklist

- [ ] Python test matrix passes.
- [ ] Traversal, expiry, signature, symlink, and permissions tests pass.
- [ ] Custom scanner and gitleaks report no findings.
- [ ] No vault data, logs, or signing secrets are tracked.
- [ ] Protected `main` requires CI and secret scan checks.
