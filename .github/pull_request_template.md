## Description

<!-- Brief description of the changes -->

## Type of Change

<!-- Check all that apply -->

- [ ] Normative change (affects specification behavior)
- [ ] Editorial change (typos, clarifications, formatting)
- [ ] Schema change (JSON Schema modifications)
- [ ] Test vectors (new or modified test cases)
- [ ] Conformance (runner or profile updates)
- [ ] Documentation (non-normative docs)
- [ ] CI/Infrastructure

## Checklist

<!-- Complete all applicable items -->

### For All Changes

- [ ] I have read the [CONTRIBUTING](../CONTRIBUTING.adoc) guidelines
- [ ] My commits are signed (DCO)
- [ ] I have updated relevant documentation

### For Normative Changes

- [ ] I have added/updated test vectors for this change
- [ ] I have updated affected JSON schemas
- [ ] I have considered backwards compatibility (see below)

### For Schema Changes

- [ ] I have run `just schema-validate`
- [ ] All existing valid vectors still pass
- [ ] New vectors added for new functionality

### For Test Vectors

- [ ] Vectors follow the format in `vectors/README.adoc`
- [ ] I have run `just vectors-validate`
- [ ] Coverage report shows adequate coverage

## Compatibility Analysis

<!-- Required for normative changes -->

### Is this a breaking change?

- [ ] Yes - requires MAJOR version bump
- [ ] No - backwards compatible

### If breaking, describe migration path:

<!-- How should existing implementations adapt? -->

### Affected surfaces:

<!-- List affected interfaces from docs/surface-contract.adoc -->

- [ ] Producer seam
- [ ] Consumer seam
- [ ] Transparency log seam
- [ ] None / Internal only

## Security Analysis

<!-- Required for normative changes -->

### Security impact:

- [ ] No security impact
- [ ] Security improvement
- [ ] Potential security consideration (describe below)

### Security considerations:

<!-- If applicable, describe security implications -->

### Threat model updates:

<!-- Does this change require updates to docs/threat-model.adoc? -->

- [ ] No updates needed
- [ ] Updates included in this PR

## Testing

### How was this tested?

<!-- Describe testing performed -->

### Test commands run:

```bash
# Example:
just check
just schema-validate
just vectors-validate
```

## Related Issues

<!-- Link related issues using #number -->

Fixes #
Related to #

## Additional Notes

<!-- Any additional context or notes for reviewers -->
