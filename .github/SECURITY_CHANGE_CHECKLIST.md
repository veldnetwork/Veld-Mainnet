# Security-sensitive change checklist

- [ ] State the trust boundary and attacker-controlled inputs.
- [ ] Identify consensus, replay, reorganization, persistence, and downgrade
      effects.
- [ ] Confirm strict parsing, canonical serialization, and bounded resource use.
- [ ] Confirm secret material is neither logged nor accepted through process
      arguments.
- [ ] Add accepted-path, rejection-path, restart, and rollback tests as relevant.
- [ ] Re-run the applicable sanitizer, provenance, profile-interlock, and
      process-boundary tests.
- [ ] Record every unavailable platform or external review as a release blocker;
      do not count it as passing.
- [ ] Keep live activation, signing, tagging, publishing, and deployment outside
      the code-review decision unless separately authorized.
