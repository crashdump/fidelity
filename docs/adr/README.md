# Architecture decisions

Accepted decisions:

- [ADR-0001: Separate platform probes from detectors](0001-probe-detector-separation.md)
- [ADR-0002: Use signal strength without scoring](0002-signal-strength-without-scoring.md)
- [ADR-0003: Keep the detector set closed](0003-closed-detector-set.md)
- [ADR-0004: Prohibit remote network I/O](0004-no-network-in-library.md)
- [ADR-0005: Own one explicit runtime per process](0005-library-owned-runtime.md)
- [ADR-0006: Make responses explicit and configurable](0006-configurable-responses.md)
- [ADR-0007: Make the protected-operation check value-producing](0007-value-producing-check.md)
- [ADR-0008: Keep every capability trait object safe](0008-object-safe-capability-traits.md)

ADR-0001's probe and detector separation, ADR-0002's strength model, and ADR-0006's response
contract are v1 invariants. To change one, supersede the ADR and supply clean and hostile evidence.
Do not relax one quietly to accommodate a difficult detector.
