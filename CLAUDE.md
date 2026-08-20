# CLAUDE.md

Guidance for Claude Code in this repository. `AGENTS.md` is a symbolic link to this file.

## 0. The one rule that applies everywhere

**This project uses ASD-STE100 Simplified Technical English, and no other English.** This is not a
documentation style. It applies to every word you write here, in a file and in a message:

| Surface | STE applies |
|---|---|
| Markdown in `README.md`, `docs/`, and this file | yes |
| Rustdoc comments, `//` comments, and `# Safety` notes | yes |
| Error messages, `Display` and `Debug` text, and `tracing` messages | yes |
| Commit messages, pull request titles and bodies | yes |
| Answers to the user, a plan, and a summary of your work | yes |
| A shell script, a comment in it, and the text it prints | yes |
| Identifiers, when a plain word and a clever word both fit | yes |
| Quoted standards text, third-party names, and code output | no, quote them exactly |

A short answer, a scratch file, and a temporary note get the same rules. Speed is not an exception.

Section 2 gives the rules. Section 3 gives the word list. When a rule and clarity conflict, choose
clarity and record the exception in section 3.

## 1. Project state

`fidelity` is an open-source Rust library. It detects changes to an application's runtime
environment and applies a response that the host application selects.

Every v1 category holds a detector. Five platforms run, each with real clean and hostile controls.
All five compare executable memory against a baseline that `start()` captured, and all five read
tracer state. Four read the machine that runs the system, and iOS is the one that does not. macOS
adds `guarded!()`, and Linux, Android, and Windows add unaccounted code. Four read the dispatch
table of the main image, so a redirected call is a finding that the baseline misses, and Android is
the one that does not, because an app forks from zygote. `UiAbuse` takes a host report and reads no
operating system, so it sits off the platform axis, and the coverage matrix holds no row for it.
The iOS results come from the simulator, so a device has still to confirm them. The Windows results
come from the QEMU guest that `tests/platform/vm/windows/` builds, and the identity controls of that
platform sign the subject in the guest, because the tier reads the signature of the running image.
The macOS machine-host control needs a guest too, and `tests/platform/vm/macos/` builds that one.
Linux, Windows, and Android hold the hostile machine-host control alone, because every control of
those three runs in a guest or an emulator. No platform is supported yet, because that needs the
full release tests.

Capabilities are traits, in `fidelity-core/src/capability/`. Operating systems are crates, under
`crates/probe/`. `docs/plan/06-delivery.md` holds both axes and the shape that every probe crate
repeats. Follow it rather than inventing a second pattern.

- Rustdoc is authoritative for the Rust surface. `docs/plan/` keeps behavior, security semantics,
  and release criteria.
- Add a crate only with the layout in `docs/plan/06-delivery.md`.
- Never label a platform supported without real clean and hostile controls.

Read `docs/plan/README.md` first. The locked decision index in that file is settled. Do not reopen
a locked decision, and do not ask the product owner to choose it again.

## 2. Writing rules

Full STE compliance needs the STE dictionary, which this project does not hold. Apply the Part 1
writing rules in full. Apply the dictionary rules through the project word list in section 3.

Sentences and paragraphs:

1. Write in the active voice. Write "the backend captures the baseline", not "the baseline is
   captured".
2. Keep an instruction to 20 words or less. Keep a descriptive sentence to 25 words or less.
3. Write one instruction in one sentence.
4. Keep a paragraph to 6 sentences or less. Write one topic in one paragraph.
5. Use the simple present tense. Use the past or future tense only when the time is important.
6. Keep the articles. Write "the detector", not "detector".
7. Do not write a noun cluster of more than 3 words.
8. Do not use an `-ing` form as a noun or a verb. Technical names such as `Debugging` are an
   approved exception.
9. Write a positive statement. Do not write "not unusual".
10. Use a vertical list for 3 or more conditions.

Words:

11. Use one word for one meaning, and one meaning for one word. Use the same word every time. Do
    not change the word for variety.
12. Use a word in one part of speech only.
13. Do not use slang, an idiom, a metaphor, or a joke.
14. Do not use marketing words. Examples: robust, powerful, seamless, enterprise-grade,
    military-grade, bulletproof.

Format:

15. Write en-US spelling.
16. Use straight quotes. Do not use a curly quote.
17. Do not use an em dash. Use a comma, a colon, or a new sentence.
18. Do not write "e.g.", "i.e.", or "etc.". Write "for example", "that is", and a complete list.
19. Wrap Markdown at 100 columns.
20. Use "must", "must not", "should", and "may" as RFC 2119 and BCP 14 define them. These words
    carry normative weight in `docs/plan/`.

## 3. Project word list

STE lets a project approve its own Technical Names and Technical Verbs. These are approved:

attacker, baseline, callback, category, clean control, control, debugger, detector, emulator,
evidence, finding, handle, hook, hostile control, injection, jailbreak, latch, overlay, probe,
report, root, runtime, scan, signal strength, snapshot, test record, threshold, tracer, virtual
machine.

`evidence` names one thing only: what a finding carries, which is the `Evidence` type. It never
names a test, a test run, or the record in `tests/platform/`. Rule 11 is the reason, and the word
covered both meanings until 2026-08-18.

Replace these words:

| Do not write | Write |
|---|---|
| adversary | attacker |
| bless, sanction | accept |
| leverage, utilize | use |
| ensure | make sure |
| via | with, by |
| in order to | to |
| deliberately, materially, naturally | delete the word |
| evidence, for a test record or a test run | test record, control, test |
| artefact, destabilise, behaviour | artifact, destabilize, behavior |

A Rust identifier keeps its own name. `ensure_allowed()` is an API name, not prose.

## 4. Document set and size

Fidelity keeps a small, dense document set. Lean means no duplication and no padding. Lean does not
mean short. Density is the goal, and a line count is only a way to notice that density dropped.

**A fact that a reader needs always wins over a number in this section.** Never delete or compress
a decision, a constraint, a reason, or a measured value to make room for another one. If an
addition and a size trigger conflict, the addition lands and the trigger moves.

| Path | Role | Size trigger |
|---|---|---|
| `README.md` | What the library is, and the first example | 100 lines |
| `docs/plan/` | Normative specification, 8 files | 600 lines per file |
| `docs/adr/` | One enduring constraint and its reason | 60 lines per file |
| `docs/research/` | Non-normative notes: operating systems, and the vendor survey | 175 lines per file |

A size trigger is a question, not a wall. A file that passes its trigger gets one question in the
change: does this file still hold one role, or did it absorb a fact that another file owns? A good
answer keeps every line, and it raises the number in the table. Say which answer you reached.

Every number above rose on 2026-08-20, and the answer that raised them is on the record.
`04-detectors-and-platforms.md` passed 500, and it still holds one role: its sections are the signal
model, the excluded mechanisms, the identity tiers, one section for each detector, and the platform
floors, which is what section 5 gives it. It grew because three detectors landed, and a section for
each detector is what the file is for. The other three numbers rose by the same share, because three
files sat within 5 lines of a trigger that the same growth had made too tight.

Run `wc -l README.md CLAUDE.md docs/plan/*.md docs/adr/*.md docs/research/*.md` to see the corpus.
It is about 2360 lines. Read the whole set for duplication when it passes 2900, because many files
that each grow a little is the one kind of bloat a per-file trigger cannot see.

The 2200 reading came on 2026-08-19, and that pass ran the same day. It removed six duplicated facts
and repaired eight wraps, and it found four stale claims that no per-file trigger could see, because
each one sat in a file that a change to another file had falsified. That is the value of the pass:
duplication is what it looks for, and a contradiction is what it finds.

### What earns a line

Keep a line that carries a decision, a constraint, a reason, a measured value, or a fact that a
reader acts on. Delete a line that:

- repeats a fact that another document owns. Link to it instead, as section 5 states;
- restates in prose the table or the list above it;
- describes what the code already states clearly; or
- sells, reassures, or fills. See rule 14.

An addition removes what the addition itself makes redundant, in the same change, and names it.
That is the duplication check, and it is not a trade. An addition that duplicates nothing removes
nothing.

### Fixed rules

- Do not add a new document without a decision from the product owner.
- Do not add a roadmap, a FAQ, a vision statement, or a competitor comparison.
- Do not paste research surveys back into the repository. The research was condensed on purpose.
- Prefer a table or a list.

Two things sit outside this section:

- The platform test record, in `tests/platform/`. It lives with the tests, and it holds the
  controls that reproduce it. Never compress a test record. A gap in that record is the work list.
  See `docs/plan/05-verification.md`.
- Repository metadata: `LICENSE` and `SECURITY.md`.

## 5. One fact, one place

State a fact once. Every other document links to it.

| Fact | Home |
|---|---|
| Scope, categories, actions, non-goals | `docs/plan/01-product.md` |
| Trust boundary, invariants, false-positive policy | `docs/plan/02-security-model.md` |
| Lifecycle, configuration, API shape | `docs/plan/03-runtime-and-api.md` |
| Report contents, retention, memory and performance budgets | `docs/plan/07-state-and-budgets.md` |
| Signal strength, detector outcomes, excluded mechanisms, identity tiers, platform floors | `docs/plan/04-detectors-and-platforms.md` |
| Test layers, release tests, standards traceability | `docs/plan/05-verification.md` |
| Workspace layout, crates, native code, sequence, engineering constraints | `docs/plan/06-delivery.md` |
| The single summary of locked decisions | `docs/plan/README.md` |
| Operating-system mechanism candidates and hazards | `docs/research/platform-notes.md` |
| What commercial vendors do, and what we take from them | `docs/research/vendor-survey.md` |

The research notes are non-normative. The plan wins if the two disagree. Research must not restate a
settled decision, because two copies drift apart.

An ADR records the decision and the reason. An ADR must not repeat the operational detail that
`docs/plan/` holds. If a fact appears in two files, delete one copy and add a link.

## 6. Standards rules

Map to a standard only when the mapping is exact. Do not add a standard to look complete.

- OWASP MASVS, MASWE, and MASTG apply to mobile platforms only. Do not map a desktop detector to
  MASVS.
- MITRE D3FEND applies only when a detector implements that exact defensive technique.
- MITRE ATT&CK names attacker behavior. An ATT&CK identifier is never a Fidelity control.
- Do not add a CWE column, a CAPEC column, a coverage count, or a compliance claim.
- Record the standard version and the check date next to every mapping table.

## 7. Claims and links

- Verify every standards identifier against the live site before you commit it. Do not write an
  identifier from memory. Identifiers move between releases.
- Check every external link with an HTTP request before you commit it.
- Re-check operating-system version floors against the vendor lifecycle page before a release.
- Mark an unverified claim with the word "unverified". Do not present it as a fact.
- The plan wins if the research notes disagree with it.

## 8. Rust code rules

Read the skills in `.agents/skills/` before you write Rust here. `rust-best-practices` carries nine
chapters, and `rust-testing` carries the test patterns. Load them, do not work from memory.

General:

- Rustdoc becomes authoritative for the Rust surface. `docs/plan/` keeps behavior, security
  semantics, and release criteria.
- Follow the Rust API Guidelines and the skills in `.agents/skills/`.
- Section 0 applies to Rust comments, error text, and commit messages. STE is not only for Markdown.
- A platform is supported only after real clean and hostile controls exists. A mock, a stub, or a
  successful compile does not count. See `docs/plan/05-verification.md`.

Structure. `docs/plan/06-delivery.md` holds the layout, and it is normative:

- Capabilities are traits, in `fidelity-core/src/capability/`. Operating systems are crates, under
  `crates/probe/`. Do not invent a third pattern.
- Every crate except a probe crate sets `#![forbid(unsafe_code)]`. Platform `unsafe` stays in the
  `sys/` module of one probe crate.
- Only `fidelity/src/backend.rs` carries a `#[cfg]` on a target. A platform need anywhere else is a
  capability that nobody declared yet.
- Never select a platform with a Cargo feature.

Dispatch, errors, and lints:

- A detector takes the narrow capability it reads, as a generic bound with `?Sized`. The engine
  holds `Box<dyn Environment>`, so every capability trait stays object safe. See
  [ADR-0008](docs/adr/0008-object-safe-capability-traits.md).
- Return `Result` with a typed error. Never `unwrap()` or `expect()`, in a test or anywhere else:
  the workspace lints deny both, and `--all-targets` lints a test too. Use `let ... else`, `map_or`,
  `unwrap_or_else`, or `is_some_and`. In a test, write `let Some(x) = ... else { panic!("...") }`,
  which states the same thing and passes the lint.
- Write `#[expect(clippy::lint, reason = "...")]`, never `#[allow]`. The reason states why the code
  is better as written.
- Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.

Two deliberate deviations from the skills, with the reason. Do not "fix" either one:

- **No `thiserror`.** The skill recommends it for a library error. Fidelity writes `Display` and
  `Error` by hand, because `thiserror` pulls a proc-macro chain into the dependency tree of a
  security library. A default build of the workspace resolves to no external crate, and that
  supply-chain property is worth more than the saved lines. The optional `serde` feature is the one
  exception, and a host asks for it on purpose.
- **No `criterion`, `proptest`, `rstest`, or `mockall`.** Same reason. A measurement runs as an
  example that prints its numbers, and a fake environment is a plain struct in `fidelity-testkit`.

Tests:

- Name a test for the behavior it proves, and prefer one assertion.
- A rule that a document states needs a test. Four files in `crates/fidelity/tests/` hold them:
  `architecture.rs` for the shape of the workspace, `capability_matrix.rs` for the coverage table,
  `test_record.rs` for the generated record and the gate, and `public_surface.rs` for the SemVer
  surface. Add to one of them rather than trusting a claim. Break each new rule on purpose first,
  and check that it fails.
- A pure reader takes a recorded fixture, so its tests run on any machine.
