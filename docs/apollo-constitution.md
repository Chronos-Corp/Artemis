# Apollo — Product Constitution

*Product Constitution · Apollo / 4NSIC · Rev. 0.1 · 16 August 2026*

> **RETIRED — Superseded by [Artemis Product Constitution v0.3](artemis-product-constitution.md).** This document is retained as implementation history, not living product doctrine. Section numbers below are unchanged from Rev. 0.1 and remain valid for existing citations into this file, but they no longer correspond to the current constitution's numbering — do not use this document, or its section numbers, as current authority. See `artemis-product-constitution.md` for the governing product identity, and `docs/chronos-constitution.md` (or its own successor, Chronos Strategic Constitution v0.3, not yet landed in this repository) for company-level doctrine.

> *Start with a file. Follow the evidence. Hunt outward.*

**Relationship to the Chronos Constitution.** The Chronos Corp Strategic Constitution (`docs/chronos-constitution.md`) defines why the company exists and the principles every product must obey. This document applies those principles to Apollo. It defines what Apollo is, which user problem it owns, what must remain true as the product grows, and which strategic questions are still open.

**What this document is not.** This is not a marketing page, a feature backlog, or a claim that every idea below is settled. The roadmap and the Dossier can change rapidly. The Constitution changes only when the product thesis, trust model, or core practitioner workflow changes.

---

## 1. Apollo's Product Thesis

> **LOCKED — Apollo is a threat-hunting platform/tool.** Apollo exists to help security practitioners understand suspicious or unfamiliar artifacts on live systems, connect those artifacts to relevant threat intelligence, and pivot those relationships into evidence-driven hunts.

> **LOCKED — The filesystem is Apollo's primary investigation surface.** Apollo begins where analysts often begin: a file or directory on a live system. The file explorer is not a secondary utility attached to a threat-intelligence product. It is the primary interaction surface through which Apollo turns the filesystem into an explorable security context.

> **LOCKED — Apollo owns the verb: Hunt.** Capabilities belong in Apollo when they materially improve threat hunting. Full digital-forensics acquisition belongs elsewhere in the Chronos portfolio. Malware detonation, offensive emulation, and unrelated SOC administration should not expand Apollo by default.

### The north-star experience

> *Click a file, understand what it is and why it exists, see how it relates to known threats, then use any meaningful relationship as a pivot to hunt the surrounding filesystem for associated evidence.*

Apollo should progressively answer five questions:

1. What is this file?
2. What is it for?
3. Is it expected here, in this form, on this system?
4. What security intelligence or risk relationships are associated with it?
5. What else in the chosen scope is related to the same threat?

## 2. The Practitioner Problem Apollo Owns

Threat hunting frequently begins with an artifact whose meaning is unclear. The analyst may have a filename, path, hash, signer, or alert context, but establishing purpose and relevance often requires manually combining operating-system knowledge, vendor metadata, threat-intelligence portals, vulnerability data, ATT&CK mappings, rule repositories, web research, EDR history, and local filesystem context.

> **HYPOTHESIS — The gap is not raw file metadata.** Existing products can already provide hashes, signatures, reputation, prevalence, and other metadata. Apollo's product opportunity is to unify file purpose, expectedness, threat relationships, evidence quality, and the ability to pivot immediately from a relationship into a recursive hunt.

> **HYPOTHESIS — The expensive question is "what does this mean here?"** Security practitioners often need context rather than another verdict. A legitimate binary in the wrong location, an expected component with an exposed version, or a signed utility used in an unusual way may be more important than a simple known-bad hash match.

### The Tuesday-morning workflow

| Without Apollo | With Apollo |
| --- | --- |
| Search filename/hash across several sources. | Select the file once and see identity, purpose, location, signer, version, relationships, and provenance. |
| Determine whether the path and owner make sense. | Apollo evaluates expectedness and explains the basis for that judgment. |
| Manually connect a CVE/APT/IOC to relevant artifacts. | Relationships are first-class objects and can become hunt pivots. |
| Write or gather ad hoc searches for the rest of the tree. | Launch a recursive hunt against the chosen scope. |
| Reconcile hits manually and judge significance. | Receive evidence-ranked findings with source, confidence, and freshness. |

## 3. The Laws of Apollo

1. **Hunt from evidence, not labels.** Apollo should never let a reputation score or category replace the underlying evidence needed to understand why an artifact matters.
2. **Every meaningful relationship should be actionable.** If Apollo shows a CVE, IOC, APT, campaign, malware family, detection, certificate, signer, or risk association, the analyst should eventually be able to pivot from that relationship into an appropriate hunt.
3. **Explain purpose before declaring danger.** Apollo's differentiator is partly understanding what a file is supposed to do and whether its location, version, ownership, signature, and surrounding context are expected.
4. **Recursive scope is a first-class hunting primitive.** The current directory tree is the initial hunt boundary. Apollo may expand the same hunt model to a drive, host, selected hosts, or fleet without changing the core interaction.
5. **No finding outranks its provenance.** Source, confidence, time, freshness, and method remain attached to findings and relationships.
6. **"No match" is not "safe."** Absence of known evidence is not proof of safety. Apollo should state what was checked, against which corpus, and how current that corpus was.
7. **Established detection languages remain portable.** YARA and Sigma are the rule formats. Apollo must not create a bespoke detection language merely to capture customers.
8. **AI may accelerate reasoning; it may not invent observed facts.** AI-generated explanations, summaries, classifications, or hypotheses must remain separable from collected evidence and deterministic matches.
9. **The agent extends reach; it does not define Apollo.** Apollo's sensor and fleet substrate are execution mechanisms. The product remains threat hunting, not endpoint administration.

## 4. Core Interaction Model

| Stage | Analyst question | Apollo responsibility |
| --- | --- | --- |
| **FILE** | What am I looking at? | Identify artifact type, metadata, hashes, ownership, signer, version, path, and other available facts. |
| **UNDERSTAND** | What is this for? | Explain likely purpose, parent product/component, expected location, and contextual role. |
| **RELATE** | What security knowledge is connected to it? | Expose relevant IOCs, CVEs, actors, campaigns, malware, techniques, detections, risk associations, and provenance. |
| **PIVOT** | Which relationship do I want to investigate? | Turn the selected relationship into a concrete hunt hypothesis. |
| **HUNT** | What else in scope supports or weakens that hypothesis? | Recursively inspect the selected scope and return evidence-ranked related artifacts. |
| **EXPLAIN** | What does the combined evidence mean? | Show the relationship chain, uncertainty, freshness, and actionable next steps without hiding underlying evidence. |

> **LOCKED — The interaction must remain understandable without AI.** Apollo may use AI to explain and accelerate. The fundamental File → Understand → Relate → Pivot → Hunt → Explain flow must remain coherent and usable through structured evidence and deterministic capabilities alone.

### Initial scope ladder

| Scope | Status | Meaning |
| --- | --- | --- |
| Current file | CORE | Understand one artifact deeply. |
| Current directory / subtree | CORE | Recursive relationship-driven hunt. |
| Drive / host | NEAR-TERM | Apply the same hunt model across a broader local scope. |
| Selected remote hosts | LATER | Execute via Apollo Sensor or another approved backend. |
| Fleet / external telemetry | LATER | Scale the same hunt model across multiple collection and query systems. |

## 5. File Intelligence

> **LOCKED — "What is this file for?" is a product requirement.** Apollo is not complete if it only reports hashes, metadata, reputation, and vulnerabilities. It must develop a reliable way to explain the role and expected purpose of an artifact while making uncertainty visible.

### File Intelligence Object

| Domain | Examples |
| --- | --- |
| **Identity** | Path, filename, file type, hashes, size, timestamps, architecture. |
| **Authenticity** | Signature status, signer, certificate, publisher, trust chain. |
| **Product context** | Product name, component, package, version, vendor, installed-software relationship. |
| **Purpose** | What the artifact normally does and which system/application function it serves. |
| **Expectedness** | Whether this file is normally expected at this location, under this owner, with this signer/version/context. |
| **Threat relationships** | CVE, IOC, APT/group, campaign, malware family, ATT&CK technique, detection rule, risk/abuse relationship. |
| **Evidence quality** | Source, confidence, freshness, observation time, match method. |
| **Local context** | Neighboring files, path characteristics, duplicated names, suspicious placement, relevant local observations. |

### Purpose-source hierarchy

> **HYPOTHESIS — Prefer deterministic and curated sources before model-only classification.** Apollo should first exploit trusted metadata, signatures, package manifests, vendor/product resources, OS catalogs, known-file knowledge, curated intelligence, and local relationships. Model-assisted explanations may synthesize those facts, but an AI guess should never be indistinguishable from verified product knowledge.

## 6. Threat Relationship Intelligence

Apollo should treat security concepts as graph relationships rather than flat labels attached to a file. Relationships are valuable because they explain context and become hunt pivots.

| Relationship | Examples of what it can mean | Potential pivot |
| --- | --- | --- |
| **IOC** | Known hash, domain, IP, path, certificate, mutex, or related indicator. | Find direct and related indicators in scope. |
| **CVE** | Affected product/version or artifact associated with exploitation. | Assess exposure and hunt for compromise evidence. |
| **Threat actor / APT** | Artifact, malware, infrastructure, technique, or campaign relationship. | Hunt for actor-associated evidence with explicit confidence. |
| **Campaign** | Known cluster of infrastructure, malware, tactics, or artifacts. | Search for campaign-associated artifacts and detections. |
| **Malware family** | Known or suspected family relationship. | Find variants, configs, payloads, and family-specific detections. |
| **ATT&CK technique** | Behavioral or software-use relationship. | Hunt for artifacts supporting a technique hypothesis. |
| **Detection** | YARA/Sigma or other established detection content. | Run or trace the detection and related evidence. |
| **Risk-based relationship** | Dual-use tool, LOLBin, commonly abused signer/tool, unusual location, unsupported version. | Expand contextual hunt without presenting weak association as direct compromise. |

> **OPEN — Relationship strength semantics.** Apollo needs an explicit vocabulary for direct evidence, strong association, contextual support, and weak association. The product must avoid turning "related to" into an unbounded graph that floods the analyst with technically true but operationally useless connections.

## 7. Recursive Hunting and Hunt Packs

> **LOCKED — Recursive hunting is Apollo's signature mechanic.** When an analyst selects a meaningful threat relationship, Apollo should be able to recursively inspect the chosen filesystem scope for other artifacts that support, contradict, or contextualize that relationship.

### A hunt is a hypothesis applied to a scope

> *Given this relationship, what other evidence should exist here if the hypothesis is true?*

A recursive hunt should return structured findings rather than a flat list of matches: artifact/observation, relationship to the selected hunt concept, detection/match method, evidence strength, source and provenance, observation and receipt time where relevant, threat-intelligence freshness, and an explanation of why the finding matters.

> **DECIDED — Hunt Packs are executable knowledge, not a proprietary language.** A Hunt Pack packages the evidence Apollo knows to look for around a threat concept. It can reference YARA, Sigma, hashes, paths, filenames, versions, registry checks, known indicators, and provenance. It must not become a new detection DSL.

> **HYPOTHESIS — CVE compromise assessment is a high-value Apollo workflow.** Apollo should eventually distinguish "this vulnerable software exists" from "there is evidence this vulnerability was exploited." A CVE pivot can become a compromise-assessment hunt that looks for exploitation artifacts, payloads, persistence, post-exploitation evidence, related IOCs, and vulnerable versions.

## 8. Evidence, Verdicts, and Trust

> **LOCKED — Provenance over boolean.** Apollo findings and verdicts preserve the path from observation to evidence to inference to conclusion. A conclusion is useful only if the analyst can understand what produced it.

| Layer | Definition | Example |
| --- | --- | --- |
| **Observation** | What Apollo actually saw or collected. | File hash X exists at path Y. |
| **Evidence** | Why the observation is security-relevant. | Hash X appears in source Z; YARA rule Q matched. |
| **Inference** | What the evidence suggests. | Artifacts are consistent with exploitation of CVE-N. |
| **Conclusion** | Current judgment with uncertainty. | Probable compromise; confidence high. |
| **Action** | What the analyst/system chooses to do. | Expand hunt, acquire sample, escalate case, contain through another tool. |

> **DECIDED — Intel freshness belongs with the verdict.** PR #17 established that a clean-looking result is incomplete without the age of the intelligence corpus behind it. Freshness should remain per source where sources can age independently.

### Language rules for verdicts

- Prefer "no matching evidence found in the available corpus" over "clean" when the distinction matters.
- Never hide never-synced or stale intelligence behind a normal-looking empty result.
- Separate deterministic matches from contextual associations.
- Show uncertainty rather than forcing every artifact into malicious/benign.
- Keep analyst-visible evidence sufficient to challenge Apollo's conclusion.

## 9. AI Doctrine for Apollo

> **LOCKED — AI is an accelerator, not the evidentiary authority.** Apollo may use AI to explain files, synthesize relationships, propose hunts, prioritize findings, summarize evidence, and generate hypotheses. The authoritative record remains the observed and sourced evidence.

**Good uses of AI:** explain a complex file/component in practitioner language using grounded metadata and sources; summarize why several independent findings are related; suggest the next hunt pivot and explain the hypothesis behind it; cluster or prioritize large result sets while preserving raw findings; translate an analyst's natural-language question into a structured hunt plan; highlight missing evidence that would strengthen or falsify a hypothesis.

**Prohibited product behavior:** presenting model-generated facts as if Apollo observed them; inventing threat relationships because they sound plausible; concealing deterministic evidence behind an opaque risk score; allowing an AI explanation to overwrite source provenance; treating confidence language from a model as equivalent to measured evidence confidence.

> *Reason intelligently. Prove with evidence.*

## 10. Architecture and Reach

> **LOCKED — Live systems, not dead-box forensics.** Apollo reasons about the current state of running systems. Traditional dead-box disk-image forensics is outside Apollo's product scope and belongs to a different Chronos discipline.

> **LOCKED — Userland only.** Apollo does not require a kernel driver. This is a trust and deployment boundary, not merely an implementation preference.

> **LOCKED — Hashes may leave the host; file contents leave only by explicit request.** Sample retrieval is an intentional, logged, attributable analyst action. Apollo should not silently centralize file contents as the price of using the product.

### Collection and execution backends

| Backend | Role in Apollo | Status |
| --- | --- | --- |
| Local application | Direct filesystem analysis and local hunts. | CORE |
| Apollo Sensor | Optional remote collection and hunt execution. | PROVEN FOUNDATION |
| EDR / SIEM / telemetry connectors | Alternative evidence and execution backends. | OPEN / LATER |
| Offline or disconnected workflows | Potential deployment mode for constrained environments. | OPEN |

> **DECIDED — Fleet substrate is sufficient for now.** Enrollment, credential rotation, sample retrieval, fleet UI, sensor health, scan coverage, and staleness prove the agent architecture. Further fleet-administration work is paused while Apollo's core hunting interaction is completed.

> **OPEN — Agentless-first is not a constitutional requirement.** External EDR/SIEM integration may reduce enterprise adoption friction, but it should not redefine Apollo's local filesystem wedge. The product should choose expansion backends based on customer evidence, not on a prior assumption that every useful hunt must begin in external telemetry.

## 11. Scope Boundaries Across Chronos

Apollo should remain focused enough that the rest of the Chronos portfolio can exist without duplication.

| Capability | Apollo's role | Likely Chronos home |
| --- | --- | --- |
| Threat hunting | Owns the workflow. | Apollo |
| Filesystem intelligence and relationship pivots | Owns as core hunting capability. | Apollo |
| Recursive directory/host/fleet hunt execution | Owns the hunt; may use shared backends. | Apollo |
| Digital-forensics acquisition and deep reconstruction | Consumes results where useful; does not own full discipline. | Hermes hypothesis |
| Malware detonation / sandbox analysis | Can submit or consume results; does not own detonation. | Hades hypothesis |
| Red-team / adversary emulation | Can hunt for traces produced by exercises; does not own attack execution. | Ares hypothesis |
| Detection engineering | Uses YARA/Sigma and Hunt Packs; does not need to own full authoring lifecycle. | Hephaestus reserved |
| Case reasoning across many investigations | May provide hunt context; enterprise case orchestration may belong elsewhere. | Athena reserved |
| Continuous endpoint monitoring | Can consume observations; should not quietly become an EDR replacement. | Argus reserved / external tools |

> **LOCKED — Apollo is not an EDR or SIEM replacement.** Apollo can integrate with or complement those systems. Its value is not to recreate broad telemetry collection, alert management, or generic SOC operations. Its value is to turn artifacts and relationships into explainable hunts.

## 12. Current Product Build Doctrine

> **NOTE — Constitutions guide roadmaps; they are not roadmaps.** The sequence below is the current implementation interpretation of this Constitution. It is Decided, not Locked, and can change if customer evidence or technical findings justify a better path.

| Sequence | Capability | Why it advances the Constitution |
| --- | --- | --- |
| PR #17 | Intel freshness in verdicts | Strengthens the evidence and trust doctrine. **Completed.** |
| PR #18 | File Intelligence Model | Makes "what is this file and what is it for?" a first-class contract. |
| PR #19 | Threat Relationship Model | Turns CVE/IOC/APT/campaign/malware/risk associations into structured, actionable objects. |
| PR #20 | Recursive Hunt Engine | Implements the core relationship-to-hunt mechanic. |
| PR #21 | First real Hunt Pack | Proves executable curated knowledge against the hunt engine. |
| PR #22 | Hunt Scope Expansion | Extends from subtree to broader drive/host scopes without changing the core interaction. |
| Later | Remote/fleet and external execution backends | Scales the same hunt model only after the local product thesis works. |

> **DECIDED — Do not let infrastructure lead the product.** If a proposed PR improves fleet administration, connector breadth, deployment mechanics, or generic platform plumbing but does not materially advance the core hunt experience or an explicitly validated need, it should lose priority to product-thesis work.

## 13. First Customer and Commercial Hypotheses

> **OPEN — The first buyer is not yet known.** Potential early users include independent or boutique IR practitioners, MSSP analysts, in-house threat hunters, and SOC/IR teams. "Security teams" is not a sufficiently specific customer definition.

> **OPEN — The first paid outcome is not yet known.** Apollo might earn budget through faster unknown-file triage, better filesystem context, recursive pivots, CVE compromise assessment, reduced investigation time, or increased confidence. The product should not choose pricing before learning which result practitioners value enough to pay for.

### Customer-discovery questions

1. When you encounter a file you do not recognize on a live system, how do you determine what it is and what it is for?
2. How do you decide whether that file belongs in that location and context?
3. How do you connect the artifact to CVEs, IOCs, campaigns, threat actors, or known abuse patterns?
4. Once you identify a meaningful relationship, how do you search the surrounding filesystem for related evidence?
5. Which part of that process is slow, unreliable, or requires the most specialist knowledge?
6. What result would make you use the same tool again on the next investigation?

> **EVIDENCE REQUIRED — Evidence that Apollo's wedge is real.** Practitioners outside the project should be able to use the core workflow against their own or representative systems, reach useful conclusions without a founder-led walkthrough, and voluntarily return to the workflow on another hunt.

## 14. Competitive Boundary

Apollo will coexist with mature tools for endpoint detection, SIEM, forensic collection, rule execution, timeline analysis, and threat intelligence. The product must win through a workflow those tools do not make sufficiently coherent, not by claiming they do nothing useful.

> **HYPOTHESIS — Apollo's differentiation is the joined workflow.** The defensible experience is the combination of file purpose, expectedness, threat relationships, recursive pivot hunting, evidence ranking, and provenance in one filesystem-first interaction. Any one element may be copyable; the product value comes from the integrated analyst workflow and the curated relationship knowledge underneath it.

### The five-minute test

> *A practitioner should be able to understand why Apollo is better than composing file metadata, threat-intelligence portals, YARA/Sigma tools, Velociraptor-style collection, and a spreadsheet within five minutes of using the core workflow.*

> **EVIDENCE REQUIRED — A demo must make the answer obvious.** The decisive demo is not a slide. It is: select an unfamiliar file → understand purpose and expectedness → see a meaningful threat relationship → click the relationship → recursively hunt → receive evidence-ranked related artifacts with provenance.

## 15. Product Success Measures

> **HYPOTHESIS — Measure analyst outcomes before platform scale.** Early Apollo metrics should prove that the product improves threat-hunting work, not merely that it can scan many hosts or ingest many feeds.

| Measure | What it tests |
| --- | --- |
| Time to understand an unfamiliar file | Whether Apollo reduces research and context-switching. |
| Time from first artifact to meaningful hunt pivot | Whether relationships are actionable rather than decorative. |
| Precision of recursive hunt findings | Whether Apollo avoids flooding analysts with weak associations. |
| Evidence explainability | Whether analysts can understand and challenge why a result appeared. |
| Intel freshness visibility | Whether users can distinguish current coverage from stale or absent knowledge. |
| Repeat usage by external practitioners | Whether Apollo solves a recurring problem rather than producing a good demo. |
| Useful finding rate | Whether hunts surface evidence practitioners say they would otherwise have missed or taken materially longer to find. |
| Founder assistance required | Whether the product can stand on its own. |

## 16. Expansion Gates

Apollo earns broader scope through evidence, not through the availability of engineering ideas.

1. The local file-intelligence experience is coherent and trustworthy.
2. Relationship pivots work on real threat concepts.
3. Recursive hunts return useful, explainable evidence with acceptable precision.
4. At least one Hunt Pack demonstrates repeatable value on a real or representative hunt.
5. External practitioners use Apollo without a walkthrough and choose to use it again.
6. A specific buyer and paid outcome become visible.
7. Only then should broad fleet execution, major connector work, hosted architecture, or adjacent Chronos products receive substantial product investment.

## 17. Immediate Open Questions

### Open · 1 — File purpose

How can Apollo explain what an artifact is for with enough reliability to deserve analyst trust?

**Evidence required:** Prototype metadata/catalog/package/curated sources and measure correctness before relying on model-only classification.

### Open · 2 — Expectedness

How should Apollo judge that a legitimate file is unusual in this location or context without turning rarity into suspicion?

**Evidence required:** Define deterministic expected-location and ownership signals, then validate them against real systems.

### Open · 3 — Relationship strength

What threshold makes an IOC/CVE/APT/campaign/risk relationship worth presenting and huntable?

**Evidence required:** Create evidence-strength classes and test analyst precision/recall expectations.

### Open · 4 — Recursive hunt semantics

What evidence should a pivot seek, and how should it rank direct matches versus contextual associations?

**Evidence required:** Implement against one real CVE or campaign and review result quality with practitioners.

### Open · 5 — First customer

Which practitioner experiences this pain frequently enough to adopt Apollo first?

**Evidence required:** Interview 3–5 practitioners from the most reachable candidate groups using the actual workflow questions.

### Open · 6 — Commercial model

What is free, paid, hosted, licensed, or intelligence-subscribed?

**Evidence required:** Choose only after the buyer and paid outcome are evidenced.

### Open · 7 — Remote execution

When does Apollo Sensor outperform using an existing EDR/collection system as the backend?

**Evidence required:** Compare adoption friction, data access, hunt fidelity, and customer preference after the local wedge works.

### Open · 8 — Curated knowledge operations

Who maintains Hunt Packs and file-purpose/threat relationships as the corpus grows?

**Evidence required:** Model update cadence, reviewer burden, quality controls, provenance requirements, and economics before scaling pack count.

## 18. Decision Discipline

Apollo inherits the Chronos drawers. Product strategy should distinguish constitutional truth from current implementation choices so that code cannot silently redefine the product.

| Drawer | Apollo meaning | Rule |
| --- | --- | --- |
| **LOCKED** | Product identity, trust boundary, or core practitioner workflow. | Reopen only through an explicit product-strategy conversation. |
| **DECIDED** | Current implementation or sequencing choice. | Execute until evidence supports a better decision. |
| **HYPOTHESIS** | Belief about user value, differentiation, architecture, or expansion. | Test before treating as product truth. |
| **OPEN** | Material unanswered question. | Keep visible; do not let implementation decide accidentally. |
| **EVIDENCE REQUIRED** | Observable result needed to resolve a hypothesis or open question. | Name it before prolonged debate. |

### Constitutional test for an Apollo feature

1. Does it materially improve the Hunt workflow?
2. Which stage does it advance: File, Understand, Relate, Pivot, Hunt, or Explain?
3. Does it strengthen evidence quality, trust, or scope without replacing the core interaction?
4. Could it belong more naturally to another Chronos product?
5. Is the proposed behavior grounded in evidence or merely technically possible?
6. Does it preserve userland trust boundaries, provenance, and established rule portability?
7. What would we remove or deprioritize to build it?

## 19. The Apollo North Star

Apollo should be able to grow from a local filesystem tool into a host and fleet hunting platform without losing the interaction that made it valuable in the first place. Scale is an expansion of scope, not a replacement of purpose.

> *Start with a file. Understand it. Follow its relationships. Hunt the evidence outward.*

> **LOCKED — Apollo must remain recognizable as it scales.** Whether a hunt runs against one directory, an entire host, thousands of endpoints, or telemetry from external security tools, the product should preserve the same essential promise: turn an artifact or threat relationship into an explainable, evidence-backed hunt.

---

## Status of this document

Revision 0.1 re-centers Apollo on the original filesystem threat-hunting vision while preserving the strongest architecture and trust decisions already built. The next revision should incorporate practitioner evidence, the first validated file-purpose model, explicit relationship-strength semantics, and results from the first end-to-end recursive hunt.

## Revision discipline

This file is the Apollo-scoped constitution, subordinate to `docs/chronos-constitution.md` for anything company- or portfolio-level, and superseding that document's shorter §7 treatment of Apollo specifically wherever the two differ in detail (this file is more current and more precise). It supersedes the strategic framing previously written into `README.md`'s roadmap and the standalone "Apollo Dossier" artifact — see PR history for the corrections. Revise the drawer that changed; do not rewrite a hypothesis as a principle because code was written for it.
