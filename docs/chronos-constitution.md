# Chronos Corp — Strategic Constitution

*Founder working document · Rev. 0.1 · 16 August 2026*

> *Secure what is. Prepare for what comes next.*
>
> Working expression, not yet an approved public tagline.

**Purpose — what this document is for.** This Constitution is the founder-level source of truth for Chronos Corp. It separates what is locked from what is merely decided, hypothetical, unresolved, or still in need of evidence. It exists to prevent roadmap momentum, branding enthusiasm, market pressure, or technical convenience from quietly redefining the company.

**Discipline — how to use it.** When strategy changes, revise the drawer that changed. Do not rewrite a hypothesis as a principle simply because code was written for it. Do not treat a product name as a commitment. Do not let a compelling feature redefine the company's purpose.

This file is the versioned home for that document going forward — see "Revision discipline" at the bottom before editing it.

---

## 1. The Chronos Thesis

Chronos Corp exists to pioneer security posture advancement across an evolving technological landscape. It develops offensive and defensive intelligence, research, and tools that help security practitioners understand risk, expose weakness, hunt threats, investigate compromise, validate defenses, and adapt before yesterday's assumptions become tomorrow's failures.

> **LOCKED — Security posture advancement is the company-level mission.** Chronos is not defined by a single security category, a single product, or a single technology cycle. The company exists to measurably advance security posture. Products, research programs, and services are means to that end.

> **LOCKED — Chronos is built for change, not merely for AI.** Artificial intelligence is the current security frontier, not the company's permanent identity. Chronos must be prepared for the technologies, attack surfaces, trust failures, and defensive requirements that emerge after AI as well as those created by AI today.

### The temporal doctrine

The name Chronos should have operational meaning. Security posture changes with time. Intelligence becomes stale. Vulnerabilities move from theoretical to exploited. Legitimate tools acquire new abuse patterns. New technologies invalidate old assumptions. Chronos therefore treats time, freshness, sequence, change, and historical context as first-class security variables.

| Temporal lens | Core question | Chronos obligation |
| --- | --- | --- |
| **Past** | What happened, and what evidence remains? | Preserve, reconstruct, learn, and retain institutional memory. |
| **Present** | What is happening now, and how strong is the current posture? | Hunt, investigate, validate, detect, and explain current risk. |
| **Future** | What is changing, and which security assumptions will fail next? | Anticipate, research, test, and build before the new frontier becomes ordinary. |

> *Security posture is not a state. It is a continuous race against change.*

## 2. The Laws of Chronos

1. **Advance posture, not feature count.** Every Chronos product or capability must materially help a practitioner understand, expose, investigate, validate, prevent, contain, recover from, or adapt to real security risk.
2. **Reason intelligently. Prove with evidence.** AI may accelerate reasoning, synthesis, prioritization, and hypothesis generation. Evidence must remain inspectable, attributable, and distinguishable from inference. Chronos systems may reason about evidence; they may not manufacture it.
3. **Offense and defense strengthen one another.** Chronos will not treat red-team and blue-team knowledge as separate worlds. Offensive testing should generate defensive evidence. Defensive findings should improve adversary emulation, detection engineering, validation, and posture.
4. **Time is part of truth.** Findings without observation time, source freshness, sequence, or historical context are incomplete when those variables affect meaning. Chronos must avoid presenting stale knowledge as current certainty.
5. **Prefer established security primitives over proprietary reinvention.** Where mature, trusted formats and standards exist, Chronos should orchestrate and extend them rather than create unnecessary vendor lock-in. Apollo's YARA and Sigma rule-format decision is the current exemplar.
6. **Specialize the tools; share the evidence.** Chronos products should solve distinct practitioner workflows while inheriting shared evidence, intelligence, provenance, identity, and interoperability foundations. A product should not exist merely to justify another Greek name.
7. **Follow risk, not hype.** Emerging technology earns Chronos investment when it creates a meaningful new capability, invalidates a security assumption, or changes attacker/defender economics in a measurable way.

## 3. AI and the Frontier Beyond AI

> **LOCKED — AI security risk is a first-class concern.** Chronos must address AI as both a source of new adversary capability and a new class of systems requiring protection. AI security is not a bolt-on practice area and not a marketing label.

Chronos should be able to confront AI-assisted adversary operations, agentic systems, tool and connector abuse, prompt injection, model and data trust failures, machine identity, AI supply-chain risk, autonomous attack behavior, and new forms of authorization or provenance failure as these domains mature.

> **LOCKED — AI is not the final frontier.** Chronos must preserve the ability to move beyond AI. Future technological shifts may create entirely new security categories. The company should be structurally capable of recognizing those shifts early and building offensive and defensive capabilities before the market fully stabilizes around them.

### Chronos Futures

> **HYPOTHESIS — A permanent emerging-security research function.** Chronos Futures would study technologies before they become conventional security markets. Its purpose would be to identify new attack surfaces, broken assumptions, telemetry requirements, attacker advantages, defensive gaps, and opportunities for new Chronos capabilities. This is a strategic concept, not yet an operating unit.

A Chronos Futures assessment should begin with five questions:

1. What new capability has appeared?
2. Which existing security assumption does it invalidate or weaken?
3. What new attack path, trust boundary, or scale advantage follows?
4. What evidence or telemetry will defenders need that they do not reliably have today?
5. What can be tested, measured, or built now rather than merely predicted?

## 4. Offensive and Defensive Security as One System

> **LOCKED — Chronos operates on both sides of security posture advancement.** The company will build for authorized offensive security and defensive security. The objective is not parity of product count. The objective is a closed learning loop in which each side improves the other.

The strategic loop: **Expose → Emulate → Hunt / Investigate → Improve → Validate Again.**

A future offensive system should be able to create evidence a defensive system can hunt. A defensive failure should be able to become a detection-engineering requirement. A new detection should be testable through authorized emulation. The long-term value of Chronos lies partly in closing this loop without flattening every discipline into one monolithic product.

> **DECIDED — Authorized offensive use must be governed.** Offensive Chronos products must be designed for legitimate red-team, penetration-testing, security-validation, and research workflows with authorization, scope, auditability, and misuse resistance treated as product requirements rather than afterthoughts.

## 5. Product Doctrine

> **LOCKED — One product, one discipline.** Every Chronos product must own a distinct security discipline and a clear practitioner workflow. Capabilities should live with the product whose primary job they advance. Shared substrate belongs below the products rather than being duplicated inside each one.

A proposed Chronos product must answer all of the following before it is funded:

1. Which practitioner owns this problem on an ordinary workday?
2. What specific security workflow does this product improve?
3. What is its primary verb?
4. Why is this a distinct product rather than a capability of an existing one?
5. Which shared Chronos assets make it meaningfully better or cheaper to build?
6. What evidence would prove that users value the workflow?
7. What does the product explicitly not do?

### Current portfolio status

| Name | Working discipline | Primary verb | Status | Constitutional note |
| --- | --- | --- | --- | --- |
| **Apollo** | Threat hunting | Hunt | **COMMITTED** | The only committed product. Its current product thesis is filesystem-first threat hunting. |
| Hermes | Digital forensics / evidence acquisition | Acquire | Strong hypothesis | Conceptually coherent; not yet earned by customer evidence or sequencing. |
| Hades | Malware analysis / isolation / containment | Analyze / Contain | Strong hypothesis | Potential handoff from Apollo and Hermes; scope requires further definition. |
| Ares | Red team / adversary emulation | Emulate / Attack | Strong hypothesis | Offensive counterpart within the Chronos posture loop; requires rigorous governance. |
| Athena | Investigation / analytical reasoning | Investigate | Reserved | Could own case reasoning and hypothesis management; may overlap other products if defined too early. |
| Hephaestus | Detection engineering | Forge | Reserved | Potential home for YARA, Sigma, validation, and detection-as-code workflows. |
| Argus | Continuous detection / monitoring | Watch | Reserved | Name and concept fit strongly; no commitment to build. |
| Aegis | Exposure / defensive posture | Protect / Assess | Reserved | Possible exposure-management discipline; must avoid duplicating mature markets without a clear wedge. |
| Nemesis | Breach and attack simulation | Validate | Reserved | Potential automated complement to Ares. |
| Daedalus | Attack-path analysis | Navigate | Reserved | Potential identity/network/cloud path modeling; category already competitive. |
| Mnemosyne | Organizational security memory | Remember | Reserved | Could become shared platform capability rather than a standalone product. |
| Iris | Integrations / data connectivity | Connect | Reserved | Likely substrate rather than a customer-facing product. |

> **OPEN — Product names are not legal clearances.** The mythology-based portfolio is a working product architecture. Trademark, domain, naming-conflict, and regulatory diligence have not been completed and must occur before external commitment.

## 6. The Shared Chronos Foundation

> **HYPOTHESIS — Specialized tools should share a common security reality.** The long-term portfolio becomes economically and technically plausible only if new products inherit shared foundations rather than recreating them. The exact platform boundary is not yet locked.

Candidate shared foundations:

- **Evidence graph** — artifacts, observations, findings, relationships, and their history.
- **Provenance model** — source, confidence, observation time, receipt time, freshness, and attribution.
- **Threat relationship graph** — CVEs, IOCs, campaigns, malware families, threat actors, techniques, software, and risk associations.
- **File intelligence** — identity, purpose, expectedness, ownership, signature, version, location, and relationship knowledge.
- **Hunt and detection content** — YARA, Sigma, path/version/registry checks, and curated relationship logic.
- **Case and investigation objects** — hypotheses, findings, analyst decisions, prior conclusions, and evidence chains.
- **Identity and audit** — who performed, requested, approved, or observed an action.
- **Connector framework** — controlled access to endpoint, EDR, SIEM, cloud, identity, and other telemetry sources.

> **OPEN — Which foundations become platform products?** Some shared capabilities may remain invisible infrastructure; others may justify customer-facing products later. Chronos should not force platform branding where a shared library, service, or schema is sufficient.

## 7. Apollo: The First Proof of Chronos

*See [`docs/apollo-constitution.md`](apollo-constitution.md) for Apollo's full product-level constitution -- this section is the condensed, company-level view; that document is more current and more precise wherever the two differ in detail.*

> **LOCKED — Apollo is a threat-hunting platform/tool.** Apollo's core is filesystem-first threat hunting on live systems. The analyst begins with a file or directory, understands the artifact, sees its security relationships, and pivots those relationships into recursive hunts for associated evidence.

> *Start with a file. Follow the evidence. Hunt outward.*

### Apollo's non-negotiable product promise

Selecting a file should progressively answer: What is this file? What is it for? Is it expected here? Is it related to known IOCs, CVEs, APTs, campaigns, malware, detections, or other risk-based threats? If a relationship is selected, Apollo should be able to hunt the chosen recursive scope for related evidence.

### Apollo's interaction doctrine

**File → Understand → Relate → Pivot → Hunt.**

### Inherited Apollo constraints

- **Live systems, not disk images.** Dead-box forensics is outside Apollo's scope. Apollo reasons about a running system's current state.
- **Userland trust boundary.** No kernel driver. Hashes may leave the host; file contents leave only on explicit, logged, attributed analyst request.
- **Established rule formats.** YARA and Sigma remain the rule formats. Apollo does not invent a bespoke detection language.

> **DECIDED — The agent is not the product.** Apollo's endpoint agent is infrastructure that can extend collection and execution. It must not become the definition of Apollo. Fleet substrate built through PR #16 is sufficient to prove the remote-agent architecture while the core hunting experience is developed.

> **DECIDED — Hunt Packs are important machinery, not the whole product.** Curated CVE-to-indicator and broader threat-relationship knowledge can become a durable moat, but Apollo is not a hunt-pack company. Hunt Packs operationalize relationship knowledge so an analyst can turn a threat concept into an executable hunt.

> **OPEN — How Apollo expands beyond the local host.** Apollo may eventually execute the same hunt through its own sensor, EDR/SIEM connectors, remote collection systems, or other evidence backends. The local filesystem experience should not depend on selecting that answer prematurely.

## 8. Evidence Doctrine

> **LOCKED — Provenance over boolean.** A Chronos conclusion must not collapse a security relationship into an unexplained yes/no answer when evidence quality, source, confidence, freshness, or time materially affect meaning.

Apollo already embodies this discipline through provenance-oriented verdicts and intelligence freshness. The broader Chronos portfolio should preserve the same distinction between observation, evidence, inference, and conclusion.

### Required conceptual layers

| Layer | Meaning |
| --- | --- |
| **Observation** | What was actually seen, collected, executed, or returned. |
| **Evidence** | Why that observation matters and which source or rule supports it. |
| **Inference** | What the available evidence suggests, including uncertainty. |
| **Conclusion** | The current security judgment, with enough context to challenge it. |
| **Decision / Action** | What a human or authorized system chose to do because of the conclusion. |

> **LOCKED — AI reasoning never erases the evidence chain.** When AI is used, Chronos must preserve the analyst's ability to inspect the underlying observations and sources. An AI-generated explanation may be useful; an AI-generated fact presented as observed evidence is not acceptable.

## 9. What Chronos Refuses to Become

> **HYPOTHESIS — Negative constraints.** These reflect the company philosophy established so far and should be challenged before being promoted to Locked.

- **A monolithic "single pane of glass"** built by absorbing every security workflow into one interface. Chronos should specialize products where the practitioner workflow genuinely differs.
- **An opaque AI security oracle.** AI can accelerate work, but evidence, provenance, uncertainty, and human challengeability must survive.
- **A proprietary-rule-language vendor** when established detection primitives already solve the representation problem. Interoperability is a strategic asset, not a concession.
- **A compliance company** that treats passing an audit as the definition of being secure. Compliance may matter, but Chronos exists to advance real posture against changing risk.
- **A future-tech hype company.** Chronos follows measurable changes in capability and risk, not fashionable terminology.
- **A portfolio that expands because the brand has unused mythology names.** Every new product must earn its existence through a distinct workflow, customer evidence, and shared-platform leverage.
- **An offensive-security vendor that ignores authorization and misuse risk.** Scope, auditability, control, and legitimate use must be designed into offensive products.

## 10. Expansion Gates

The mythology creates enormous conceptual space. The Constitution must therefore make restraint explicit. Chronos does not earn the right to build Product #2 because Product #2 is exciting.

> **DECIDED — Apollo must earn the portfolio.** Apollo is the first commercial and technical proof that the Chronos philosophy can produce a product practitioners repeatedly value. Chronos should not fund a broad product suite before that proof exists.

A working expansion gate:

1. Apollo's core filesystem hunting experience exists and is usable without a founder-led walkthrough.
2. External practitioners use Apollo on real or representative systems and return to it.
3. The company identifies a specific first buyer and a repeatable problem worth paying to solve.
4. At least one commercial model is supported by customer evidence rather than preference.
5. The shared Chronos foundation is stable enough that a second product can reuse meaningful infrastructure, intelligence, or evidence models.
6. A proposed second product solves a distinct workflow whose customer demand is independently validated.
7. The expected value of Product #2 is greater than the opportunity cost of deepening Apollo.

## 11. Decision Discipline

Chronos will use explicit epistemic drawers so that confidence is visible and strategy can change without pretending the past was certain.

| Drawer | Meaning | Required behavior |
| --- | --- | --- |
| **LOCKED** | Identity, architectural principle, or founder doctrine treated as load-bearing. | Do not change by momentum. Reopen only through an explicit strategic conversation. |
| **DECIDED** | Current strategic or technical choice with a reason behind it. | Execute it, but reverse it when evidence justifies reversal. |
| **HYPOTHESIS** | Plausible belief that has not earned commitment. | Design a test. Do not write it as fact. |
| **OPEN** | A material question with no accepted answer yet. | Keep visible. Avoid accidental decisions through implementation. |
| **EVIDENCE REQUIRED** | The observable fact, customer behavior, experiment, or data needed to settle an open question. | Name the evidence before debating opinions indefinitely. |

### Constitutional test for a major decision

1. Which Locked principle does this decision advance or threaten?
2. Is the proposal a product decision, a platform decision, a market hypothesis, or an implementation convenience?
3. What evidence supports it today?
4. What evidence would cause Chronos to reverse it?
5. Does it improve a practitioner's real security posture or merely expand feature surface?
6. Does it preserve evidence, interoperability, and temporal context?
7. Does it make Chronos more adaptable to future change or more dependent on today's assumptions?

## 12. Immediate Open Questions

### Open · 1 — Apollo's first customer

Which specific practitioner has the strongest recurring need for filesystem-first threat hunting: independent IR consultants, boutique incident-response firms, MSSPs, in-house threat hunters, SOC/IR teams, or another persona?

**Evidence required:** Interview real practitioners about how they identify unknown files, determine expectedness, connect artifacts to threats, and expand a local finding into a broader hunt.

### Open · 2 — Apollo's first paid outcome

Which result is valuable enough to buy: faster unknown-file triage, recursive threat pivots, CVE compromise assessment, reduced investigation time, improved confidence, or something else?

**Evidence required:** Observe which outcome practitioners quantify, repeat, or ask to keep using.

### Open · 3 — File-purpose intelligence

How will Apollo determine what a file is actually for, not merely its type or reputation?

**Evidence required:** Prototype multiple deterministic and curated sources before deciding where model-assisted classification belongs.

### Open · 4 — Hunt relationship semantics

What does "associated with this CVE/APT/IOC" mean strongly enough to show in a recursive hunt?

**Evidence required:** Define direct, strong, contextual, and weak relationships with explicit evidence and precision targets.

### Open · 5 — Commercial model

Open-core, commercial desktop/console, hosted, intelligence subscription, enterprise licensing, services-attached, or a hybrid?

**Evidence required:** Do not choose until the first buyer and paid outcome are clearer.

### Open · 6 — Second product

Which portfolio hypothesis deserves to become real after Apollo?

**Evidence required:** No answer is required now. The correct evidence is repeated customer demand plus substantial reuse of the Chronos foundation.

## 13. The Founder North Star

Chronos should be able to change products, technologies, architectures, and markets without losing its identity. The durable identity is not AI, Greek mythology, threat hunting, red teaming, or any single implementation. It is the commitment to advance security posture against a threat landscape that changes with time.

> *Chronos Corp advances security posture across time: learning from what has happened, defending against what is happening, and preparing organizations for what comes next.*

> **LOCKED — The company is built to outlive the current frontier.** Chronos must be capable of meeting AI security risk head-on while preserving the strategic, technical, and organizational flexibility to confront whatever succeeds AI as the next major security frontier.

---

## Status of this document

Revision 0.1 establishes the founder doctrine and portfolio discipline from the decisions made to date. It is intentionally incomplete. The next revision should incorporate customer evidence, the finalized Apollo product thesis, and any corrections that emerge when this Constitution is actively used to challenge roadmap decisions.

## Revision discipline

This file supersedes the strategic framing previously written into `README.md`'s "Build order" section and the standalone "Apollo Dossier" artifact. Where either disagrees with this Constitution, this Constitution wins — see PR history for the correction. Revise the drawer that changed; do not rewrite a hypothesis as a principle because code was written for it.
