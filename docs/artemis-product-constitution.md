# Artemis — Product Constitution

*Product Constitution · Artemis · Rev. 0.3 · 17 August 2026*

> *Start with a file. Understand it. Follow its relationships. Hunt the evidence outward.*

> **NOTE — Revision 0.3 formalizes the ARTEMIS operating framework.** Revision 0.3 preserves the Artemis product identity and architecture established in v0.2 and formalizes its seven responsibilities as the ARTEMIS framework: Analyze, Relate, Trace, Execute, Model, Interpret, Sustain. Hunt remains the product-level verb, while Execute names the action pillar inside that hunt lifecycle.

> **NOTE — Relationship to Chronos.** The Chronos Corp Strategic Constitution remains the parent doctrine. Artemis is the first committed Chronos product and the first proof that the company can advance security posture through specialized, evidence-driven tools.

## 1. Product Identity

> **LOCKED — Artemis is the Chronos threat-hunting platform.** Artemis exists to help security practitioners discover, understand, trace, and hunt hidden threats across live systems by connecting artifacts, behaviors, threat intelligence, and other evidence without erasing provenance or uncertainty.

> **LOCKED — Artemis owns the verb: Hunt.** Capabilities belong in Artemis when they materially improve threat hunting. Digital-forensics acquisition, malware detonation, red-team execution, broad SIEM operations, and unrelated security administration belong elsewhere unless they are consumed as evidence or execution backends for a hunt.

> **LOCKED — Filesystem-first, not filesystem-only.** The filesystem remains Artemis's primary starting surface because files and directories provide a concrete, understandable entry point into an investigation. As a hunt expands, Artemis may incorporate process, identity, network, cloud, vulnerability, and external telemetry evidence without abandoning the artifact-centric workflow.

> **DECIDED — Apollo is reserved for a future Chronos capability.** The former Project Apollo name should not be reused for this threat-hunting product after the Artemis transition. Apollo remains available for a future Chronos product whose purpose better matches its mythology.

### The Artemis promise

> *Select an artifact or form a hypothesis. Artemis helps the analyst analyze what it means, relate the intelligence around it, trace meaningful paths, execute the hunt, model the evidence that is found, interpret what that evidence supports, and sustain enough knowledge to reinterpret the past when threat knowledge changes.*

## 2. The Practitioner Problem Artemis Owns

Threat hunters routinely assemble meaning from fragmented sources: file metadata, threat-intelligence feeds, vulnerability data, ATT&CK mappings, YARA and Sigma content, endpoint telemetry, identity relationships, cloud events, prior investigations, and analyst memory. Many existing platforms excel at collecting or querying one class of data. Artemis is built around the gap between finding an artifact and understanding the security story that artifact participates in.

> **HYPOTHESIS — The expensive problem is context reconstruction.** The product opportunity is not another hash lookup or another generic telemetry lake. It is reducing the analyst effort required to move from an unfamiliar artifact or hypothesis to a defensible, evidence-backed understanding of what is happening and what should be hunted next.

> **HYPOTHESIS — The strongest differentiation is joined workflow.** File purpose, expectedness, threat relationships, relational tracing, hypothesis-driven querying, recursive hunting, cross-layer correlation, provenance, and memory become substantially more valuable when they operate as one analyst workflow rather than isolated features.

## 3. The ARTEMIS Framework

ARTEMIS is both the product name and the operating framework: Analyze → Relate → Trace → Execute → Model → Interpret → Sustain. These are product responsibilities, not separate products. Hunt remains the product-level verb; Execute is the pillar that turns a relationship or hypothesis into an actual hunt.

| **Pillar**        | **Primary Question**                                                        | **Core Responsibility**                                                                                                                               |
|-------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| **A · ANALYZE**   | What am I looking at, and what does it mean here?                           | Analyze artifacts, filesystems, local context, identity, purpose, authenticity, version, ownership, and expectedness.                                 |
| **R · RELATE**    | What security knowledge connects to it?                                     | Expose CVE, IOC, malware, campaign, actor, ATT&CK, detection, certificate, software, and risk relationships.                                          |
| **T · TRACE**     | How are these things connected?                                             | Use Orion to traverse evidence and threat relationships, find meaningful paths, and distinguish possible relationships from observed evidence.        |
| **E · EXECUTE**   | Which hunt should I execute next?                                           | Execute guided pivots, Hunt Packs, recursive hunts, analyst-defined queries, and hypothesis-driven searches.                                          |
| **M · MODEL**     | What evidence-backed model explains the activity?                           | Model filesystem, process, identity, network, cloud, vulnerability, and external telemetry observations as one evidence-backed investigation context. |
| **I · INTERPRET** | What does the evidence support, and why should I trust that interpretation? | Interpret evidence chains while preserving confidence, freshness, source attribution, uncertainty, and grounded AI-assisted reasoning.                |
| **S · SUSTAIN**   | What knowledge must persist, and what changed?                              | Sustain investigations, findings, decisions, evidence state, Hunt Pack versions, and enough history to support retroactive re-evaluation.             |

> **LOCKED — Scale must preserve the ARTEMIS flow.** Artemis may grow from a local filesystem tool into a federated enterprise hunting platform, but scale must extend Analyze → Relate → Trace → Execute → Model → Interpret → Sustain rather than replace it with generic alert or telemetry administration.

## 4. Orion: Artemis Relational Hunt Engine

> **LOCKED — Orion is the named relational subsystem inside Artemis.** Orion traces relationships between artifacts, threats, behaviors, identities, systems, detections, and historical evidence. Artemis hunts; Orion traces. Orion is not a standalone Chronos product.

> *Orion follows the trail from evidence to threat.*

### The Orion Graph

The Orion Graph is the evidence-aware, temporal relationship graph used by the Orion engine. It should model both external threat knowledge and locally observed evidence without pretending they are the same thing.

| **Node family**   | **Representative entities**                                                                                |
|-------------------|------------------------------------------------------------------------------------------------------------|
| **ARTIFACT**      | File, directory, registry artifact, service, scheduled task, certificate, package, configuration artifact. |
| **EXECUTION**     | Process, command, parent-child process relationship, module load, execution observation.                   |
| **SYSTEM**        | Host, user, identity, application, software package, cloud resource.                                       |
| **THREAT**        | IOC, CVE, malware family, campaign, threat actor/APT, infrastructure.                                      |
| **BEHAVIOR**      | ATT&CK tactic/technique/sub-technique, YARA rule, Sigma rule, detection, risk/abuse pattern.               |
| **INVESTIGATION** | Observation, finding, hypothesis, hunt, case, analyst decision, prior classification.                      |
| **TIME / SOURCE** | Observation time, receipt time, first/last seen, intelligence source, freshness, pack/rule version.        |

### Relationship requirements

> **LOCKED — Relationships carry evidence, not just labels.** An Orion edge must be capable of carrying the source, evidence, confidence, observation time, first/last seen, intelligence freshness, relationship strength, and method needed to explain why the relationship exists.

- File → signed_by → Certificate
- File → created_by → Process
- Process → executed_as → Identity
- Process → connected_to → Infrastructure
- File → affected_by → CVE
- Artifact → matches → YARA Rule
- Behavior → maps_to → ATT&CK Technique
- Campaign → attributed_to → Threat Actor
- Observation → supports → Hypothesis
- Historical Finding → reinterpreted_by → New Intelligence

> **LOCKED — Security relationships must be navigable, not merely displayed.** Any relationship important enough to show should be traceable through Orion and, where meaningful, convertible into a hunt pivot or a question about supporting evidence.

> **LOCKED — Possible paths and observed paths are different.** Artemis must not conflate a path that could exist with evidence that the path was actually exercised. Orion should preserve the distinction between capability, association, inference, and observation.

### Orion analyst primitives

| **Primitive**        | **Meaning**                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------|
| **Orion Trace**      | Traverse from one entity through selected relationship types and evidence thresholds.            |
| **Orion Path**       | A specific relationship chain between entities.                                                  |
| **Orion Pivot**      | Turn a selected node, relationship, or path into a hunt hypothesis.                              |
| **Orion View**       | Interactive visualization and inspection of the relevant graph neighborhood.                     |
| **Orion Retrotrace** | Trace new intelligence through retained historical evidence.                                     |
| **Strongest Path**   | Prefer the highest-evidence path rather than the shortest path when analyst intent calls for it. |

## 5. Specialist Graph Integration

> **DECIDED — Artemis should integrate specialist graphs rather than recreate them by default.** Orion owns Artemis's threat-evidence relationship model. Where another system has deep expertise in a distinct relationship domain, Artemis should consume or query that system when doing so improves the hunt.

> **HYPOTHESIS — BloodHound should be a first-class identity attack-path integration.** BloodHound can provide identity and privilege path context while Orion provides observed threat and evidence relationships. The valuable handoff is not cloning identity attack-path analysis; it is connecting theoretical reachability to evidence that a path may have been exercised.

> *A specialist graph can tell Artemis where an attacker could move. Orion should help determine whether the evidence says they did.*

> **OPEN — Integration boundary.** The exact BloodHound/OpenGraph/API integration strategy remains an implementation decision. Artemis must not make BloodHound mandatory for the core product, and Orion must remain authoritative for Artemis-specific threat-evidence semantics.

## 6. Analyze: File and Artifact Intelligence

> **LOCKED — What is this file for? is a product requirement.** Artemis must go beyond type, hash, and reputation. It should explain an artifact's likely role, product ownership, expected location, authenticity, version, and surrounding context while preserving uncertainty.

| **Domain**               | **Examples**                                                                                                    |
|--------------------------|-----------------------------------------------------------------------------------------------------------------|
| **Identity**             | Path, name, type, hashes, size, timestamps, architecture.                                                       |
| **Authenticity**         | Signature status, signer, publisher, certificate, trust chain.                                                  |
| **Product context**      | Application/product, component, package, version, vendor.                                                       |
| **Purpose**              | What the artifact normally does and which function it serves.                                                   |
| **Expectedness**         | Whether the artifact is expected at this location, under this identity/owner, with this signer/version/context. |
| **Threat relationships** | CVE, IOC, actor, campaign, malware, ATT&CK, detection, abuse/risk relationship.                                 |
| **Local context**        | Neighboring files, duplicate names, creation/execution context, relevant process or host observations.          |
| **Evidence quality**     | Source, method, confidence, freshness, observation time.                                                        |

> **HYPOTHESIS — Deterministic and curated sources should precede model-only classification.** Trusted metadata, signatures, package manifests, vendor resources, OS catalogs, known-file knowledge, curated relationships, and local observations should ground purpose/expectedness. AI may synthesize or explain those facts but should not silently substitute a guess for verified knowledge.

## 7. Relate: Threat and Behavior Intelligence

> **LOCKED — Threat concepts are first-class relationship objects.** CVEs, IOCs, malware families, campaigns, actors/APTs, ATT&CK techniques, detections, certificates, vulnerable products, and risk relationships should exist as structured entities with navigable evidence rather than flat labels.

> **DECIDED — MITRE ATT&CK becomes an actionable hunting dimension.** ATT&CK mappings should not be decorative taxonomy. Techniques and sub-techniques should be traceable in Orion and usable as hunt pivots where Artemis has meaningful evidence or detection logic to seek.

> *If Artemis displays T1218, the analyst should be able to ask what evidence of T1218 exists here, on this host, or across the selected scope.*

> **OPEN — Relationship strength vocabulary.** Artemis needs explicit classes for direct evidence, strong association, contextual support, weak association, and possibly contradictory evidence. The vocabulary should be validated against practitioner expectations before it becomes stable UI language.

## 8. Execute: Guided, Relational, and Analyst-Defined Hunting

> **LOCKED — A hunt is a hypothesis applied to evidence and scope.** Artemis hunting begins either from a relationship pivot or from an analyst-defined hypothesis. The output is structured evidence, not a generic list of search matches.

### Two complementary hunt modes

| **Mode**                    | **Example**                                                                                 | **Purpose**                                                              |
|-----------------------------|---------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| **Guided / relational**     | File → CVE → Hunt this subtree                                                              | Make meaningful relationships immediately actionable.                    |
| **Analyst-defined / query** | Find unsigned DLLs created recently under ProgramData, excluding expected product locations | Let expert hunters ask original questions beyond prebuilt relationships. |

> **DECIDED — Artemis requires a serious Hunt Query Engine.** A mature threat-hunting platform cannot limit experts to clickable pivots. Artemis needs a fast, expressive query capability over its accessible evidence while preserving structured fields, provenance, and scope.

> **OPEN — Query representation and language.** The first implementation may be a structured/visual hunt builder backed by a stable internal representation. A textual syntax may follow if practitioners need it. Artemis should not invent an incompatible query language merely to create vendor lock-in.

### Recursive hunting remains signature behavior

> **LOCKED — Recursive scope is a first-class primitive.** The original Artemis wedge remains the ability to take a relationship or hypothesis and recursively inspect the selected filesystem scope for associated evidence. Broader scopes extend that mechanic rather than replace it.

### Hunt Packs

> **DECIDED — Hunt Packs are executable knowledge, not the product.** Hunt Packs package what Artemis knows to seek around a threat concept using established primitives such as YARA, Sigma, hashes, filenames, paths, versions, registry checks, indicators, ATT&CK relationships, and provenance. They must not become a proprietary detection DSL.

> **HYPOTHESIS — CVE compromise assessment is a high-value hunt pattern.** A CVE pivot should eventually distinguish exposure from evidence of exploitation by looking for vulnerable versions, exploit artifacts, payloads, persistence, post-exploitation behavior, related detections, and known intelligence relationships.

## 9. Model: Federated Evidence, Centralized Reasoning

> **LOCKED — Artemis scales the hunt, not the data lake.** Artemis does not need to own every raw telemetry stream in order to hunt it. The platform should be capable of asking local collectors, Artemis Sensor, EDR, SIEM, identity, cloud, and other systems for evidence and normalizing relevant results into the Artemis evidence model.

> *Federated evidence. Centralized reasoning.*

> **LOCKED — Artemis is artifact-centric, not artifact-limited.** A hunt may begin with a file and expand into process, identity, network, cloud, vulnerability, and historical evidence when those relationships help prove or disprove the hypothesis.

| **Evidence layer**     | **Representative questions**                                                               |
|------------------------|--------------------------------------------------------------------------------------------|
| **Filesystem**         | Which files, paths, versions, signatures, or artifacts support this hypothesis?            |
| **Process**            | What executed, loaded, spawned, or created the artifact?                                   |
| **Identity**           | Which user, service account, token, privilege, or identity relationship matters?           |
| **Network**            | What infrastructure, DNS, connection, or transfer evidence exists?                         |
| **Cloud**              | Which resource, workload, identity, event, or control-plane action is connected?           |
| **Vulnerability**      | Was vulnerable software present, and is there evidence of exploitation?                    |
| **External telemetry** | What does the customer's existing EDR/SIEM/collector know about the same entities or path? |

> **DECIDED — Cross-layer correlation is a product direction; backend choice remains open.** Artemis should grow toward artifact-centric cross-layer correlation. Whether evidence is gathered by Artemis Sensor, external security tools, or both should be determined by fidelity, adoption friction, customer need, and trust boundaries.

> **LOCKED — Artemis is not an EDR or SIEM replacement.** The platform may integrate with and query those systems, but broad telemetry collection, generic alert operations, and central-log ownership are not Artemis's product identity.

## 10. Interpret: Evidence, Verdicts, and Trust

> **LOCKED — Provenance over boolean.** No important Artemis conclusion should collapse into an unexplained yes/no answer when evidence quality, source, confidence, freshness, time, or method materially affect meaning.

| **Layer**       | **Meaning**                                                                   |
|-----------------|-------------------------------------------------------------------------------|
| **Observation** | What Artemis or an integrated source actually saw.                            |
| **Evidence**    | Why the observation matters and which source/rule/relationship supports it.   |
| **Inference**   | What the available evidence suggests, including uncertainty and alternatives. |
| **Conclusion**  | The current security judgment with enough context to challenge it.            |
| **Action**      | What the analyst or an authorized downstream system chooses to do.            |

> **LOCKED — No match is not safe.** Artemis must state what was checked, against which corpus and sources, and how current that knowledge was. An empty result is not proof of safety.

> **DECIDED — Per-source intelligence freshness remains part of verdict quality.** The existing freshness work establishes a durable rule: independent intelligence sources can become stale independently, and Artemis must not hide that fact behind a clean-looking verdict.

## 11. AI Doctrine

> **LOCKED — AI accelerates hunting; evidence remains authoritative.** AI may explain artifacts, synthesize relationships, suggest pivots, translate natural-language hypotheses into hunt plans, prioritize findings, and identify missing evidence. Observed facts, deterministic matches, sourced relationships, and analyst decisions remain distinguishable from model output.

- Good: explain a complex file using grounded metadata and evidence.
- Good: propose which Orion path or ATT&CK pivot deserves investigation next.
- Good: summarize a multi-source evidence chain while linking every claim back to supporting observations.
- Good: translate an analyst question into a structured query/hunt plan for review.
- Bad: invent an APT relationship because it is plausible.
- Bad: hide evidence behind an opaque AI risk score.
- Bad: present generated facts as if Artemis observed them.

> *Reason intelligently. Prove with evidence.*

## 12. Sustain: Investigation Memory and Retroactive Hunting

> **DECIDED — Artemis should preserve investigative memory, not become a raw-log archive.** Historical value comes from retaining hunts, hypotheses, relevant observations, findings, analyst decisions, file classifications, relationship state, query definitions, Hunt Pack versions, and the intelligence context needed to understand what was known at the time.

> **HYPOTHESIS — Retroactive hunting can become a signature Artemis capability.** When new threat intelligence arrives, Artemis should be able to determine whether retained historical evidence now has a different meaning and surface prior investigations worth reopening.

> *Threat knowledge changes. Evidence does not.*

### Retrohunt concept

1. New intelligence, Hunt Pack content, attribution, or detection knowledge arrives.
2. Orion traces the new relationship through historical Artemis evidence.
3. Artemis identifies prior observations or hunts that are newly relevant.
4. The analyst sees what was known then, what is known now, and why the conclusion changed.
5. The analyst can reopen or launch a new hunt using the updated knowledge.

> **HYPOTHESIS — Temporal re-interpretation is a Chronos-level differentiator expressed through Artemis.** Artemis can operationalize the parent company's time doctrine by using current intelligence to reinterpret past evidence without rewriting the historical record of what the analyst actually knew at the time.

## 13. Trust Boundaries and Scope

> **LOCKED — Live systems, not dead-box forensics.** Artemis reasons about current or accessible evidence from live systems. Traditional disk-image forensics remains outside Artemis and is better suited to a future Chronos forensics product.

> **LOCKED — Userland only.** Artemis does not require a kernel driver. This remains a trust, deployment, and architectural boundary.

> **LOCKED — Hashes may leave the host; file contents require explicit analyst action.** Sample retrieval must remain intentional, logged, and attributable. Artemis should not silently centralize file contents as the price of participation.

> **LOCKED — YARA and Sigma remain standard detection formats.** Artemis should orchestrate portable security content rather than trap customers in a bespoke rule language.

## 14. Product Boundaries Across Chronos

| **Capability**                           | **Artemis role**                                                     | **Likely home / partner**                                      |
|------------------------------------------|----------------------------------------------------------------------|----------------------------------------------------------------|
| Threat hunting                           | Owns end-to-end hunting workflow.                                    | Artemis                                                        |
| File/artifact intelligence               | Owns as core Analyze capability.                                     | Artemis                                                        |
| Relational threat/evidence tracing       | Owns through Orion.                                                  | Artemis / Orion subsystem                                      |
| Filesystem/host/fleet hunt execution     | Owns the hunt; may delegate evidence retrieval.                      | Artemis plus execution backends                                |
| Identity attack-path modeling            | Consumes specialist graph context where useful.                      | BloodHound integration / future Chronos attack-path capability |
| Deep forensic acquisition/reconstruction | Consumes evidence but does not own discipline.                       | Hermes hypothesis                                              |
| Malware detonation/sandboxing            | Can submit/consume results.                                          | Hades hypothesis                                               |
| Adversary emulation                      | Can hunt traces from exercises.                                      | Ares hypothesis                                                |
| Detection engineering lifecycle          | Consumes YARA/Sigma/Hunt Packs; does not need to own full lifecycle. | Hephaestus reserved                                            |
| Continuous monitoring/EDR                | May query and consume evidence; does not become generic EDR.         | Argus reserved / external products                             |

## 15. The ARTEMIS Hunt Flow

> **LOCKED — The platform must remain understandable as one continuous hunt.** The ARTEMIS pillars are not separate workspaces that force the analyst to mentally reassemble the investigation. Artemis should preserve continuity from initial artifact or question through evidence, trace, hunt, explanation, and memory.

> *Analyze → Relate → Trace → Execute → Model → Interpret → Sustain*

### Two entry points, one evidence model

| **Entry point**      | **Flow**                                                                               |
|----------------------|----------------------------------------------------------------------------------------|
| **Artifact-first**   | File/artifact → Analyze → Relate → Orion Trace → Execute → Model → Interpret → Sustain |
| **Hypothesis-first** | Analyst question → Hunt Query → Evidence → Orion Trace → Model → Interpret → Sustain   |

## 16. Architectural Principles

1. Artemis should own a stable evidence model even when evidence comes from external systems.
2. Orion should model relationships with time, source, confidence, and evidence semantics rather than generic edges.
3. Query execution and evidence retrieval should be separable from evidence interpretation so multiple backends can participate.
4. Hunt Packs should reference established detection primitives and structured checks rather than introduce a proprietary DSL.
5. Historical evidence must preserve the state of knowledge at the time so retroactive reinterpretation does not rewrite history.
6. AI-generated interpretation must remain separable from observations and deterministic results.
7. The local filesystem wedge must remain useful even if enterprise integrations are absent.

## 17. Current Build Interpretation

> **NOTE — This sequence is Decided, not constitutional.** The product identity and architecture have changed enough that the former PR #18–22 sequence should be reconsidered before implementation. The table below is the new working interpretation and should be reconciled against the actual repository state before work begins.

| **Capability block**                       | **Working objective**                                                                                                                   | **Why now**                                              |
|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Naming transition                          | Rename Project Apollo/product references to Artemis in a dedicated PR without pretending the architecture changed because the name did. | Keeps product identity and repository history clear.     |
| File Intelligence                          | Formalize the artifact model for purpose, expectedness, ownership, authenticity, version, and evidence.                                 | Completes Analyze and the original wedge.                |
| Threat Relationship Model                  | Represent CVE/IOC/APT/campaign/malware/ATT&CK/risk relationships explicitly.                                                            | Enables Relate and Orion.                                |
| Orion Graph Foundation                     | Define node/edge ontology, evidence metadata, strength semantics, and basic graph traversal.                                            | Enables Trace without waiting for every evidence source. |
| Recursive Hunt Engine                      | Turn selected relationships and hypotheses into scoped filesystem hunts.                                                                | Implements the signature mechanic.                       |
| Hunt Query Engine                          | Support analyst-defined structured hunts alongside guided pivots.                                                                       | Makes Artemis credible for expert hunters.               |
| First Hunt Pack / CVE assessment           | Prove executable curated knowledge end to end.                                                                                          | Tests product value against a concrete threat.           |
| Cross-layer evidence adapter               | Introduce one process/identity/network or external telemetry source into the same evidence model.                                       | Proves filesystem-first does not mean filesystem-only.   |
| Investigation Memory / Retrohunt prototype | Persist enough hunt context to re-evaluate prior evidence against new intelligence.                                                     | Tests the Chronos temporal differentiator.               |

> **DECIDED — Infrastructure must not outrun the hunt.** Fleet administration, deployment tooling, generic telemetry ingestion, and other platform plumbing should remain subordinate to completing Analyze, Relate, Orion Trace, Execute, and Interpret unless customer evidence proves otherwise.

## 18. First Customer and Commercial Hypotheses

> **OPEN — The first buyer remains unresolved.** Candidates include independent or boutique IR practitioners, MSSP analysts, dedicated threat hunters, and SOC/IR teams. The answer should come from observed workflow pain and willingness to adopt/pay, not category preference.

> **OPEN — The first paid outcome remains unresolved.** Potential value includes faster unknown-artifact understanding, more reliable relational hunting, CVE compromise assessment, cross-tool evidence correlation, reduced investigation time, retroactive detection from new intelligence, or improved analyst confidence.

### Discovery questions for Artemis

1. When you find an unfamiliar file or artifact, how do you determine what it is, what it is for, and whether it belongs there?
2. How do you move from one artifact to related CVEs, IOCs, malware, campaigns, actors, ATT&CK techniques, or other evidence?
3. How do you decide which relationship is strong enough to pursue?
4. How do you hunt recursively or across other telemetry once you have a lead?
5. How do you connect a possible identity/attack path to evidence that it was actually used?
6. What information from old investigations do you wish you could automatically re-check when new intelligence arrives?
7. Which part of this process consumes the most analyst time or specialized expertise?

## 19. Product Success Measures

| **Measure**                            | **What it proves**                                                               |
|----------------------------------------|----------------------------------------------------------------------------------|
| Time to understand unfamiliar artifact | Analyze reduces research/context switching.                                      |
| Time from artifact to meaningful trace | Orion makes relationships navigable rather than decorative.                      |
| Recursive hunt precision               | Hunt results are operationally useful rather than relationship noise.            |
| Query usefulness                       | Expert hunters can express meaningful hypotheses not covered by prebuilt pivots. |
| Cross-source correlation success       | Artemis can join evidence without owning all telemetry.                          |
| Evidence explainability                | Analysts can challenge why a path, finding, or conclusion exists.                |
| Retrohunt useful findings              | New intelligence can surface previously missed relevant evidence.                |
| Repeat external usage                  | The workflow solves a recurring problem.                                         |
| Founder assistance required            | The product stands on its own.                                                   |

## 20. Competitive Doctrine

> **LOCKED — Do not copy category checklists blindly.** Artemis should satisfy the real needs behind threat-hunting platform expectations without automatically adopting the architecture used by SIEM/XDR products. Centralized telemetry becomes federated evidence. Deep retention becomes investigation memory. Behavioral analytics becomes contextual evidence. ATT&CK becomes a pivot, not a label.

> **HYPOTHESIS — Artemis wins through relational hunting plus evidence discipline.** Any individual feature may be available elsewhere. The differentiated experience is the joined system: artifact understanding, purpose/expectedness, structured threat relationships, Orion path tracing, guided and custom hunts, cross-layer evidence, provenance, and temporal memory.

### The five-minute proof

> *Select an unfamiliar artifact → understand purpose and expectedness → see a meaningful relationship → trace it in Orion → turn the path into a hunt → correlate supporting evidence → understand why it matters.*

## 21. Immediate Open Questions

### Open · 1 — Orion ontology

Which node and edge types are essential for the first useful relational hunt, and which should wait?

**EVIDENCE REQUIRED:** Prototype the smallest graph that can support one real file→CVE/campaign/ATT&CK hunt without producing relationship noise.

### Open · 2 — Relationship strength

How should Artemis distinguish direct evidence, strong association, contextual support, weak association, and contradiction?

**EVIDENCE REQUIRED:** Review real threat-intelligence relationships with practitioners and measure which classifications they trust.

### Open · 3 — Query model

What query representation gives expert hunters power without forcing Artemis into a proprietary language trap?

**EVIDENCE REQUIRED:** Prototype visual/structured queries and compare against practitioner workflows and existing query habits.

### Open · 4 — Expectedness

How can Artemis judge context without equating rarity with maliciousness?

**EVIDENCE REQUIRED:** Validate location, ownership, product, signer, baseline, and environmental signals against representative systems.

### Open · 5 — BloodHound integration

What is the cleanest contract for bringing identity path context into Orion?

**EVIDENCE REQUIRED:** Implement a narrow proof that connects one compromised artifact/identity to a BloodHound path and then hunts for observed evidence.

### Open · 6 — Cross-layer first expansion

Which non-filesystem evidence layer creates the most value first: process, identity, network, cloud, or existing EDR telemetry?

**EVIDENCE REQUIRED:** Let first-user workflows select the adapter rather than architecture preference.

### Open · 7 — Retrohunt retention

What minimum historical evidence must Artemis retain to make retroactive hunting useful without becoming a telemetry warehouse?

**EVIDENCE REQUIRED:** Test one new-intel event against retained hunt state and measure what data was actually needed.

### Open · 8 — Commercial packaging

Which Artemis capabilities belong in individual, team, enterprise, or intelligence subscriptions?

**EVIDENCE REQUIRED:** Price only after first buyer and first paid outcome are validated.

## 22. Expansion Gates

1. Artemis can explain an unfamiliar artifact and its expectedness with transparent evidence.
2. Orion can trace meaningful threat/evidence paths without overwhelming the analyst.
3. Relationship pivots and analyst-defined queries both produce useful hunts.
4. Recursive hunts return precise, explainable evidence on real or representative systems.
5. At least one Hunt Pack demonstrates exposure-versus-compromise value end to end.
6. At least one cross-layer or external source can contribute evidence without Artemis centralizing all telemetry.
7. External practitioners use Artemis without a walkthrough and voluntarily return to it.
8. A first buyer and paid outcome are supported by evidence.
9. Only after those gates should large-scale fleet management, broad connector catalogs, hosted data architecture, or another Chronos product receive major investment.

## 23. Decision Discipline

> **LOCKED — The Constitution outranks the roadmap.** A technically convenient implementation must not silently redefine Artemis. Major product changes should be classified as Locked, Decided, Hypothesis, Open, or Evidence Required before code momentum converts them into assumptions.

| **Drawer**            | **Meaning for Artemis**                                                |
|-----------------------|------------------------------------------------------------------------|
| **LOCKED**            | Product identity, core workflow, trust boundary, or evidence doctrine. |
| **DECIDED**           | Current architecture or sequencing choice with a reason behind it.     |
| **HYPOTHESIS**        | Plausible product or market belief that still needs validation.        |
| **OPEN**              | Material unanswered question that must remain visible.                 |
| **EVIDENCE REQUIRED** | Observable result that would resolve an open question or hypothesis.   |

### Constitutional test for an Artemis feature

1. Which pillar does it materially advance?
2. Does it improve threat hunting or merely expand platform surface area?
3. Does Orion need this relationship, or can it remain external context?
4. Does it preserve the distinction between observation, association, possibility, and inference?
5. Can Artemis use existing security primitives or external specialist tools instead of rebuilding them?
6. Does it preserve provenance, freshness, time, and userland trust boundaries?
7. What evidence says practitioners need it now?
8. What higher-priority Artemis capability would be delayed to build it?

## 24. The Artemis North Star

Artemis should remain recognizable whether it is examining one file, traversing an Orion path, running a custom hunt across a host, correlating evidence from an EDR, or revisiting an investigation months later. The product is not defined by where the evidence lives. It is defined by how effectively the hunter can move from uncertainty to defensible understanding.

> *Artemis hunts. Orion traces. Evidence proves.*

> **LOCKED — Artemis must preserve its original soul as it becomes a platform.** The original filesystem idea remains the foundation: start with something concrete, understand what it is, follow the relationships around it, and hunt outward. The broader platform exists to let that same investigative instinct operate across more evidence, more systems, and more time.

**STATUS OF THIS DOCUMENT**

Revision 0.3 formalizes the ARTEMIS operating framework without changing the product thesis established in v0.2. Analyze, Relate, Trace, Execute, Model, Interpret, and Sustain now name the seven product responsibilities. The next revision should be driven by implementation proof and practitioner evidence, especially Orion relationship quality, Hunt Query usability, expectedness accuracy, and the first retroactive hunt.
