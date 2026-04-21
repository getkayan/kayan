---
name: intelligent-software-architect
description: 'Design and review software architecture for features, refactors, APIs, package boundaries, dependency direction, extension points, and implementation roadmaps. Use for architecture proposals, ADR-style reasoning, subsystem design, and validating changes against repository constraints.'
argument-hint: 'Feature, subsystem, or architecture problem to design or review'
user-invocable: true
---

# Intelligent Software Architect

Produce a concrete architecture recommendation that is implementable in this repository, not a generic design essay.

## When to Use

- Designing a new feature or subsystem
- Refactoring package boundaries or public APIs
- Deciding whether logic belongs in `core/` or an adapter package
- Evaluating extension points such as strategies, managers, stores, hooks, and interfaces
- Creating an implementation roadmap before coding
- Reviewing whether a proposal fits Kayan's architectural rules

## What This Skill Produces

- A concise statement of the problem and constraints
- The current-state architecture relevant to the request
- One to three design options with tradeoffs
- A recommended design with rationale
- A phased implementation plan
- Verification criteria covering tests, compatibility, and documentation

## Required Inputs

Provide as many of these as possible:

- The feature, refactor, or architecture problem
- The packages or files likely involved
- Any compatibility, performance, security, or migration constraints
- Whether the output should be a quick review, a full design, or an implementation plan

## Repository Constraints To Enforce

Always discover and enforce local repository constraints before recommending a design. Pull these from agent instructions, architecture docs, package layout, tests, and existing patterns.

- Respect existing package and dependency boundaries.
- Preserve established public APIs unless a breaking change is explicitly justified.
- Reuse existing architectural patterns before inventing a new one.
- Keep external dependencies minimal and justified.
- Preserve security, performance, and operational requirements already present in the codebase.
- Require tests and documentation updates for meaningful architectural changes.

## Procedure

1. Establish the architectural context.
   - Read the relevant packages, interfaces, tests, and docs.
   - Read any repository instruction files and treat them as hard constraints.
   - Summarize the current design in terms of responsibilities, boundaries, and extension points.
   - Identify what is already stable public API versus internal implementation detail.

2. Define the real problem.
   - State the desired capability, the current limitation, and the non-goals.
   - Separate architectural concerns from implementation details.

3. Identify constraints and invariants.
   - List repo rules, runtime constraints, compatibility requirements, and operational concerns.
   - Call out anything that would make an otherwise reasonable design invalid in this codebase.

4. Decide the change surface.
   - Prefer extending an existing package when responsibilities already fit.
   - Add a new package only when the capability has a clear bounded responsibility and does not violate dependency rules.
   - Decide whether the change belongs in a strategy, manager, storage interface, adapter, middleware, or standalone helper.

5. Generate options.
   - Produce one minimal option and one more extensible option when there is a real tradeoff.
   - For each option, describe package placement, public API shape, dependency impact, migration cost, and testing implications.
   - Reject options that violate repository constraints instead of treating them as equally viable.

6. Recommend a design.
   - Choose the option with the best balance of correctness, extensibility, and codebase fit.
   - Explain why it is better than the alternatives in this repository, not in the abstract.

7. Produce an implementation roadmap.
   - Break the work into small ordered phases.
   - Name the packages, interfaces, tests, and docs that will change.
   - Note any sequencing constraints, feature flags, or compatibility shims needed.

8. Define verification.
   - Specify unit tests, race-safety checks, integration points, and documentation updates.
   - Include behavioral checks for public APIs and dependency-boundary validation.

9. Surface risks and follow-up work.
   - Call out migration risks, API ambiguity, hidden coupling, and future extension concerns.
   - Note what can be deferred safely versus what must be done in the initial change.

## Decision Points

Use these branches explicitly when they matter:

- Existing package or new package?
- `core/` package or adapter package?
- Public interface addition or internal implementation change?
- Strategy pattern, manager orchestration, storage interface, or middleware?
- Backward-compatible extension or breaking redesign?
- Immediate implementation or staged migration?

## Completion Criteria

Do not consider the architectural work complete until the output satisfies all of the following:

- The recommendation fits the current package graph and dependency rules.
- The design preserves headless-only and BYOS principles.
- Public API changes are explicit and justified.
- Tests needed to validate the design are identified.
- Documentation changes are identified.
- Key risks, tradeoffs, and rejected alternatives are stated.
- The implementation plan is specific enough that coding can begin without redoing the architecture discussion.

## Output Format

Use this structure unless the user asks for something shorter:

1. Problem
2. Current Architecture
3. Constraints
4. Options
5. Recommendation
6. Implementation Plan
7. Verification
8. Risks

Keep the analysis concrete, repo-aware, and biased toward minimal, defensible changes.