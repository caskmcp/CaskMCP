# AGENTS.md

## 0) Purpose
This repo is worked on by coding agents. This file defines mandatory workflow, quality gates, and documentation rules.

<IMPORTANT>
For complex tasks (3+ steps, research, projects):
1. Read skill: `cat /Users/thomasallicino/.codex/skills/planning-with-files/skills/planning-with-files/SKILL.md`
2. Create task_plan.md, findings.md, progress.md in your project directory
3. Follow 3-file pattern throughout the task
</IMPORTANT>

<IMPORTANT>
Use the superpowers skill/plugin. Not redundantly or stupidly, as in don't make the same request to it twice in a row. I'm saying this because I see it's listed twice in the skills list and I don't want you to be confused into thinking you should use it twice whenever you do use it.
</IMPORTANT>

<IMPORTANT>
When analyzing and testing your work, make sure you take a very deep look at the output your code produces independently of any automated tests, and analyze it against the inputs and expectations to see whether anything is being missed, and to analyze the quality of our systems, and to get a good understanding of them.
</IMPORTANT>

<IMPORTANT>
Use any skills and plugins you see fit for a given task. If there's one you think the user should install, ask for their permission to install it and then install it and set it up.
When implementing UIs, use your playwright skill/plugin to control the browser and test it out, or the agent-browser one or browser-use one if the playwright one isn't available.
</IMPORTANT>

<IMPORTANT>
If you ever need anything from the user, like API keys, credentials, or anything else, ask the user for it, but make sure the way you propose it is secure and that the keys/credentials remain local. You never need to see the keys/credentials yourself, we can store them in a secure way locally.
</IMPORTANT>

## 1) Documentation rules
- Keep README.md in the repo root up to date.
- If README.md does not exist, create it.
- Update diagrams and any referenced docs when changes affect architecture, flows, data models, or APIs.
- If a decision changes public behavior, README and any public docs must reflect it in the same PR.
- When you realize a key insight that should be remembered and reused, create a new skill out of it if it makes sense to do so, especially if it's a task that'll be done relatively frequently.
- Keep all user guide md files up to date.

## 2) Quality gates (mandatory)
Before marking a task done:
- Tests pass
- Lint/typecheck passes (if applicable)
- Manual verification is performed by inspecting real outputs against inputs and expectations
- No unexplained TODOs
- Docs updated (README, diagrams, and any touched docs)

## 3) TDD policy (default rule)
All behavior changes must follow TDD:
1. RED: add a failing test that captures the new behavior or bug
2. GREEN: minimal code to pass the test
3. REFACTOR: improve clarity and structure while keeping tests green

Agents must not write implementation code for behavior changes before a failing test exists and has been run.

### Explicit exceptions (allowed, must be recorded in progress.md)
TDD is not required for:
- docs-only changes
- formatting-only changes
- non-behavioral refactors (pure moves/renames with no semantic change)
- build/CI config changes where tests are not the right primary signal

Even under exceptions:
- add regression tests if the change risks behavior
- still run the full test suite after

## 4) Testing conventions
- Tests live under: ./tests/
- Mirror source structure under tests
- Naming: test_*.py (or repo language equivalent)
- Test command: `python -m pytest tests/ -v`
- Coverage target: not configured (add when pytest/coverage is wired)

## 5) Research rules
- Research is allowed and encouraged when it reduces risk.
- Any external research that influences decisions must be summarized in findings.md:
  - what was checked
  - date checked
  - conclusion and how it affected the approach

## 6) Subagents
Subagents are allowed.
Rules:
- Subagents do not make final architecture decisions independently.
- Subagent outputs must be written into findings.md with clear recommendations and tradeoffs.

## 7) Git hygiene
- Initialize git if missing.
- Use feature branches.
- Commit in logical chunks with clear messages.
- Do not commit broken tests.
- Keep changes reviewable (avoid mega commits).

## 8) Project-specific values
- Language/framework: Python 3.11+ (Click CLI, Pydantic models)
- Style guide: PEP 8; format/lint via black/ruff
- Dependency manager: pip + pyproject.toml
- Lint/typecheck commands: ruff check, mypy
- Primary architecture docs/diagrams live in: ARCHITECTURE.md

## 9) CaskMCP Design Principles
- **Safe by default**: All capture/enforcement requires explicit allowlists
- **First-party only**: Third-party requests excluded unless explicitly included
- **Redaction on**: Remove sensitive data (cookies, tokens, PII) by default
- **No bypass language**: No features that imply circumventing protections
- **Audit everything**: Every compile, drift, enforce decision is logged
- **Compiler mindset**: We convert behavior into contracts, not scan for vulnerabilities
