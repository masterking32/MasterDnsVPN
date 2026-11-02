---
name: teamwork-resume
description: >-
  Resumes an interrupted /teamwork multi-agent execution after quota reset, process stop, or 429 lockout.
  Activates when the user asks to resume, continue, recover, or restart an in-progress or interrupted teamwork run in any project.
---

# Teamwork Resume Runbook

This skill recovers and resumes an interrupted `/teamwork` multi-agent project run across any codebase without losing progress, re-surveying, or re-running completed milestones.

## When to Use
- A `/teamwork` session stopped due to quota exhaustion (`RESOURCE_EXHAUSTED` / `429`).
- A `/teamwork` run was interrupted by terminal restart, timeout, or accidental cancellation.
- The user wants to cleanly continue the remaining milestones of a teamwork run.

---

## Procedure

### Step 1: Discover & Audit Teamwork Workspace State
Locate `.agents/teamwork/` in the project root. Inspect the persistent state files:

1. **Original Mission**: Read `.agents/teamwork/ORIGINAL_REQUEST.md` to capture user objectives, constraints, invariants, and acceptance criteria.
2. **Decomposition & Architecture**: Read `.agents/teamwork/orchestrator/PROJECT.md` to map:
   - All Milestones ($M_1, M_2, \dots, M_n$)
   - Feature inventory and dependencies
   - Module interfaces and contracts
3. **Milestone Quality Gates**: Read `.agents/teamwork/orchestrator/GATE_STATUS.md`:
   - Identify all milestones marked `PASS` (these are frozen and completed).
   - Identify the first incomplete, failed, or active milestone ($M_k$).
4. **Interrupted Worker Progress**:
   - Inspect `.agents/teamwork/worker_m<k>/DISPATCH.md` (assigned tasks).
   - Inspect `.agents/teamwork/worker_m<k>/progress.md` (what was checked `[x]` vs unchecked `[ ]`).
   - Check if `.agents/teamwork/worker_m<k>/handoff.md` exists.
5. **Git Working Tree Hygiene**:
   - Run `git status` to see modified and untracked files left by the interrupted worker.
   - Clean up transient scratch files (e.g. `*.tmp_*`, dangling lock files).
   - Verify existing code compiles and unit tests for passed milestones still pass.

---

### Step 2: Determine Resumption Mode with User

Ask or evaluate whether the user prefers:
- **Mode 1: Autonomous Multi-Agent Swarm (`/teamwork`)**:
  Spawns fresh subagents (workers, reviewers, challengers, auditors) to complete remaining milestones. Best when multi-agent adversarial validation is strictly required and quota is abundant.
- **Mode 2: In-Session Direct Continuation (Quota-Safe)**:
  The current agent executes the remaining tasks in $M_k \dots M_n$ directly following `PROJECT.md` and runs the verification suite. Best when recovering from quota exhaustion to avoid re-triggering quota limits.

---

### Step 3: Resuming via `/teamwork` (Mode 1)

If resuming via `/teamwork`, **NEVER** pass a blank or generic prompt, and **ALWAYS** use `[skip-interview]`. Otherwise, the teamwork interviewer and surveyor will overwrite existing files or re-run from scratch.

Format the resume prompt using the **Universal Teamwork Resume Schema**:

```text
/teamwork [skip-interview] RESUME PROJECT RUN

Working Directory: <project_root>
State Root: .agents/teamwork/
Scope & Architecture: .agents/teamwork/orchestrator/PROJECT.md
Gate Status: .agents/teamwork/orchestrator/GATE_STATUS.md
Original Request: .agents/teamwork/ORIGINAL_REQUEST.md

## RESUMPTION DIRECTIVES:
1. DO NOT re-survey the codebase, re-run Phase 0, or overwrite PROJECT.md.
2. MILESTONE RECOVERY:
   - The following milestones have PASSED gates in GATE_STATUS.md and are COMPLETE:
     <List completed milestones: e.g. M1, M2>
   - Do NOT re-execute or modify code for completed milestones.
3. CURRENT ACTIVE MILESTONE: <Milestone M_k: Name>
   - Interrupted worker: worker_m<k>
   - Completed sub-tasks: <List tasks checked in worker_m<k>/progress.md>
   - Remaining sub-tasks: <List remaining unchecked tasks from worker_m<k>/DISPATCH.md>
   - Existing working tree modifications should be retained and built upon.
4. EXECUTION PLAN:
   - Dispatch a fresh worker for the remainder of Milestone M_k.
   - Run Milestone M_k review, challenger, and auditor gates per GATE_STATUS.md.
   - Proceed sequentially through remaining milestones (<M_{k+1} .. M_n>) and final acceptance verification.
```

---

### Step 4: Resuming via In-Session Continuation (Mode 2)

If continuing directly in-session:
1. Finish the unchecked tasks of the active milestone $M_k$ according to its `DISPATCH.md`.
2. Run milestone unit and adversarial tests.
3. Update `.agents/teamwork/orchestrator/GATE_STATUS.md` and `.agents/teamwork/orchestrator/progress.md`.
4. Proceed through remaining milestones ($M_{k+1} \dots M_n$).
5. Run full test suite, binary builds, and invariant checks specified in `ORIGINAL_REQUEST.md` §Acceptance Criteria.
