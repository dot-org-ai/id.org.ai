# Phase 11 · Workspace app policy

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first.

**Goal:** Workspaces can allow only approved apps. A blocked person can request access (7c), and an admin approves for one person or everyone (3d). Orgs default to `open`, so nothing changes for existing workspaces.

**Depends on:** Phases 5 and 8.

**Read first:** `../spec/backend.md#b11`, `../spec/screens.md#3d` and `#7c`.

## Tasks
- [ ] `org-policy:{orgId}`, default `open`. Add `PUT /api/orgs/:id/policy` (owner or admin only) to set the mode. Approvals come from 3d.
- [ ] Authorize check: for an `approved_only` workspace and an unapproved client, render 7c. Keep the person's other workspaces available through "Use another workspace" (2b).
- [ ] `POST /admin/requests {client, org, note}` (CSRF; note ≤ 500 characters) creates `access-request:{id}` and emails the org's admins and owners (phase 12 template; until then log the link). 7c shows "Request sent" in place.
- [ ] `GET/POST /admin/requests/:id` renders 3d (admins only). Approve for `everyone` or `requester`, or decline. Notify the requester.

## Acceptance
- Tests cover:
  - `open` orgs are unaffected;
  - `approved_only` blocks;
  - request, approve, then the retry passes;
  - approval for the requester only doesn't unblock others;
  - non-admins get 403 on 3d;
  - the note limit.
- The visual diff for 3d and 7c is still 0 px.

## Commit
`feat(policy): workspace app approvals` → push.
