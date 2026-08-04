# Requirement Analysis & Specification

Turn a raw client request — an email, a call transcript, a bullet list, a
screenshot — into a specification a developer can build from and a client can
sign off on, plus a defensible effort estimate.

## When to use this skill

Use it when the input is a *want* rather than a *task*: "we need a portal for
our vendors", "can you add reporting", "the app should sync with their CRM".
Skip it when the request is already a well-defined change with a known file and
acceptance criteria — write the code instead.

## Step 1 — Separate what you know from what you are guessing

Before writing anything, split the request into three lists. Do not skip this;
it is what stops invented requirements from reaching a client document.

- **Stated** — written or said explicitly by the client. Quote or paraphrase closely.
- **Implied** — a reasonable reading, but the client never said it. Every item
  here becomes a numbered assumption in the spec, or a question in Step 2.
- **Missing** — cannot be inferred at all (user volumes, integration
  credentials, who approves what, which browsers, data residency).

## Step 2 — Ask only the questions that change the work

Group the **Missing** list into two buckets:

- **Blocking** — a different answer produces a materially different build
  (single-tenant vs multi-tenant; real-time sync vs nightly batch; who owns the
  data). Ask these. Cap it at 5–7 questions; a 20-question list reads as though
  you did not engage with the brief.
- **Non-blocking** — pick the conventional default, state it as an assumption,
  and carry on. Note it for confirmation rather than holding up the document.

Write questions so a non-technical stakeholder can answer them without a
follow-up call. Ask "Should a vendor see other vendors' orders?", not "Should we
scope the query by tenant_id?".

## Step 3 — Write the specification

Use exactly these sections, in this order:

### Overview
Two or three sentences: the business problem, who feels it, and what changes for
them once this ships. No technology names here.

### Requirements
Numbered (`FR-1`, `FR-2`, …) so a reviewer can reference `FR-4` in an email.
One testable behaviour per line — if a line contains "and", consider splitting it.

Write each as an observable outcome, not an implementation:

> **FR-3.** A vendor can upload a PDF invoice up to 10 MB against an open
> purchase order. The system rejects other file types with a message naming the
> accepted formats.

Put measurable limits (page-load target, retention period, concurrent users)
under a `NFR-` prefix in the same list. A non-functional requirement with no
number is a non-functional requirement nobody will test.

### Technical Approach
How it will be built, in the existing stack unless the client has specified
otherwise. Name the components, the integration points, and the data that moves
between them. Flag anything that needs a third-party account, a credential, or a
client-side decision before development can start.

### Assumptions
Numbered. Every **Implied** item from Step 1 and every non-blocking default from
Step 2 lands here. This section is what protects the estimate — if an assumption
turns out to be wrong, the estimate is openly renegotiable rather than "over
budget".

### Out of Scope
Name the things a reader would reasonably expect but is not getting: native
mobile apps, data migration from the legacy system, SSO, training material,
content authoring. Silence here is read as inclusion.

## Step 4 — Estimate

Break every requirement into the four phases and give **ranges**, never a single
number. A single number reads as a commitment; a range communicates the real
uncertainty.

| Requirement | Analysis | Development | Testing | Deployment | Total |
|---|---|---|---|---|---|
| FR-1 Vendor login | 2–3 hrs | 8–10 hrs | 3–4 hrs | 1–2 hrs | 14–19 hrs |
| FR-2 Invoice upload | 2–3 hrs | 10–14 hrs | 4–6 hrs | 1 hr | 17–24 hrs |

Then state, below the table:

- **Key assumptions driving the estimate** — the two or three that would move
  the total most if wrong.
- **Risks** — third-party API quality, undocumented legacy behaviour, client
  review turnaround, unavailable test data.
- **Needs clarification before finalising** — anything you estimated on a guess.
  Say so explicitly rather than padding the number silently.

If a requirement cannot be estimated at all, say that and state what you need in
order to estimate it. Do not emit a number you would not defend on a call.

## Step 5 — Check before you hand it over

- [ ] Every requirement is numbered and independently testable.
- [ ] No requirement contains a solution the client did not ask for.
- [ ] Every guess appears as a numbered assumption, not as a fact.
- [ ] Out of Scope names the expensive misunderstandings.
- [ ] Estimates are ranges, broken into all four phases.
- [ ] A developer could start on FR-1 without another meeting.
- [ ] A non-technical client could read the Overview and Requirements unaided.

## Rules

- Never invent client names, project names, user names, or business data. If the
  brief lacks them, write `<Client>` and `<System>` placeholders.
- Client-facing sections: formal, confident, jargon-free — unless the reader is
  technical. Internal notes may be blunt.
- Distinguish **must**, **should**, and **could** explicitly. An unprioritised
  requirement list gets built in the wrong order.
- If the request as stated cannot work — contradictory rules, an integration
  that does not expose the needed data — say so in two sentences, then specify
  the closest thing that does work. Do not quietly redesign around the problem.
- Close every client-facing document with one clear next step: what you need,
  from whom, by when.
