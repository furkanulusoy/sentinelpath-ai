# Leakage Prevention in Attack-Path Prediction Evaluation

This document describes the discipline SentinelPath AI follows to avoid
ground-truth leakage when evaluating against labeled security datasets
(e.g. the LANL Comprehensive Multi-Source Cyber-Security Events dataset).
It is written to be useful independently of this codebase — if you are
building or evaluating your own attack-path / lateral-movement
prediction system, the same three leakage categories apply to you.

## Why this matters

In supervised machine learning, "leakage" usually means test-set
information accidentally influencing training. In attack-path
prediction against a labeled red-team dataset, leakage is easier to
introduce and easier to miss, because the "test set" (the labels) is a
single small file (e.g. `redteam.txt`) that is tempting to peek at
during *every* design decision — not just during model fitting.

We found it useful to separate leakage into three distinct categories,
because they are introduced at different pipeline stages and require
different discipline to avoid. Treating "leakage" as one undifferentiated
concern makes it easy to guard against one form while walking straight
into another — which is what happened to us during development (see
the worked example below).

## The three categories

### 1. Labeling leakage

**Definition:** Using the ground-truth labels to decide what a raw event
*is* (i.e. to assign a technique/category to it) instead of relying
solely on independently observable signal.

**Why it's tempting:** When raw data lacks an obvious feature to key off
(e.g. our `auth.txt` events have no port number), it's tempting to say
"well, we know which events are malicious from `redteam.txt`, so let's
weight our classification logic toward getting those right."

**How we avoided it:** Our three-tier auth-event classification
(`ADR 0014`) assigns MITRE technique IDs using only: (a) the Windows
logon-type field's own documented semantics, and (b) cross-referencing
against an independently collected flow log, matched on host-pair and
time proximity — never on whether the event appears in the red-team
file. Events that can't be classified this way fall to an explicit
low-confidence bucket rather than being pushed toward a label that
would "look right" in hindsight.

**Test:** Would your classification logic produce the *same* output if
you deleted the label file entirely before running it? If not, you have
labeling leakage.

### 2. Parameter-tuning leakage

**Definition:** Selecting a threshold, weight, or hyperparameter by
searching for the value that maximizes an accuracy metric against the
labels — even if no single event was ever individually mislabeled.

**Why it's more dangerous than it looks:** This form is easy to miss
because no single step looks like "cheating." Splitting data into a
"calibration" and "test" portion *feels* rigorous — but if the
calibration step still optimizes against the same ground truth you'll
report results against, you've simply renamed the problem. We caught
ourselves doing exactly this: an earlier design iteration proposed
tuning a detection threshold on a "calibration" data window using
"whichever value gives the best Top-K score" — which is parameter
fitting with a leakage-shaped hole in the middle, regardless of the
calibration/test split's existence.

**How we avoided it:** Every threshold in our scanning detector
(`ADR 0015`) — the statistical outlier method, the time window, the
volume cutoff — is justified by an external, label-independent
principle (a standard statistical method, or the existing system's own
internal scale) rather than by which value scores best against the
labels.

**Test:** Can you justify every constant in your detection/scoring
logic *without ever mentioning* the accuracy number it produces? If a
constant's only justification is "this is what gave the best result,"
you have parameter-tuning leakage.

### 3. Baseline contamination

**Definition:** Letting the malicious activity you're trying to detect
influence your model of what "normal" looks like.

**Why it's the easiest to miss:** Unlike the first two categories, this
one doesn't involve looking at the label file at all — which is
precisely why it's easy to introduce by accident. If you compute a
host's "typical" behavior from a time window that includes the attack
itself, the attack's own traffic quietly raises what counts as
"typical," making the detector less sensitive to the exact thing it's
supposed to catch.

**How we handle it:** Where possible, baselines should be computed from
a period that structurally precedes the evaluation period (a fixed
"first N days" split, chosen without reference to *where* the labeled
events fall — see `ADR 0006`'s explicit `window_start`/`window_end`
parameters). Where a single-window design is used instead (our
`ADR 0015` "single window" decision), the detector's own statistical
method must have a known tolerance for a minority of contaminated
observations (we rely on the Tukey IQR method's documented breakdown
point) — and this reliance should be stated explicitly, not assumed.

**Test:** If you doubled the amount of attack traffic in your
"normal" baseline window, would your detector's threshold move in a
way that makes the attack harder to catch? If yes, you have baseline
contamination risk.

## A worked example from this project

`ADR 0015` documents a real instance of us catching ourselves mid-design:
an early proposal for calibrating a detection threshold used the phrase
"whichever value gives the best Top-K result" — which is category 2
leakage, introduced *while trying to design a leakage-free system*. This
is worth stating plainly: leakage discipline is not a one-time checklist
you complete and move past. It requires re-examining each new design
decision against all three categories, including decisions that feel
like they're "about the method" rather than "about the data."

## A note on evaluation honesty, related but distinct

A rigorously leakage-free pipeline still doesn't guarantee an
interpretable accuracy number. In heavily imbalanced datasets (labeled
attacks are typically a tiny fraction of total events), a recall-only
metric can be misleadingly reassuring, and a precision/false-positive
estimate may be unavailable in the strict sense if the dataset only
labels positives (see the "base-rate fallacy" discussion in Axelsson,
2000). We treat this as a fourth, related discipline: report what your
metric can and cannot support, rather than letting an unqualified
percentage imply more than the data allows.

## Checklist for your own project

- [ ] Can every classification rule run correctly with the label file deleted?
- [ ] Can every threshold/weight be justified without citing the accuracy it produces?
- [ ] Is your "normal" baseline computed from a period structurally
      separated from the evaluation period — or, if not, does your
      detection method have a stated, known tolerance for contamination?
- [ ] Have you re-applied all three checks to *every new* design
      decision, not just the first pass?
- [ ] Does your reported metric honestly state what it can't prove
      (e.g. "approximate precision" vs. a rigorous false-positive rate)?

## References in this codebase

- `ADR 0009` — why an untrained, frequency-based model was chosen in
  the absence of labeled training data
- `ADR 0014` — labeling leakage avoidance in auth-event classification
- `ADR 0015` — parameter-tuning leakage avoidance and the single-window
  baseline decision, including the self-caught near-miss described above
- `ADR 0006` / `ADR 0010` — baseline window semantics and honest
  confidence reporting