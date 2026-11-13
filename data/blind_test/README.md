Build a BLIND test of the classifiers from real ORG-0005 records (data/blind_test/).

Every record is REAL WitFoo data from ORG-0005's TEST period (after the 2024-07-27 00:00 UTC cut-off), so none
of it was used for training. The evidence files contain only the columns the app reads from any upload
(time, message, type, action, protocol, severity, IPs, ports): no label and no post-label column. The true
labels go to KEY_DO_NOT_UPLOAD/answer_key.csv, which only the scoring script (score_blind_test.py) reads.

  A  balanced       250 benign + 250 suspicious + 250 malicious, random over the whole test period.
                    Written twice: test_A_balanced.csv (structured) and test_A_balanced_raw.log (message
                    text only), to compare how much the structured columns help.
                    Harder than real use: the records are spread over ~6 hours, so the context features
                    (how active each IP was in the minutes before) see far fewer neighbours than in a full log.
  B  look-alikes    150 malicious + 150 suspicious whose message is the same text pattern (digits masked) as
                    some malicious message: only behaviour/context can separate them. No benign records.
  C  realistic      every record of the 20-minute test-period window with the most malicious records,
                    in its natural mix (mostly benign): real-world conditions, full context.

## How to run the test

1. Create one case per test and upload ONLY that test's file(s):
   - `test_A_balanced.csv` and `test_A_balanced_raw.log` (two cases, or one case per file)
   - `test_B_lookalikes.csv`
   - `test_C_realistic_20min.csv` (window starts 2024-07-27 05:00:00+00:00; ~1-2 min to process)
2. Never upload anything from `KEY_DO_NOT_UPLOAD/`.
3. Score a case (server running):  `.venv\Scripts\python scripts\score_blind_test.py <case-id>`
   The case id is the last part of the case's address, e.g. `blind-test-a-1a2b3c`.
