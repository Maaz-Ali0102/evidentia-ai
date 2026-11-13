# Blind test results (13 November 2026)

Real ORG-0005 records from the **test period** (never used for training), labels removed from the evidence and
kept in a separate answer key. Each test was uploaded as its own case to the running app and scored with
`scripts/score_blind_test.py`. Models: the deployed (pooled) Logistic Regression and Random Forest.

## Summary

| Test | Records (benign / suspicious / malicious) | Model | Benign recall | Suspicious recall | **Malicious recall** | Malicious precision | Accuracy | Macro-F1 |
|---|---|---|---|---|---|---|---|---|
| A balanced, CSV | 250 / 250 / 250 | LR | 100% | 98% | **54%** | 0.96 | 83.9% | 0.830 |
| | | RF | 100% | 98% | **71%** | 0.97 | 89.5% | 0.893 |
| A balanced, raw log lines | 250 / 250 / 250 | LR | 100% | 98% | **56%** | 0.97 | 84.8% | 0.841 |
| | | RF | 100% | 98% | **69%** | 0.97 | 89.1% | 0.888 |
| B look-alikes (same text pattern) | 0 / 150 / 150 | LR | – | 97% | **52%** | 0.94 | 74.3% | 0.730 |
| | | RF | – | 98% | **69%** | 0.97 | 83.7% | 0.833 |
| C realistic 20-min window | 14,598 / 2,862 / 84 | LR | 100% | 97% | **56%** | **0.35** | 99.2% | 0.803 |
| | | RF | 100% | 97% | **58%** | **0.34** | 99.1% | 0.802 |

## What the results say

1. **Normal (benign) logs: 100% correct in every test.** As expected: in this data the log type decides
   benign vs alert (Stage 1 is a router). Not a sign of a clever model; a property of the data.
2. **Suspicious: 97-98% recognised.** Few suspicious records are wrongly called malicious (2-3%).
3. **Malicious: the real difficulty.** Random Forest catches about **7 in 10** malicious records, Logistic
   Regression about **5 in 10**; the rest are called "suspicious" (never "benign": no attack is missed as normal).
4. **Look-alikes (test B):** when suspicious and malicious lines have the same text pattern, LR drops to 52%
   while RF keeps 69%: RF uses the behaviour (context) features better.
5. **Raw log lines vs CSV give the same results.** The parser rebuilds the structure (IPs, ports, action) from
   the raw Cisco ASA text, so the format of the evidence doesn't matter.
6. **Precision depends on how rare attacks are.** In the balanced tests a "malicious" flag is right 96-97% of
   the time; in the realistic window (84 malicious among 2,946 alerts) only **~35%**, because 3% of 2,862
   suspicious records (~90 false alarms) outnumber the true detections. Same model, same error rate: the
   difference is prevalence. This is why the app treats flags as leads for an analyst, not verdicts.
7. **Accuracy misleads:** test C has 99% accuracy while catching only 56-58% of malicious records.
8. These results agree with the offline evaluation (Stage 2 on ORG-0005: RF recall 76%, LR 42%, malicious
   precision ~0.35), so the app behaves in use as the report says.

## Caveats

- Test A spreads 750 records over ~6 hours, so the context features see fewer neighbours than in a full log:
  harder than real use. Test C (full window) is the realistic condition.
- Labels are WitFoo's automated correlation labels, not analyst-verified ground truth.
- 22 benign records in test C were marked "not applicable" (lines the gate did not trust); counted as errors.
- ORG-0005 only. On ORG-0004 (AWS VPC) the models are near chance (see the Model evaluation page).

## Reproduce

```
python scripts/make_blind_test.py                          # needs the WitFoo dataset (data/raw)
# create one case per test file, upload it, wait until Ready, then:
python scripts/score_blind_test.py <case-id>               # prints the tables above for that case
```
