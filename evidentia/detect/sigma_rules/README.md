# Sigma rules

Rules in this folder are loaded by `evidentia/detect/sigma.py` and run on every case.

## Bundled rules

`linux/` holds the 22 rules of SigmaHQ's `rules/linux/builtin` folder, copied unchanged from
https://github.com/SigmaHQ/sigma at commit `d7c9da10c170a6988d68ebdf2c9f7bd8782b7c55` (2026-11-10).

They are released by SigmaHQ under the **Detection Rule License (DRL) 1.1**
(https://github.com/SigmaHQ/Detection-Rule-License). Each rule keeps its `author` and `references`
fields; Evidentia shows the rule's title, author and id with every match, as the licence requires.

## Adding rules

Drop any Sigma `.yml` rule into this folder (subfolders are fine). Supported:

- `keywords` / selections that are a list of strings (any must appear) or `{'|all': [...]}` (all must appear),
  with `*` and `?` wildcards; matching is case-insensitive over the record's text;
- field selections on fields Evidentia stores: `message`, `src_ip`, `dst_ip`, `dst_port`, `action`,
  `protocol`, `severity`, `message_type` (Sigma names such as `CommandLine`, `SourceIp`, `DestinationIp`,
  `DestinationPort` are mapped), with the modifiers `contains`, `startswith`, `endswith`, `re`, `all`;
- conditions with `and`, `or`, `not`, brackets, `1 of name*`, `all of name*`, `1 of them`, `all of them`.

A rule using anything else (other fields, aggregations, correlations) is skipped and listed as unsupported;
it never stops the other rules.
