# External threat data

Run `python eval/fetch_external_data.py` on a laptop with the laptop
requirements installed. The script preserves each source's `train`, `validation`
and `test` membership, removes empty rows and exact normalized duplicates
(first split encountered wins), and writes JSONL fields `text`, `label`,
`source`, `split`, and `license` here. It never runs as part of VM setup.

English filtering is a documented heuristic: a row must contain alphabetic
characters, at least 90% of its letters must be ASCII, and it must contain a
word from a small common-English vocabulary. This avoids an additional language
model dependency, but can reject short or unusual English text and is not a
general language identification guarantee.

## Sources and licenses

- [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions)
  — MIT. The dataset card describes prompt injection examples and includes
  train, validation, and test splits. Lakera's citation is arXiv:2501.07927.
- [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification)
  — Apache-2.0. The card provides balanced train and test splits; labels are
  converted from `jailbreak`/`benign` to `1`/`0`.
- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
  — skipped because its card metadata declares both Apache-2.0 and CC-BY-4.0.
  The downloader reports this conflict and does not write its rows.

The downloader checks card YAML metadata before loading any dataset and only
accepts an unambiguous MIT, Apache-2.0, or CC-BY-4.0 declaration. The source
license is copied into every row. Downloaded text remains attributed to its
source; the generated synthetic examples are maintained separately.
