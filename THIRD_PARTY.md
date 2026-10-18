# Third-party components

This file records direct Python dependencies declared by `requirements.txt` and `requirements-laptop.txt`, external training datasets, and the compiled packages installed from Ubuntu on LinuxONE. Python package versions and license labels below come from `importlib.metadata` in the project laptop venv; they describe that environment, not necessarily the versions installed on another machine. A license is marked **license not verified** when the available package metadata or project files do not establish it.

## Python dependencies

| Package | Installed venv version | License declared in package metadata |
|---|---:|---|
| FastAPI | 0.143.3 | MIT |
| Uvicorn | 0.54.0 | BSD-3-Clause |
| Faker | 39.1.0 | MIT License |
| `datasets` | 5.1.0 | Apache 2.0 |
| NumPy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| SciPy | 1.18.1 | BSD License (metadata classifier) |
| scikit-learn | 1.4.2 | new BSD |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |

`requirements-laptop.txt` includes the pure-Python requirements and `datasets`, plus NumPy, SciPy, scikit-learn (pinned to `1.4.*`) and cryptography for laptop development. The LinuxONE VM installs the compiled packages below from Ubuntu apt instead of PyPI.

## LinuxONE system Python packages

`scripts/setup_vm.sh` installs `python3-numpy`, `python3-scipy`, `python3-sklearn`, and `python3-cryptography` from Ubuntu packages. The recorded VM versions are from `evidence/platform-20261017T081813Z.txt`:

| Ubuntu package | VM version | License entries in the package's copyright file |
|---|---:|---|
| `python3-numpy` | 1.26.4 | Apache-2, BSD-3-Clause, Expat (MIT), Zlib |
| `python3-scipy` | 1.11.4 | Apache-2.0, Apache-2.0+MIT, Boost-1.0, BSD-2-clause, BSD-3-clause, BSD-generic, BSD-LBNL, bsdlike, Expat, PSF-2, public-domain, qhullbsd |
| `python3-sklearn` | 1.4.1.post1 | BSD-2-Clause, BSD-3-Clause, Python |
| `python3-cryptography` | 41.0.7 | Apache, Expat |

These were read on the VM from `/usr/share/doc/<package>/copyright` by listing every `License:` entry (de-duplicated; entries that differed only in letter case, such as Zlib/ZLib and expat/Expat, are shown once). The Ubuntu packages bundle several upstream components, which is why SciPy lists many entries; the full texts are in those files on the VM. They are not the venv metadata above, which describes the laptop environment.

## Threat-classifier training datasets

The trainer `eval/train_threat.py` reads JSONL files under `eval/data/external/`. For the selected option D it trains with the `train` splits and evaluates on the separate `test` splits. The test files are not included in fitting or generated-validation threshold selection; `models/threat_metrics.json` records the threshold-selection source as `generated_validation_families_only`. External test metrics were used when comparing ablation options, so they are not an untouched post-selection measurement.

| Dataset | License | Exact files and splits |
|---|---|---|
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | `eval/data/external/lakera_gandalf_ignore_instructions_train.jsonl` (train); `eval/data/external/lakera_gandalf_ignore_instructions_test.jsonl` (test) |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | `eval/data/external/jackhhao_jailbreak_classification_train.jsonl` (train); `eval/data/external/jackhhao_jailbreak_classification_test.jsonl` (test) |

Dataset files are redistributed under their original licenses (MIT for Lakera/gandalf_ignore_instructions, Apache-2.0 for jackhhao/jailbreak-classification); see each dataset card for the full text.

`deepset/prompt-injections` was not used because its dataset card declares two licenses, so the licensing was unclear for this project.

The trainer also generates templated examples from `eval/threat_data.py`; option D adds its healthcare persona-attack families. These are project-generated data, not third-party datasets. The separate hand-written development set is declared in `eval/threat_data.py` and is used for evaluation/model development, not as an external dataset.

## AI assistance

An AI coding assistant wrote most of the code, and a separate AI chat assistant helped with planning and review and wrote the final held-out prompt set. The team reviewed the code, tests, and results.
