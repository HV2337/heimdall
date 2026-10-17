# Third-party components

| Name | Link | License | Use |
| --- | --- | --- | --- |
| FastAPI | https://github.com/fastapi/fastapi | MIT | Minimal HTTP health endpoint |
| Uvicorn | https://github.com/encode/uvicorn | BSD-3-Clause | ASGI server for `make run` |
| Faker | https://github.com/joke2k/faker | MIT | Synthetic patient seed data |
| NumPy | https://github.com/numpy/numpy | BSD-3-Clause | Classifier feature arrays; apt package on LinuxONE |
| SciPy | https://github.com/scipy/scipy | BSD-3-Clause | Classifier/scientific computing dependency; apt package on LinuxONE |
| scikit-learn | https://github.com/scikit-learn/scikit-learn | BSD-3-Clause | Threat classifier; apt package on LinuxONE |
| cryptography | https://github.com/pyca/cryptography | Apache-2.0 OR BSD-3-Clause | Encrypted session vault; apt package on LinuxONE |
| Hugging Face Datasets | https://github.com/huggingface/datasets | Apache-2.0 | Laptop-only download of external threat data |
| Lakera/gandalf_ignore_instructions | https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions | MIT | External prompt-injection training and test data; source credit and filtering details in `eval/data/external/README.md` |
| jackhhao/jailbreak-classification | https://huggingface.co/datasets/jackhhao/jailbreak-classification | Apache-2.0 | External jailbreak training and test data; source credit and filtering details in `eval/data/external/README.md` |
| deepset/prompt-injections | https://huggingface.co/datasets/deepset/prompt-injections | Apache-2.0 and CC-BY-4.0 both declared in card metadata; skipped as ambiguous | Considered for external data; not downloaded or used |

The application code and seed schema are written for this project. Synthetic records contain no source patient data.
