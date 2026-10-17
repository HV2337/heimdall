.PHONY: setup setup-vm setup-laptop test run eval demo evidence

setup:
	python -m pip install -r requirements.txt

setup-vm:
	bash scripts/setup_vm.sh

setup-laptop:
	python -m pip install -r requirements-laptop.txt

test:
	python -m unittest discover -s tests -v

run:
	python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000

eval:
	python -m unittest discover -s tests -v

demo:
	python -m data.seed_synthetic

evidence:
	bash evidence/capture_platform.sh
