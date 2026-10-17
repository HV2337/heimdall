.PHONY: setup test run eval demo evidence

setup:
	python -m pip install -e .

test:
	python -m unittest discover -s tests -v

run:
	python -m gateway.main

eval:
	python -m unittest discover -s tests -v

demo:
	python -m data.seed_synthetic

evidence:
	python --version
