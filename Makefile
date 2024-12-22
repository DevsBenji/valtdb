.PHONY: install test lint type security clean docs build publish check init

install:
	pip install -e ".[dev]"

test:
	pytest tests/ --cov=valtdb --cov-report=term-missing

lint:
	black .
	isort .
	flake8 valtdb tests

type:
	mypy valtdb tests

security:
	bandit -c pyproject.toml -r valtdb

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".tox" -exec rm -rf {} +

docs:
	cd docs && make html

build: clean
	python -m build

publish: build
	twine upload dist/*

check: lint type security test

init:
	pip install -r requirements-dev.txt
	pre-commit install
