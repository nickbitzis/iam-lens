PORT ?= 8839

.PHONY: install test lint format data findings reduction suggest simulate check check-bad campaign run docker-build screenshot clean

install:
	uv sync --python 3.12

test:
	uv run pytest -q

lint:
	uvx ruff check .
	uvx ruff format --check .

format:
	uvx ruff format .
	uvx ruff check . --fix

data:  ## regenerate the synthetic environment and 90 days of access logs (seed 7)
	uv run iamlens generate --out examples

findings:
	uv run iamlens findings --severity critical --severity high

reduction:  ## granted actions before and after least privilege, by principal kind
	uv run iamlens reduction

suggest:  ## generated policy and its proof for one principal
	uv run iamlens suggest 111100143333:role/app-ml-worker

simulate:
	uv run iamlens simulate 111100143333:role/app-ml-worker s3:GetObject arn:aws:s3:::cobaltline-data-lake/curated/features-2026.parquet

check:  ## the CI gate on the clean example policies (exit 0)
	uv run iamlens check examples/policies --sarif iamlens.sarif --summary summary.md

check-bad:  ## the CI gate on the bad example policies (exit 1)
	-uv run iamlens check examples/policies-bad --sarif iamlens.sarif --summary summary.md

campaign:
	uv run iamlens campaign --evidence data/evidence.csv

run:
	IAMLENS_STATE=data uv run iamlens serve --port $(PORT)

docker-build:
	docker build -t iam-lens .

screenshot:  ## needs the server running on $(PORT) and Google Chrome
	uv run python scripts/screenshot.py --port $(PORT)

clean:
	rm -rf .pytest_cache .ruff_cache data iamlens.sarif summary.md
