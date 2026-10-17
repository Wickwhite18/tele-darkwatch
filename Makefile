.PHONY: install test lint fmt daemon clean

install:
pip install -e ".[dev]"

test:
pytest -q

lint:
ruff check src tests

fmt:
ruff format src tests

daemon:
darkwatch daemon

docker-build:
docker build -t tele-darkwatch .

docker-up:
docker compose up -d

clean:
rm -rf .pytest_cache .ruff_cache dist build *.egg-info
find . -name "__pycache__" -type d -exec rm -rf {} +
