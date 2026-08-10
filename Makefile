.PHONY: install test run cli docker-up docker-down

install:
	cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

test:
	cd backend && . .venv/bin/activate && python -m pytest tests/ -v

run:
	cd backend && . .venv/bin/activate && uvicorn app.main:app --reload

cli:
	cd backend && . .venv/bin/activate && python cli.py --input ../data/sample_access.log

docker-up:
	docker compose up --build

docker-down:
	docker compose down
