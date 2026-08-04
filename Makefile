.PHONY: help up down logs build migrate seed mint test fmt lint install

help:
	@echo "Targets:"
	@echo "  up        - build & start Postgres + app (docker compose)"
	@echo "  down      - stop and remove containers"
	@echo "  logs      - tail app logs"
	@echo "  migrate   - run alembic migrations inside the app container"
	@echo "  seed      - seed roles + bootstrap admin token"
	@echo "  mint u=<username> [n=<name>] - mint a token for a user"
	@echo "  test      - run the pytest suite (SQLite, no ML needed)"
	@echo "  install   - editable install with dev+ml extras (local)"

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f app

build:
	docker compose build

migrate:
	docker compose exec app alembic upgrade head

seed:
	docker compose exec app mpv-seed

mint:
	docker compose exec app mpv-mint-token $(u) --name $(or $(n),default)

test:
	pytest -q

fmt:
	ruff format src tests

lint:
	ruff check src tests

install:
	pip install -e ".[dev,ml]"
