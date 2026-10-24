.PHONY: compile test chain-gen chain-up chain-deploy
compile:
	cd chain && npm ci && node compile.js
test: compile
	python -m pytest -q
chain-gen:
	./scripts/gen-network.sh
chain-up:
	docker compose -f deploy/docker-compose.chain.yml --env-file deploy/besu/.env up -d --build
chain-deploy:
	docker compose -f deploy/docker-compose.chain.yml --profile deploy run --rm deployer
