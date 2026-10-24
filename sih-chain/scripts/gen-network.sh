#!/usr/bin/env bash
# Generate a 4-validator QBFT network (keys + genesis with the validator set) using Besu itself.
# UNTESTED in the build environment (needs Docker). Dev keys only: do not reuse for anything real.
set -euo pipefail
BESU_IMAGE="${BESU_IMAGE:-hyperledger/besu:24.12.2}"   # pin by digest in production
cd "$(dirname "$0")/../deploy/besu"
rm -rf networkFiles config .env
docker run --rm -v "$PWD":/work -w /work "$BESU_IMAGE" \
  operator generate-blockchain-config --config-file=qbft-config.json --to=networkFiles --private-key-file-name=key
mkdir -p config
cp networkFiles/genesis.json config/genesis.json
i=1
for d in networkFiles/keys/*/; do
  mkdir -p "config/node$i"
  cp "${d}key" "${d}key.pub" "config/node$i/"
  i=$((i + 1))
done
PUB="$(sed 's/^0x//' config/node1/key.pub)"
echo "BOOTNODE_ENODE=enode://${PUB}@besu-1:30303" > .env
echo "Generated $((i - 1)) validators. Next: docker compose -f deploy/docker-compose.chain.yml --env-file deploy/besu/.env up -d"
