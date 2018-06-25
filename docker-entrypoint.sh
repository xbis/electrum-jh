#!/usr/bin/env sh
set -ex

# Graceful shutdown
trap 'pkill -TERM -P1; electrum daemon stop; exit 0' SIGTERM

# Set config
#electrum --regtest setconfig rpcuser user
#electrum --regtest setconfig rpcpassword password
#electrum --regtest setconfig rpcport 22000

# XXX: Check load wallet or create

# Run application
electrum --regtest daemon start

# Wait forever
while true; do
  tail -f /dev/null & wait ${!}
done
