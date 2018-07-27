# ELECTRUM_VERSION = $(strip $(shell cat VERSION))

DOCKER_REPO = attic
DOCKER_TAG = electrum-jh

# Build Docker image
build: 
	docker_build output

# Run daemon
run: 
	docker run --rm --name wallet-deposit --publish 23000:23000 --volume /opt/btc-deposit:/data $(DOCKER_REPO):$(DOCKER_TAG) 

run_cold: 
	docker run --rm --name wallet-cold  --publish 23100:23000 --volume /opt/btc-cold:/data $(DOCKER_REPO):$(DOCKER_TAG)

run_hot: 
	docker run --rm --name wallet-hot --publish 23200:23000 --volume /opt/btc-hot:/data $(DOCKER_REPO):$(DOCKER_TAG)

# load wallet
load:
	docker exec -it wallet-deposit electrum --regtest daemon load_wallet -w /data/.electrum/regtest/wallets/default_wallet

load_cold:
	docker exec -it wallet-cold electrum --regtest daemon load_wallet -w /data/.electrum/regtest/wallets/default_wallet

load_hot:
	docker exec -it wallet-hot electrum --regtest daemon load_wallet -w /data/.electrum/regtest/wallets/default_wallet

# stop daemon
stop:
	docker stop wallet-deposit

stop_cold:
	docker stop wallet-cold

stop_hot:
	docker stop wallet-hot

default: 
	docker_build output

docker_build: 
	docker build -t $(DOCKER_REPO):$(DOCKER_TAG) .

output:
	@echo Docker Image: $(DOCKER_REPO):$(DOCKER_TAG)
