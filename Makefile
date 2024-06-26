
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
SERVICES_DIR=$(ROOT_DIR)/services

.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v

## audit: run quality control checks
.PHONY: audit
audit:
	go mod verify
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go test -race -buildvcs -vet=off ./...

## lint: run golangci linter
.PHONY: lint
lint:
	golangci-lint run

## test: run all tests
.PHONY: test
test:
	go test -v -race -buildvcs ./...

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover:
	go test -v -race -buildvcs -coverprofile=/tmp/coverage.out ./...
	go tool cover -html=/tmp/coverage.out

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## run/auth: starts dev auth service
.PHONY: run/auth
run/auth:
	@go run $(SERVICES_DIR)/auth/main.go server -c $(SERVICES_DIR)/auth/config/config.yml

## run/callback: start dev callback service
.PHONY: run/callback
run/callback:
	@go run $(SERVICES_DIR)/callback/main.go server -c $(SERVICES_DIR)/callback/config/config.yml

## run/gateway: starts gateway auth service
.PHONY: run/gateway
run/gateway:
	@go run $(SERVICES_DIR)/gateway/main.go server -c $(SERVICES_DIR)/gateway/config/config.yml

.PHONY: run/runner
run/runner:
	@go run $(SERVICES_DIR)/runner/main.go server -c $(SERVICES_DIR)/runner/config/config.yml
# ==================================================================================== #
# BUILD AND CLEANUP
# ==================================================================================== #

## build: compile all services
.PHONY: build
build: build/auth build/callback build/gateway build/runner

## build/auth: compile auth service
.PHONY: build/auth
build/auth:
	@go build -o build/auth $(SERVICES_DIR)/auth/main.go

## build/callback: compile callback service
.PHONY: build/callback
build/callback:
	@go build -o build/callback $(SERVICES_DIR)/callback/main.go

## build/gateway: compile gateway service
.PHONY: build/gateway
build/gateway:
	@go build -o build/gateway $(SERVICES_DIR)/gateway/main.go

## build/runner: compile runner service
.PHONY: build/runner
build/runner:
	@go build -o build/runner $(SERVICES_DIR)/runner/main.go

## images: build and push docker images
IMAGES = gateway callback auth runner
IMAGE_TARGETS = $(addprefix images/,$(IMAGES))
DOCKER_REGISTRY = registry.nicedoc.cn

.PHONY: images
images: $(IMAGE_TARGETS)

images/%:
	docker build . --target $* -t $(DOCKER_REGISTRY)/biyue-$*:latest
	docker push $(DOCKER_REGISTRY)/biyue-$*:latest

## clean: remove build directory
.PHONY: clean
clean:
	@rm -rf build
