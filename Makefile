# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
REPO_DIR := $(shell basename $(CURDIR))

PLUGIN_NAME := $(shell command ls cmd/)
ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif
PLUGIN_DIR ?= $(GOPATH)/vault-plugins
PLUGIN_PATH ?= local-secrets-ldap

# env vars

#setup ldap server:
LDAP_DOMAIN ?= example.com
LDAP_ORG ?= example
LDAP_ADMIN_PW ?= adminpassword
IMAGE_TAG ?= 1.5.0
LDAP_PORT ?= 389
LDIF_PATH ?= $(PWD)/bootstrap/ldif/seed.ldif

#configure ldap plugin
MAKEFILE_DIR ?= $(PWD)
PLUGIN_SOURCE_TYPE ?= local_build
PLUGIN_DIR_VAULT ?= /etc/vault/plugins
LDAP_URL ?= ldap://127.0.0.1:389
LDAP_BIND_DN ?= cn=admin,dc=example,dc=com
LDAP_BIND_PASS ?= adminpassword
LDAP_USER_DN ?= ou=users,dc=example,dc=com
LDAP_SCHEMA ?= openldap

export LDAP_DOMAIN
export LDAP_ORG
export LDAP_ADMIN_PW
export IMAGE_TAG
export LDAP_PORT
export PLUGIN_DIR
export PLUGIN_NAME
export PLUGIN_PATH
export PLUGIN_SOURCE_TYPE
export MAKEFILE_DIR
export PLUGIN_DIR_VAULT
export LDAP_URL
export LDAP_BIND_DN
export LDAP_BIND_PASS
export LDAP_USER_DN
export LDAP_SCHEMA
export LDIF_PATH

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/$(PLUGIN_NAME) cmd/$(PLUGIN_NAME)/main.go

.PHONY: run
run:
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/run.sh'"

# bootstrap the build by downloading additional tools
.PHONY: bootstrap
bootstrap:
	@echo "Downloading tools ..."
	@go generate -tags tools tools/tools.go
	# This should only ever be performed once, so we lean on the cmd/ directory
	# to indicate whether this has already been done.
	@if [ "$(PLUGIN_NAME)" != "$(REPO_DIR)" ]; then \
		echo "Renaming cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR) ..."; \
		mv cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR); \
		echo "Renaming Go module to github.com/hashicorp/$(REPO_DIR) ..."; \
        go mod edit -module github.com/hashicorp/$(REPO_DIR); \
	fi


.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test ./... $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -l -w .

.PHONY: setup-env
setup-env:
	cd bootstrap && ./setup-docker.sh
	cd bootstrap && ./setup-openldap.sh

.PHONY: plugin-build
plugin-build:
	cd enos/modules/build_local && ./scripts/plugin-build.sh

.PHONY: plugin-register
plugin-register:
	cd enos/modules/setup_plugin && \
	PLUGIN_BINARY_SRC="$(PLUGIN_DIR)/$(PLUGIN_NAME)" ./scripts/plugin-register.sh

.PHONY: plugin-enable
plugin-enable:
	cd enos/modules/setup_plugin && ./scripts/plugin-enable.sh

.PHONY: plugin-configure
plugin-configure:
	cd enos/modules/configure_plugin/ldap && ./scripts/plugin-configure.sh

.PHONY: configure
configure: plugin-build plugin-register plugin-enable plugin-configure

.PHONY: teardown-env
teardown-env:
	cd bootstrap && ./teardown-env.sh
