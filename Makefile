# AWS Org Security Controls — common dev & deploy commands.
#
# Usage:
#   make            # list available targets
#   make test       # run the full test suite
#   make deploy     # synth + deploy all stacks to every region
#
# AWS_PROFILE selects the credentials/account. Override on the command line:
#   make deploy AWS_PROFILE=other-profile
AWS_PROFILE ?= seb
export AWS_PROFILE

.DEFAULT_GOAL := help

.PHONY: help install build watch test test-watch lint synth diff deploy \
        bootstrap login destroy clean

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install npm dependencies
	npm install

build: ## Compile TypeScript (tsc)
	npm run build

watch: ## Compile TypeScript in watch mode
	npm run watch

test: ## Run the full Jest test suite
	npm test

test-watch: ## Run Jest in watch mode
	npx jest --watch

synth: ## Synthesize all CloudFormation templates
	npx cdk synth --all

diff: ## Show deployed-vs-local diff for all stacks
	npx cdk diff --all

login: ## Refresh the AWS SSO session for AWS_PROFILE
	aws sso login --profile $(AWS_PROFILE)

bootstrap: ## One-off CDK bootstrap of every notifier region
	bash bin/bootstrap-all-regions.sh

deploy: ## Deploy all stacks to every region (no approval prompt)
	npm run deploy

destroy: ## Tear down all deployed stacks
	npx cdk destroy --all

clean: ## Remove build artifacts
	rm -rf cdk.out dist
