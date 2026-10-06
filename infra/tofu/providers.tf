# Coldline - Task 4.10
# File: infra/tofu/providers.tf
# Component: OpenTofu provider configuration
# Purpose: Pin the AWS provider and point it at the stack's LocalStack with its development credentials.
# Interacts With: infra/tofu/variables.tf, infra/tofu/main.tf, infra/tofu/.terraform.lock.hcl, compose.yaml, poe tofu-plan, poe tofu-apply, poe tofu-destroy
# Sprint/Task: Sprint 4 - Project 4 / Task 4.10
# Concepts: Infrastructure as code, a pinned provider, a local emulator in place of a cloud account
# Tools: OpenTofu, LocalStack

# Supplied and not student-editable. The supplied commands run OpenTofu in a container on the
# stack's Compose network, where LocalStack answers as `localstack` on its container port
# 4566, whatever host port `COLDLINE_LOCALSTACK_HOST_PORT` publishes. The access key and the
# secret key are LocalStack's development values from compose.yaml: they grant nothing
# outside the local Compose network and are not secrets. Never replace them with a real
# credential, and never add a real account, a profile or a remote state backend here.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.10.0"
    }
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "localstack-development-key"
  secret_key = "localstack-development-secret"

  # The provider skips the account and credential lookups LocalStack doesn't serve.
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # LocalStack does not resolve virtual-host bucket names inside the Compose network.
  s3_use_path_style = true

  endpoints {
    s3             = "http://localstack:4566"
    sqs            = "http://localstack:4566"
    secretsmanager = "http://localstack:4566"
  }
}
