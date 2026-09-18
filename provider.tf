# ============================================================
# AWS Cloud Security Operations Centre — Provider Configuration
# ============================================================
# Portfolio Standard: provider.tf contains BOTH the terraform{}
# block AND all provider configurations. No versions.tf.
#
# Portfolio Position: 4 of 6
# Depends on:
#   - aws-enterprise-landing-zone   (GuardDuty, Security Hub, CloudTrail,
#                                    KMS keys, logging account)
#   - aws-devsecops-pipeline        (ECR findings, pipeline alerts SNS topic)
# Consumed by:
#   - multi-cloud-governance         (unified security posture findings)
# ============================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Remote backend — overridden per environment in environments/<env>/backend.tf
  backend "s3" {}
}

# ---- SOC / Security account (default) ----------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-cloud-security-operations-center"
      ManagedBy   = "Terraform"
      Owner       = var.owner
      CostCenter  = var.cost_center
      Environment = var.environment
      Repository  = "aws-cloud-security-operations-center"
      Portfolio   = "enterprise-cloud-platform"
    }
  }
}

# ---- Management account (read landing-zone outputs) --------
provider "aws" {
  alias  = "management"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.management_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformSOC-Management"
  }

  default_tags {
    tags = {
      Project   = "aws-cloud-security-operations-center"
      ManagedBy = "Terraform"
      Portfolio = "enterprise-cloud-platform"
    }
  }
}

# ---- Logging account (CloudTrail S3, Config delivery) ------
provider "aws" {
  alias  = "logging"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.logging_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformSOC-Logging"
  }

  default_tags {
    tags = {
      Project   = "aws-cloud-security-operations-center"
      ManagedBy = "Terraform"
      Portfolio = "enterprise-cloud-platform"
    }
  }
}

# ---- DR / secondary region provider ------------------------
provider "aws" {
  alias  = "dr"
  region = var.dr_region

  default_tags {
    tags = {
      Project   = "aws-cloud-security-operations-center"
      ManagedBy = "Terraform"
      Portfolio = "enterprise-cloud-platform"
    }
  }
}

provider "aws" {
  alias  = "securityhub"
  region = "eu-west-1"
}