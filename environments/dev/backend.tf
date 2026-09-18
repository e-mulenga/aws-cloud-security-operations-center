terraform {
  backend "s3" {
    bucket         = "REPLACE-ME-dev-terraform-state"
    key            = "soc/dev/terraform.tfstate"
    region         = "af-south-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key-dev"
    dynamodb_table = "REPLACE-ME-dev-terraform-state-lock"
  }
}
