variable "organization_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "member_account_ids" {
  type    = list(string)
  default = []
}