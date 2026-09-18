output "macie_account_id" {
  value = aws_macie2_account.main.id
}

output "sa_id_identifier_id" {
  value = aws_macie2_custom_data_identifier.sa_id_number.id
}
