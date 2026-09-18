output "athena_workgroup_name" { value = aws_athena_workgroup.soc.name }
output "athena_workgroup_arn" { value = aws_athena_workgroup.soc.arn }
output "glue_database_name" { value = aws_glue_catalog_database.cloudtrail.name }
output "glue_crawler_name" { value = aws_glue_crawler.cloudtrail.name }
output "athena_results_bucket" { value = aws_s3_bucket.athena_results.bucket }
