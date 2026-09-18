output "graph_arn" {
  value = aws_detective_graph.main.graph_arn
}

output "graph_created_at" {
  value = aws_detective_graph.main.created_time
}
