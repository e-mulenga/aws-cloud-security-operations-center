# ============================================================
# Module: detective — Amazon Detective
# ============================================================
# Provisions a Detective behaviour graph for investigation
# of Security Hub and GuardDuty findings. Member accounts
# are invited to contribute data to the graph.

resource "aws_detective_graph" "main" {
  tags = { Name = "${var.organization_name}-${var.environment}-detective-graph" }
}

resource "aws_detective_member" "members" {
  for_each                   = toset(var.member_account_ids)
  account_id                 = each.value
  email_address              = "placeholder-${each.value}@example.com" # Overridden by actual member account email
  graph_arn                  = aws_detective_graph.main.graph_arn
  message                    = "Invitation from ${var.organization_name} SOC to join Amazon Detective behaviour graph."
  disable_email_notification = false
}
