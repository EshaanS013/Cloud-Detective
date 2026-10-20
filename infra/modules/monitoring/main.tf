locals {
  lambda_functions = {
    collector = var.collector_function_name
    responder = var.responder_function_name
  }
  dead_letter_queues = {
    events    = var.event_dlq_name
    responses = var.response_dlq_name
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.lambda_functions

  alarm_name          = "${var.name_prefix}-${each.key}-errors"
  alarm_description   = "${each.key} Lambda reported errors in two of the last three minutes"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
  ok_actions          = [var.alert_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dead_letter_queue" {
  for_each = local.dead_letter_queues

  alarm_name          = "${var.name_prefix}-${each.key}-dlq"
  alarm_description   = "Messages are waiting in the ${each.key} dead-letter queue"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
  ok_actions          = [var.alert_topic_arn]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name_prefix
  dashboard_body = jsonencode({
    start          = "-PT8H"
    periodOverride = "inherit"
    widgets = [
      {
        type       = "text", x = 0, y = 0, width = 24, height = 2
        properties = { markdown = "# Cloud Detective\nControl-plane detection and response health" }
      },
      {
        type = "metric", x = 0, y = 2, width = 12, height = 6
        properties = {
          title = "Lambda invocations and errors", region = var.aws_region, period = 60, stat = "Sum"
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", var.collector_function_name, { label = "Collector invocations" }],
            [".", "Errors", ".", ".", { label = "Collector errors" }],
            ["AWS/Lambda", "Invocations", "FunctionName", var.responder_function_name, { label = "Responder invocations" }],
            [".", "Errors", ".", ".", { label = "Responder errors" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 2, width = 12, height = 6
        properties = {
          title = "Dead-letter queues", region = var.aws_region, period = 60, stat = "Maximum"
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.event_dlq_name, { label = "Event DLQ" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.response_dlq_name, { label = "Response DLQ" }]
          ]
        }
      },
      {
        type = "log", x = 0, y = 8, width = 12, height = 7
        properties = {
          title = "API errors", region = var.aws_region, view = "table"
          query = "SOURCE '${var.api_log_group_name}' | fields @timestamp, @message | filter @message like /ERROR|Exception/ | sort @timestamp desc | limit 50"
        }
      },
      {
        type = "log", x = 12, y = 8, width = 12, height = 7
        properties = {
          title = "Worker errors", region = var.aws_region, view = "table"
          query = "SOURCE '${var.worker_log_group_name}' | fields @timestamp, @message | filter @message like /ERROR|Exception/ | sort @timestamp desc | limit 50"
        }
      }
    ]
  })
}
