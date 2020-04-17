output alarms_sns_topic_arn {
  value = aws_sns_topic.all_cis_alarms[0].arn
}
