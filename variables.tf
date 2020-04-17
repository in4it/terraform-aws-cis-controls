variable "resource_name_prefix" {
  description = "All the resources will be prefixed with this varible"
  default     = "aws-cis"
}

# SNS
variable sns_arn {
  description = "SNS for CIS notifications"
}

# S3
variable s3_enabled {
  default = true
}

variable audit_log_bucket_custom_policy_json {
  default = ""
}

# AWS Config
variable config_enabled {
  default = true
}

variable config_s3_bucket_name {
  default = ""
}

variable include_global_resource_types {
  default = true
}

# CloudTrail
variable cloudtrail_log_group_name {
  description = "CloudTrail LogGroup name"
}

variable "clodtrail_event_selector_type" {
  description = "Log type for event selectors"
  default     = "All"
}

variable "cloudtrail_s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  default     = ""
}

variable aws_account_id {
  description = "AWS Account ID"
}

variable region {
  description = "AWS region"
}

variable cloudtrail_kms_policy {
  description = "KMS policy for Cloudtrail logs."
  default     = ""
}

# Alerting
variable alerting_enabled {
  description = "Enable alerting"
  default     = true
}

variable alarm_namespace {
  description = "Alarm metric namespace"
  default     = "CISBenchmark"
}

variable tags {
  default = {
    "key"   = "AWS_CIS_Benchmark"
    "value" = "1.2.0"
  }
}

# Password Policy
variable "iam_allow_users_to_change_password" {
  description = "Can users change their own password"
  default     = true
}

variable "iam_hard_expiry" {
  description = "Everyone needs hard reset for expired passwords"
  default     = true
}

variable "iam_require_uppercase_characters" {
  description = "Require at least one uppercase letter in passwords"
  default     = true
}

variable "iam_require_lowercase_characters" {
  description = "Require at least one lowercase letter in passwords"
  default     = true
}

variable "iam_require_symbols" {
  description = "Require at least one symbol in passwords"
  default     = true
}

variable "iam_require_numbers" {
  description = "Require at least one number in passwords"
  default     = true
}

variable "iam_minimum_password_length" {
  description = "Require minimum lenght of password"
  default     = 14
}

variable "iam_password_reuse_prevention" {
  description = "Prevent password reuse N times"
  default     = 24
}

variable "iam_max_password_age" {
  description = "Passwords expire in N days"
  default     = 90
}
