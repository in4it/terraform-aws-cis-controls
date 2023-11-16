resource "aws_cloudwatch_log_group" "cloudtrail_events" {
  count      = var.cw_log_enabled ? 1 : 0
  name       = var.cloudtrail_log_group_name
  kms_key_id = var.cloudwatch_logs_kms
  tags       = var.tags
}

data "aws_iam_policy_document" "cloudtrail_key_policy" {
  policy_id     = "Key policy created by CloudTrail"
  override_json = var.cloudtrail_kms_policy

  statement {
    sid = "Enable IAM User Permissions"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${var.aws_account_id}:root"
      ]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "Allow CloudTrail to encrypt logs"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.aws_account_id}:trail/*"]
    }
  }

  statement {
    sid = "Allow CloudTrail to describe key"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  statement {
    sid = "Allow principals in the account to decrypt log files"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = ["${var.aws_account_id}"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.aws_account_id}:trail/*"]
    }
  }

  statement {
    sid = "Allow alias creation during setup"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = ["${var.aws_account_id}"]
    }
  }

  statement {
    sid = "Enable cross account log decryption"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = ["${var.aws_account_id}"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.aws_account_id}:trail/*"]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "Encrypt/Decrypt cloudtrail logs"
  deletion_window_in_days = 30
  is_enabled              = true
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_key_policy.json
  tags                    = var.tags
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.resource_name_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

data "aws_iam_policy_document" "cloudwatch_delivery_assume_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cloudwatch_delivery" {
  name               = "${var.resource_name_prefix}-cloudtrail-cloudwatch-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_delivery_assume_policy.json

  tags = var.tags
}

resource "aws_iam_role_policy" "cloudwatch_delivery_policy" {
  count  = var.cw_log_enabled ? 1 : 0
  name   = "${var.resource_name_prefix}-cloudtrail-cloudwatch-logs"
  role   = aws_iam_role.cloudwatch_delivery.id
  policy = data.aws_iam_policy_document.cloudwatch_delivery_policy[0].json
}

data "aws_iam_policy_document" "cloudwatch_delivery_policy" {
  count = var.cw_log_enabled ? 1 : 0
  statement {
    sid       = "AWSCloudTrailCreateLogStream20141101"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_events[0].name}:log-stream:*"]
  }
  statement {
    sid       = "AWSCloudTrailPutLogEvents20141101"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_events[0].name}:log-stream:*"]
  }
}

# 2.1 – Ensure CloudTrail is enabled in all Regions
# 2.2. – Ensure CloudTrail log file validation is enabled
# 2.4 – Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs
# 2.7 – Ensure CloudTrail logs are encrypted at rest using AWS KMS CMKs

resource "aws_cloudtrail" "cloudtrail" {
  cloud_watch_logs_group_arn    = var.cw_log_enabled ? "${aws_cloudwatch_log_group.cloudtrail_events[0].arn}:*" : ""
  cloud_watch_logs_role_arn     = var.cw_log_enabled ? aws_iam_role.cloudwatch_delivery.arn : ""
  name                          = "${var.resource_name_prefix}-trail"
  s3_key_prefix                 = "cloudtrail"
  s3_bucket_name                = aws_s3_bucket.audit[0].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = var.clodtrail_event_selector_type
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }
  depends_on = [
    aws_s3_bucket_policy.audit_log[0],
    aws_s3_bucket_public_access_block.audit[0]
  ]
  tags = var.tags
}
