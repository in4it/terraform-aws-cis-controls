resource "aws_cloudwatch_log_group" "cloudtrail_events" {
  name = var.cloudtrail_log_group_name
  tags = var.tags
}

data "aws_iam_policy_document" "cloudtrail_key_policy" {
  policy_id = "Key policy created by CloudTrail"

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
  policy                  = "${var.cloudtrail_kms_policy != "" ? "${var.cloudtrail_kms_policy}" : "${data.aws_iam_policy_document.cloudtrail_key_policy.json}"}"
  tags                    = var.tags
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.resource_name_prefix}-cloudtrail"
  target_key_id = "${aws_kms_key.cloudtrail.key_id}"
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
  name   = "${var.resource_name_prefix}-cloudtrail-cloudwatch-logs"
  role   = aws_iam_role.cloudwatch_delivery.id
  policy = data.aws_iam_policy_document.cloudwatch_delivery_policy.json
}

data "aws_iam_policy_document" "cloudwatch_delivery_policy" {
  statement {
    sid       = "AWSCloudTrailCreateLogStream20141101"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_events.name}:log-stream:*"]
  }
  statement {
    sid       = "AWSCloudTrailPutLogEvents20141101"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_events.name}:log-stream:*"]
  }
}

# 2.1 – Ensure CloudTrail is enabled in all Regions
# 2.2. – Ensure CloudTrail log file validation is enabled
# 2.4 – Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs
# 2.7 – Ensure CloudTrail logs are encrypted at rest using AWS KMS CMKs

resource "aws_cloudtrail" "cloudtrail" {
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_events.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudwatch_delivery.arn
  name                          = "${var.resource_name_prefix}-trail"
  s3_bucket_name                = var.cloudtrail_s3_bucket_name
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

  tags = var.tags
}
