data "aws_iam_policy_document" "audit_log" {
  count = var.s3_enabled ? 1 : 0

  override_json = var.audit_log_bucket_custom_policy_json

  statement {
    sid     = "AWSCloudTrailAclCheckForConfig"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.audit[0].arn]
  }

  statement {
    sid     = "AWSCloudTrailWriteForConfig"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [
      "${aws_s3_bucket.audit[0].arn}/config/AWSLogs/${var.aws_account_id}/Config/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "AWSCloudTrailAclCheckForCloudTrail"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.audit[0].arn]
  }
  statement {
    sid     = "AWSCloudTrailWriteForCloudTrail"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [
      "${aws_s3_bucket.audit[0].arn}/cloudtrail/AWSLogs/${var.aws_account_id}/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_log" {
  depends_on = ["aws_s3_bucket_public_access_block.audit"]
  count      = var.s3_enabled ? 1 : 0
  bucket     = aws_s3_bucket.audit[0].id
  policy     = data.aws_iam_policy_document.audit_log[0].json
}

resource "aws_s3_bucket" "access_log" {
  count  = var.s3_enabled ? 1 : 0
  bucket = "${var.resource_name_prefix}-access-logs"
  acl    = "log-delivery-write"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  force_destroy = true
  tags          = var.tags
}

# 2.3 – Ensure the S3 bucket CloudTrail logs to is not publicly accessible
# 2.6 – Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
resource "aws_s3_bucket_public_access_block" "access_log" {
  count = var.s3_enabled ? 1 : 0

  bucket = aws_s3_bucket.access_log[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "audit" {
  count  = var.s3_enabled ? 1 : 0
  bucket = "${var.resource_name_prefix}-audit-logs"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  force_destroy = true

  logging {
    target_bucket = aws_s3_bucket.access_log[0].id
  }

  versioning {
    enabled = true
  }

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count = var.s3_enabled ? 1 : 0

  bucket = aws_s3_bucket.audit[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
