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
  statement {
    sid = "AllowSSLRequestsOnly"
    principals {
      type = "*"
      identifiers = ["*"]
    }
    effect = "Deny"
    actions = ["s3:*"]
    resources = [
      "${aws_s3_bucket.audit[0].arn}/*",
      "${aws_s3_bucket.audit[0].arn}"
    ]
    condition {
      test  = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid = "S3DenyDeletePolicy"
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    effect = "Deny"
    actions = ["s3:DeleteBucket"]
    resources = [aws_s3_bucket.audit[0].arn]
  }
}

resource "aws_s3_bucket_policy" "audit_log" {
  depends_on = [aws_s3_bucket_public_access_block.audit]
  count      = var.s3_enabled ? 1 : 0
  bucket     = aws_s3_bucket.audit[0].id
  policy     = data.aws_iam_policy_document.audit_log[0].json
}

resource "aws_s3_bucket" "access_log" {
  count  = var.s3_enabled ? 1 : 0
  bucket = "${var.resource_name_prefix}-${var.aws_account_id}-access-logs"
  force_destroy = true
  tags          = var.tags
}
resource "aws_s3_bucket_acl" "access_log" {
  count  = var.s3_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_log[0].id
  acl    = "log-delivery-write"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "access_log" {
   count  = var.s3_enabled ? 1 : 0
   bucket = aws_s3_bucket.access_log[0].bucket
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
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
  bucket = "${var.resource_name_prefix}-${var.aws_account_id}-audit-logs"
  force_destroy = true
  tags = var.tags
}

resource "aws_s3_bucket_acl" "audit" {
  count  = var.s3_enabled ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = var.s3_enabled ? 1 : 0
  bucket = aws_s3_bucket.audit[0].bucket
  rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
}
resource "aws_s3_bucket_logging" "audit" {
  bucket = aws_s3_bucket.audit[0].id

  target_bucket = aws_s3_bucket.access_log[0].id
  target_prefix = "log/"
}

  resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit[0].id
  versioning_configuration {
    status = "Enabled"
  }
} 

resource "aws_s3_bucket_public_access_block" "audit" {
  count = var.s3_enabled ? 1 : 0

  bucket = aws_s3_bucket.audit[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "access_log" {
  count  = var.s3_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_log[0].id
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSSLRequestsOnly",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.access_log[0].arn}/*",
                "${aws_s3_bucket.access_log[0].arn}"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        },
        {
            "Sid": "S3DenyDeletePolicy",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "s3:DeleteBucket",
            "Resource": [aws_s3_bucket.access_log[0].arn]
        }
    ]
  })
}