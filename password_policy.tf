#https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html

resource "aws_iam_account_password_policy" "cis" {
  #1.5 – Ensure IAM password policy requires at least one uppercase letter 
  require_uppercase_characters = var.iam_require_uppercase_characters

  #1.6 – Ensure IAM password policy requires at least one lowercase letter
  require_lowercase_characters = var.iam_require_lowercase_characters

  # 1.7 – Ensure IAM password policy requires at least one symbol 
  require_symbols = var.iam_require_symbols

  # 1.8 – Ensure IAM password policy requires at least one number 
  require_numbers = var.iam_require_numbers

  # 1.9 – Ensure IAM password policy requires a minimum length of 14 or greater 1.9
  minimum_password_length = var.iam_minimum_password_length

  # 1.10 – Ensure IAM password policy prevents password reuse 
  password_reuse_prevention = var.iam_password_reuse_prevention

  # 1.11 – Ensure IAM password policy expires passwords within 90 days or less 
  max_password_age = var.iam_max_password_age

  allow_users_to_change_password = var.iam_allow_users_to_change_password

  hard_expiry = var.iam_hard_expiry
}
