# terraform-aws-cis-controls
AWS CIS Controls module for terraform

https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html

### Controls covered:
- 1.1 Avoid the use of the "root" account
- 1.5 Ensure IAM password policy requires at least one uppercase letter 
- 1.6 Ensure IAM password policy requires at least one lowercase letter
- 1.7 Ensure IAM password policy requires at least one symbol 
- 1.8 Ensure IAM password policy requires at least one number 
- 1.9 Ensure IAM password policy requires a minimum length of 14 or greater 1.9
- 1.10 Ensure IAM password policy prevents password reuse 
- 1.11 Ensure IAM password policy expires passwords within 90 days or less 
- 2.1 Ensure CloudTrail is enabled in all Regions
- 2.2 Ensure CloudTrail log file validation is enabled
- 2.4 Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs
- 2.7 Ensure CloudTrail logs are encrypted at rest using AWS KMS CMKs
- 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls
- 3.2 Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA 
- 3.3 Ensure a log metric filter and alarm exist for usage of "root" account
- 3.4 Ensure a log metric filter and alarm exist for IAM policy changes
- 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
- 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
- 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
- 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes
- 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
- 3.10 Ensure a log metric filter and alarm exist for security group changes
- 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
- 3.12 Ensure a log metric filter and alarm exist for changes to network gateways
- 3.13 Ensure a log metric filter and alarm exist for route table changes
- 3.14 Ensure a log metric filter and alarm exist for VPC changes 
