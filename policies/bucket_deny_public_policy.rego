package compliance_framework.bucket_deny_public_policy

import rego.v1

title := "S3 bucket policy should not allow public access"

description := "Amazon S3 buckets should not expose public access through bucket policy."

violation[{"id": "bucket_policy_public_access"}] if {
	data.require_non_public_bucket_policy
	object.get(object.get(input.bucket_context, "current", {}), "is_public", false)
}
