package compliance_framework.bucket_require_encryption

import rego.v1

title := "S3 bucket encryption should be enabled"

description := "Amazon S3 buckets should enforce server-side encryption at rest."

violation[{"id": "bucket_encryption_required"}] if {
	data.require_bucket_encryption
	not object.get(object.get(input.bucket_context, "current", {}), "encryption_enabled", false)
}
