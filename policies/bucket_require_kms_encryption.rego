package compliance_framework.bucket_require_kms_encryption

import rego.v1

title := "S3 bucket encryption should use AWS KMS for scoped buckets"

description := "Scoped Amazon S3 buckets should use SSE-KMS or DSSE-KMS encryption for stronger key control and auditability."

kms_encryption_required if {
	data.require_kms_encryption_for_all
}

kms_encryption_required if {
	tags := object.get(input.bucket_context, "tags", {})
	some key in data.kms_encryption_required_bucket_tag_keys
	object.get(tags, key, "") != ""
}

violation[{"id": "bucket_kms_encryption_required"}] if {
	kms_encryption_required
	not object.get(object.get(input.bucket_context, "current", {}), "uses_kms", false)
}
