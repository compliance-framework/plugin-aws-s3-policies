package compliance_framework.bucket_require_versioning_for_scoped_buckets

import rego.v1

title := "S3 bucket versioning should be enabled for scoped buckets"

description := "Scoped Amazon S3 buckets should keep versioning enabled."

versioning_required if {
	data.require_bucket_versioning_for_all
}

versioning_required if {
	tags := object.get(input.bucket_context, "tags", {})
	some key in data.versioning_required_bucket_tag_keys
	object.get(tags, key, "") != ""
}

violation[{"id": "bucket_versioning_required"}] if {
	versioning_required
	not object.get(object.get(input.bucket_context, "current", {}), "is_versioned", false)
}
