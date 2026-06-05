package compliance_framework.bucket_require_lifecycle_retention

import rego.v1

title := "S3 bucket lifecycle retention should be configured"

description := "Scoped Amazon S3 buckets should define lifecycle retention rules that meet the configured retention requirements."

lifecycle_required if {
	data.require_lifecycle_for_all
}

lifecycle_required if {
	tags := object.get(input.bucket_context, "tags", {})
	some key in data.lifecycle_required_bucket_tag_keys
	object.get(tags, key, "") != ""
}

violation[{"id": "bucket_lifecycle_retention_required"}] if {
	lifecycle_required
	not object.get(object.get(input.bucket_context, "current", {}), "has_lifecycle_rules", false)
}

violation[{"id": "bucket_lifecycle_expiration_too_short"}] if {
	lifecycle_required
	data.minimum_lifecycle_expiration_days > 0
	current := object.get(input.bucket_context, "current", {})
	object.get(current, "has_lifecycle_rules", false)
	expiration_days := object.get(current, "lifecycle_min_expiration_days", 0)
	expiration_days > 0
	expiration_days < data.minimum_lifecycle_expiration_days
}

violation[{"id": "bucket_lifecycle_expiration_missing"}] if {
	lifecycle_required
	data.minimum_lifecycle_expiration_days > 0
	current := object.get(input.bucket_context, "current", {})
	object.get(current, "has_lifecycle_rules", false)
	object.get(current, "lifecycle_min_expiration_days", 0) == 0
}
