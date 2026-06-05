package compliance_framework.bucket_require_replication_for_scoped_buckets

import rego.v1

title := "S3 bucket replication should be enabled for scoped buckets"

description := "Scoped Amazon S3 buckets should enable replication where resilience or durable evidence storage is required."

replication_required if {
	data.require_replication_for_all
}

replication_required if {
	tags := object.get(input.bucket_context, "tags", {})
	some key in data.replication_required_bucket_tag_keys
	object.get(tags, key, "") != ""
}

violation[{"id": "bucket_replication_required"}] if {
	replication_required
	not object.get(object.get(input.bucket_context, "current", {}), "replication_enabled", false)
}
