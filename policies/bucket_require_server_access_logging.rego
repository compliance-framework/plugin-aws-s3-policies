package compliance_framework.bucket_require_server_access_logging

import rego.v1

title := "S3 bucket server access logging should be enabled for scoped buckets"

description := "Scoped Amazon S3 buckets should enable server access logging so bucket requests can be audited."

server_access_logging_required if {
	data.require_server_access_logging_for_all
}

server_access_logging_required if {
	tags := object.get(input.bucket_context, "tags", {})
	some key in data.server_access_logging_required_bucket_tag_keys
	object.get(tags, key, "") != ""
}

violation[{"id": "bucket_server_access_logging_required"}] if {
	server_access_logging_required
	not object.get(object.get(input.bucket_context, "current", {}), "logging_enabled", false)
}
