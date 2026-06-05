package compliance_framework.bucket_require_server_access_logging

import rego.v1

title := "S3 bucket server access logging should be enabled for scoped buckets"

description := "Scoped Amazon S3 buckets should enable server access logging so bucket requests can be audited."

risk_templates := [{
	"name": "S3 bucket server access logging is disabled",
	"title": "S3 bucket request logging gap",
	"statement": "The scoped S3 bucket does not have server access logging enabled, reducing visibility into bucket requests and weakening audit and incident investigation coverage.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"violation_ids": ["bucket_server_access_logging_required"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-778",
		"title": "Insufficient Logging",
		"url": "https://cwe.mitre.org/data/definitions/778.html",
	}],
	"remediation": {
		"title": "Enable S3 bucket server access logging",
		"description": "Configure server access logging for the scoped bucket and deliver logs to an approved log archive bucket with appropriate retention.",
		"tasks": [
			{"title": "Create or select an approved S3 log archive bucket"},
			{"title": "Enable server access logging on the source bucket"},
			{"title": "Set a target prefix that identifies the source bucket"},
			{"title": "Re-run policy evaluation to confirm logging is enabled"},
		],
	},
}]

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
