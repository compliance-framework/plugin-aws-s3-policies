package compliance_framework.bucket_require_server_access_logging_test

import data.compliance_framework.bucket_require_server_access_logging
import rego.v1

test_violation_when_scoped_bucket_logging_is_disabled if {
	violations := bucket_require_server_access_logging.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"logging_enabled": false}, "tags": {"log_archive": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_server_access_logging_required"}]
}

test_no_violation_when_scoped_bucket_logging_is_enabled if {
	violations := bucket_require_server_access_logging.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"logging_enabled": true}, "tags": {"log_archive": "true"}}}
	count(violations) == 0
}

test_no_violation_when_bucket_is_out_of_scope if {
	violations := bucket_require_server_access_logging.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"logging_enabled": false}, "tags": {}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_server_access_logging.title != ""
	bucket_require_server_access_logging.description != ""
}

test_risk_template_maps_to_server_access_logging_violation if {
	template := bucket_require_server_access_logging.risk_templates[0]
	template.violation_ids == ["bucket_server_access_logging_required"]
	template.threat_refs[0].external_id == "CWE-778"
}
