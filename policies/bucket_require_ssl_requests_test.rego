package compliance_framework.bucket_require_ssl_requests_test

import data.compliance_framework.bucket_require_ssl_requests
import rego.v1

ssl_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

test_no_violation_when_bucket_policy_denies_insecure_transport if {
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"policy": {"raw": ssl_policy}}}
	count(violations) == 0
}

test_violation_when_bucket_policy_does_not_require_ssl if {
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"policy": {"raw": json.marshal({"Statement": []})}}}
	count(violations) == 1
	violations[{"id": "bucket_ssl_requests_required"}]
}

test_violation_when_ssl_deny_statement_only_covers_prefix if {
	prefix_only_policy := json.marshal({"Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "arn:aws:s3:::example/prefix/*",
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}]})
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"policy": {"raw": prefix_only_policy}}}
	count(violations) == 1
	violations[{"id": "bucket_ssl_requests_required"}]
}

test_violation_when_ssl_deny_statement_only_covers_bucket_arn if {
	bucket_only_policy := json.marshal({"Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "arn:aws:s3:::example",
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}]})
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"policy": {"raw": bucket_only_policy}}}
	count(violations) == 1
	violations[{"id": "bucket_ssl_requests_required"}]
}

test_violation_when_bucket_policy_missing if {
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {}}
	count(violations) == 1
	violations[{"id": "bucket_ssl_requests_required"}]
}

test_no_violation_when_ssl_check_disabled if {
	violations := bucket_require_ssl_requests.violation with input as {"bucket": {"name": "example"}, "bucket_context": {}} with data.require_ssl_requests_only as false
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_ssl_requests.title != ""
	bucket_require_ssl_requests.description != ""
}

test_risk_template_maps_to_ssl_violation if {
	template := bucket_require_ssl_requests.risk_templates[0]
	template.violation_ids == ["bucket_ssl_requests_required"]
	template.threat_refs[0].external_id == "CWE-319"
}
