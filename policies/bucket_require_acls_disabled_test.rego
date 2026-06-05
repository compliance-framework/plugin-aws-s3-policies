package compliance_framework.bucket_require_acls_disabled_test

import data.compliance_framework.bucket_require_acls_disabled
import rego.v1

test_violation_when_acls_are_not_disabled if {
	violations := bucket_require_acls_disabled.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"ownership_enforced": false}}}
	count(violations) == 1
	violations[{"id": "bucket_acls_disabled_required"}]
}

test_no_violation_when_acls_are_disabled if {
	violations := bucket_require_acls_disabled.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"ownership_enforced": true}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_acls_disabled.title != ""
	bucket_require_acls_disabled.description != ""
}
