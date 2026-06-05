package compliance_framework.bucket_deny_public_policy_test

import data.compliance_framework.bucket_deny_public_policy
import rego.v1

test_violation_when_bucket_policy_is_public if {
	violations := bucket_deny_public_policy.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"is_public": true}}}
	count(violations) == 1
	violations[{"id": "bucket_policy_public_access"}]
}

test_no_violation_when_bucket_policy_is_not_public if {
	violations := bucket_deny_public_policy.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"is_public": false}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_deny_public_policy.title != ""
	bucket_deny_public_policy.description != ""
}
