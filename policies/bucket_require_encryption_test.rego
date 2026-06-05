package compliance_framework.bucket_require_encryption_test

import data.compliance_framework.bucket_require_encryption
import rego.v1

test_violation_missing_bucket_encryption if {
	violations := bucket_require_encryption.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"encryption_enabled": false}}}
	count(violations) == 1
	violations[{"id": "bucket_encryption_required"}]
}

test_no_violation_when_bucket_encryption_enabled if {
	violations := bucket_require_encryption.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"encryption_enabled": true}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_encryption.title != ""
	bucket_require_encryption.description != ""
}
