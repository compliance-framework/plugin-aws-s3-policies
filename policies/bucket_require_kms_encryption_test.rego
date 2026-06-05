package compliance_framework.bucket_require_kms_encryption_test

import data.compliance_framework.bucket_require_kms_encryption
import rego.v1

test_violation_when_scoped_bucket_does_not_use_kms if {
	violations := bucket_require_kms_encryption.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"uses_kms": false}, "tags": {"confidential": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_kms_encryption_required"}]
}

test_no_violation_when_scoped_bucket_uses_kms if {
	violations := bucket_require_kms_encryption.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"uses_kms": true}, "tags": {"confidential": "true"}}}
	count(violations) == 0
}

test_no_violation_when_bucket_is_out_of_scope if {
	violations := bucket_require_kms_encryption.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"uses_kms": false}, "tags": {}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_kms_encryption.title != ""
	bucket_require_kms_encryption.description != ""
}
