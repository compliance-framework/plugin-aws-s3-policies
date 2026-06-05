package compliance_framework.bucket_require_lifecycle_retention_test

import data.compliance_framework.bucket_require_lifecycle_retention
import rego.v1

test_violation_when_scoped_bucket_has_no_lifecycle_rules if {
	violations := bucket_require_lifecycle_retention.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"has_lifecycle_rules": false, "lifecycle_min_expiration_days": 0}, "tags": {"privacy": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_lifecycle_retention_required"}]
}

test_violation_when_scoped_bucket_lifecycle_expiration_is_too_short if {
	violations := bucket_require_lifecycle_retention.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"has_lifecycle_rules": true, "lifecycle_min_expiration_days": 7}, "tags": {"privacy": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_lifecycle_expiration_too_short"}]
}

test_violation_when_scoped_bucket_lifecycle_expiration_is_missing if {
	violations := bucket_require_lifecycle_retention.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"has_lifecycle_rules": true, "lifecycle_min_expiration_days": 0}, "tags": {"privacy": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_lifecycle_expiration_missing"}]
}

test_no_violation_when_scoped_bucket_meets_minimum_lifecycle_days if {
	violations := bucket_require_lifecycle_retention.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"has_lifecycle_rules": true, "lifecycle_min_expiration_days": 90}, "tags": {"privacy": "true"}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_lifecycle_retention.title != ""
	bucket_require_lifecycle_retention.description != ""
}
