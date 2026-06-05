package compliance_framework.bucket_require_replication_for_scoped_buckets_test

import data.compliance_framework.bucket_require_replication_for_scoped_buckets
import rego.v1

test_violation_when_scoped_bucket_replication_is_disabled if {
	violations := bucket_require_replication_for_scoped_buckets.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"replication_enabled": false}, "tags": {"resilience": "true"}}}
	count(violations) == 1
	violations[{"id": "bucket_replication_required"}]
}

test_no_violation_when_scoped_bucket_replication_is_enabled if {
	violations := bucket_require_replication_for_scoped_buckets.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"replication_enabled": true}, "tags": {"resilience": "true"}}}
	count(violations) == 0
}

test_no_violation_when_bucket_is_out_of_scope if {
	violations := bucket_require_replication_for_scoped_buckets.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"current": {"replication_enabled": false}, "tags": {}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_replication_for_scoped_buckets.title != ""
	bucket_require_replication_for_scoped_buckets.description != ""
}
