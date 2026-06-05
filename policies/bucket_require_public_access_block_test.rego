package compliance_framework.bucket_require_public_access_block_test

import data.compliance_framework.bucket_require_public_access_block
import rego.v1

test_violation_when_any_public_access_block_setting_missing if {
	violations := bucket_require_public_access_block.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"public_access_block": {"block_public_acls": true, "ignore_public_acls": true, "block_public_policy": false, "restrict_public_buckets": true}}}
	count(violations) == 1
	violations[{"id": "bucket_public_access_block_required"}]
}

test_no_violation_when_all_public_access_block_settings_enabled if {
	violations := bucket_require_public_access_block.violation with input as {"bucket": {"name": "example"}, "bucket_context": {"public_access_block": {"block_public_acls": true, "ignore_public_acls": true, "block_public_policy": true, "restrict_public_buckets": true}}}
	count(violations) == 0
}

test_policy_result_metadata_present if {
	bucket_require_public_access_block.title != ""
	bucket_require_public_access_block.description != ""
}

test_risk_template_maps_to_public_access_block_violation if {
	template := bucket_require_public_access_block.risk_templates[0]
	template.violation_ids == ["bucket_public_access_block_required"]
	template.threat_refs[0].external_id == "CWE-732"
}
