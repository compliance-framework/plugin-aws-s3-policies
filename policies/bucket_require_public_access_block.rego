package compliance_framework.bucket_require_public_access_block

import rego.v1

title := "S3 bucket public access block should be enabled"

description := "Amazon S3 buckets should enable all public access block settings."

all_public_access_block_settings_enabled if {
	pab := object.get(input.bucket_context, "public_access_block", {})
	object.get(pab, "block_public_acls", false)
	object.get(pab, "ignore_public_acls", false)
	object.get(pab, "block_public_policy", false)
	object.get(pab, "restrict_public_buckets", false)
}

violation[{"id": "bucket_public_access_block_required"}] if {
	data.require_public_access_block
	not all_public_access_block_settings_enabled
}
