package compliance_framework.bucket_require_acls_disabled

import rego.v1

title := "S3 bucket ACLs should be disabled"

description := "Amazon S3 buckets should use Object Ownership bucket owner enforced mode so ACLs are disabled."

violation[{"id": "bucket_acls_disabled_required"}] if {
	data.require_acls_disabled
	not object.get(object.get(input.bucket_context, "current", {}), "ownership_enforced", false)
}
