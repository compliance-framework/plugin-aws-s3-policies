package compliance_framework.bucket_require_acls_disabled

import rego.v1

title := "S3 bucket ACLs should be disabled"

description := "Amazon S3 buckets should use Object Ownership bucket owner enforced mode so ACLs are disabled."

risk_templates := [{
	"name": "S3 bucket ACLs are not disabled",
	"title": "S3 bucket ACL permission exposure risk",
	"statement": "The S3 bucket does not enforce Object Ownership bucket owner enforced mode, leaving ACL-based permissions available and increasing the chance of unintended access grants.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["bucket_acls_disabled_required"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-732",
		"title": "Incorrect Permission Assignment for Critical Resource",
		"url": "https://cwe.mitre.org/data/definitions/732.html",
	}],
	"remediation": {
		"title": "Disable S3 bucket ACLs",
		"description": "Configure S3 Object Ownership to bucket owner enforced so ACLs are disabled and access is controlled through IAM and bucket policies.",
		"tasks": [
			{"title": "Review existing ACL dependencies for the bucket"},
			{"title": "Set Object Ownership to bucket owner enforced"},
			{"title": "Move required grants to IAM or bucket policy controls"},
			{"title": "Re-run policy evaluation to confirm ACLs are disabled"},
		],
	},
}]

violation[{"id": "bucket_acls_disabled_required"}] if {
	data.require_acls_disabled
	not object.get(object.get(input.bucket_context, "current", {}), "ownership_enforced", false)
}
