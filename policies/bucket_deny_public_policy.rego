package compliance_framework.bucket_deny_public_policy

import rego.v1

title := "S3 bucket policy should not allow public access"

description := "Amazon S3 buckets should not expose public access through bucket policy."

risk_templates := [{
	"name": "S3 bucket policy allows public access",
	"title": "S3 bucket policy public exposure risk",
	"statement": "The S3 bucket policy allows public access, increasing the chance that bucket contents can be read or modified by unintended actors.",
	"likelihood_hint": "high",
	"impact_hint": "high",
	"violation_ids": ["bucket_policy_public_access"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-732",
		"title": "Incorrect Permission Assignment for Critical Resource",
		"url": "https://cwe.mitre.org/data/definitions/732.html",
	}],
	"remediation": {
		"title": "Remove public access from the S3 bucket policy",
		"description": "Update the bucket policy so access is granted only to intended AWS principals and does not allow public or anonymous access.",
		"tasks": [
			{"title": "Review bucket policy statements that allow public principals"},
			{"title": "Remove or constrain public principals with least-privilege conditions"},
			{"title": "Confirm required application access is still granted to named principals"},
			{"title": "Re-run policy evaluation to confirm the bucket policy is no longer public"},
		],
	},
}]

violation[{"id": "bucket_policy_public_access"}] if {
	data.require_non_public_bucket_policy
	object.get(object.get(input.bucket_context, "current", {}), "is_public", false)
}
