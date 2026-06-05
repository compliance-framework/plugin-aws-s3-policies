package compliance_framework.bucket_require_public_access_block

import rego.v1

title := "S3 bucket public access block should be enabled"

description := "Amazon S3 buckets should enable all public access block settings."

risk_templates := [{
	"name": "S3 bucket public access block is incomplete",
	"title": "S3 bucket public access guardrail gap",
	"statement": "The S3 bucket does not enable every public access block setting, increasing the chance that ACL or bucket policy changes can expose bucket contents beyond intended principals.",
	"likelihood_hint": "high",
	"impact_hint": "high",
	"violation_ids": ["bucket_public_access_block_required"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-732",
		"title": "Incorrect Permission Assignment for Critical Resource",
		"url": "https://cwe.mitre.org/data/definitions/732.html",
	}],
	"remediation": {
		"title": "Enable all S3 bucket public access block settings",
		"description": "Configure the bucket public access block so public ACLs and public bucket policies are blocked and restricted according to policy.",
		"tasks": [
			{"title": "Enable BlockPublicAcls for the bucket"},
			{"title": "Enable IgnorePublicAcls for the bucket"},
			{"title": "Enable BlockPublicPolicy for the bucket"},
			{"title": "Enable RestrictPublicBuckets for the bucket"},
		],
	},
}]

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
