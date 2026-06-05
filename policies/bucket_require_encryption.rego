package compliance_framework.bucket_require_encryption

import rego.v1

title := "S3 bucket encryption should be enabled"

description := "Amazon S3 buckets should enforce server-side encryption at rest."

risk_templates := [{
	"name": "S3 bucket encryption is not enabled",
	"title": "S3 bucket encryption-at-rest gap",
	"statement": "The S3 bucket does not enforce server-side encryption at rest, increasing the chance that sensitive bucket contents could be exposed if storage access controls are bypassed or misconfigured.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["bucket_encryption_required"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-312",
		"title": "Cleartext Storage of Sensitive Information",
		"url": "https://cwe.mitre.org/data/definitions/312.html",
	}],
	"remediation": {
		"title": "Enable S3 bucket server-side encryption",
		"description": "Configure default server-side encryption for the bucket so objects are encrypted at rest with an approved AWS-managed or customer-managed key.",
		"tasks": [
			{"title": "Enable default server-side encryption on the bucket"},
			{"title": "Use an approved SSE-S3 or SSE-KMS encryption configuration"},
			{"title": "Review application uploads that override bucket encryption defaults"},
			{"title": "Re-run policy evaluation to confirm encryption is enabled"},
		],
	},
}]

violation[{"id": "bucket_encryption_required"}] if {
	data.require_bucket_encryption
	not object.get(object.get(input.bucket_context, "current", {}), "encryption_enabled", false)
}
