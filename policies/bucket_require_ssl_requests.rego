package compliance_framework.bucket_require_ssl_requests

import rego.v1

title := "S3 bucket policy should require SSL requests"

description := "Amazon S3 bucket policies should deny non-SSL requests using the aws:SecureTransport condition."

risk_templates := [{
	"name": "S3 bucket allows non-SSL requests",
	"title": "S3 bucket cleartext transport exposure risk",
	"statement": "The S3 bucket policy does not deny non-SSL requests, increasing the chance that sensitive bucket traffic can be transmitted without TLS protection.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["bucket_ssl_requests_required"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-319",
		"title": "Cleartext Transmission of Sensitive Information",
		"url": "https://cwe.mitre.org/data/definitions/319.html",
	}],
	"remediation": {
		"title": "Deny non-SSL S3 bucket requests",
		"description": "Update the bucket policy to deny requests where aws:SecureTransport is false so bucket access requires TLS-protected transport.",
		"tasks": [
			{"title": "Add a bucket policy deny statement for aws:SecureTransport=false"},
			{"title": "Apply the deny statement to all S3 actions and principals that access the bucket"},
			{"title": "Confirm applications use HTTPS endpoints for S3 requests"},
			{"title": "Re-run policy evaluation to confirm non-SSL requests are denied"},
		],
	},
}]

bucket_policy := json.unmarshal(raw) if {
	raw := object.get(object.get(input.bucket_context, "policy", {}), "raw", "")
	raw != ""
}

bucket_policy_statements contains statement if {
	statement := bucket_policy.Statement[_]
}

bucket_policy_statements contains statement if {
	statement := bucket_policy.Statement
	not is_array(statement)
}

principal_applies_to_all(statement) if {
	object.get(statement, "Principal", "") == "*"
}

principal_applies_to_all(statement) if {
	principal_map := object.get(statement, "Principal", {})
	object.get(principal_map, "AWS", "") == "*"
}

principal_applies_to_all(statement) if {
	principal_map := object.get(statement, "Principal", {})
	principals := object.get(principal_map, "AWS", [])
	some principal in principals
	principal == "*"
}

action_denies_all_s3(statement) if {
	action := object.get(statement, "Action", "")
	is_string(action)
	lower(action) == "s3:*"
}

action_denies_all_s3(statement) if {
	action := object.get(statement, "Action", "")
	is_string(action)
	action == "*"
}

action_denies_all_s3(statement) if {
	actions := object.get(statement, "Action", [])
	some action in actions
	lower(action) == "s3:*"
}

action_denies_all_s3(statement) if {
	actions := object.get(statement, "Action", [])
	some action in actions
	action == "*"
}

secure_transport_false(statement) if {
	bools := object.get(object.get(statement, "Condition", {}), "Bool", {})
	some key, value in bools
	lower(key) == "aws:securetransport"
	value == "false"
}

secure_transport_false(statement) if {
	bools := object.get(object.get(statement, "Condition", {}), "Bool", {})
	some key, value in bools
	lower(key) == "aws:securetransport"
	value == false
}

ssl_requests_required if {
	some statement in bucket_policy_statements
	lower(object.get(statement, "Effect", "")) == "deny"
	principal_applies_to_all(statement)
	action_denies_all_s3(statement)
	secure_transport_false(statement)
}

violation[{"id": "bucket_ssl_requests_required"}] if {
	data.require_ssl_requests_only
	not ssl_requests_required
}
