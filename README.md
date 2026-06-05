# AWS S3 policies

Standalone OPA/Rego policy bundle for S3 bucket evidence emitted by the plugin-aws-s3 collector.

## Input schema

Each policy evaluates one S3 bucket at a time using:

- input.bucket
- input.bucket_context

Current bucket context includes the current bucket summary, bucket home region, tags, encryption settings, public access block settings, bucket policy details, policy public status, ownership controls, versioning, object lock, lifecycle rules, replication, logging, and website hosting configuration.

## Current coverage

This bundle currently checks S3 bucket posture such as:

- bucket policy must not allow public access
- server-side bucket encryption must be enabled
- all bucket public access block settings must be enabled
- versioning must be enabled for all buckets when required, or for buckets with configured tag keys
- lifecycle retention rules must exist where required
- lifecycle expiration must meet the configured minimum day threshold

## Policy data

Default baselines live in policies/data.json and can be overridden by agent-supplied policy data. Current settings cover:

- require_bucket_encryption
- require_public_access_block
- require_non_public_bucket_policy
- require_bucket_versioning_for_all
- versioning_required_bucket_tag_keys
- require_lifecycle_for_all
- lifecycle_required_bucket_tag_keys
- minimum_lifecycle_expiration_days

The policy data values are expected at the root of data.json and are referenced directly as data.<setting> in Rego.

## Testing

Run local checks with:

~~~shell
opa check policies
opa test policies
~~~

Or use the Makefile wrappers:

~~~shell
make validate
make test
~~~

## Bundling

Build the distributable bundle with:

~~~shell
make build
~~~

This writes dist/bundle.tar.gz.
