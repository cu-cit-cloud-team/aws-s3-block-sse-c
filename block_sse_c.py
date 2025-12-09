#!/usr/bin/env python3
"""
Block SSE-C encryption for target S3 buckets.
Reads targets.json and blocks SSE-C for buckets where "target" = True.
"""

import json
import argparse
import boto3
from botocore.exceptions import ClientError

def block_sse_c_for_bucket(s3_client, bucket_name):
    """
    Block SSE-C encryption for a specific bucket by adding BlockedEncryptionTypes
    to existing bucket encryption configuration.
    Preserves existing encryption rules and only adds SSE-C to blocked types.
    """
    try:
        # Get existing bucket encryption configuration
        print("  → Fetching existing encryption configuration...")
        try:
            response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            print(f"  → Found {len(rules)} existing encryption rule(s)")
            for i, rule in enumerate(rules, 1):
                algo = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'N/A')
                bucket_key = rule.get('BucketKeyEnabled', 'N/A')
                blocked = rule.get('BlockedEncryptionTypes', {}).get('EncryptionType', [])
                print(f"     Rule {i}: Algorithm={algo}, BucketKey={bucket_key}, Blocked={blocked}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                # No encryption configured, create default with SSE-S3
                print("  → No existing encryption configuration found")
                print("  → Creating default SSE-S3 encryption rule")
                rules = [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': False
                    }
                ]
            else:
                raise
        # Add BlockedEncryptionTypes to each rule (or update if already exists)
        print("  → Adding SSE-C to blocked encryption types...")
        for i, rule in enumerate(rules, 1):
            if 'BlockedEncryptionTypes' not in rule:
                print(f"     Rule {i}: No BlockedEncryptionTypes found, creating new")
                rule['BlockedEncryptionTypes'] = {'EncryptionType': []}
            # Add SSE-C if not already in the list
            encryption_types = rule['BlockedEncryptionTypes'].get('EncryptionType', [])
            if 'SSE-C' not in encryption_types:
                encryption_types.append('SSE-C')
                rule['BlockedEncryptionTypes']['EncryptionType'] = encryption_types
                print(f"     Rule {i}: Added SSE-C to blocked types")
            else:
                print(f"     Rule {i}: SSE-C already in blocked types")
        # Apply the updated configuration
        print("  → Applying updated encryption configuration...")
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': rules
            }
        )
        print("  → Configuration applied successfully")
        return {'success': True, 'message': 'SSE-C blocked successfully'}
    except ClientError as e:
        print(f"  → ClientError: {e.response['Error']['Code']}")
        return {
            'success': False,
            'error': str(e),
            'error_code': e.response['Error']['Code'] if hasattr(e, 'response') else 'Unknown'
        }
    except Exception as e:
        print(f"  → Unexpected error: {type(e).__name__}: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'error_code': 'UnexpectedError'
        }

def main():
    """
    Block SSE-C encryption for S3 buckets marked as targets.
    
    Reads a JSON file containing bucket information and applies SSE-C blocking
    to buckets where "target" is True and SSE-C is not already blocked.
    Preserves existing encryption configurations while adding SSE-C to the
    blocked encryption types list.
    
    Returns:
        int: 0 on success, 1 on error
    """
    parser = argparse.ArgumentParser(
        description="Block SSE-C encryption for target S3 buckets")
    parser.add_argument("--output", "-o", default="block_sse_c_results.json",
                        help="Output JSON filename (default: block_sse_c_results.json)")
    parser.add_argument("--input", "-i", default="buckets.json",
                        help="Input JSON filename (default: buckets.json)")
    args = parser.parse_args()

    # Read targets.json
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {args.input} not found")
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}")
        return 1
    # Initialize S3 client
    s3_client = boto3.client('s3')
    # Process buckets
    target_buckets = data.get('buckets', [])
    print(f"Found {len(target_buckets)} buckets in file ...")
    print("=" * 80)
    results = []
    for bucket in target_buckets:
        bucket_name = bucket['name']
        region = bucket['region']
        print(f"\nProcessing bucket: {bucket_name} (region: {region})")
        if bucket.get('target') is not True:
            print("  ℹ️  Bucket not marked as target, skipping")
            results.append({
                'bucket': bucket_name,
                'region': region,
                'action': 'skipped',
                'reason': 'not_target'
            })
            continue

        # Skip if already blocked
        if bucket.get('sse_c_blocked') is True:
            print("  ℹ️  SSE-C already blocked, skipping")
            results.append({
                'bucket': bucket_name,
                'region': region,
                'action': 'skipped',
                'reason': 'already_blocked'
            })
            continue
        # Block SSE-C
        result = block_sse_c_for_bucket(s3_client, bucket_name)
        if result['success']:
            print("  ✓ Successfully blocked SSE-C")
            results.append({
                'bucket': bucket_name,
                'region': region,
                'action': 'blocked',
                'status': 'success'
            })
        else:
            print(f"  ✗ Failed to block SSE-C: {result.get('error_code', 'Unknown')}")
            print(f"     {result.get('error', 'No error details')}")
            results.append({
                'bucket': bucket_name,
                'region': region,
                'action': 'failed',
                'error_code': result.get('error_code'),
                'error': result.get('error')
            })
    print("\n" + "=" * 80)
    print("Summary:")
    print(f"  Total target buckets: {len(target_buckets)}")
    print(f"  Successfully blocked: {sum(1 for r in results if r['action'] == 'blocked')}")
    print(f"  Skipped (already blocked): {sum(1 for r in results if r['action'] == 'skipped')}")
    print(f"  Failed: {sum(1 for r in results if r['action'] == 'failed')}")
    # Write results to file
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results written to: {args.output}")
    return 0

if __name__ == "__main__":
    exit(main())
