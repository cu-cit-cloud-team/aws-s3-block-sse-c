#!/usr/bin/env python3
"""
List all S3 buckets and their tags. Optionally scope to buckets in a specific region.
Output in JSON format.
"""

import json
import sys
import argparse
import boto3
from botocore.exceptions import ClientError


def get_bucket_region(s3_client, bucket_name):
    """Get the region where the bucket is located."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        # None means us-east-1
        location = response.get('LocationConstraint')
        return 'us-east-1' if location is None else location
    except ClientError as e:
        print(f"Error getting region for bucket {bucket_name}: {e}", file=sys.stderr)
        return None


def get_bucket_tags(s3_client, bucket_name):
    """Get tags for a specific bucket."""
    try:
        response = s3_client.get_bucket_tagging(Bucket=bucket_name)
        return response.get('TagSet', [])
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchTagSet':
            return []
        else:
            print(f"Error getting tags for bucket {bucket_name}: {e}", file=sys.stderr)
            return None


def is_sse_c_blocked(s3_client, bucket_name):
    """Check if SSE-C encryption method is blocked for the bucket.

    Checks the BlockedEncryptionTypes.EncryptionTypes list to see if SSE-C is blocked.
    """
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get(
            'ServerSideEncryptionConfiguration', {}).get('Rules', [])

        # Check if SSE-C is in the blocked encryption types
        for rule in rules:
            blocked_types = rule.get(
                'BlockedEncryptionTypes', {}).get('EncryptionType', [])
            if 'SSE-C' in blocked_types:
                return True

        return False

    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            # No default encryption configured, SSE-C is not blocked
            return False
        else:
            # Unable to determine, return None
            return None
    except Exception:
        # Unexpected error
        return None


def main():
    """
    List all S3 buckets with their tags, regions, and SSE-C blocking status.

    Scans S3 buckets and outputs their metadata to a JSON file. Optionally filters
    buckets by region. For each bucket, retrieves its region, tags, creation date,
    and whether SSE-C encryption is blocked.

    Returns:
        int: 0 on success, 1 on error
    """
    parser = argparse.ArgumentParser(
        description="List S3 buckets and their tags to JSON")
    parser.add_argument("--output", "-o", default="buckets.json",
                        help="Output JSON filename (default: buckets.json)")
    parser.add_argument(
        "--region", "-r", help="Optional AWS region to scope bucket scan (e.g., us-east-1)")
    args = parser.parse_args()

    # Target regions - either specified region or None (all regions)
    target_regions = [args.region] if args.region else None

    # Initialize S3 client
    s3_client = boto3.client('s3')

    # Output structure
    output = {
        'target_regions': target_regions,
        'buckets': [],
        'summary': {
            'total_buckets_in_target_regions': 0,
            'total_buckets_scanned': 0
        }
    }

    try:
        # List all buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        output['summary']['total_buckets_scanned'] = len(buckets)

        # Filter buckets by region and collect data
        for bucket in buckets:
            bucket_name = bucket['Name']

            # Get bucket region
            region = get_bucket_region(s3_client, bucket_name)

            # Skip if not in target regions (when region filter is specified)
            if target_regions is not None and region not in target_regions:
                continue

            output['summary']['total_buckets_in_target_regions'] += 1

            # Get bucket tags
            tags = get_bucket_tags(s3_client, bucket_name)

            # Check if SSE-C is blocked
            sse_c_blocked = is_sse_c_blocked(s3_client, bucket_name)

            # Build bucket data
            bucket_data = {
                'name': bucket_name,
                'region': region,
                'creation_date': bucket['CreationDate'].isoformat(),
                'sse_c_blocked': sse_c_blocked,
                'tags': {},

                # Optionally, add a boolean expression of your choice to automatically determine
                # whether this bucket should be targeted for SSE-C restriction.
                'target': True
            }

            # Convert tag list to dictionary
            if tags:
                for tag in tags:
                    bucket_data['tags'][tag['Key']] = tag['Value']

            output['buckets'].append(bucket_data)

        # Save JSON to file specified by --output
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        print(f"Wrote bucket data to {args.output}", file=sys.stderr)

    except ClientError as e:
        error_output = {
            'error': str(e),
            'error_code': e.response['Error']['Code'] if hasattr(e, 'response') else 'Unknown'
        }
        print(json.dumps(error_output, indent=2), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
