import sys
import os
import gzip
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import boto3
from src.utils.config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION

BUCKET_NAME = "aws-cloudtrail-logs-109678734772-3889d564"


def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )


def list_cloudtrail_log_files(s3_client, bucket_name):
    paginator = s3_client.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".json.gz"):
                keys.append(obj["Key"])
    return keys


def download_and_parse_log(s3_client, bucket_name, key):
    response = s3_client.get_object(Bucket=bucket_name, Key=key)
    compressed_body = response["Body"].read()
    decompressed = gzip.decompress(compressed_body)
    data = json.loads(decompressed)
    return data["Records"]  # CloudTrail log files wrap events in a "Records" list


if __name__ == "__main__":
    s3 = get_s3_client()

    log_keys = list_cloudtrail_log_files(s3, BUCKET_NAME)
    print(f"Found {len(log_keys)} log file(s) in bucket")
    for key in log_keys:
        print(f"  - {key}")

    all_records = []
    for key in log_keys:
        records = download_and_parse_log(s3, BUCKET_NAME, key)
        all_records.extend(records)

    print(f"\nTotal CloudTrail events parsed: {len(all_records)}")
    print("\nFirst event, full structure:")
    print(json.dumps(all_records[0], indent=2))