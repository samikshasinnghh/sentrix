import sys
import os
import gzip
import json
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import boto3
import pandas as pd
from src.utils.config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION

BUCKET_NAME = "aws-cloudtrail-logs-109678734772-3889d564"

PRIVILEGED_ACTION_PATTERNS = [
    r"^Delete", r"^Put.*Policy", r"^Create.*Key", r"^Attach.*Policy",
    r"^Detach.*Policy", r"^Update.*Policy", r"^CreateUser$", r"^DeleteUser$",
]


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
    return data["Records"]


def is_privileged(event_name):
    return any(re.match(pattern, event_name) for pattern in PRIVILEGED_ACTION_PATTERNS)


def map_cloudtrail_record(record):
    identity = record.get("userIdentity", {})
    user_id = identity.get("arn") or identity.get("type", "Unknown")

    status = "FAILURE" if record.get("errorCode") else "SUCCESS"

    return {
        "event_id": record.get("eventID"),
        "timestamp": record.get("eventTime"),
        "user_id": user_id,
        "identity_type": identity.get("type", "Unknown"),
        "source_ip": record.get("sourceIPAddress", "unknown"),
        "aws_region": record.get("awsRegion", "unknown"),
        "action": record.get("eventName"),
        "event_source": record.get("eventSource"),
        "status": status,
        "is_privileged_action": is_privileged(record.get("eventName", "")),
        "read_only": record.get("readOnly", None),
    }


if __name__ == "__main__":
    s3 = get_s3_client()

    log_keys = list_cloudtrail_log_files(s3, BUCKET_NAME)
    print(f"Found {len(log_keys)} log file(s) in bucket")

    all_records = []
    for key in log_keys:
        records = download_and_parse_log(s3, BUCKET_NAME, key)
        all_records.extend(records)

    print(f"Total raw CloudTrail events: {len(all_records)}")

    mapped = [map_cloudtrail_record(r) for r in all_records]
    df = pd.DataFrame(mapped)

    print(f"\nMapped DataFrame shape: {df.shape}")
    print("\nColumn dtypes:")
    print(df.dtypes)
    print("\nidentity_type breakdown:")
    print(df["identity_type"].value_counts())
    print("\nstatus breakdown:")
    print(df["status"].value_counts())
    print("\nis_privileged_action breakdown:")
    print(df["is_privileged_action"].value_counts())
    print("\nTop 10 actions:")
    print(df["action"].value_counts().head(10))

    df.to_csv("data/raw/cloudtrail_events.csv", index=False)
    print("\nSaved data/raw/cloudtrail_events.csv")