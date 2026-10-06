import gzip
import io
import json

import pytest

from src.utils.ingest_cloudtrail import (
    is_privileged,
    map_cloudtrail_record,
    list_cloudtrail_log_files,
    download_and_parse_log,
)

# A made-up CloudTrail record (documentation-range IP, fake account id).
RECORD = {
    "eventID": "abc-123",
    "eventTime": "2026-01-01T10:00:00Z",
    "eventName": "DeleteBucket",
    "eventSource": "s3.amazonaws.com",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.5",
    "readOnly": False,
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::111122223333:user/alice",
    },
}


# ---------- fakes: no real AWS is ever called ----------

class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, Bucket):
        return iter(self._pages)


class FakeS3:
    def __init__(self, pages=None, files=None):
        self._pages = pages or []
        self._files = files or {}
        self.requested = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakePaginator(self._pages)

    def get_object(self, Bucket, Key):
        self.requested.append((Bucket, Key))
        return {"Body": io.BytesIO(self._files[Key])}


def _gz(records):
    return gzip.compress(json.dumps({"Records": records}).encode("utf-8"))


# ---------- is_privileged ----------

@pytest.mark.parametrize("name", [
    "DeleteUser",
    "DeleteBucket",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "AttachUserPolicy",
    "DetachRolePolicy",
    "UpdateAssumeRolePolicy",
    "CreateUser",
])
def test_privileged_actions_are_detected(name):
    assert is_privileged(name) is True


@pytest.mark.parametrize("name", [
    "DescribeInstances",
    "ListBuckets",
    "GetObject",
    "ConsoleLogin",
    "AssumeRole",
    "CreateBucket",
    "",
])
def test_normal_actions_are_not_privileged(name):
    assert is_privileged(name) is False


# ---------- map_cloudtrail_record ----------

def test_map_record_maps_all_fields():
    assert map_cloudtrail_record(RECORD) == {
        "event_id": "abc-123",
        "timestamp": "2026-01-01T10:00:00Z",
        "user_id": "arn:aws:iam::111122223333:user/alice",
        "identity_type": "IAMUser",
        "source_ip": "203.0.113.5",
        "aws_region": "us-east-1",
        "action": "DeleteBucket",
        "event_source": "s3.amazonaws.com",
        "status": "SUCCESS",
        "is_privileged_action": True,
        "read_only": False,
    }


@pytest.mark.parametrize("identity_type", ["AWSService", "Root"])
def test_user_id_falls_back_to_identity_type_when_no_arn(identity_type):
    record = dict(RECORD, userIdentity={"type": identity_type})
    out = map_cloudtrail_record(record)
    assert out["user_id"] == identity_type
    assert out["identity_type"] == identity_type


@pytest.mark.parametrize("error_code, expected", [
    ("AccessDenied", "FAILURE"),
    (None, "SUCCESS"),
])
def test_error_code_decides_status(error_code, expected):
    record = dict(RECORD)
    if error_code:
        record["errorCode"] = error_code
    assert map_cloudtrail_record(record)["status"] == expected


def test_minimal_record_uses_safe_defaults():
    out = map_cloudtrail_record({"eventID": "x", "eventName": "ListBuckets"})
    assert out["user_id"] == "Unknown"
    assert out["identity_type"] == "Unknown"
    assert out["source_ip"] == "unknown"
    assert out["aws_region"] == "unknown"
    assert out["read_only"] is None
    assert out["status"] == "SUCCESS"
    assert out["is_privileged_action"] is False


def test_privileged_flag_follows_event_name():
    assert map_cloudtrail_record(RECORD)["is_privileged_action"] is True
    safe = dict(RECORD, eventName="ListBuckets")
    assert map_cloudtrail_record(safe)["is_privileged_action"] is False


def test_mapped_record_has_expected_schema_keys():
    # If a column is added or removed on purpose, update this list too.
    assert set(map_cloudtrail_record(RECORD)) == {
        "event_id", "timestamp", "user_id", "identity_type", "source_ip",
        "aws_region", "action", "event_source", "status",
        "is_privileged_action", "read_only",
    }


# ---------- list_cloudtrail_log_files ----------

def test_list_returns_only_json_gz_keys_across_pages():
    s3 = FakeS3(pages=[
        {"Contents": [{"Key": "AWSLogs/a.json.gz"}, {"Key": "AWSLogs/readme.txt"}]},
        {"Contents": [{"Key": "AWSLogs/b.json.gz"}]},
        {},  # a page with no "Contents" key must not crash
    ])
    assert list_cloudtrail_log_files(s3, "test-bucket") == [
        "AWSLogs/a.json.gz",
        "AWSLogs/b.json.gz",
    ]


def test_list_empty_bucket_returns_empty_list():
    assert list_cloudtrail_log_files(FakeS3(pages=[{}]), "test-bucket") == []


# ---------- download_and_parse_log ----------

def test_download_returns_records_from_gzipped_json():
    other = dict(RECORD, eventID="def-456", eventName="ListBuckets")
    s3 = FakeS3(files={"AWSLogs/a.json.gz": _gz([RECORD, other])})
    records = download_and_parse_log(s3, "test-bucket", "AWSLogs/a.json.gz")
    assert records == [RECORD, other]


def test_download_requests_the_given_bucket_and_key():
    s3 = FakeS3(files={"AWSLogs/a.json.gz": _gz([RECORD])})
    download_and_parse_log(s3, "test-bucket", "AWSLogs/a.json.gz")
    assert s3.requested == [("test-bucket", "AWSLogs/a.json.gz")]