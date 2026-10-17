"""A recursive S3 delete fails when DeleteObjects refused keys.

DeleteObjects answers HTTP 200 also when it refused some keys
(AccessDenied, object lock, ...): those come back in ``Errors``.
_remove_prefix never read the answer, so remove(dir, recursive=True)
reported success while objects stayed. A ClientError of the call itself
escaped as a non-OSError. botocore's Stubber plays the server.
"""

from __future__ import annotations

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from core.s3_client import S3Session  # noqa: E402


def _session(pages: list[list[str]], answers: list):
    client = boto3.client(
        "s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y"
    )
    stub = Stubber(client)
    first = pages[0][0] if pages and pages[0] else None
    stub.add_response(
        "list_objects_v2",
        {"KeyCount": 1 if first else 0, "Contents": [{"Key": first}] if first else []},
        {"Bucket": "b", "Prefix": "data/", "MaxKeys": 1},
    )
    # The paginator lists a page, the page is deleted, then the next one.
    for i, (keys, answer) in enumerate(zip(pages, answers)):
        resp = {"KeyCount": len(keys), "Contents": [{"Key": k} for k in keys]}
        params = {"Bucket": "b", "Prefix": "data/"}
        if i + 1 < len(pages):
            resp.update(IsTruncated=True, NextContinuationToken=f"t{i + 1}")
        else:
            resp["IsTruncated"] = False
        if i:
            params["ContinuationToken"] = f"t{i}"
        stub.add_response("list_objects_v2", resp, params)
        expected = {"Bucket": "b", "Delete": {"Objects": [{"Key": k} for k in keys]}}
        if isinstance(answer, str):
            stub.add_client_error("delete_objects", service_error_code=answer,
                                  http_status_code=403, expected_params=expected)
        else:
            stub.add_response("delete_objects", answer, expected)
    stub.activate()
    s = S3Session.__new__(S3Session)
    s._s3 = client
    s._bucket = "b"
    s._anonymous = False
    return s, stub


def test_happy_every_key_deleted_is_success():
    deleted = {"Deleted": [{"Key": "data/a"}, {"Key": "data/b"}]}
    s, stub = _session([["data/a", "data/b"]], [deleted])
    s.remove("/data", recursive=True)
    stub.assert_no_pending_responses()


def test_sad_refused_key_fails_the_remove_after_every_page():
    s, stub = _session(
        [["data/a", "data/locked"], ["data/z"]],
        [
            {
                "Deleted": [{"Key": "data/a"}],
                "Errors": [{"Key": "data/locked", "Code": "AccessDenied", "Message": "no"}],
            },
            {"Deleted": [{"Key": "data/z"}]},
        ],
    )
    with pytest.raises(OSError, match="data/locked.*AccessDenied"):
        s.remove("/data", recursive=True)
    # The second page was still deleted: the user asked for the tree.
    stub.assert_no_pending_responses()


def test_sad_delete_objects_client_error_is_an_oserror():
    s, stub = _session([["data/a"]], ["AccessDenied"])
    with pytest.raises(OSError, match="AccessDenied"):
        s.remove("/data", recursive=True)


def test_edge_errors_list_empty_or_missing_is_success():
    s, stub = _session([["data/a"]], [{"Errors": []}])
    s.remove("/data", recursive=True)
    stub.assert_no_pending_responses()
