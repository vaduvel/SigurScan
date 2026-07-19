"""Durable, privacy-safe storage for multi-artifact payment investigations."""

from __future__ import annotations

import copy
import threading
import time
import uuid
from typing import Any, Mapping, Sequence

from services import supabase_store
from services.payment_case import (
    build_case_artifact,
    client_owner_fingerprint,
    reduce_payment_case,
)


PAYMENT_CASE_TTL_SECONDS = 24 * 60 * 60
PAYMENT_CASE_MAX_ARTIFACTS = 12
_LOCAL_RECORDS: dict[str, dict[str, Any]] = {}
_LOCAL_LOCK = threading.RLock()


class PaymentCaseNotFoundError(LookupError):
    pass


class PaymentCaseArtifactNotReadyError(RuntimeError):
    pass


class PaymentCaseCapacityError(RuntimeError):
    pass


class PaymentCasePersistenceError(RuntimeError):
    pass


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _now() -> int:
    return int(time.time())


def _copy(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(
        {
            key: raw
            for key, raw in value.items()
            if not str(key).startswith("_storage_")
        }
    )


def _save(record: dict[str, Any]) -> bool:
    saved = supabase_store.save_scan_job(record)
    if saved is False:
        return False
    with _LOCAL_LOCK:
        _LOCAL_RECORDS[str(record["scan_id"])] = _copy(record)
    return True


def _load(record_id: str) -> dict[str, Any] | None:
    record = supabase_store.load_scan_job(record_id)
    if not isinstance(record, dict):
        with _LOCAL_LOCK:
            local = _LOCAL_RECORDS.get(record_id)
            record = _copy(local) if isinstance(local, Mapping) else None
    if not isinstance(record, dict):
        return None
    if record.get("deleted") is True or int(record.get("expires_at") or 0) <= _now():
        return None
    return record


def _owner(client_instance_id: str) -> str:
    return client_owner_fingerprint(client_instance_id)


def _assert_owner(record: Mapping[str, Any] | None, owner: str, record_type: str) -> dict[str, Any]:
    if (
        not isinstance(record, Mapping)
        or record.get("record_type") != record_type
        or record.get("owner_fingerprint") != owner
    ):
        raise PaymentCaseNotFoundError
    return dict(record)


def register_server_artifact(
    *,
    client_instance_id: str,
    artifact_type: str,
    verdict: str,
    is_final: bool,
    reason_codes: Sequence[str] | None,
    facts: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Persist an artifact snapshot produced by a scanner, never by the client."""

    return register_server_artifact_for_owner(
        owner_fingerprint=_owner(client_instance_id),
        artifact_type=artifact_type,
        verdict=verdict,
        is_final=is_final,
        reason_codes=reason_codes,
        facts=facts,
    )


def register_server_artifact_for_owner(
    *,
    owner_fingerprint: str,
    artifact_type: str,
    verdict: str,
    is_final: bool,
    reason_codes: Sequence[str] | None,
    facts: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not str(owner_fingerprint or "").startswith("hmac-sha256:"):
        raise ValueError("owner_fingerprint is required")

    artifact_ref = _new_id("pc-art")
    artifact = build_case_artifact(
        artifact_ref=artifact_ref,
        artifact_type=artifact_type,
        verdict=verdict,
        is_final=is_final,
        reason_codes=reason_codes,
        facts=facts,
    )
    record = {
        "scan_id": artifact_ref,
        "record_type": "payment_case_artifact",
        "status": "complete" if is_final else "scanning",
        "input_type": "payment_case_artifact",
        "source_channel": "server_scan",
        "owner_fingerprint": owner_fingerprint,
        "artifact": artifact,
        "created_at": _now(),
        "expires_at": _now() + PAYMENT_CASE_TTL_SECONDS,
    }
    if not _save(record):
        raise PaymentCasePersistenceError("artifact persistence conflict")
    return artifact


def create_payment_case(client_instance_id: str) -> dict[str, Any]:
    owner = _owner(client_instance_id)
    case_id = _new_id("pc")
    result = reduce_payment_case([])
    record = {
        "scan_id": case_id,
        "record_type": "payment_case",
        "status": "open",
        "input_type": "payment_case",
        "source_channel": "android_native",
        "owner_fingerprint": owner,
        "artifacts": [],
        "result": result,
        "created_at": _now(),
        "updated_at_epoch": _now(),
        "expires_at": _now() + PAYMENT_CASE_TTL_SECONDS,
    }
    if not _save(record):
        raise PaymentCasePersistenceError("case persistence conflict")
    return public_payment_case(record)


def _artifact_for_owner(artifact_ref: str, owner: str) -> dict[str, Any]:
    record = _assert_owner(_load(artifact_ref), owner, "payment_case_artifact")
    artifact = record.get("artifact")
    if not isinstance(artifact, Mapping):
        raise PaymentCaseNotFoundError
    if artifact.get("is_final") is not True:
        raise PaymentCaseArtifactNotReadyError
    return dict(artifact)


def attach_artifact(case_id: str, artifact_ref: str, client_instance_id: str) -> dict[str, Any]:
    owner = _owner(client_instance_id)
    artifact = _artifact_for_owner(str(artifact_ref or "").strip(), owner)
    for _attempt in range(3):
        case = _assert_owner(_load(case_id), owner, "payment_case")
        artifacts = [dict(item) for item in case.get("artifacts") or [] if isinstance(item, Mapping)]
        if not any(item.get("artifact_ref") == artifact.get("artifact_ref") for item in artifacts):
            if len(artifacts) >= PAYMENT_CASE_MAX_ARTIFACTS:
                raise PaymentCaseCapacityError
            artifacts.append(artifact)
        case["artifacts"] = artifacts
        case["result"] = reduce_payment_case(artifacts)
        case["updated_at_epoch"] = _now()
        if _save(case):
            return public_payment_case(case)
    raise PaymentCasePersistenceError("case update conflict")


def get_payment_case(case_id: str, client_instance_id: str) -> dict[str, Any]:
    case = _assert_owner(_load(case_id), _owner(client_instance_id), "payment_case")
    return public_payment_case(case)


def delete_payment_case(case_id: str, client_instance_id: str) -> None:
    owner = _owner(client_instance_id)
    case = _assert_owner(_load(case_id), owner, "payment_case")
    artifact_records: list[dict[str, Any]] = []
    for artifact in case.get("artifacts") or []:
        if not isinstance(artifact, Mapping):
            continue
        artifact_ref = str(artifact.get("artifact_ref") or "")
        record = _load(artifact_ref)
        if (
            isinstance(record, Mapping)
            and record.get("record_type") == "payment_case_artifact"
            and record.get("owner_fingerprint") == owner
        ):
            artifact_records.append(dict(record))

    _delete_record(case, sensitive_keys=("artifacts", "result"))
    for record in artifact_records:
        _delete_record(record, sensitive_keys=("artifact",))


def _delete_record(record: Mapping[str, Any], *, sensitive_keys: Sequence[str]) -> None:
    record_id = str(record.get("scan_id") or "")
    if not record_id:
        raise PaymentCasePersistenceError("record id missing")
    with _LOCAL_LOCK:
        _LOCAL_RECORDS.pop(record_id, None)
    if supabase_store.delete_scan_job(record_id):
        return

    tombstone = dict(record)
    for key in sensitive_keys:
        tombstone.pop(key, None)
    tombstone["deleted"] = True
    tombstone["expires_at"] = _now()
    if not _save(tombstone):
        raise PaymentCasePersistenceError("record deletion failed")


def public_payment_case(record: Mapping[str, Any]) -> dict[str, Any]:
    result = record.get("result") if isinstance(record.get("result"), Mapping) else reduce_payment_case([])
    artifacts = [item for item in record.get("artifacts") or [] if isinstance(item, Mapping)]
    return {
        **dict(result),
        "schema": "sigurscan_payment_case_v1",
        "case_id": str(record.get("scan_id") or ""),
        "status": str(record.get("status") or "open"),
        "artifact_count": len(artifacts),
        "artifact_types": sorted({str(item.get("artifact_type") or "unknown") for item in artifacts}),
    }


def reset_local_payment_case_store_for_tests() -> None:
    with _LOCAL_LOCK:
        _LOCAL_RECORDS.clear()


def load_case_for_tests(case_id: str) -> dict[str, Any] | None:
    return _load(case_id)
