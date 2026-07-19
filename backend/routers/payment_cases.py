"""Payment Case endpoints: one fraud verdict across trusted scan artifacts."""

from fastapi import APIRouter, HTTPException, Request, Response

from api_models import PaymentCaseArtifactRequest
from core.request_security import _extract_client_instance_id
from services import payment_case_store


router = APIRouter()


def _client_instance_or_400(request: Request) -> str:
    client_instance_id = _extract_client_instance_id(request)
    if not client_instance_id:
        raise HTTPException(status_code=400, detail="Instanța aplicației nu poate fi identificată.")
    return client_instance_id


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, payment_case_store.PaymentCaseNotFoundError):
        return HTTPException(status_code=404, detail="Cazul sau artefactul nu a fost găsit.")
    if isinstance(exc, payment_case_store.PaymentCaseArtifactNotReadyError):
        return HTTPException(status_code=409, detail="Scanarea artefactului nu are încă un verdict final.")
    if isinstance(exc, payment_case_store.PaymentCaseCapacityError):
        return HTTPException(status_code=409, detail="Cazul a atins numărul maximum de dovezi.")
    return HTTPException(status_code=503, detail="Cazul nu a putut fi salvat. Încearcă din nou.")


@router.post("/v1/payment-cases")
async def create_payment_case(request: Request):
    try:
        return payment_case_store.create_payment_case(_client_instance_or_400(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get("/v1/payment-cases/{case_id}")
async def get_payment_case(case_id: str, request: Request):
    try:
        return payment_case_store.get_payment_case(case_id, _client_instance_or_400(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.post("/v1/payment-cases/{case_id}/artifacts")
async def attach_payment_case_artifact(case_id: str, payload: PaymentCaseArtifactRequest, request: Request):
    try:
        return payment_case_store.attach_artifact(
            case_id,
            payload.artifact_ref,
            _client_instance_or_400(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.delete("/v1/payment-cases/{case_id}", status_code=204)
async def delete_payment_case(case_id: str, request: Request):
    try:
        payment_case_store.delete_payment_case(case_id, _client_instance_or_400(request))
        return Response(status_code=204)
    except HTTPException:
        raise
    except Exception as exc:
        raise _translate_error(exc) from exc
