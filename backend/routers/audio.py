"""Audio semantic-review endpoints.

Only redacted transcript windows are accepted here. Raw audio stays on-device.
"""

from fastapi import APIRouter

from api_models import AudioSemanticReviewRequest
from services.audio_semantic_review import review_redacted_audio_transcript

router = APIRouter()


@router.post("/v1/audio/semantic-review")
async def audio_semantic_review(request: AudioSemanticReviewRequest):
    return await review_redacted_audio_transcript(request)
