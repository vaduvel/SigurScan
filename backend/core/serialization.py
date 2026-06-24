import json
from typing import Any, Dict


def _deep_copy_jsonable(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value))
    except Exception:
        return value


def _merge_missing_dict_values(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if value in (None, "", [], {}):
            continue
        current = target.get(key)
        if current in (None, "", [], {}):
            target[key] = _deep_copy_jsonable(value)


def _merge_progress_dict(
    base: Dict[str, Any],
    overlay: Dict[str, Any],
    *,
    ranker,
) -> Dict[str, Any]:
    if not base:
        return _deep_copy_jsonable(overlay)
    if not overlay:
        return _deep_copy_jsonable(base)
    base_rank = ranker(base)
    overlay_rank = ranker(overlay)
    winner = _deep_copy_jsonable(overlay if overlay_rank > base_rank else base)
    loser = base if overlay_rank > base_rank else overlay
    _merge_missing_dict_values(winner, loser)
    return winner
