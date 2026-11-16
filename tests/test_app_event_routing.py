from unittest.mock import MagicMock, patch

from fastapi.responses import JSONResponse

from src.app import handle_event


def test_handle_event_returns_listener_response_for_pull_request():
    listener = MagicMock()
    listener.on_pull_request.return_value = JSONResponse(
        content={"error": "Invalid value: bad"}, status_code=400
    )

    response = handle_event("pull_request", listener, {"repository": {}})

    listener.on_pull_request.assert_called_once_with({"repository": {}})
    assert response.status_code == 400


def test_handle_event_ignores_review_events_without_reviewers_configured():
    listener = MagicMock()

    with patch("src.app.get_secret", side_effect=RuntimeError("should not be called")):
        response = handle_event("ping", listener, {})

    listener.on_pull_request_review.assert_not_called()
    assert response.status_code == 200


def test_handle_event_routes_review_events_when_reviewers_configured():
    listener = MagicMock()
    listener.on_pull_request_review.return_value = JSONResponse(
        content={"message": "ok"}, status_code=200
    )

    with patch("src.app.get_secret", return_value=["reviewer-1"]):
        response = handle_event("pull_request_review", listener, {})

    listener.on_pull_request_review.assert_called_once_with({})
    assert response.status_code == 200
