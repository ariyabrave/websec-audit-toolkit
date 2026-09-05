import httpx


USER_AGENT = "WebSec-Audit-Toolkit/0.1.0"


class FetchError(Exception):
    """
    Raised when the target cannot be retrieved.
    """


def fetch_target(target: str) -> httpx.Response:
    """
    Fetch a target using a simple HTTP GET request.

    Redirects are followed automatically.
    """

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": USER_AGENT,
            },
        ) as client:
            response = client.get(target)

    except httpx.TimeoutException as exc:
        raise FetchError(
            f"Request to {target} timed out."
        ) from exc

    except httpx.RequestError as exc:
        raise FetchError(
            f"Could not connect to {target}: {exc}"
        ) from exc

    return response