import uuid

from fastapi import Request, Response

from app.core.config import get_settings


def get_or_create_client_id(request: Request, response: Response) -> str:
    settings = get_settings()
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        try:
            uuid.UUID(cookie)
            return cookie
        except ValueError:
            pass
    client_id = str(uuid.uuid4())
    response.set_cookie(
        key=settings.session_cookie_name,
        value=client_id,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure or settings.is_production,
        max_age=60 * 60 * 24 * 30,
        path="/",
    )
    return client_id
