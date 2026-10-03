from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from cloud_detective.config import get_settings

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    groups: frozenset[str]


@lru_cache
def _jwks_client(issuer: str) -> PyJWKClient:
    return PyJWKClient(f"{issuer}/.well-known/jwks.json", cache_keys=True)


CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def current_principal(credentials: CredentialsDep) -> Principal:
    settings = get_settings()
    if not settings.auth_enabled:
        return Principal(
            subject="local",
            username="local-developer",
            groups=frozenset({"Responder"}),
        )
    if not credentials or not settings.cognito_user_pool_id or not settings.cognito_app_client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    issuer = (
        f"https://cognito-idp.{settings.aws_region}.amazonaws.com/"
        f"{settings.cognito_user_pool_id}"
    )
    try:
        signing_key = _jwks_client(issuer).get_signing_key_from_jwt(credentials.credentials)
        claims = jwt.decode(
            credentials.credentials,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "sub"], "verify_aud": False},
        )
        token_use = claims.get("token_use")
        expected_client = settings.cognito_app_client_id
        if token_use == "id" and claims.get("aud") != expected_client:
            raise jwt.InvalidAudienceError("ID token audience does not match")
        if token_use == "access" and claims.get("client_id") != expected_client:
            raise jwt.InvalidAudienceError("Access token client does not match")
        if token_use not in {"id", "access"}:
            raise jwt.InvalidTokenError("Unsupported Cognito token type")
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        ) from exc

    groups = claims.get("cognito:groups", [])
    if isinstance(groups, str):
        groups = [groups]
    return Principal(
        subject=claims["sub"],
        username=claims.get("cognito:username", claims.get("email", claims["sub"])),
        groups=frozenset(groups),
    )


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def require_analyst(principal: PrincipalDep) -> Principal:
    if not principal.groups.intersection({"Analyst", "Responder"}):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst access required")
    return principal


def require_responder(principal: PrincipalDep) -> Principal:
    if "Responder" not in principal.groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Responder access required",
        )
    return principal
