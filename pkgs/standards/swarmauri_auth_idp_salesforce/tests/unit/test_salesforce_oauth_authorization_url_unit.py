from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretBytes, SecretStr

from swarmauri_auth_idp_salesforce import (
    SalesforceOAuth20Login,
    SalesforceOAuth21Login,
)


@pytest.mark.parametrize(
    "login_class",
    [SalesforceOAuth20Login, SalesforceOAuth21Login],
)
@pytest.mark.unit
@pytest.mark.asyncio
async def test_auth_url_encodes_query_values_and_preserves_endpoint_query(
    login_class: type[SalesforceOAuth20Login] | type[SalesforceOAuth21Login],
) -> None:
    login = login_class(
        base_url="https://login.salesforce.com",
        client_id="client&extra=1&code_challenge_method=plain + = café",
        client_secret=SecretStr("secret"),
        redirect_uri="https://example.com/callback?next=a+b&x=1",
        state_secret=SecretBytes(b"state-secret"),
        scope="read&state=attacker + = café",
    )
    login.AUTH_PATH = "/services/oauth2/authorize?tenant=team&mode=login"

    payload = await login.auth_url()
    parsed = urlsplit(payload["url"])
    query = parse_qs(parsed.query, keep_blank_values=True)

    assert parsed.path == "/services/oauth2/authorize"
    assert set(query) == {
        "tenant",
        "mode",
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    assert query["tenant"] == ["team"]
    assert query["mode"] == ["login"]
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [
        "client&extra=1&code_challenge_method=plain + = café"
    ]
    assert query["redirect_uri"] == ["https://example.com/callback?next=a+b&x=1"]
    assert query["scope"] == ["read&state=attacker + = café"]
    assert query["state"] == [payload["state"]]
    assert len(query["code_challenge"]) == 1
    assert query["code_challenge"][0]
    assert query["code_challenge_method"] == ["S256"]
