"""Tests for twine's credential resolution and keyring handling."""
import base64
import getpass
import logging
import platform
import re
import time
import typing as t

import pytest
import requests.auth

from twine import auth
from twine import exceptions
from twine import utils


@pytest.fixture
def config() -> utils.RepositoryConfig:
    """Return a minimal repository config for the auth tests."""
    return dict(repository="system")


def test_get_username_keyring_defers_to_prompt(monkeypatch, entered_username, config):
    """Prompt for a username when keyring has no stored credential."""
    class MockKeyring:
        @staticmethod
        def get_credential(system, user):
            return None

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    username = auth.Resolver(config, auth.CredentialInput()).username
    assert username == "entered user"


def test_get_username_keyring_not_installed_defers_to_prompt(
    monkeypatch, entered_username, config
):
    """Prompt for a username when keyring is not installed."""
    monkeypatch.setattr(auth, "keyring", None)

    username = auth.Resolver(config, auth.CredentialInput()).username
    assert username == "entered user"


def test_get_password_keyring_defers_to_prompt(monkeypatch, entered_password, config):
    """Prompt for a password when keyring has no stored password."""
    class MockKeyring:
        @staticmethod
        def get_password(system, user):
            return None

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_get_password_keyring_not_installed_defers_to_prompt(
    monkeypatch, entered_password, config
):
    """Prompt for a password when keyring is not installed."""
    monkeypatch.setattr(auth, "keyring", None)

    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_no_password_defers_to_prompt(monkeypatch, entered_password, config):
    """Prompt for a password when the config has none."""
    config.update(password=None)
    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_empty_password_bypasses_prompt(monkeypatch, entered_password, config):
    """Use an empty password from the config without prompting."""
    config.update(password="")
    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == ""


def test_no_username_non_interactive_aborts(config):
    """Abort in non-interactive mode when no username is available."""
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput()).username


def test_no_password_non_interactive_aborts(config):
    """Abort in non-interactive mode when no password is available."""
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput("user")).password


def test_get_username_and_password_keyring_overrides_prompt(
    monkeypatch, config, caplog
):
    """Prefer keyring credentials over prompted ones and log the source."""
    caplog.set_level(logging.INFO, "twine")

    class MockKeyring:
        @staticmethod
        def get_credential(system, user):
            return auth.CredentialInput(
                "real_user", f"real_user@{system} sekure pa55word"
            )

        @staticmethod
        def get_password(system, user):
            cred = MockKeyring.get_credential(system, user)
            if user != cred.username:
                raise RuntimeError("unexpected username")
            return cred.password

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    res = auth.Resolver(config, auth.CredentialInput())

    assert res.username == "real_user"
    assert res.password == "real_user@system sekure pa55word"

    assert caplog.messages == [
        "Querying keyring for username",
        "username set from keyring",
        "Querying keyring for password",
        "password set from keyring",
    ]


@pytest.fixture
def keyring_missing_get_credentials(monkeypatch):
    """Simulate keyring prior to 15.2 that does not have the 'get_credential' API."""
    monkeypatch.delattr(auth.keyring, "get_credential")


@pytest.fixture
def entered_username(monkeypatch):
    """Stub input so username prompts return a fixed value."""
    monkeypatch.setattr(auth, "input", lambda prompt: "entered user", raising=False)


def test_get_username_keyring_missing_get_credentials_prompts(
    entered_username, keyring_missing_get_credentials, config
):
    """Prompt for a username when keyring lacks get_credential."""
    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"


def test_get_username_keyring_missing_non_interactive_aborts(
    entered_username, keyring_missing_get_credentials, config
):
    """Abort in non-interactive mode when keyring lacks get_credential."""
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput()).username


def test_get_password_keyring_missing_non_interactive_aborts(
    entered_username, keyring_missing_get_credentials, config
):
    """Abort in non-interactive mode when keyring lacks get_password."""
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput("user")).password


def test_get_username_keyring_runtime_error_logged(
    entered_username, monkeypatch, config, caplog
):
    """Log and fall back to a prompt when keyring raises RuntimeError."""
    class FailKeyring:
        """Simulate missing keyring backend raising RuntimeError on get_credential."""

        @staticmethod
        def get_credential(system, username):
            raise RuntimeError("fail!")

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"

    assert re.search(
        r"Error getting username from keyring.+Traceback.+RuntimeError: fail!",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_runtime_error_logged(
    entered_username, entered_password, monkeypatch, config, caplog
):
    """Log and fall back to a prompt when keyring raises RuntimeError."""
    class FailKeyring:
        """Simulate missing keyring backend raising RuntimeError on get_password."""

        @staticmethod
        def get_password(system, username):
            raise RuntimeError("fail!")

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).password == "entered pw"

    assert re.search(
        r"Error getting password from keyring.+Traceback.+RuntimeError: fail!",
        caplog.text,
        re.DOTALL,
    )


def _raise_home_key_error():
    """Simulate environment from https://github.com/pypa/twine/issues/889."""
    try:
        raise KeyError("HOME")
    except KeyError:
        raise KeyError("uid not found: 999")


def test_get_username_keyring_key_error_logged(
    entered_username, monkeypatch, config, caplog
):
    """Log and fall back to a prompt when keyring raises KeyError."""
    class FailKeyring:
        @staticmethod
        def get_credential(system, username):
            _raise_home_key_error()

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"

    assert re.search(
        r"Error getting username from keyring"
        r".+Traceback"
        r".+KeyError: 'HOME'"
        r".+KeyError: 'uid not found: 999'",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_key_error_logged(
    entered_username, entered_password, monkeypatch, config, caplog
):
    """Log and fall back to a prompt when keyring raises KeyError."""
    class FailKeyring:
        @staticmethod
        def get_password(system, username):
            _raise_home_key_error()

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).password == "entered pw"

    assert re.search(
        r"Error getting password from keyring"
        r".+Traceback"
        r".+KeyError: 'HOME'"
        r".+KeyError: 'uid not found: 999'",
        caplog.text,
        re.DOTALL,
    )


def test_logs_cli_values(caplog, config):
    """Log the credentials supplied on the command line."""
    caplog.set_level(logging.INFO, "twine")

    res = auth.Resolver(config, auth.CredentialInput("username", "password"))

    assert res.username == "username"
    assert res.password == "password"

    assert caplog.messages == [
        "username set by command options",
        "password set by command options",
    ]


def test_logs_config_values(config, caplog):
    """Log the credentials read from the config file."""
    caplog.set_level(logging.INFO, "twine")

    config.update(username="username", password="password")
    res = auth.Resolver(config, auth.CredentialInput())

    assert res.username == "username"
    assert res.password == "password"

    assert caplog.messages == [
        "username set from config file",
        "password set from config file",
    ]


@pytest.mark.parametrize(
    "password, warning",
    [
        ("", "Your password is empty"),
        ("\x16", "Your password contains control characters"),
        ("entered\x16pw", "Your password contains control characters"),
    ],
)
def test_warns_for_empty_password(
    password,
    warning,
    monkeypatch,
    entered_username,
    config,
    caplog,
):
    """Warn when the resolved password is empty."""
    # Avoiding additional warning "No recommended backend was available"
    monkeypatch.setattr(auth.keyring, "get_password", lambda system, user: None)

    monkeypatch.setattr(getpass, "getpass", lambda prompt: password)

    assert auth.Resolver(config, auth.CredentialInput()).password == password

    assert caplog.messages[0].startswith(warning)


@pytest.mark.skipif(
    platform.machine() in {"ppc64le", "s390x"},
    reason="keyring module is optional on ppc64le and s390x",
)
def test_keyring_module():
    """Assert that a keyring module is importable."""
    assert auth.keyring is not None


def test_resolver_authenticator_config_authentication(config):
    """Build an HTTPBasicAuth from config credentials."""
    config.update(username="username", password="password")
    res = auth.Resolver(config, auth.CredentialInput())
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_credential_input_authentication(config):
    """Build an HTTPBasicAuth from prompted credentials."""
    res = auth.Resolver(config, auth.CredentialInput("username", "password"))
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_trusted_publishing_authentication(config):
    """Build a trusted-publishing authenticator for a token credential."""
    res = auth.Resolver(
        config, auth.CredentialInput(username="__token__", password="skip-stdin")
    )
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="fake-tp-token",
    )
    assert isinstance(res.authenticator, auth.TrustedPublishingAuthenticator)


class MockResponse:
    """A stand-in for a requests response with a fixed status and body."""

    def __init__(self, status_code: int, json: t.Any) -> None:
        self.status_code = status_code
        self._json = json

    def json(self, *args, **kwargs) -> t.Any:
        """Return the canned JSON body."""
        return self._json

    def raise_for_status(self) -> None:
        """Raise HTTPError when the status code is an error."""
        if 400 <= self.status_code:
            raise requests.exceptions.HTTPError()

    @property
    def ok(self) -> bool:
        """Report whether the status code is a success."""
        return self.status_code < 400


class MockSession:
    """A stand-in for a requests session replaying canned responses."""

    def __init__(
        self,
        get_response_list: t.List[MockResponse],
        post_response_list: t.List[MockResponse],
    ) -> None:
        self.post_counter = self.get_counter = 0
        self.get_response_list = get_response_list
        self.post_response_list = post_response_list

    def get(self, url: str, **kwargs) -> MockResponse:
        """Return the next canned GET response."""
        response = self.get_response_list[self.get_counter]
        self.get_counter += 1
        return response

    def post(self, url: str, **kwargs) -> MockResponse:
        """Return the next canned POST response."""
        response = self.post_response_list[self.post_counter]
        self.post_counter += 1
        return response


def test_trusted_publish_authenticator_refreshes_token(monkeypatch, config):
    """Fetch a fresh token when the cached one is missing."""
    def make_session():
        return MockSession(
            get_response_list=[
                MockResponse(status_code=200, json={"audience": "fake-aud"})
            ],
            post_response_list=[
                MockResponse(
                    status_code=200,
                    json={
                        "success": True,
                        "token": "new-token",
                        "expires": int(time.time()) + 900,
                    },
                ),
            ],
        )

    def detect_credential(*args, **kwargs) -> str:
        return "fake-oidc-token"

    config.update({"repository": utils.TEST_REPOSITORY})
    res = auth.Resolver(config, auth.CredentialInput(username="__token__"))
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="expiring-tp-token",
    )
    res._expires = int(time.time()) + 4 * 60
    monkeypatch.setattr(auth, "detect_credential", detect_credential)
    monkeypatch.setattr(auth.utils, "make_requests_session", make_session)
    authenticator = auth.TrustedPublishingAuthenticator(resolver=res)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})
    request = authenticator(prepped_req)
    assert (
        request.headers["Authorization"]
        == f"Basic {base64.b64encode(b'__token__:new-token').decode()}"
    )


def test_trusted_publish_authenticator_reuses_token(monkeypatch, config):
    """Reuse the cached token without re-fetching it."""
    def make_session():
        return MockSession(
            get_response_list=[
                MockResponse(status_code=200, json={"audience": "fake-aud"})
            ],
            post_response_list=[
                MockResponse(
                    status_code=200,
                    json={
                        "success": True,
                        "token": "new-token",
                        "expires": int(time.time()) + 900,
                    },
                ),
            ],
        )

    def detect_credential(*args, **kwargs) -> str:
        return "fake-oidc-token"

    config.update({"repository": utils.TEST_REPOSITORY})
    res = auth.Resolver(config, auth.CredentialInput(username="__token__"))
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="valid-tp-token",
    )
    res._expires = int(time.time()) + 900
    monkeypatch.setattr(auth, "detect_credential", detect_credential)
    monkeypatch.setattr(auth.utils, "make_requests_session", make_session)
    authenticator = auth.TrustedPublishingAuthenticator(resolver=res)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})
    request = authenticator(prepped_req)
    assert (
        request.headers["Authorization"]
        == f"Basic {base64.b64encode(b'__token__:valid-tp-token').decode()}"
    )


def test_inability_to_make_token_raises_error():
    """Raise TrustedPublishingFailure when no token can be obtained."""
    class MockResolver:
        def make_trusted_publishing_token(self) -> None:
            return None

    authenticator = auth.TrustedPublishingAuthenticator(
        resolver=MockResolver(),
    )
    with pytest.raises(exceptions.TrustedPublishingFailure):
        authenticator(None)
