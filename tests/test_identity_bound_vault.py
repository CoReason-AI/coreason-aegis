from unittest.mock import MagicMock

import pytest

# We import UserContext to mock it properly, assuming it is available
from coreason_identity.models import UserContext

from coreason_aegis.exceptions import SecurityException
from coreason_aegis.main import Aegis


@pytest.fixture
def aegis():
    return Aegis()


def test_sanitize_stores_owner_id(aegis):
    user_context = MagicMock(spec=UserContext)
    user_context.sub = "owner-1"
    user_context.permissions = []

    text = "Call me at 555-1234."
    sanitized, deid_map = aegis.sanitize(text, user_context=user_context)

    assert deid_map.owner_id == "owner-1"
    assert deid_map.session_id is not None


def test_desanitize_allows_owner(aegis):
    user_context = MagicMock(spec=UserContext)
    user_context.sub = "owner-1"
    user_context.permissions = []

    text = "Hello John Doe"
    sanitized, deid_map = aegis.sanitize(text, user_context=user_context)
    session_id = deid_map.session_id

    desanitized = aegis.desanitize(sanitized, session_id, user_context=user_context)
    assert desanitized == text


def test_desanitize_denies_non_owner(aegis):
    owner_context = MagicMock(spec=UserContext)
    owner_context.sub = "owner-1"
    owner_context.permissions = []

    attacker_context = MagicMock(spec=UserContext)
    attacker_context.sub = "attacker-1"
    attacker_context.permissions = []

    text = "Hello John Doe"
    sanitized, deid_map = aegis.sanitize(text, user_context=owner_context)
    session_id = deid_map.session_id

    with pytest.raises(SecurityException):
        aegis.desanitize(sanitized, session_id, user_context=attacker_context)


def test_desanitize_allows_admin(aegis):
    owner_context = MagicMock(spec=UserContext)
    owner_context.sub = "owner-1"
    owner_context.permissions = []

    admin_context = MagicMock(spec=UserContext)
    admin_context.sub = "admin-1"
    admin_context.permissions = ["Compliance_Admin"]

    text = "Hello John Doe"
    sanitized, deid_map = aegis.sanitize(text, user_context=owner_context)
    session_id = deid_map.session_id

    desanitized = aegis.desanitize(sanitized, session_id, user_context=admin_context)
    assert desanitized == text
