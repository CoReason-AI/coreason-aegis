import pytest
from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager
from presidio_analyzer import RecognizerResult


@pytest.fixture
def engine() -> MaskingEngine:
    vault = VaultManager()
    return MaskingEngine(vault)


def test_synthetic_unicode_stability(engine: MaskingEngine) -> None:
    """Verify that non-ASCII characters are handled deterministically."""
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    # "Jian Yang" in Chinese characters (example)
    text = "User \u674e\u660e (Li Ming) logged in."
    # Assume \u674e\u660e is detected as PERSON
    results = [RecognizerResult("PERSON", 5, 7, 1.0)]
    session_id = "sess_unicode"

    masked1, _ = engine.mask(text, results, policy, session_id)
    masked2, _ = engine.mask(text, results, policy, session_id)

    assert masked1 == masked2
    assert "\u674e\u660e" not in masked1
    # Should replace with a fake name (ASCII or whatever Faker produces, usually ASCII for default locale)
    # Just verify it changed and is consistent
    assert masked1 != text


def test_synthetic_repeated_entities(engine: MaskingEngine) -> None:
    """Verify that the same entity appearing multiple times gets the same synthetic value."""
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "John went to the store. John bought milk."
    # Both "John"s detected
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 24, 28, 1.0),
    ]
    session_id = "sess_repeated"

    # Actually call the mask function to ensure it runs
    engine.mask(text, results, policy, session_id)

    # Manual white-box verification for strict equality
    repl1 = engine._get_synthetic_replacement("John", "PERSON")
    repl2 = engine._get_synthetic_replacement("John", "PERSON")
    assert repl1 == repl2


def test_synthetic_cross_session_determinism(engine: MaskingEngine) -> None:
    """Verify that the same entity gets the same synthetic value across sessions."""
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "Sarah Connor"
    results = [RecognizerResult("PERSON", 0, 12, 1.0)]

    masked1, _ = engine.mask(text, results, policy, "session_A")
    masked2, _ = engine.mask(text, results, policy, "session_B")

    assert masked1 == masked2


def test_synthetic_same_text_different_type(engine: MaskingEngine) -> None:
    """Verify that the same text detected as different types produces different values."""
    # Case 1: PERSON
    repl_person = engine._get_synthetic_replacement("Paris", "PERSON")

    # Case 2: DATE_TIME (Just as a different type example that uses a different faker provider)
    # (Using DATE_TIME because we implemented explicit support for it)
    repl_date = engine._get_synthetic_replacement("Paris", "DATE_TIME")

    assert repl_person != repl_date
    # repl_person should look like a name
    # repl_date should look like a date


def test_synthetic_email_consistency(engine: MaskingEngine) -> None:
    """Verify consistency for emails."""
    text = "test@example.com"
    repl1 = engine._get_synthetic_replacement(text, "EMAIL_ADDRESS")
    repl2 = engine._get_synthetic_replacement(text, "EMAIL_ADDRESS")
    assert repl1 == repl2
    assert "@" in repl1


def test_synthetic_ip_consistency(engine: MaskingEngine) -> None:
    """Verify consistency for IPs."""
    text = "192.168.1.1"
    repl1 = engine._get_synthetic_replacement(text, "IP_ADDRESS")
    repl2 = engine._get_synthetic_replacement(text, "IP_ADDRESS")
    assert repl1 == repl2
    assert repl1.count(".") == 3
