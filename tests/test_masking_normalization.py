from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


def test_normalization_replace_mode() -> None:
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_norm"

    # Construct text
    phone = "555-0199"
    date = "2023-01-01"
    email = "test@example.com"
    ip = "192.168.1.1"
    key = "KEY"

    text = f"Call {phone} on {date}. Email: {email}. IP: {ip} {key}"

    # Calculate exact indices
    phone_start = text.find(phone)
    phone_end = phone_start + len(phone)

    date_start = text.find(date)
    date_end = date_start + len(date)

    email_start = text.find(email)
    email_end = email_start + len(email)

    ip_start = text.find(ip)
    ip_end = ip_start + len(ip)

    key_start = text.find(key)
    key_end = key_start + len(key)

    # Presidio Types
    results = [
        RecognizerResult("PHONE_NUMBER", phone_start, phone_end, 1.0),
        RecognizerResult("DATE_TIME", date_start, date_end, 1.0),
        RecognizerResult("EMAIL_ADDRESS", email_start, email_end, 1.0),
        RecognizerResult("IP_ADDRESS", ip_start, ip_end, 1.0),
        RecognizerResult("SECRET_KEY", key_start, key_end, 1.0),
    ]

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Check mappings for normalized keys
    # PHONE_NUMBER -> PHONE
    assert "[PHONE_A]" in deid_map.mappings
    assert deid_map.mappings["[PHONE_A]"] == phone

    # DATE_TIME -> DATE
    assert "[DATE_A]" in deid_map.mappings
    assert deid_map.mappings["[DATE_A]"] == date

    # EMAIL_ADDRESS -> EMAIL
    assert "[EMAIL_A]" in deid_map.mappings
    assert deid_map.mappings["[EMAIL_A]"] == email

    # IP_ADDRESS -> IP
    assert "[IP_A]" in deid_map.mappings
    assert deid_map.mappings["[IP_A]"] == ip

    # SECRET_KEY -> KEY
    assert "[KEY_A]" in deid_map.mappings
    assert deid_map.mappings["[KEY_A]"] == key


def test_normalization_mask_mode() -> None:
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.MASK)
    session_id = "sess_norm_mask"

    text = "2023-01-01"
    results = [RecognizerResult("DATE_TIME", 0, 10, 1.0)]

    masked_text, _ = engine.mask(text, results, policy, session_id)

    # Should be [DATE] not [DATE_TIME]
    assert masked_text == "[DATE]"
