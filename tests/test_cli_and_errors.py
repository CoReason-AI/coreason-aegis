
import pytest
from coreason_aegis.main import Aegis, AegisAsync, mask, reidentify, scan


def test_sanitize_missing_context(mock_scanner_engine):
    aegis = Aegis()
    with pytest.raises(ValueError, match="UserContext is required"):
        aegis.sanitize("text", "sess", context=None) # type: ignore

def test_desanitize_missing_context(mock_scanner_engine):
    aegis = Aegis()
    with pytest.raises(ValueError, match="UserContext is required"):
        aegis.desanitize("text", "sess", context=None) # type: ignore

@pytest.mark.asyncio
async def test_sanitize_async_missing_context(mock_scanner_engine):
    async with AegisAsync() as aegis:
        with pytest.raises(ValueError, match="UserContext is required"):
            await aegis.sanitize("text", "sess", context=None) # type: ignore

@pytest.mark.asyncio
async def test_desanitize_async_missing_context(mock_scanner_engine):
    async with AegisAsync() as aegis:
        with pytest.raises(ValueError, match="UserContext is required"):
            await aegis.desanitize("text", "sess", context=None) # type: ignore

def test_cli_scan(capsys, mock_scanner_engine):
    # Mock Scanner.scan to avoid real model
    # Note: scan() instantiates Scanner() internally.
    # We rely on mock_scanner_engine patching AnalyzerEngine.

    scan("John Doe")
    captured = capsys.readouterr()
    assert "Scan Results:" in captured.out

def test_cli_mask(capsys, mock_scanner_engine):
    mask("John Doe", "sess_cli")
    captured = capsys.readouterr()
    assert "Masked Text:" in captured.out

def test_cli_reidentify(capsys, mock_scanner_engine):
    # reidentify uses a new VaultManager, so it will be empty.
    # It should return original text if not found.
    reidentify("[PATIENT_A]", "sess_cli_reid")
    captured = capsys.readouterr()
    assert "Reidentified Text:" in captured.out
