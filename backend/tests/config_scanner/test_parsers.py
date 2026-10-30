"""Tests for Configuration Parsers.
Verifies multi-format parsing, line number tracking, path traversal security,
binary rejection, and safe error handling.
"""

from pathlib import Path
import pytest

from app.scanners.config_scanner.parsers import (
    SafeConfigParser,
    ParserSecurityError,
    ParsedConfigFile,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "config_scanner"
SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


def test_yaml_parsing_and_line_tracking():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    core_yaml = SAMPLE_DIR / "core_banking" / "core_ledger.yaml"
    result = parser.parse_file(core_yaml)

    assert result.format == "YAML"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    # Verify line numbers are tracked and positive integers
    entries_with_lines = [e for e in result.entries if e.line is not None]
    assert len(entries_with_lines) > 0
    for e in entries_with_lines:
        assert e.line > 0


def test_json_parsing_and_line_tracking():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    upi_json = SAMPLE_DIR / "upi_backend" / "upi_switch.json"
    result = parser.parse_file(upi_json)

    assert result.format == "JSON"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    # Check key paths
    paths = {e.path for e in result.entries}
    assert any("transport_security.cipher_suite" in p for p in paths)


def test_toml_parsing():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    pqc_toml = SAMPLE_DIR / "upi_backend" / "pqc_pilot.toml"
    result = parser.parse_file(pqc_toml)

    assert result.format == "TOML"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    paths = {e.path for e in result.entries}
    assert any("crypto.primitives.kem_algorithm" in p for p in paths)


def test_ini_parsing():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    card_ini = SAMPLE_DIR / "payment_gateway" / "payment_switch.ini"
    result = parser.parse_file(card_ini)

    assert result.format == "INI"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    paths = {e.path for e in result.entries}
    assert "tls_transport.tls_version" in paths
    assert "hardware_security_module.hsm_vendor" in paths


def test_properties_parsing():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    prop_file = SAMPLE_DIR / "payment_gateway" / "tokenization.properties"
    result = parser.parse_file(prop_file)

    assert result.format == "PROPERTIES"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    paths = {e.path for e in result.entries}
    assert "tokenization.algorithm" in paths


def test_env_parsing():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    env_file = SAMPLE_DIR / "core_banking" / "database_crypto.env"
    result = parser.parse_file(env_file)

    assert result.format == "ENV"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    paths = {e.path for e in result.entries}
    assert "DB_ENCRYPTION_CIPHER" in paths


def test_xml_parsing():
    parser = SafeConfigParser(root_dir=FIXTURES_DIR)
    xml_file = FIXTURES_DIR / "sample_xml.xml"
    result = parser.parse_file(xml_file)

    assert result.format == "XML"
    assert len(result.errors) == 0
    assert len(result.entries) > 0

    paths = {e.path for e in result.entries}
    assert any("protocol" in p for p in paths)


def test_malformed_yaml_safe_handling():
    parser = SafeConfigParser(root_dir=FIXTURES_DIR)
    mal_yaml = FIXTURES_DIR / "malformed.yaml"
    result = parser.parse_file(mal_yaml)

    # Should not crash; errors captured
    assert len(result.errors) > 0


def test_malformed_json_safe_handling():
    parser = SafeConfigParser(root_dir=FIXTURES_DIR)
    mal_json = FIXTURES_DIR / "malformed.json"
    result = parser.parse_file(mal_json)

    assert len(result.errors) > 0


def test_unsupported_file_extension():
    parser = SafeConfigParser(root_dir=FIXTURES_DIR)
    unsupported = FIXTURES_DIR / "unsupported.xyz"
    result = parser.parse_file(unsupported)

    assert result.format == "UNSUPPORTED"
    assert len(result.errors) > 0


def test_path_traversal_rejection():
    parser = SafeConfigParser(root_dir=SAMPLE_DIR)
    # Attempting to access file outside root_dir
    outside_file = FIXTURES_DIR / "sample_xml.xml"

    with pytest.raises(ParserSecurityError, match="Path traversal detected"):
        parser.validate_file_path(outside_file)


def test_binary_file_rejection():
    parser = SafeConfigParser(root_dir=FIXTURES_DIR)
    bin_file = FIXTURES_DIR / "binary_mock.bin"

    with pytest.raises(ParserSecurityError, match="Binary file rejected"):
        parser.validate_file_path(bin_file)
