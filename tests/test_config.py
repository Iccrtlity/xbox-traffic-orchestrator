"""Tests for config loading logic (load_config, _write_default_config)."""

import os
import sys
from pathlib import Path

import pytest
import yaml

# Add src/ to path so we can import main
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import main as orchestrator_module


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Remove any ADGUARD_* / POLL_* env vars that might leak between tests."""
    for key in [
        "ADGUARD_URL",
        "ADGUARD_USER",
        "ADGUARD_PASS",
        "POLL_INTERVAL",
        "STARTUP_TIMEOUT",
    ]:
        monkeypatch.delenv(key, raising=False)


class TestWriteDefaultConfig:
    def test_creates_file_with_all_keys(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        orchestrator_module._write_default_config(config_file)

        assert config_file.exists()
        data = yaml.safe_load(config_file.read_text())
        for key in orchestrator_module.DEFAULT_CONFIG:
            assert key in data, f"Missing key: {key}"

    def test_default_values_match(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        orchestrator_module._write_default_config(config_file)
        data = yaml.safe_load(config_file.read_text())

        assert data["adguard_url"] == "http://dns-server:80"
        assert data["adguard_user"] == "admin"
        assert data["adguard_pass"] == ""
        assert data["bypass_duration"] == 3600
        assert data["poll_interval"] == 30
        assert isinstance(data["xbox_domain"], list)
        assert len(data["xbox_domain"]) == 14

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "sub" / "dir" / "config.yaml"
        orchestrator_module._write_default_config(nested)
        assert nested.exists()


class TestLoadConfig:
    def test_loads_from_yaml(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "adguard_url": "http://custom:3000",
                    "adguard_user": "testuser",
                    "adguard_pass": "secret",
                    "xbox_domain": ["a.example.com"],
                    "bypass_duration": 120,
                    "poll_interval": 10,
                    "xbox_client_ip": "10.0.0.5",
                    "startup_timeout": 60,
                }
            )
        )
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)
        config = orchestrator_module.load_config()

        assert config["adguard_url"] == "http://custom:3000"
        assert config["adguard_user"] == "testuser"
        assert config["adguard_pass"] == "secret"
        assert config["xbox_domain"] == ["a.example.com"]
        assert config["bypass_duration"] == 120
        assert config["poll_interval"] == 10
        assert config["xbox_client_ip"] == "10.0.0.5"
        assert config["startup_timeout"] == 60

    def test_env_overrides_sensitive_fields(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(orchestrator_module.DEFAULT_CONFIG))
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)

        monkeypatch.setenv("ADGUARD_URL", "http://env-host:9999")
        monkeypatch.setenv("ADGUARD_USER", "env_user")
        monkeypatch.setenv("ADGUARD_PASS", "env_pass")

        config = orchestrator_module.load_config()

        assert config["adguard_url"] == "http://env-host:9999"
        assert config["adguard_user"] == "env_user"
        assert config["adguard_pass"] == "env_pass"

    def test_env_overrides_numeric_fields(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(orchestrator_module.DEFAULT_CONFIG))
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)

        monkeypatch.setenv("POLL_INTERVAL", "5")
        monkeypatch.setenv("STARTUP_TIMEOUT", "10")

        config = orchestrator_module.load_config()

        assert config["poll_interval"] == 5
        assert config["startup_timeout"] == 10
        assert isinstance(config["poll_interval"], int)

    def test_missing_file_creates_template_and_exits(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)

        with pytest.raises(SystemExit, match="Default config written"):
            orchestrator_module.load_config()

        assert config_file.exists()

    def test_yaml_values_not_in_defaults_are_ignored(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    **orchestrator_module.DEFAULT_CONFIG,
                    "unknown_key": "should_be_ignored",
                }
            )
        )
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)
        config = orchestrator_module.load_config()

        assert "unknown_key" not in config
        # But existing keys are still present
        assert "adguard_url" in config

    def test_empty_env_vars_dont_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "adguard_url": "http://yaml-host:80",
                    "adguard_user": "yaml_user",
                    "adguard_pass": "yaml_pass",
                    "xbox_domain": [],
                    "bypass_duration": 100,
                    "poll_interval": 5,
                    "xbox_client_ip": "",
                    "startup_timeout": 10,
                }
            )
        )
        monkeypatch.setattr(orchestrator_module, "CONFIG_PATH", config_file)
        # Set env to empty string (falsy) – should NOT override
        monkeypatch.setenv("ADGUARD_URL", "")
        monkeypatch.setenv("POLL_INTERVAL", "")

        config = orchestrator_module.load_config()

        assert config["adguard_url"] == "http://yaml-host:80"
        assert config["poll_interval"] == 5
