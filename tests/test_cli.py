import pytest
from typer.testing import CliRunner
import respx
import httpx
from argus.main import app

runner = CliRunner()

@respx.mock
def test_cli_scan_command():
    # Mock baseline and fuzz endpoints
    respx.get("https://api.example.com/users/123").mock(
        return_value=httpx.Response(200, text="User 123 profile")
    )
    
    result = runner.invoke(
        app,
        [
            "scan",
            "--base-url", "https://api.example.com",
            "--endpoint", "/users/123",
            "--payloads", "payloads/attacks.yaml",
            "--format", "table"
        ]
    )
    assert result.exit_code == 0
    assert "Argus Scan Summary" in result.stdout
