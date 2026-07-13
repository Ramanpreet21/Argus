# ponytail: simplified from class wrapper to direct function
import yaml
from typing import List
from pathlib import Path
from pydantic import ValidationError
import logging

from argus.models import AttackPayload

logger = logging.getLogger(__name__)

def load_payloads(payload_file: str | Path = "payloads/attacks.yaml") -> List[AttackPayload]:
    """Reads YAML file and parses it into AttackPayload objects."""
    path = Path(payload_file)
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")
        
    with open(path, "r") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML file: {e}")
            raise ValueError(f"Invalid YAML in {path}") from e

    if not data or "attacks" not in data:
        raise ValueError(f"Missing 'attacks' root key in {path}")

    payloads: List[AttackPayload] = []
    for item in data["attacks"]:
        try:
            payloads.append(AttackPayload(**item))
        except ValidationError as e:
            logger.warning(f"Validation error for payload: {e}")
            continue
            
    logger.info(f"Successfully loaded {len(payloads)} payloads.")
    return payloads
