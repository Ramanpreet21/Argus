import yaml
from typing import List, Dict, Any
from pathlib import Path
from pydantic import ValidationError
import logging

from argus.models import AttackPayload

logger = logging.getLogger(__name__)

class PayloadLoader:
    """Loads and validates attack payloads from YAML files."""
    
    def __init__(self, payload_file: str = "payloads/attacks.yaml"):
        self.payload_file = Path(payload_file)
        
    def load_payloads(self) -> List[AttackPayload]:
        """
        Reads the YAML file and parses it into a list of AttackPayload objects.
        Raises ValueError if the file is invalid or missing.
        """
        if not self.payload_file.exists():
            raise FileNotFoundError(f"Payload file not found: {self.payload_file}")
            
        with open(self.payload_file, "r") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse YAML file: {e}")
                raise ValueError(f"Invalid YAML in {self.payload_file}") from e

        if not data or "attacks" not in data:
            raise ValueError(f"Missing 'attacks' root key in {self.payload_file}")

        payloads: List[AttackPayload] = []
        for index, item in enumerate(data["attacks"]):
            try:
                payload = AttackPayload(**item)
                payloads.append(payload)
            except ValidationError as e:
                logger.warning(f"Validation error for payload at index {index}: {e}")
                continue
                
        logger.info(f"Successfully loaded {len(payloads)} payloads.")
        return payloads
