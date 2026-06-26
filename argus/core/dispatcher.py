import asyncio
import time
import logging
from typing import List, Dict, Any, Union

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, wait_fixed

from argus.models import AttackPayload, EndpointConfig, ResponseSnapshot, TargetParam

logger = logging.getLogger(__name__)

class RateLimitException(Exception):
    """Raised when a 429 Too Many Requests is encountered."""
    pass

def log_attempt_number(retry_state):
    logger.debug(f"Retrying request... attempt {retry_state.attempt_number}")

class AsyncDispatcher:
    """Handles asynchronous dispatch of attack payloads to a target endpoint."""

    def __init__(self, config: EndpointConfig, batch_size: int = 5):
        self.config = config
        self.semaphore = asyncio.Semaphore(batch_size)
        self._headers: Dict[str, str] = {}
        if self.config.auth_header:
            # Simple "Header: Value" parsing
            if ":" in self.config.auth_header:
                k, v = self.config.auth_header.split(":", 1)
                self._headers[k.strip()] = v.strip()

    def _prepare_request(self, payload: AttackPayload) -> Dict[str, Any]:
        """Prepares the URL, headers, and data based on the payload target_param."""
        url = f"{self.config.base_url.rstrip('/')}/{self.config.endpoint_path.lstrip('/')}"
        method = payload.method or self.config.method
        
        req_kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": self._headers.copy(),
            "timeout": self.config.timeout_seconds,
        }

        # Inject payload based on target_param
        if payload.target_param == TargetParam.QUERY:
            # We assume a dummy param for pure fuzzing, or append to existing.
            # For this MVP, we just set a 'q' parameter or inject directly.
            req_kwargs["params"] = {"fuzz": payload.payload_value}
        elif payload.target_param == TargetParam.PATH:
            # Simple replacement if {id} exists, otherwise append
            if "{id}" in url:
                req_kwargs["url"] = url.replace("{id}", payload.payload_value)
            else:
                req_kwargs["url"] = f"{url}/{payload.payload_value}"
        elif payload.target_param == TargetParam.HEADER:
            # Assuming payload value is "HeaderName: Value" or just a value for a custom header
            if ":" in payload.payload_value:
                k, v = payload.payload_value.split(":", 1)
                req_kwargs["headers"][k.strip()] = v.strip()
            else:
                req_kwargs["headers"]["X-Argus-Fuzz"] = payload.payload_value
        elif payload.target_param == TargetParam.BODY:
            # Assuming payload value is JSON string or raw text
            req_kwargs["content"] = payload.payload_value

        return req_kwargs

    # Rate limiting gets a strict 30s backoff (per SSOT)
    @retry(
        retry=retry_if_exception_type(RateLimitException),
        wait=wait_fixed(30),
        stop=stop_after_attempt(3),
        before_sleep=log_attempt_number,
        reraise=True
    )
    # General network issues get exponential backoff
    @retry(
        retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        before_sleep=log_attempt_number,
        reraise=True
    )
    async def _send_request(self, client: httpx.AsyncClient, payload: AttackPayload) -> ResponseSnapshot:
        """Sends a single request with retry logic and returns a ResponseSnapshot."""
        req_kwargs = self._prepare_request(payload)
        
        start_time = time.time()
        logger.debug(f"Dispatching payload {payload.id} to {req_kwargs['url']}")
        
        response = await client.request(**req_kwargs)
        
        if response.status_code == 429:
            logger.warning(f"Rate limit hit (429) on payload {payload.id}. Backing off.")
            raise RateLimitException("429 Too Many Requests")
            
        latency_ms = (time.time() - start_time) * 1000
        
        # Truncate body to 1000 chars as per SSOT Ledger
        body_text = response.text[:1000] if response.text else ""
        
        return ResponseSnapshot(
            status_code=response.status_code,
            body=body_text,
            headers_dict=dict(response.headers),
            latency_ms=latency_ms
        )

    async def _bounded_dispatch(self, client: httpx.AsyncClient, payload: AttackPayload) -> Union[ResponseSnapshot, Exception]:
        """Runs the request within the concurrency semaphore."""
        async with self.semaphore:
            try:
                return await self._send_request(client, payload)
            except Exception as e:
                logger.error(f"Failed to dispatch payload {payload.id}: {e}")
                return e

    async def dispatch_all(self, payloads: List[AttackPayload]) -> Dict[str, Union[ResponseSnapshot, str]]:
        """
        Dispatches all payloads concurrently. 
        Returns a mapping of payload.id to either a ResponseSnapshot or an error message.
        """
        results = {}
        
        # Use a single connection pool
        async with httpx.AsyncClient(verify=False) as client:
            tasks = [self._bounded_dispatch(client, p) for p in payloads]
            # return_exceptions=True prevents one failed payload from killing the whole batch
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for payload, res in zip(payloads, responses):
                if isinstance(res, Exception):
                    results[payload.id] = str(res)
                else:
                    results[payload.id] = res
                    
        return results
