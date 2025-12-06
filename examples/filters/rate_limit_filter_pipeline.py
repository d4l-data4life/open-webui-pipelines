from typing import List, Optional
from pydantic import BaseModel
from schemas import OpenAIChatMessage
from fastapi import HTTPException, status
from datetime import datetime, timezone

import os
import time
import json
import uuid

class Pipeline:
    class Valves(BaseModel):
        # List target pipeline ids (models) that this filter will be connected to.
        # If you want to connect this filter to all pipelines, you can set pipelines to ["*"]
        pipelines: List[str] = []

        # Assign a priority level to the filter pipeline.
        # The priority level determines the order in which the filter pipelines are executed.
        # The lower the number, the higher the priority.
        priority: int = 0

        # Valves for rate limiting
        requests_per_minute: Optional[int] = None
        requests_per_hour: Optional[int] = None
        sliding_window_limit: Optional[int] = None
        sliding_window_minutes: Optional[int] = None

        # Static service metadata
        service_name: str
        service_version: str 
        environment: str

    def __init__(self):
        # Pipeline filters are only compatible with Open WebUI
        # You can think of filter pipeline as a middleware that can be used to edit the form data before it is sent to the OpenAI API.
        self.type = "filter"

        # Optionally, you can set the id and name of the pipeline.
        # Best practice is to not specify the id so that it can be automatically inferred from the filename, so that users can install multiple versions of the same pipeline.
        # The identifier must be unique across all pipelines.
        # The identifier must be an alphanumeric string that can include underscores or hyphens. It cannot contain spaces, special characters, slashes, or backslashes.
        # self.id = "rate_limit_filter_pipeline"
        self.name = "Rate Limit Filter"

        # Initialize rate limits
        self.valves = self.Valves(
            **{
                "pipelines": os.getenv("RATE_LIMIT_PIPELINES", "*").split(","),
                "requests_per_minute": int(
                    os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", 10)
                ),
                "requests_per_hour": int(
                    os.getenv("RATE_LIMIT_REQUESTS_PER_HOUR", 1000)
                ),
                "sliding_window_limit": int(
                    os.getenv("RATE_LIMIT_SLIDING_WINDOW_LIMIT", 100)
                ),
                "sliding_window_minutes": int(
                    os.getenv("RATE_LIMIT_SLIDING_WINDOW_MINUTES", 15)
                ),
                "service_name": os.getenv("AUDIT_LOG_SERVICE_NAME", "open-webui"),
                "service_version": os.getenv("AUDIT_LOG_SERVICE_VERSION", ""),
                "environment": os.getenv("AUDIT_LOG_ENVIRONMENT", ""),
            }
        )

        # Tracking data - user_id -> (timestamps of requests)
        self.user_requests = {}

    async def on_startup(self):
        # This function is called when the server is started.
        print(f"on_startup:{__name__}")
        pass

    async def on_shutdown(self):
        # This function is called when the server is stopped.
        print(f"on_shutdown:{__name__}")
        pass

    def prune_requests(self, user_id: str):
        """Prune old requests that are outside of the sliding window period."""
        now = time.time()
        if user_id in self.user_requests:
            self.user_requests[user_id] = [
                req
                for req in self.user_requests[user_id]
                if (
                    (self.valves.requests_per_minute is not None and now - req < 60)
                    or (self.valves.requests_per_hour is not None and now - req < 3600)
                    or (
                        self.valves.sliding_window_limit is not None
                        and now - req < self.valves.sliding_window_minutes * 60
                    )
                )
            ]

    def log_request(self, user_id: str):
        """Log a new request for a user."""
        now = time.time()
        if user_id not in self.user_requests:
            self.user_requests[user_id] = []
        self.user_requests[user_id].append(now)

    def _base_log(self, body: dict, __user__: Optional[dict]) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        user = __user__["email"]
        # Prefer explicit chat identifiers if present
        trace_id = (
            body.get("chat_id")
            or body.get("metadata", {}).get("chat_id")
            or body.get("session_id")
            or (user.get("id") if user else None)
            or str(uuid.uuid4())
        )

        # Extract and store both model name and ID if available
        model_id = body.get("model")

        return {
            "log-type": "audit",
            "timestamp": now,
            "trace-id": trace_id,
            "service-name": self.valves.service_name,
            "service-version": self.valves.service_version,
            "environment": self.valves.environment,
            "audit-log-type": "security",
            "security-event": "rate_limit_exceeded",
            "successful": False,
            "message": "",
            "caller-ip": "",
            "subject-id": user,
            "owner-id": user,
            "resource-type": model_id,
        }

    def _print_log(self, payload: dict):
        try:
            print(json.dumps(payload, ensure_ascii=False))
        except Exception as e:
            # Fallback to a minimal safe representation
            print(json.dumps({"audit-log-error": str(e)}))

    def rate_limited(self, user_id: str) -> str:
        """Check if a user is rate limited."""
        self.prune_requests(user_id)

        user_reqs = self.user_requests.get(user_id, [])

        if self.valves.requests_per_minute is not None:
            requests_last_minute = sum(1 for req in user_reqs if time.time() - req < 60)
            if requests_last_minute >= self.valves.requests_per_minute:
                return "Requests per minute limit exceeded"

        if self.valves.requests_per_hour is not None:
            requests_last_hour = sum(1 for req in user_reqs if time.time() - req < 3600)
            if requests_last_hour >= self.valves.requests_per_hour:
                return "Requests per hour limit exceeded"

        if self.valves.sliding_window_limit is not None:
            requests_in_window = len(user_reqs)
            if requests_in_window >= self.valves.sliding_window_limit:
                return "Sliding window limit exceeded"

        return ""

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        if user.get("role", "admin") == "user" or True:
            user_id = user["id"] if user and "id" in user else "default_user"
            rate_limit_message = self.rate_limited(user_id)
            if rate_limit_message:
                metadata = body.get("metadata", {})
                chat_id = metadata.get("chat_id", str(uuid.uuid4()))

                # Handle temporary chats
                if chat_id == "local":
                    session_id = metadata.get("session_id")
                    chat_id = f"temporary-session-{session_id}"

                metadata["chat_id"] = chat_id
                body["metadata"] = metadata

                base = self._base_log(body, user)
                base["message"] = rate_limit_message

                self._print_log(self._base_log(body, user))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"{rate_limit_message}. Please try again later.",
                )

            self.log_request(user_id)
        return body
