"""
title: Audit Log Filter
author: David Weese
date: 2025-09-30
version: 1.0
license: MIT
description: Logs prompts and responses to console in a dedicated audit-log JSON format.
"""

from utils.pipelines.main import get_last_assistant_message, get_last_user_message
from typing import List, Optional, Any
from pydantic import BaseModel
from datetime import datetime, timezone

import os
import json
import uuid
import traceback


def _extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text") or part.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


class Pipeline:
    class Valves(BaseModel):
        pipelines: List[str] = ["*"]
        priority: int = 0

        # Static service metadata
        service_name: str = os.getenv("AUDIT_LOG_SERVICE_NAME", "open-webui")
        service_version: str = os.getenv("AUDIT_LOG_SERVICE_VERSION", "")
        environment: str = os.getenv("AUDIT_LOG_ENVIRONMENT", "")

        # Whether to include content (prompt/response) in logs
        include_content: bool = True

    def __init__(self):
        self.type = "filter"
        self.name = "Audit Log Filter"

        self.valves = self.Valves(
            **{
                "pipelines": os.getenv("AUDIT_LOG_PIPELINES", "*").split(","),
            }
        )

    async def on_startup(self):
        print(f"on_startup:{__name__}")

    async def on_shutdown(self):
        print(f"on_shutdown:{__name__}")

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
            "audit-log-type": "access",
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

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        try:
            metadata = body.get("metadata", {})
            chat_id = metadata.get("chat_id", str(uuid.uuid4()))

            # Handle temporary chats
            if chat_id == "local":
                session_id = metadata.get("session_id")
                chat_id = f"temporary-session-{session_id}"

            metadata["chat_id"] = chat_id
            body["metadata"] = metadata

            base = self._base_log(body, user)
            base["event-type"] = "user_input"

            if self.valves.include_content:
                user_message = get_last_user_message(body["messages"])
                base["additional-data"] = user_message
            else:
                base["additional-data"] = ""

            self._print_log(base)
        except Exception as e:
            print(f"Error: {e}")
            print(traceback.format_exc())
            return body
        return body

    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        try:
            metadata = body.get("metadata", {})
            chat_id = body.get("chat_id")

            # Handle temporary chats
            if chat_id == "local":
                session_id = body.get("session_id")
                chat_id = f"temporary-session-{session_id}"

            metadata["chat_id"] = chat_id
            body["metadata"] = metadata

            base = self._base_log(body, user)
            base["event-type"] = "llm_response"

            if self.valves.include_content:
                assistant_message = get_last_assistant_message(body["messages"])
                base["additional-data"] = assistant_message
            else:
                base["additional-data"] = ""

            self._print_log(base)
        except Exception as e:
            print(f"Error: {e}")
            print(traceback.format_exc())
            return body
        return body
