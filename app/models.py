"""Pydantic models: validated query parameters and API responses."""

from datetime import datetime, timedelta
from enum import IntEnum
from typing import Annotated, Self

from pydantic import BaseModel, Field, StringConstraints, model_validator


class Priority(IntEnum):
    """Standard syslog severity levels (0 = most severe)."""

    EMERG = 0
    ALERT = 1
    CRIT = 2
    ERR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


# Allow-list of characters seen in real SYSLOG_IDENTIFIER values
# (e.g. "brave-browser.desktop", "firefox_firefox.desktop", "(sd-pam)").
Identifier = Annotated[
    str, StringConstraints(pattern=r"^[\w.@:/()+-]{1,128}$")
]

MAX_RANGE = timedelta(days=31)
DEFAULT_RANGE = timedelta(hours=1)


class LogQuery(BaseModel):
    """Filters accepted by GET /api/logs. Every field is bounded."""

    model_config = {"extra": "forbid"}

    identifiers: list[Identifier] = Field(default_factory=list, max_length=20)
    priorities: set[Priority] = Field(default_factory=lambda: set(Priority))
    since: datetime | None = None
    until: datetime | None = None
    text: Annotated[str, StringConstraints(max_length=200, strip_whitespace=True)] = ""
    crash_only: bool = False
    limit: int = Field(default=500, ge=1, le=5000)

    @model_validator(mode="after")
    def check_time_range(self) -> Self:
        # Naive datetimes (from <input type="datetime-local">) are local time.
        until = (self.until or datetime.now()).astimezone()
        since = (self.since or until - DEFAULT_RANGE).astimezone()
        if since >= until:
            raise ValueError("'since' must be before 'until'")
        if until - since > MAX_RANGE:
            raise ValueError("time range cannot exceed 31 days")
        if not self.priorities:
            raise ValueError("select at least one priority")
        self.since, self.until = since, until
        return self


class LogEntry(BaseModel):
    timestamp: datetime
    priority: Priority
    priority_name: str
    identifier: str
    pid: int | None
    unit: str | None
    message: str
    crash_hint: bool


class LogResult(BaseModel):
    entries: list[LogEntry]
    truncated: bool  # True when `limit` was reached: older entries exist
