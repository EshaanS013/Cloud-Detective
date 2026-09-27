from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import fmean, pstdev

from cloud_detective.detection.models import EventContext
from cloud_detective.schemas.events import CanonicalEvent


@dataclass
class PrincipalHistory:
    events: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    regions: set[str] = field(default_factory=set)
    hourly_counts: dict[datetime, int] = field(default_factory=dict)


class BaselineTracker:
    def __init__(self, started_at: datetime, warmup_hours: int = 24) -> None:
        self.started_at = started_at
        self.warmup = timedelta(hours=warmup_hours)
        self._history: dict[str, PrincipalHistory] = defaultdict(PrincipalHistory)

    def context_for(self, event: CanonicalEvent, country: str | None = None) -> EventContext:
        key = event.principal_arn or event.principal_name or "unknown"
        history = self._history[key]
        hour = event.event_time.replace(minute=0, second=0, microsecond=0)
        completed_counts = [
            count for bucket, count in history.hourly_counts.items() if bucket < hour
        ]
        current_count = history.hourly_counts.get(hour, 0) + 1
        rate_anomaly = False
        if len(completed_counts) >= 2:
            rate_anomaly = current_count > fmean(completed_counts) + 3 * pstdev(completed_counts)
        return EventContext(
            country=country,
            baseline_warmed=event.event_time >= self.started_at + self.warmup,
            api_seen=event.event_name in history.events,
            country_seen=country is None or country in history.countries,
            ip_seen=event.source_ip is None or event.source_ip in history.ips,
            region_seen=event.aws_region in history.regions,
            rate_anomaly=rate_anomaly,
        )

    def update(self, event: CanonicalEvent, country: str | None = None) -> None:
        key = event.principal_arn or event.principal_name or "unknown"
        history = self._history[key]
        hour = event.event_time.replace(minute=0, second=0, microsecond=0)
        history.hourly_counts[hour] = history.hourly_counts.get(hour, 0) + 1
        history.events.add(event.event_name)
        history.regions.add(event.aws_region)
        if event.source_ip:
            history.ips.add(event.source_ip)
        if country:
            history.countries.add(country)

