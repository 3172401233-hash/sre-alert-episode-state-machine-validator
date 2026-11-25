"""离线告警 episode 状态机校验器。

该模块只做本地计算，不连接 Alertmanager、Webhook、邮件或任何通知通道。
它消费已经发生的 firing/resolved、silence、GroupKey、窗口和通知状态，
输出 episode 时间线、合并事件以及有问题的通知审计。

设计要点：

* 事件按“事件发生时间”而不是通知到达时间重放，因此乱序输入是安全的。
* resolved 优先通过 occurrence/event 关联；没有关联 ID 时使用 resolved
  自带的原始 firing 时间，避免迟到恢复关闭后续 firing。
* silence 只改变通知是否应发送/被抑制，不删除或改写真实告警状态。
* 同一 GroupKey 在恢复窗口内的再次 firing 会重开同一个 episode，保留
  连续证据；超过窗口才形成新 episode。

目标语法兼容 Python 3.8.2。
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


FIRING = "firing"
RESOLVED = "resolved"

STATUS_FIRING = FIRING
STATUS_RESOLVED = RESOLVED

NOTIFICATION_SENT = "sent"
NOTIFICATION_DELIVERED = "delivered"
NOTIFICATION_FAILED = "failed"
NOTIFICATION_SUPPRESSED = "suppressed"
NOTIFICATION_PENDING = "pending"

DELIVERED_NOTIFICATION_STATUSES = frozenset(
    [NOTIFICATION_SENT, NOTIFICATION_DELIVERED, "acknowledged"]
)

_ALERT_STATUS_ALIASES = {
    "firing": FIRING,
    "triggered": FIRING,
    "active": FIRING,
    "alerting": FIRING,
    "触发": FIRING,
    "告警中": FIRING,
    "resolved": RESOLVED,
    "recovered": RESOLVED,
    "ok": RESOLVED,
    "closed": RESOLVED,
    "恢复": RESOLVED,
    "已恢复": RESOLVED,
}

_NOTIFICATION_STATUS_ALIASES = {
    "sent": NOTIFICATION_SENT,
    "delivered": NOTIFICATION_DELIVERED,
    "success": NOTIFICATION_DELIVERED,
    "successful": NOTIFICATION_DELIVERED,
    "ok": NOTIFICATION_DELIVERED,
    "已发送": NOTIFICATION_SENT,
    "已送达": NOTIFICATION_DELIVERED,
    "failed": NOTIFICATION_FAILED,
    "failure": NOTIFICATION_FAILED,
    "error": NOTIFICATION_FAILED,
    "发送失败": NOTIFICATION_FAILED,
    "失败": NOTIFICATION_FAILED,
    "suppressed": NOTIFICATION_SUPPRESSED,
    "silenced": NOTIFICATION_SUPPRESSED,
    "muted": NOTIFICATION_SUPPRESSED,
    "已抑制": NOTIFICATION_SUPPRESSED,
    "已静默": NOTIFICATION_SUPPRESSED,
    "pending": NOTIFICATION_PENDING,
    "queued": NOTIFICATION_PENDING,
    "待发送": NOTIFICATION_PENDING,
}


# ---------------------------------------------------------------------------
# 值对象和解析函数
# ---------------------------------------------------------------------------


def parse_time(value: Any) -> Optional[float]:
    """把数字秒、datetime 或 ISO 8601 字符串转换为 Unix 秒。

    不带时区的 datetime/ISO 字符串按 UTC 处理。``None`` 原样返回。
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass

    iso_text = text
    if iso_text.endswith(("Z", "z")):
        iso_text = iso_text[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso_text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def format_time(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    return (
        datetime.fromtimestamp(float(value), tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_duration_seconds(value: Any, default: float = 1800.0) -> float:
    """解析秒数、timedelta 或 ``30m`` / ``1h`` / ``PT30M`` 形式。"""
    if value is None:
        return float(default)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, timedelta):
        return value.total_seconds()

    text = str(value).strip()
    if not text:
        return float(default)
    try:
        return float(text)
    except ValueError:
        pass

    iso_match = re.fullmatch(
        r"P(?:(\d+)D)?T?(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?",
        text,
        flags=re.IGNORECASE,
    )
    if text.upper().startswith("P") and iso_match:
        days = float(iso_match.group(1) or 0)
        hours = float(iso_match.group(2) or 0)
        minutes = float(iso_match.group(3) or 0)
        seconds = float(iso_match.group(4) or 0)
        return days * 86400 + hours * 3600 + minutes * 60 + seconds

    match = re.fullmatch(
        r"(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|秒|m|min|mins|minute|minutes|分钟|分|h|hr|hour|hours|小时|时)?",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError("unsupported duration: %r" % (value,))
    amount = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    if unit.startswith("h") or unit in ("小时", "时"):
        return amount * 3600
    if unit.startswith("m") or unit in ("min", "mins") or unit in ("分钟", "分"):
        return amount * 60
    return amount


def normalize_alert_status(value: Any, default: Optional[str] = None) -> str:
    if value is None:
        if default is None:
            raise ValueError("alert status is required")
        return default
    key = str(value).strip().lower()
    if key in _ALERT_STATUS_ALIASES:
        return _ALERT_STATUS_ALIASES[key]
    if key in (FIRING, RESOLVED):
        return key
    raise ValueError("unknown alert status: %r" % (value,))


def normalize_notification_status(value: Any) -> Tuple[str, bool]:
    """返回标准状态和是否可识别。未知状态保留原值并标记 invalid。"""
    if value is None:
        return "unknown", False
    key = str(value).strip().lower()
    normalized = _NOTIFICATION_STATUS_ALIASES.get(key)
    if normalized:
        return normalized, True
    return str(value), False


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _parse_group_key_string(text: str) -> Dict[str, str]:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        body = stripped[1:-1].strip()
        result = {}  # type: Dict[str, str]
        if not body:
            return result
        for part in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", body):
            if "=" not in part:
                continue
            name, raw_value = part.split("=", 1)
            name = name.strip()
            raw_value = raw_value.strip()
            if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] == '"':
                raw_value = raw_value[1:-1].replace('\\"', '"')
            result[name] = raw_value
        if result:
            return result
    return {"__key__": stripped}


class GroupKey:
    """不可变、可哈希的告警 GroupKey。

    支持 ``GroupKey("cpu")``、``GroupKey(alertname="CPU", service="api")``、
    dict、Alertmanager 风格字符串以及已有 ``GroupKey``。
    """

    def __init__(
        self,
        value: Any = None,
        labels: Optional[Mapping[str, Any]] = None,
        group_by: Optional[Sequence[str]] = None,
        **kwargs: Any
    ) -> None:
        data = {}  # type: Dict[str, Any]

        if isinstance(value, GroupKey):
            data.update(value.as_dict())
        elif isinstance(value, Mapping):
            data.update(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, Mapping):
                    data.update(item)
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    data[str(item[0])] = item[1]
                else:
                    data["__key__"] = item
        elif value is not None:
            data.update(_parse_group_key_string(_stringify(value)))

        if labels:
            data.update(labels)
        if kwargs:
            data.update(kwargs)

        if group_by:
            allowed = set(group_by)
            data = {name: item for name, item in data.items() if name in allowed}

        self._labels = tuple(
            sorted(
                (str(name), _stringify(item))
                for name, item in data.items()
                if item is not None
            )
        )
        self._label_dict = dict(self._labels)
        self._canonical = self._build_canonical()

    def _build_canonical(self) -> str:
        if len(self._labels) == 1 and self._labels[0][0] == "__key__":
            return self._labels[0][1]
        if not self._labels:
            return "default"
        parts = []
        for name, value in self._labels:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            parts.append('%s="%s"' % (name, escaped))
        return "{" + ", ".join(parts) + "}"

    @property
    def canonical(self) -> str:
        return self._canonical

    @property
    def labels(self) -> Dict[str, str]:
        return dict(self._label_dict)

    def as_dict(self) -> Dict[str, str]:
        return dict(self._label_dict)

    def matches(self, matchers: Optional[Mapping[str, Any]]) -> bool:
        if not matchers:
            return True
        return all(self._label_dict.get(str(name)) == _stringify(value)
                   for name, value in matchers.items())

    def __str__(self) -> str:
        return self._canonical

    def __repr__(self) -> str:
        return "GroupKey(%r)" % self._canonical

    def __hash__(self) -> int:
        return hash(self._labels)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, GroupKey):
            return NotImplemented
        return self._labels == other._labels


# ---------------------------------------------------------------------------
# 输入模型
# ---------------------------------------------------------------------------


@dataclass
class AlertEvent:
    kind: str
    time: float
    group_key: GroupKey
    event_id: str
    input_index: int = 0
    occurrence_id: Optional[str] = None
    correlation_id: Optional[str] = None
    correlation_time: Optional[float] = None
    received_at: Optional[float] = None
    source: str = "unknown"
    labels: Dict[str, str] = field(default_factory=dict)
    notification_id: Optional[str] = None
    notification_status: Optional[str] = None
    notification_sent_at: Optional[float] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Silence:
    silence_id: str
    starts_at: float
    ends_at: Optional[float] = None
    group_key: Optional[GroupKey] = None
    matchers: Dict[str, str] = field(default_factory=dict)
    comment: Optional[str] = None

    def matches(
        self,
        group_key: Optional[GroupKey],
        labels: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        if self.group_key is not None and group_key is not None:
            if self.group_key != group_key:
                return False
        elif self.group_key is not None and group_key is None:
            return False

        if self.matchers:
            source_labels = dict(labels or {})
            if group_key is not None:
                for name, value in group_key.labels.items():
                    source_labels.setdefault(name, value)
            if not all(
                _stringify(source_labels.get(str(name))) == _stringify(value)
                for name, value in self.matchers.items()
            ):
                return False

        return True

    def active_at(
        self,
        timestamp: float,
        group_key: Optional[GroupKey] = None,
        labels: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        if timestamp < self.starts_at:
            return False
        if self.ends_at is not None and timestamp >= self.ends_at:
            return False
        return self.matches(group_key, labels)


@dataclass
class NotificationRecord:
    notification_id: str
    input_index: int = 0
    group_key: Optional[GroupKey] = None
    kind: Optional[str] = None
    status: Optional[str] = None
    raw_status: Any = None
    valid_status: bool = True
    event_id: Optional[str] = None
    occurrence_id: Optional[str] = None
    created_at: Optional[float] = None
    sent_at: Optional[float] = None
    error: Optional[str] = None
    applied_episode_id: Optional[str] = None
    applied_occurrence_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


def _first_key(data: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return None


def _coerce_labels(value: Any) -> Dict[str, str]:
    if not value:
        return {}
    if isinstance(value, Mapping):
        return {str(k): _stringify(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        result = {}
        for item in value:
            if isinstance(item, Mapping):
                name = _first_key(item, ("name", "key"))
                val = _first_key(item, ("value", "val"))
                if name is not None:
                    result[str(name)] = _stringify(val)
        return result
    return {"labels": _stringify(value)}


def _key_from_item(
    item: Mapping[str, Any],
    default_key: Optional[GroupKey],
    group_by: Optional[Sequence[str]],
) -> GroupKey:
    raw_key = _first_key(
        item,
        ("group_key", "GroupKey", "groupKey", "group", "key"),
    )
    if raw_key is not None:
        return GroupKey(raw_key, group_by=group_by)

    labels = _coerce_labels(item.get("labels") or item.get("Labels"))
    if group_by and labels:
        return GroupKey(labels=labels, group_by=group_by)
    if labels and default_key is None:
        return GroupKey(labels=labels)
    if default_key is not None:
        return default_key
    if labels:
        return GroupKey(labels=labels)
    return GroupKey("default")


def coerce_event(
    item: Any,
    kind: Optional[str] = None,
    default_key: Optional[GroupKey] = None,
    group_by: Optional[Sequence[str]] = None,
    input_index: int = 0,
) -> AlertEvent:
    if isinstance(item, AlertEvent):
        item.input_index = input_index
        return item

    if not isinstance(item, Mapping):
        inferred_kind = kind or FIRING
        return AlertEvent(
            kind=inferred_kind,
            time=parse_time(item) or 0.0,
            group_key=default_key or GroupKey("default"),
            event_id="event-%d" % (input_index + 1),
            input_index=input_index,
        )

    raw_kind = kind or _first_key(item, ("kind", "event_type", "type", "alert_type"))
    if raw_kind is None:
        raw_kind = item.get("status") if item.get("status") in (FIRING, RESOLVED) else None
    event_kind = normalize_alert_status(raw_kind, default=FIRING)

    if event_kind == RESOLVED:
        raw_time = _first_key(
            item,
            (
                "resolved_at",
                "recovery_at",
                "recovered_at",
                "ended_at",
                "end_time",
                "ends_at",
                "endsAt",
                "time",
                "timestamp",
                "occurred_at",
                "event_time",
            ),
        )
    else:
        raw_time = _first_key(
            item,
            (
                "fired_at",
                "start_time",
                "started_at",
                "starts_at",
                "startsAt",
                "time",
                "timestamp",
                "occurred_at",
                "event_time",
            ),
        )

    event_time = parse_time(raw_time)
    if event_time is None:
        raise ValueError("alert event requires a time: %r" % (item,))

    raw_received = _first_key(
        item, ("received_at", "arrived_at", "arrival_time", "notification_at")
    )
    raw_correlation_time = _first_key(
        item,
        (
            "firing_time",
            "fired_at",
            "original_starts_at",
            "originalStartsAt",
            "starts_at",
            "startsAt",
        ),
    )

    event_id = _first_key(item, ("event_id", "id", "notification_event_id"))
    occurrence_id = _first_key(
        item, ("occurrence_id", "alert_id", "firing_id", "occurrence")
    )
    correlation_id = _first_key(
        item,
        ("firing_event_id", "for_event_id", "event_ref", "in_reply_to", "caused_by"),
    )

    notification = item.get("notification")
    if isinstance(notification, Mapping):
        notification_id = notification.get("notification_id") or notification.get("id")
        notification_status = notification.get("status")
        notification_sent_at = parse_time(
            _first_key(notification, ("sent_at", "created_at", "time"))
        )
    else:
        notification_id = item.get("notification_id")
        notification_status = _first_key(
            item, ("notification_status", "notify_status", "delivery_status")
        )
        notification_sent_at = parse_time(
            _first_key(item, ("notification_sent_at", "status_updated_at"))
        )

    return AlertEvent(
        kind=event_kind,
        time=event_time,
        group_key=_key_from_item(item, default_key, group_by),
        event_id=str(event_id) if event_id is not None else "event-%d" % (input_index + 1),
        input_index=input_index,
        occurrence_id=str(occurrence_id) if occurrence_id is not None else None,
        correlation_id=str(correlation_id) if correlation_id is not None else None,
        correlation_time=parse_time(raw_correlation_time),
        received_at=parse_time(raw_received),
        source=str(item.get("source", "unknown")),
        labels=_coerce_labels(item.get("labels") or item.get("Labels")),
        notification_id=str(notification_id) if notification_id is not None else None,
        notification_status=(
            str(notification_status) if notification_status is not None else None
        ),
        notification_sent_at=notification_sent_at,
        raw=dict(item),
    )


def coerce_silence(
    item: Any,
    default_key: Optional[GroupKey] = None,
    group_by: Optional[Sequence[str]] = None,
    index: int = 0,
) -> Silence:
    if isinstance(item, Silence):
        return item
    if not isinstance(item, Mapping):
        raise ValueError("silence must be a mapping or Silence: %r" % (item,))

    starts_raw = _first_key(
        item, ("starts_at", "start", "start_at", "started_at", "startTime")
    )
    ends_raw = _first_key(
        item, ("ends_at", "end", "end_at", "ended_at", "expires_at", "endTime")
    )
    starts_at = parse_time(starts_raw)
    if starts_at is None:
        raise ValueError("silence requires starts_at: %r" % (item,))

    raw_key = _first_key(item, ("group_key", "GroupKey", "groupKey", "key"))
    group_key = GroupKey(raw_key, group_by=group_by) if raw_key is not None else None
    if group_key is None:
        labels = _coerce_labels(item.get("labels"))
        if labels:
            group_key = GroupKey(labels=labels, group_by=group_by)
        elif default_key is not None and item.get("use_default_key", False):
            group_key = default_key

    matchers = _coerce_labels(item.get("matchers") or item.get("matcher"))
    if not matchers and item.get("labels") and group_key is None:
        matchers = _coerce_labels(item.get("labels"))

    silence_id = _first_key(item, ("silence_id", "id", "uuid"))
    return Silence(
        silence_id=str(silence_id) if silence_id is not None else "silence-%d" % (index + 1),
        starts_at=starts_at,
        ends_at=parse_time(ends_raw),
        group_key=group_key,
        matchers=matchers,
        comment=item.get("comment"),
    )


def coerce_notification(
    item: Any,
    default_key: Optional[GroupKey] = None,
    group_by: Optional[Sequence[str]] = None,
    index: int = 0,
) -> NotificationRecord:
    if isinstance(item, NotificationRecord):
        item.input_index = index
        return item
    if not isinstance(item, Mapping):
        raise ValueError("notification must be a mapping: %r" % (item,))

    raw_key = _first_key(item, ("group_key", "GroupKey", "groupKey", "key"))
    raw_status = _first_key(item, ("status", "state", "delivery_status"))
    status, valid_status = normalize_notification_status(raw_status)
    kind = item.get("kind") or item.get("notification_type") or item.get("alert_status")
    if kind is not None:
        try:
            kind = normalize_alert_status(kind)
        except ValueError:
            kind = str(kind)

    created_raw = _first_key(item, ("created_at", "queued_at", "time"))
    sent_raw = _first_key(item, ("sent_at", "delivered_at", "updated_at"))
    notif_id = _first_key(item, ("notification_id", "id", "message_id"))

    return NotificationRecord(
        notification_id=str(notif_id) if notif_id is not None else "notification-%d" % (index + 1),
        input_index=index,
        group_key=(
            GroupKey(raw_key, group_by=group_by)
            if raw_key is not None
            else default_key
        ),
        kind=kind,
        status=status,
        raw_status=raw_status,
        valid_status=valid_status,
        event_id=(
            str(item["event_id"])
            if item.get("event_id") is not None
            else None
        ),
        occurrence_id=(
            str(_first_key(item, ("occurrence_id", "firing_id", "alert_id")))
            if _first_key(item, ("occurrence_id", "firing_id", "alert_id")) is not None
            else None
        ),
        created_at=parse_time(created_raw),
        sent_at=parse_time(sent_raw),
        error=item.get("error"),
        applied_episode_id=(
            str(item["applied_episode_id"])
            if item.get("applied_episode_id") is not None
            else (
                str(item["closed_episode_id"])
                if item.get("closed_episode_id") is not None
                else None
            )
        ),
        applied_occurrence_id=(
            str(item["applied_occurrence_id"])
            if item.get("applied_occurrence_id") is not None
            else (
                str(item["closed_occurrence_id"])
                if item.get("closed_occurrence_id") is not None
                else None
            )
        ),
        raw=dict(item),
    )


# ---------------------------------------------------------------------------
# 内部 occurrence
# ---------------------------------------------------------------------------


@dataclass
class Occurrence:
    occurrence_id: str
    group_key: GroupKey
    first_event: AlertEvent
    firing_events: List[AlertEvent] = field(default_factory=list)
    exact_duplicate_deliveries: List[AlertEvent] = field(default_factory=list)
    resolved_event: Optional[AlertEvent] = None
    resolved_at: Optional[float] = None
    duplicate_resolved_events: List[AlertEvent] = field(default_factory=list)
    invalid_events: List[AlertEvent] = field(default_factory=list)
    episode_id: Optional[str] = None

    @property
    def all_firing_events(self) -> List[AlertEvent]:
        return list(self.firing_events) + list(self.exact_duplicate_deliveries)


class EpisodeValidator:
    """根据离线事件构造 episode 报告。"""

    def __init__(
        self,
        window_seconds: Any = 1800,
        group_by: Optional[Sequence[str]] = None,
        now: Any = None,
    ) -> None:
        self.window_seconds = parse_duration_seconds(window_seconds)
        self.group_by = list(group_by) if group_by else None
        self.now = parse_time(now)
        self._all_silences = []  # type: List[Silence]

    def validate(
        self,
        events: Optional[Sequence[Any]] = None,
        firing: Optional[Sequence[Any]] = None,
        resolved: Optional[Sequence[Any]] = None,
        silences: Optional[Sequence[Any]] = None,
        notifications: Any = None,
        notification_status: Any = None,
        group_key: Any = None,
        window: Any = None,
        now: Any = None,
    ) -> Dict[str, Any]:
        if window is not None:
            self.window_seconds = parse_duration_seconds(window)
        if now is not None:
            self.now = parse_time(now)

        default_key = GroupKey(group_key, group_by=self.group_by) if group_key is not None else None
        alert_events = self._normalize_events(events, firing, resolved, default_key)
        silence_records = self._normalize_silences(silences, default_key)
        notification_records = self._normalize_notifications(
            notifications, notification_status, alert_events, default_key
        )

        observed_now = self.now
        if observed_now is None:
            time_values = [event.time for event in alert_events]
            time_values.extend(
                event.received_at for event in alert_events if event.received_at is not None
            )
            time_values.extend(
                record.starts_at for record in silence_records
            )
            time_values.extend(
                record.ends_at
                for record in silence_records
                if record.ends_at is not None
            )
            for notif in notification_records:
                time_values.extend(
                    value
                    for value in (notif.created_at, notif.sent_at)
                    if value is not None
                )
            observed_now = max(time_values) if time_values else 0.0

        groups, errors = self._build_groups(alert_events)
        self._all_silences = silence_records
        episodes = self._build_episodes(groups, silence_records, observed_now)
        self._assign_public_episode_ids(groups, episodes)

        timeline = self._build_timeline(
            groups, episodes, silence_records, notification_records
        )
        timeline = self._replace_internal_episode_ids(timeline, episodes)
        error_notifications, notif_reports = self._audit_notifications(
            notification_records, groups, episodes, alert_events, observed_now
        )
        silence_reports = self._build_silence_reports(groups, silence_records)
        merged_events = self._build_merged_events(groups)
        merged_events = self._replace_internal_merge_episode_ids(merged_events, episodes)

        for episode in episodes:
            episode["occurrences"] = [
                self._occurrence_report(ref["object"])
                for ref in episode["occurrences"]
            ]
            episode.pop("group_key_object", None)
            episode.pop("internal_id", None)

        group_reports = []
        for group_index, (key, group) in enumerate(groups.items(), start=1):
            group_episodes = [
                ep for ep in episodes if ep["group_key_text"] == key.canonical
            ]
            group_report = {
                "group_key": key.as_dict(),
                "group_key_text": key.canonical,
                "episode_count": len(group_episodes),
                "occurrence_count": len(group["occurrences"]),
                "episodes": [
                    {k: v for k, v in ep.items() if k != "timeline"}
                    for ep in group_episodes
                ],
                "timeline": [
                    entry
                    for entry in timeline
                    if entry.get("group_key_text") == key.canonical
                ],
            }
            group_reports.append(group_report)

        summary = {
            "window_seconds": self.window_seconds,
            "now": observed_now,
            "now_iso": format_time(observed_now),
            "group_count": len(groups),
            "episode_count": len(episodes),
            "open_episode_count": sum(
                1 for ep in episodes if ep["status"] == FIRING
            ),
            "closed_episode_count": sum(
                1 for ep in episodes if ep["status"] == "closed"
            ),
            "reopened_episode_count": sum(
                1 for ep in episodes if ep["reopen_count"] > 0
            ),
            "event_count": len(alert_events),
            "merged_event_count": len(merged_events),
            "silence_count": len(silence_records),
            "notification_count": len(notification_records),
            "error_notification_count": len(error_notifications),
            "validation_error_count": len(errors),
            "notifications_sent": False,
        }

        return {
            "summary": summary,
            "window_seconds": self.window_seconds,
            "now": observed_now,
            "now_iso": format_time(observed_now),
            "group_key": default_key.as_dict() if default_key else None,
            "groups": group_reports,
            "episodes": episodes,
            "timeline": timeline,
            "merged_events": merged_events,
            "silences": silence_reports,
            "notifications": notif_reports,
            "error_notifications": error_notifications,
            "errors": errors,
            "notifications_sent": False,
        }

    # ------------------------------------------------------------------ input

    def _normalize_events(
        self,
        events: Optional[Sequence[Any]],
        firing: Optional[Sequence[Any]],
        resolved: Optional[Sequence[Any]],
        default_key: Optional[GroupKey],
    ) -> List[AlertEvent]:
        result = []  # type: List[AlertEvent]
        index = 0

        for item in list(events or []):
            kind = None
            if isinstance(item, Mapping):
                kind = _first_key(item, ("kind", "event_type", "type"))
            result.append(
                coerce_event(item, kind, default_key, self.group_by, index)
            )
            index += 1

        for item in list(firing or []):
            result.append(
                coerce_event(item, FIRING, default_key, self.group_by, index)
            )
            index += 1

        for item in list(resolved or []):
            result.append(
                coerce_event(item, RESOLVED, default_key, self.group_by, index)
            )
            index += 1

        return result

    def _normalize_silences(
        self,
        silences: Optional[Sequence[Any]],
        default_key: Optional[GroupKey],
    ) -> List[Silence]:
        result = []
        for index, item in enumerate(silences or []):
            result.append(coerce_silence(item, default_key, self.group_by, index))
        return result

    def _normalize_notifications(
        self,
        notifications: Any,
        notification_status: Any,
        events: Sequence[AlertEvent],
        default_key: Optional[GroupKey],
    ) -> List[NotificationRecord]:
        raw_items = []  # type: List[Any]

        if notifications is not None:
            if isinstance(notifications, Mapping):
                for notif_id, value in notifications.items():
                    if isinstance(value, Mapping):
                        item = dict(value)
                        item.setdefault("notification_id", notif_id)
                    else:
                        item = {"notification_id": notif_id, "status": value}
                    raw_items.append(item)
            else:
                raw_items.extend(list(notifications))

        if notification_status is not None:
            if isinstance(notification_status, Mapping):
                for notif_id, value in notification_status.items():
                    if isinstance(value, Mapping):
                        item = dict(value)
                        item.setdefault("notification_id", notif_id)
                    else:
                        item = {"notification_id": notif_id, "status": value}
                    raw_items.append(item)
            else:
                raw_items.extend(list(notification_status))

        for event in events:
            if event.notification_status is None and not event.notification_id:
                embedded = event.raw.get("notifications")
                if isinstance(embedded, Sequence) and not isinstance(embedded, (str, bytes)):
                    for item in embedded:
                        if isinstance(item, Mapping):
                            item = dict(item)
                            item.setdefault("event_id", event.event_id)
                            item.setdefault("group_key", event.group_key)
                        raw_items.append(item)
                continue

            item = {
                "notification_id": event.notification_id
                or ("notif-%s" % event.event_id),
                "event_id": event.event_id,
                "group_key": event.group_key,
                "kind": event.kind,
                "status": event.notification_status,
                "sent_at": event.notification_sent_at,
            }
            raw_items.append(item)

        records = []
        for index, item in enumerate(raw_items):
            if isinstance(item, NotificationRecord):
                item.input_index = index
                records.append(item)
            else:
                records.append(
                    coerce_notification(item, default_key, self.group_by, index)
                )
        return records

    # ------------------------------------------------------------- occurrence

    def _build_groups(
        self, events: Sequence[AlertEvent]
    ) -> Tuple["OrderedDict[GroupKey, Dict[str, Any]]", List[Dict[str, Any]]]:
        groups = OrderedDict()  # type: OrderedDict[GroupKey, Dict[str, Any]]
        errors = []  # type: List[Dict[str, Any]]

        for event in sorted(events, key=lambda item: (item.time, item.input_index)):
            group = groups.get(event.group_key)
            if group is None:
                group = {"key": event.group_key, "occurrences": []}
                groups[event.group_key] = group

            if event.kind == FIRING:
                self._apply_firing(group, event)
            elif event.kind == RESOLVED:
                self._apply_resolved(group, event, errors)
            else:
                errors.append(
                    {
                        "code": "unknown_event_kind",
                        "event_id": event.event_id,
                        "kind": event.kind,
                        "time": event.time,
                    }
                )

        return groups, errors

    def _apply_firing(self, group: Dict[str, Any], event: AlertEvent) -> Occurrence:
        occurrences = group["occurrences"]  # type: List[Occurrence]
        occurrence = None  # type: Optional[Occurrence]

        if event.occurrence_id:
            for existing in occurrences:
                if existing.occurrence_id == event.occurrence_id:
                    occurrence = existing
                    break

        if occurrence is None and not event.occurrence_id:
            last = occurrences[-1] if occurrences else None
            if last is not None and last.resolved_at is None:
                occurrence = last

        if occurrence is None:
            occurrence_id = event.occurrence_id or "occ-%d" % (len(occurrences) + 1)
            occurrence = Occurrence(
                occurrence_id=occurrence_id,
                group_key=event.group_key,
                first_event=event,
                firing_events=[event],
            )
            occurrences.append(occurrence)
            return occurrence

        if event.event_id in [item.event_id for item in occurrence.firing_events]:
            occurrence.exact_duplicate_deliveries.append(event)
        else:
            occurrence.firing_events.append(event)
            if event.time < occurrence.first_event.time:
                occurrence.first_event = event
        return occurrence

    def _find_correlated_occurrence(
        self,
        group: Dict[str, Any],
        event: AlertEvent,
    ) -> Optional[Occurrence]:
        occurrences = group["occurrences"]  # type: List[Occurrence]

        if event.occurrence_id:
            for occ in occurrences:
                if occ.occurrence_id == event.occurrence_id:
                    return occ

        if event.correlation_id:
            for occ in occurrences:
                ids = [item.event_id for item in occ.all_firing_events]
                if event.correlation_id in ids:
                    return occ

        if event.correlation_time is not None:
            matches = [
                occ
                for occ in occurrences
                if abs(occ.first_event.time - event.correlation_time) < 1e-6
            ]
            if matches:
                return matches[-1]

        eligible = [
            occ for occ in occurrences if occ.first_event.time <= event.time + 1e-6
        ]
        unresolved = [occ for occ in eligible if occ.resolved_event is None]
        if unresolved:
            return unresolved[-1]
        if eligible:
            return eligible[-1]
        return None

    def _apply_resolved(
        self,
        group: Dict[str, Any],
        event: AlertEvent,
        errors: List[Dict[str, Any]],
    ) -> None:
        occurrence = self._find_correlated_occurrence(group, event)
        if occurrence is None:
            errors.append(
                {
                    "code": "orphan_resolved",
                    "message": "resolved event has no matching firing occurrence",
                    "event_id": event.event_id,
                    "group_key": event.group_key.canonical,
                    "time": event.time,
                }
            )
            return

        if event.time + 1e-6 < occurrence.first_event.time:
            occurrence.invalid_events.append(event)
            errors.append(
                {
                    "code": "resolved_before_firing",
                    "message": "resolved time is earlier than correlated firing",
                    "event_id": event.event_id,
                    "occurrence_id": occurrence.occurrence_id,
                    "firing_time": occurrence.first_event.time,
                    "resolved_time": event.time,
                }
            )
            return

        if occurrence.resolved_event is None:
            occurrence.resolved_event = event
            occurrence.resolved_at = event.time
        else:
            occurrence.duplicate_resolved_events.append(event)

    # --------------------------------------------------------------- episodes

    def _build_episodes(
        self,
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        silences: Sequence[Silence],
        now: float,
    ) -> List[Dict[str, Any]]:
        episodes = []  # type: List[Dict[str, Any]]

        for key, group in groups.items():
            occurrences = sorted(
                group["occurrences"], key=lambda occ: occ.first_event.time
            )
            current = None  # type: Optional[Dict[str, Any]]
            internal_number = 0

            for occ in occurrences:
                if current is None:
                    internal_number += 1
                    current = self._new_episode(
                        "internal-%s-%d" % (id(group), internal_number), key, occ
                    )
                    episodes.append(current)
                    continue

                previous = current["occurrences"][-1]
                previous_occ = previous["object"]  # type: Occurrence
                reopen_info = None

                if previous_occ.resolved_at is not None:
                    gap = occ.first_event.time - previous_occ.resolved_at
                    if -1e-6 <= gap <= self.window_seconds + 1e-6:
                        reopen_info = {
                            "at": occ.first_event.time,
                            "time_iso": format_time(occ.first_event.time),
                            "occurrence_id": occ.occurrence_id,
                            "recovered_at": previous_occ.resolved_at,
                            "recovered_at_iso": format_time(previous_occ.resolved_at),
                            "gap_seconds": max(0.0, gap),
                            "within_window": True,
                        }

                if reopen_info is not None or previous_occ.resolved_at is None:
                    if reopen_info is not None:
                        current["reopens"].append(reopen_info)
                    current["occurrences"].append(self._occurrence_ref(occ))
                    occ.episode_id = current["internal_id"]
                else:
                    internal_number += 1
                    current = self._new_episode(
                        "internal-%s-%d" % (id(group), internal_number), key, occ
                    )
                    episodes.append(current)

            for episode in episodes:
                if episode["group_key_object"] != key:
                    continue
                self._finalize_episode(episode, occurrences, silences, now)

        return episodes

    def _new_episode(
        self, internal_id: str, key: GroupKey, occ: Occurrence
    ) -> Dict[str, Any]:
        occ.episode_id = internal_id
        return {
            "internal_id": internal_id,
            "group_key_object": key,
            "group_key_text": key.canonical,
            "group_key": key.as_dict(),
            "occurrences": [self._occurrence_ref(occ)],
            "recovers": [],
            "reopens": [],
            "timeline": [],
            "merged_events": [],
        }

    def _occurrence_ref(self, occ: Occurrence) -> Dict[str, Any]:
        return {
            "object": occ,
            "occurrence_id": occ.occurrence_id,
            "fired_at": occ.first_event.time,
            "resolved_at": occ.resolved_at,
        }

    def _assign_public_episode_ids(
        self,
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        episodes: Sequence[Dict[str, Any]],
    ) -> None:
        group_indices = {}
        for group_index, key in enumerate(groups.keys(), start=1):
            group_indices[key.canonical] = group_index
        episode_indices = {}  # type: Dict[str, int]

        for episode in episodes:
            group_text = episode["group_key_text"]
            episode_index = episode_indices.get(group_text, 0) + 1
            episode_indices[group_text] = episode_index
            group_index = group_indices[group_text]
            public_id = "g%d-episode-%d" % (group_index, episode_index)
            internal_id = episode["internal_id"]
            episode["id"] = public_id
            episode["episode_id"] = public_id

            for timeline_entry in episode["timeline"]:
                if timeline_entry.get("episode_id") == internal_id:
                    timeline_entry["episode_id"] = public_id
            for merge in episode["merged_events"]:
                if merge.get("episode_id") == internal_id:
                    merge["episode_id"] = public_id
            for ref in episode["occurrences"]:
                occ = ref["object"]
                if occ.episode_id == internal_id:
                    occ.episode_id = public_id

    def _occurrence_report(self, occ: Occurrence) -> Dict[str, Any]:
        firing_ids = []
        for event in occ.firing_events:
            if event.event_id not in firing_ids:
                firing_ids.append(event.event_id)
        return {
            "occurrence_id": occ.occurrence_id,
            "fired_at": occ.first_event.time,
            "fired_at_iso": format_time(occ.first_event.time),
            "resolved_at": occ.resolved_at,
            "resolved_at_iso": format_time(occ.resolved_at),
            "firing_event_ids": firing_ids,
            "exact_duplicate_event_ids": [
                event.event_id for event in occ.exact_duplicate_deliveries
            ],
            "resolved_event_id": (
                occ.resolved_event.event_id if occ.resolved_event else None
            ),
            "duplicate_resolved_event_ids": [
                event.event_id for event in occ.duplicate_resolved_events
            ],
            "invalid_event_ids": [event.event_id for event in occ.invalid_events],
            "firing_count": len(occ.all_firing_events),
            "active": occ.resolved_at is None,
        }

    def _finalize_episode(
        self,
        episode: Dict[str, Any],
        all_occurrences: Sequence[Occurrence],
        silences: Sequence[Silence],
        now: float,
    ) -> None:
        occ_refs = episode["occurrences"]
        occurrences = [ref["object"] for ref in occ_refs]  # type: List[Occurrence]
        first_firing = min(occ.first_event.time for occ in occurrences)
        last_firing = max(
            event.time
            for occ in occurrences
            for event in occ.all_firing_events
        )
        resolved_times = [
            occ.resolved_at for occ in occurrences if occ.resolved_at is not None
        ]
        latest_resolved = max(resolved_times) if resolved_times else None
        active = any(occ.resolved_at is None for occ in occurrences)

        # Refresh refs after resolution.
        for ref in occ_refs:
            occ = ref["object"]
            ref["resolved_at"] = occ.resolved_at

        recoveries = []
        for occ in sorted(occurrences, key=lambda item: item.resolved_at or 0.0):
            if occ.resolved_at is not None and occ.resolved_event is not None:
                recoveries.append(
                    {
                        "at": occ.resolved_at,
                        "time": occ.resolved_at,
                        "time_iso": format_time(occ.resolved_at),
                        "occurrence_id": occ.occurrence_id,
                        "event_id": occ.resolved_event.event_id,
                    }
                )
        episode["recoveries"] = recoveries
        episode["recovery"] = latest_resolved
        episode["recovered_at"] = latest_resolved
        episode["recovered_at_iso"] = format_time(latest_resolved)

        closes_at = latest_resolved + self.window_seconds if latest_resolved is not None else None
        if active:
            status = FIRING
            state = "open"
            duration_end = now
        elif latest_resolved is not None and now + 1e-6 >= closes_at:
            status = "closed"
            state = "closed"
            duration_end = latest_resolved
        else:
            status = RESOLVED
            state = "recovery_window_open"
            duration_end = latest_resolved if latest_resolved is not None else now

        duration_seconds = max(0.0, duration_end - first_firing)
        firing_seconds = self._firing_seconds(occurrences, now)

        episode.update(
            {
                "start": first_firing,
                "started_at": first_firing,
                "start_iso": format_time(first_firing),
                "last_firing_at": last_firing,
                "last_firing_iso": format_time(last_firing),
                "end": latest_resolved if not active else None,
                "ended_at": latest_resolved if not active else None,
                "closed_at": closes_at if status == "closed" else None,
                "closes_at": closes_at,
                "close_after_seconds": self.window_seconds,
                "duration": duration_seconds,
                "duration_seconds": duration_seconds,
                "duration_until_close_seconds": (
                    closes_at - first_firing if closes_at is not None else None
                ),
                "firing_seconds": firing_seconds,
                "status": status,
                "state": state,
                "active": active,
                "reopen_count": len(episode["reopens"]),
                "reopen": episode["reopens"],
                "occurrence_count": len(occurrences),
                "occurrence_ids": [occ.occurrence_id for occ in occurrences],
                "evidence_event_ids": self._evidence_ids(occurrences),
                "continuous_evidence": True,
            }
        )

        matching_silences = self._matching_silences_for_episode(
            episode["group_key_object"], occurrences, silences
        )
        silence_ids = []
        for silence in matching_silences:
            if silence.silence_id not in silence_ids:
                silence_ids.append(silence.silence_id)
        episode["silence_ids"] = silence_ids
        episode["silenced_seconds"] = self._silenced_seconds(
            matching_silences, first_firing, duration_end
        )

        episode["merged_events"] = self._episode_merged_events(episode)
        episode["timeline"] = self._episode_timeline(episode, matching_silences)

    def _firing_seconds(self, occurrences: Sequence[Occurrence], now: float) -> float:
        intervals = []
        for occ in occurrences:
            end = occ.resolved_at if occ.resolved_at is not None else now
            if end >= occ.first_event.time:
                intervals.append((occ.first_event.time, end))
        if not intervals:
            return 0.0
        intervals.sort()
        total = 0.0
        current_start, current_end = intervals[0]
        for start, end in intervals[1:]:
            if start <= current_end:
                current_end = max(current_end, end)
            else:
                total += current_end - current_start
                current_start, current_end = start, end
        total += current_end - current_start
        return max(0.0, total)

    def _evidence_ids(self, occurrences: Sequence[Occurrence]) -> List[str]:
        ids = []
        for occ in occurrences:
            for event in occ.all_firing_events:
                if event.event_id not in ids:
                    ids.append(event.event_id)
            if occ.resolved_event and occ.resolved_event.event_id not in ids:
                ids.append(occ.resolved_event.event_id)
            for event in occ.duplicate_resolved_events + occ.invalid_events:
                if event.event_id not in ids:
                    ids.append(event.event_id)
        return ids

    # ---------------------------------------------------------- merged events

    def _build_merged_events(
        self, groups: "OrderedDict[GroupKey, Dict[str, Any]]"
    ) -> List[Dict[str, Any]]:
        result = []
        merge_number = 0
        for group in groups.values():
            for occ in group["occurrences"]:
                merge_number += 1
                result.append(self._firing_merge_record(occ, "merge-%d" % merge_number))
                if occ.resolved_event is not None:
                    merge_number += 1
                    result.append(
                        self._resolved_merge_record(occ, "merge-%d" % merge_number)
                    )
        return result

    def _firing_merge_record(self, occ: Occurrence, merge_id: str) -> Dict[str, Any]:
        events = sorted(occ.firing_events, key=lambda event: (event.time, event.input_index))
        unique_ids = []
        for event in events:
            if event.event_id not in unique_ids:
                unique_ids.append(event.event_id)
        exact_duplicate_ids = [
            event.event_id for event in occ.exact_duplicate_deliveries
        ]
        all_times = [event.time for event in occ.all_firing_events]
        delivery_count = len(occ.firing_events) + len(occ.exact_duplicate_deliveries)
        repeated = delivery_count > 1
        return {
            "merge_id": merge_id,
            "kind": FIRING,
            "group_key": occ.group_key.as_dict(),
            "group_key_text": occ.group_key.canonical,
            "occurrence_id": occ.occurrence_id,
            "episode_id": occ.episode_id,
            "canonical_event_id": events[0].event_id if events else occ.first_event.event_id,
            "source_event_ids": unique_ids,
            "exact_duplicate_event_ids": exact_duplicate_ids,
            "event_count": delivery_count,
            "duplicate_count": max(0, delivery_count - 1),
            "first_at": min(all_times) if all_times else occ.first_event.time,
            "last_at": max(all_times) if all_times else occ.first_event.time,
            "reason": "duplicate_firing" if repeated else "single_firing",
        }

    def _resolved_merge_record(self, occ: Occurrence, merge_id: str) -> Dict[str, Any]:
        events = [occ.resolved_event] + occ.duplicate_resolved_events
        ids = []
        for event in events:
            if event is not None and event.event_id not in ids:
                ids.append(event.event_id)
        return {
            "merge_id": merge_id,
            "kind": RESOLVED,
            "group_key": occ.group_key.as_dict(),
            "group_key_text": occ.group_key.canonical,
            "occurrence_id": occ.occurrence_id,
            "episode_id": occ.episode_id,
            "canonical_event_id": occ.resolved_event.event_id,
            "source_event_ids": ids,
            "event_count": len(ids),
            "duplicate_count": len(occ.duplicate_resolved_events),
            "first_at": occ.resolved_event.time,
            "last_at": max(event.time for event in events if event is not None),
            "reason": "duplicate_resolved" if occ.duplicate_resolved_events else "single_resolved",
        }

    def _episode_merged_events(self, episode: Dict[str, Any]) -> List[Dict[str, Any]]:
        result = []
        number = 0
        for occ in [ref["object"] for ref in episode["occurrences"]]:
            number += 1
            result.append(
                self._firing_merge_record(occ, "%s-merge-%d" % (episode["internal_id"], number))
            )
            if occ.resolved_event is not None:
                number += 1
                result.append(
                    self._resolved_merge_record(
                        occ, "%s-merge-%d" % (episode["internal_id"], number)
                    )
                )
        return result

    # -------------------------------------------------------------- silences

    def _event_labels_for_key(
        self, key: GroupKey, occurrences: Sequence[Occurrence]
    ) -> Dict[str, str]:
        labels = key.labels
        for occ in occurrences:
            for event in occ.all_firing_events:
                merged = dict(labels)
                merged.update(event.labels)
                labels = merged
            if occ.resolved_event:
                merged = dict(labels)
                merged.update(occ.resolved_event.labels)
                labels = merged
        return labels

    def _silence_matches_group(
        self,
        silence: Silence,
        key: GroupKey,
        occurrences: Sequence[Occurrence],
    ) -> bool:
        labels = self._event_labels_for_key(key, occurrences)
        return silence.matches(key, labels)

    def _matching_silences_for_episode(
        self,
        key: GroupKey,
        occurrences: Sequence[Occurrence],
        silences: Sequence[Silence],
    ) -> List[Silence]:
        return [
            silence
            for silence in silences
            if self._silence_matches_group(silence, key, occurrences)
        ]

    def _silenced_seconds(
        self,
        silences: Sequence[Silence],
        start: float,
        end: float,
    ) -> float:
        if end < start:
            return 0.0
        intervals = []
        for silence in silences:
            silence_end = silence.ends_at if silence.ends_at is not None else end
            left = max(start, silence.starts_at)
            right = min(end, silence_end)
            if right > left:
                intervals.append((left, right))
        if not intervals:
            return 0.0
        intervals.sort()
        total = 0.0
        current_start, current_end = intervals[0]
        for item_start, item_end in intervals[1:]:
            if item_start <= current_end:
                current_end = max(current_end, item_end)
            else:
                total += current_end - current_start
                current_start, current_end = item_start, item_end
        total += current_end - current_start
        return total

    def _build_silence_reports(
        self,
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        silences: Sequence[Silence],
    ) -> List[Dict[str, Any]]:
        reports = []
        for silence in silences:
            applies_to = []
            for key, group in groups.items():
                if self._silence_matches_group(silence, key, group["occurrences"]):
                    applies_to.append(key.canonical)
            reports.append(
                {
                    "silence_id": silence.silence_id,
                    "starts_at": silence.starts_at,
                    "starts_at_iso": format_time(silence.starts_at),
                    "ends_at": silence.ends_at,
                    "ends_at_iso": format_time(silence.ends_at),
                    "group_key": (
                        silence.group_key.as_dict() if silence.group_key else None
                    ),
                    "matchers": silence.matchers,
                    "applies_to_groups": applies_to,
                    "comment": silence.comment,
                    "state_effect": "none_state_retained",
                    "notification_effect": "suppress_when_active_at_dispatch",
                }
            )

        # Attach merged overlapping intervals as a convenience report.
        for key, group in groups.items():
            matching = [
                silence
                for silence in silences
                if self._silence_matches_group(silence, key, group["occurrences"])
            ]
            merged = self._merge_silence_intervals(matching)
            if merged:
                reports.append(
                    {
                        "report_type": "merged_silence_windows",
                        "group_key_text": key.canonical,
                        "group_key": key.as_dict(),
                        "windows": merged,
                    }
                )
        return reports

    def _merge_silence_intervals(self, silences: Sequence[Silence]) -> List[Dict[str, Any]]:
        ordered = sorted(silences, key=lambda item: item.starts_at)
        merged = []  # type: List[Dict[str, Any]]
        for silence in ordered:
            if not merged:
                merged.append(
                    {
                        "start": silence.starts_at,
                        "end": silence.ends_at,
                        "silence_ids": [silence.silence_id],
                        "overlapping": False,
                    }
                )
                continue
            current = merged[-1]
            current_end = current["end"]
            if current_end is None or silence.starts_at <= current_end:
                current["silence_ids"].append(silence.silence_id)
                current["overlapping"] = True
                if silence.ends_at is None:
                    current["end"] = None
                elif current_end is not None:
                    current["end"] = max(current_end, silence.ends_at)
            else:
                merged.append(
                    {
                        "start": silence.starts_at,
                        "end": silence.ends_at,
                        "silence_ids": [silence.silence_id],
                        "overlapping": False,
                    }
                )
        for window in merged:
            window["start_iso"] = format_time(window["start"])
            window["end_iso"] = format_time(window["end"])
        return merged

    # -------------------------------------------------------------- timeline

    def _episode_timeline(
        self, episode: Dict[str, Any], silences: Sequence[Silence]
    ) -> List[Dict[str, Any]]:
        entries = []
        for occ in [ref["object"] for ref in episode["occurrences"]]:
            for event in sorted(
                occ.all_firing_events, key=lambda item: (item.time, item.input_index)
            ):
                silenced = any(
                    silence.active_at(event.time, event.group_key, event.labels)
                    for silence in silences
                )
                entries.append(
                    self._timeline_entry(
                        event.time,
                        "duplicate_firing"
                        if event.event_id
                        in [item.event_id for item in occ.firing_events[1:]]
                        else FIRING,
                        episode,
                        occ,
                        event=event,
                        silenced=silenced,
                    )
                )
            if occ.resolved_event:
                event = occ.resolved_event
                silenced = any(
                    silence.active_at(event.time, event.group_key, event.labels)
                    for silence in silences
                )
                entries.append(
                    self._timeline_entry(
                        event.time,
                        RESOLVED,
                        episode,
                        occ,
                        event=event,
                        silenced=silenced,
                    )
                )

        for reopen in episode["reopens"]:
            entries.append(
                {
                    "time": reopen["at"],
                    "time_iso": format_time(reopen["at"]),
                    "kind": "reopened",
                    "episode_id": episode["internal_id"],
                    "occurrence_id": reopen["occurrence_id"],
                    "detail": "firing arrived within %.0fs window" % self.window_seconds,
                }
            )

        for silence in silences:
            entries.append(
                {
                    "time": silence.starts_at,
                    "time_iso": format_time(silence.starts_at),
                    "kind": "silence_start",
                    "episode_id": episode["internal_id"],
                    "silence_id": silence.silence_id,
                }
            )
            if silence.ends_at is not None:
                entries.append(
                    {
                        "time": silence.ends_at,
                        "time_iso": format_time(silence.ends_at),
                        "kind": "silence_end",
                        "episode_id": episode["internal_id"],
                        "silence_id": silence.silence_id,
                    }
                )

        entries.sort(key=lambda entry: (entry["time"], entry["kind"]))
        return entries

    def _timeline_entry(
        self,
        timestamp: float,
        kind: str,
        episode: Dict[str, Any],
        occ: Occurrence,
        event: Optional[AlertEvent] = None,
        silenced: bool = False,
    ) -> Dict[str, Any]:
        return {
            "time": timestamp,
            "time_iso": format_time(timestamp),
            "kind": kind,
            "status": kind if kind in (FIRING, RESOLVED) else None,
            "episode_id": episode["internal_id"],
            "occurrence_id": occ.occurrence_id,
            "event_id": event.event_id if event else None,
            "source": event.source if event else None,
            "received_at": event.received_at if event else None,
            "received_at_iso": format_time(event.received_at) if event else None,
            "silenced_at_event_time": silenced,
            "group_key_text": episode["group_key_text"],
        }

    def _build_timeline(
        self,
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        episodes: Sequence[Dict[str, Any]],
        silences: Sequence[Silence],
        notifications: Sequence[NotificationRecord],
    ) -> List[Dict[str, Any]]:
        entries = []
        for episode in episodes:
            for entry in episode["timeline"]:
                item = dict(entry)
                item["group_key_text"] = episode["group_key_text"]
                entries.append(item)

        event_to_episode = {}
        for episode in episodes:
            for occ_ref in episode["occurrences"]:
                occ = occ_ref["object"]
                for event in occ.all_firing_events:
                    event_to_episode[event.event_id] = episode["internal_id"]
                if occ.resolved_event:
                    event_to_episode[occ.resolved_event.event_id] = episode["internal_id"]

        event_by_id = {}
        for group in groups.values():
            for occ in group["occurrences"]:
                for event in occ.all_firing_events:
                    event_by_id[event.event_id] = event
                if occ.resolved_event:
                    event_by_id[occ.resolved_event.event_id] = occ.resolved_event

        for notif in notifications:
            dispatch_time = notif.sent_at or notif.created_at
            event = event_by_id.get(notif.event_id or "")
            if dispatch_time is None and event is not None:
                dispatch_time = event.received_at or event.time
            if dispatch_time is None:
                continue
            silenced = any(
                silence.active_at(
                    dispatch_time,
                    notif.group_key or (event.group_key if event else None),
                    event.labels if event else None,
                )
                for silence in silences
            )
            entries.append(
                {
                    "time": dispatch_time,
                    "time_iso": format_time(dispatch_time),
                    "kind": "notification_%s" % (notif.kind or "status"),
                    "notification_id": notif.notification_id,
                    "notification_status": notif.status,
                    "episode_id": event_to_episode.get(notif.event_id or ""),
                    "event_id": notif.event_id,
                    "silenced_at_dispatch": silenced,
                    "group_key_text": (
                        notif.group_key.canonical
                        if notif.group_key
                        else event.group_key.canonical if event else None
                    ),
                }
            )

        entries.sort(key=lambda entry: (entry["time"], entry["kind"], entry.get("notification_id") or ""))
        return entries

    def _replace_internal_episode_ids(
        self, timeline: List[Dict[str, Any]], episodes: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        mapping = {
            episode["internal_id"]: episode["id"]
            for episode in episodes
            if "id" in episode
        }
        for entry in timeline:
            internal_id = entry.get("episode_id")
            if internal_id in mapping:
                entry["episode_id"] = mapping[internal_id]
        return timeline

    def _replace_internal_merge_episode_ids(
        self, merged_events: List[Dict[str, Any]], episodes: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        mapping = {
            episode["internal_id"]: episode.get("id")
            for episode in episodes
            if "id" in episode
        }
        for merge in merged_events:
            internal_id = merge.get("episode_id")
            occ_id = merge.get("occurrence_id")
            if internal_id in mapping:
                merge["episode_id"] = mapping[internal_id]
            else:
                for episode in episodes:
                    if occ_id in episode.get("occurrence_ids", []):
                        merge["episode_id"] = episode.get("id")
                        break
        return merged_events

    # -------------------------------------------------------- notifications

    def _audit_notifications(
        self,
        notifications: Sequence[NotificationRecord],
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        episodes: Sequence[Dict[str, Any]],
        events: Sequence[AlertEvent],
        now: float,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        event_by_id = {event.event_id: event for event in events}
        occ_index = {}  # type: Dict[Tuple[str, str], Occurrence]
        episode_by_occ = {}  # type: Dict[str, Dict[str, Any]]
        for episode in episodes:
            for occ_ref in episode["occurrences"]:
                occ = occ_ref["object"]
                if episode.get("id"):
                    episode_by_occ[occ.occurrence_id] = episode
                for key in groups:
                    if occ.group_key == key:
                        occ_index[(key.canonical, occ.occurrence_id)] = occ

        error_notifications = []
        reports = []

        for notif in notifications:
            problems = []  # type: List[Dict[str, Any]]
            event = event_by_id.get(notif.event_id or "")
            key = notif.group_key or (event.group_key if event else None)
            occ = self._find_notification_occurrence(
                notif, event, key, groups, occ_index
            )
            episode = episode_by_occ.get(occ.occurrence_id) if occ else None

            dispatch_time = notif.sent_at or notif.created_at
            if dispatch_time is None and event is not None:
                dispatch_time = event.received_at or event.time

            active_silence_ids = []
            if dispatch_time is not None:
                for group_key, group in groups.items():
                    if key is not None and group_key != key:
                        continue
                    for silence in self._all_silences:
                        labels = self._event_labels_for_key(
                            group_key, group["occurrences"]
                        )
                        if silence.active_at(dispatch_time, group_key, labels):
                            active_silence_ids.append(silence.silence_id)

            if not notif.valid_status:
                problems.append(
                    {
                        "severity": "error",
                        "code": "unknown_notification_status",
                        "message": "notification status is not recognized",
                        "raw_status": notif.raw_status,
                    }
                )

            if notif.status == NOTIFICATION_FAILED or notif.error:
                problems.append(
                    {
                        "severity": "error",
                        "code": "delivery_failed",
                        "message": notif.error or "notification delivery failed",
                    }
                )

            if active_silence_ids and notif.status in DELIVERED_NOTIFICATION_STATUSES:
                problems.append(
                    {
                        "severity": "error",
                        "code": "sent_during_silence",
                        "message": "notification was delivered while a matching silence was active",
                        "silence_ids": sorted(set(active_silence_ids)),
                    }
                )

            if notif.status == NOTIFICATION_SUPPRESSED and not active_silence_ids:
                problems.append(
                    {
                        "severity": "warning",
                        "code": "suppressed_without_matching_silence",
                        "message": "record says suppressed but no matching silence is active at dispatch time",
                    }
                )

            late_info = self._late_resolution_info(
                notif, event, occ, key, groups, dispatch_time
            )
            if late_info:
                problems.append(late_info)

            if (
                notif.applied_occurrence_id
                and occ is not None
                and notif.applied_occurrence_id != occ.occurrence_id
            ):
                problems.append(
                    {
                        "severity": "error",
                        "code": "resolved_closed_wrong_occurrence",
                        "message": "resolved notification was applied to a different occurrence",
                        "correct_occurrence_id": occ.occurrence_id,
                        "applied_occurrence_id": notif.applied_occurrence_id,
                    }
                )

            correct_episode_id = episode.get("id") if episode else None
            if (
                notif.applied_episode_id
                and correct_episode_id
                and notif.applied_episode_id != correct_episode_id
            ):
                problems.append(
                    {
                        "severity": "error",
                        "code": "resolved_closed_wrong_episode",
                        "message": "late resolved notification cannot close a later episode",
                        "correct_episode_id": correct_episode_id,
                        "applied_episode_id": notif.applied_episode_id,
                    }
                )

            report = {
                "notification_id": notif.notification_id,
                "group_key_text": key.canonical if key else None,
                "kind": notif.kind or (event.kind if event else None),
                "status": notif.status,
                "event_id": notif.event_id,
                "occurrence_id": occ.occurrence_id if occ else notif.occurrence_id,
                "correct_episode_id": correct_episode_id,
                "dispatch_time": dispatch_time,
                "dispatch_time_iso": format_time(dispatch_time),
                "active_silence_ids": sorted(set(active_silence_ids)),
                "problems": problems,
                "is_error_notification": any(
                    problem.get("severity") == "error" for problem in problems
                ),
                "notification_sent": False,
            }
            reports.append(report)
            if problems:
                error_notifications.append(report)

        return error_notifications, reports

    def _find_notification_occurrence(
        self,
        notif: NotificationRecord,
        event: Optional[AlertEvent],
        key: Optional[GroupKey],
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        occ_index: Dict[Tuple[str, str], Occurrence],
    ) -> Optional[Occurrence]:
        if key is not None and notif.occurrence_id:
            found = occ_index.get((key.canonical, notif.occurrence_id))
            if found:
                return found

        if event is not None:
            for group in groups.values():
                for occ in group["occurrences"]:
                    if event in occ.all_firing_events or event is occ.resolved_event:
                        return occ

        if key is not None:
            group = groups.get(key)
            if group:
                occurrences = group["occurrences"]
                if notif.kind == RESOLVED:
                    resolved = [occ for occ in occurrences if occ.resolved_event]
                    if resolved:
                        return resolved[-1]
                if occurrences:
                    return occurrences[-1]
        return None

    def _late_resolution_info(
        self,
        notif: NotificationRecord,
        event: Optional[AlertEvent],
        occ: Optional[Occurrence],
        key: Optional[GroupKey],
        groups: "OrderedDict[GroupKey, Dict[str, Any]]",
        dispatch_time: Optional[float],
    ) -> Optional[Dict[str, Any]]:
        is_resolved = notif.kind == RESOLVED or (event is not None and event.kind == RESOLVED)
        if not is_resolved or occ is None or key is None:
            return None
        group = groups.get(key)
        if group is None:
            return None

        later_firings = []
        for candidate in group["occurrences"]:
            if candidate is occ:
                continue
            reference_time = occ.resolved_at if occ.resolved_at is not None else occ.first_event.time
            if candidate.first_event.time > reference_time + 1e-6:
                later_firings.append(candidate)
        if not later_firings:
            return None
        next_occ = min(later_firings, key=lambda item: item.first_event.time)

        arrived_after_next_firing = False
        if dispatch_time is not None and dispatch_time + 1e-6 >= next_occ.first_event.time:
            arrived_after_next_firing = True
        if event is not None and event.input_index > next_occ.first_event.input_index:
            arrived_after_next_firing = True
        if not arrived_after_next_firing:
            return None

        return {
            "severity": "error",
            "code": "late_resolved_after_next_firing",
            "message": (
                "late resolved notification belongs to an earlier occurrence and "
                "must not close the later episode"
            ),
            "resolved_occurrence_id": occ.occurrence_id,
            "next_firing_occurrence_id": next_occ.occurrence_id,
            "next_firing_event_id": next_occ.first_event.event_id,
            "next_firing_at": next_occ.first_event.time,
            "dispatch_time": dispatch_time,
            "rule": "correlate before close; event time wins over arrival order",
        }

    def run(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """从 JSON/dict 输入构造报告。"""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        group_key = _first_key(payload, ("group_key", "GroupKey", "groupKey"))
        window = _first_key(payload, ("window", "window_seconds", "window_minutes"))
        if "window_minutes" in payload and "window_seconds" not in payload and "window" not in payload:
            window = float(payload["window_minutes"]) * 60.0

        return self.validate(
            events=payload.get("events"),
            firing=payload.get("firing"),
            resolved=payload.get("resolved"),
            silences=_first_key(payload, ("silences", "silence")),
            notifications=_first_key(
                payload, ("notifications", "notification", "notification_records")
            ),
            notification_status=payload.get("notification_status"),
            group_key=group_key,
            window=window,
            now=payload.get("now") or payload.get("as_of"),
        )


def validate_episode(
    events: Optional[Sequence[Any]] = None,
    firing: Optional[Sequence[Any]] = None,
    resolved: Optional[Sequence[Any]] = None,
    silences: Optional[Sequence[Any]] = None,
    notifications: Any = None,
    notification_status: Any = None,
    group_key: Any = None,
    window_seconds: Any = 1800,
    now: Any = None,
    group_by: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    validator = EpisodeValidator(
        window_seconds=window_seconds, group_by=group_by, now=now
    )
    return validator.validate(
        events=events,
        firing=firing,
        resolved=resolved,
        silences=silences,
        notifications=notifications,
        notification_status=notification_status,
        group_key=group_key,
        now=now,
    )


def validate_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    window = _first_key(payload, ("window", "window_seconds", "window_minutes"))
    validator = EpisodeValidator(
        window_seconds=window if window is not None else 1800,
        group_by=payload.get("group_by"),
        now=payload.get("now") or payload.get("as_of"),
    )
    return validator.run(payload)


# 更贴近常见调用习惯的别名。
build_report = validate_payload
build_episode_report = validate_episode


__all__ = [
    "AlertEvent",
    "EpisodeValidator",
    "FIRING",
    "GroupKey",
    "NotificationRecord",
    "RESOLVED",
    "Silence",
    "build_episode_report",
    "build_report",
    "coerce_event",
    "coerce_notification",
    "coerce_silence",
    "format_time",
    "parse_duration_seconds",
    "parse_time",
    "validate_episode",
    "validate_payload",
]
