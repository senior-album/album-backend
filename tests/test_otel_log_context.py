"""
T-318: OTel trace_id 로그 주입 + jsonlogger rename 회귀 가드.

핵심 회귀: jsonlogger 2.0.7 의 `add_fields` 가 `merge_record_extra(record,
log_record, rename_fields=...)` 로 extras 의 rename 을 이미 적용하고, 그
뒤 `_perform_rename_log_fields(log_record)` 가 다시 `log_record[old]` 직접
접근. extras 경로로 들어온 키 (`otelTraceID`) 는 이미 `trace_id` 로 옮겨져
있고 `otelTraceID` key 가 사라진 상태라 KeyError. OTel `LoggingInstrumentor`
가 활성 span 일 때 setattr 하는 attribute 가 정확히 이 path 를 탔다.

해결책: `_JSON_FORMAT` 에 `%(otelTraceID)s %(otelSpanID)s` placeholder 를
명시적으로 두면 두 키가 `_required_fields` 로 들어가서 add_fields 의 첫
루프가 `log_record[field] = record.__dict__.get(field)` 로 채움 (없으면 None).
이후 `_perform_rename_log_fields` 는 정상 rename → `trace_id`/`span_id`.

OtelTraceContextFilter 는 None 대신 빈 문자열로 채워 출력 일관성. 두 방어선.
"""

from __future__ import annotations

import logging

from pythonjsonlogger import jsonlogger

from app.core.logging_config import _JSON_FORMAT
from app.core.logging_filters import OtelTraceContextFilter


_RENAME_FIELDS = {
    "asctime": "ts",
    "levelname": "level",
    "name": "logger",
    "otelTraceID": "trace_id",
    "otelSpanID": "span_id",
}


def _formatter() -> jsonlogger.JsonFormatter:
    """logging_config.configure_logging 과 동일한 formatter."""
    return jsonlogger.JsonFormatter(_JSON_FORMAT, rename_fields=_RENAME_FIELDS)


def _record(*, attrs: dict | None = None, msg: str = "hello %s", args=("world",)) -> logging.LogRecord:
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=None,
    )
    if attrs:
        for k, v in attrs.items():
            setattr(rec, k, v)
    return rec


def test_format_string_contains_otel_placeholders():
    """문서화 가드: _JSON_FORMAT 에 두 placeholder 가 포함돼 있어야 한다.
    빠지면 rename 단계 KeyError 회귀 — prod uvicorn access log 가 traceback
    으로 깨졌던 사고가 재발."""
    assert "%(otelTraceID)s" in _JSON_FORMAT
    assert "%(otelSpanID)s" in _JSON_FORMAT


def test_filter_sets_empty_when_missing():
    """Filter 가 record 의 두 attribute 를 빈 문자열로 보장."""
    rec = _record()
    OtelTraceContextFilter().filter(rec)
    assert rec.otelTraceID == ""
    assert rec.otelSpanID == ""


def test_filter_preserves_existing_values():
    """LoggingInstrumentor 가 채운 값은 덮어쓰지 않는다."""
    rec = _record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"})
    OtelTraceContextFilter().filter(rec)
    assert rec.otelTraceID == "abc123"
    assert rec.otelSpanID == "def456"


def test_format_no_otel_attrs_no_filter_does_not_raise():
    """회귀 핵심 가드: record 에 두 attribute 가 없고 filter 도 안 거쳤어도
    format() 이 raise 하지 않아야 한다. format string 의 placeholder 로
    add_fields 가 None 으로 채워서 rename 이 안전하게 동작."""
    _formatter().format(_record())


def test_format_with_filter_uses_empty_string():
    """filter 거친 record 는 None 대신 빈 문자열로 trace_id 가 직렬화."""
    import json

    rec = _record()
    OtelTraceContextFilter().filter(rec)
    out = _formatter().format(rec)
    payload = json.loads(out)
    assert payload.get("trace_id") == ""
    assert payload.get("span_id") == ""


def test_format_with_otel_attrs_renames_to_trace_span():
    """LoggingInstrumentor 가 채운 값은 rename 거쳐 trace_id/span_id 키로 노출."""
    import json

    rec = _record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"})
    out = _formatter().format(rec)
    payload = json.loads(out)
    assert payload["trace_id"] == "abc123"
    assert payload["span_id"] == "def456"
    assert "otelTraceID" not in payload
    assert "otelSpanID" not in payload


def test_format_with_printf_args_does_not_raise():
    """uvicorn access logger 처럼 args tuple 을 받는 record (실제 prod 회귀
    패턴) 도 안전."""
    _formatter().format(_record(
        msg='%s - "%s %s HTTP/%s" %d',
        args=("10.42.0.1:51136", "GET", "/health", "1.1", 200),
    ))


def test_filter_attached_to_handler_not_logger():
    """configure_logging 이 OtelTraceContextFilter 를 StreamHandler 에 attach
    하는지 확인. root.addFilter 면 propagate 된 child record 안 잡힘."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    saved_level = root.level
    try:
        for h in saved_handlers:
            root.removeHandler(h)
        for f in saved_filters:
            root.removeFilter(f)

        from app.core.logging_config import configure_logging
        configure_logging()

        handler_filters = [type(f).__name__ for h in root.handlers for f in h.filters]
        assert "OtelTraceContextFilter" in handler_filters
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
        for f in list(root.filters):
            root.removeFilter(f)
        for h in saved_handlers:
            root.addHandler(h)
        for f in saved_filters:
            root.addFilter(f)
        root.setLevel(saved_level)
