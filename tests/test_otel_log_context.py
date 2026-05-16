"""
T-318: OtelTraceContextFilter + 전체 logging 설정 회귀 테스트.

핵심 회귀: jsonlogger 의 `rename_fields={"otelTraceID": "trace_id", ...}` 가
record 에 source attribute 가 없을 때 KeyError 를 던지면서 StreamHandler.emit
이 `handleError` 로 빠져 access log 가 traceback 으로 stderr 에 dump 되던
사고. uvicorn access logger 는 trace context 가 종료된 뒤 호출돼 LoggingInstrumentor
가 두 attribute 를 setattr 하지 않는 케이스.

OtelTraceContextFilter 가 Handler 에 attach 된 상태에서, 두 attribute 가
없는 record 도 emit 이 KeyError 없이 끝나야 한다.
"""

from __future__ import annotations

import io
import json
import logging

from pythonjsonlogger import jsonlogger

from app.core.logging_filters import OtelTraceContextFilter


def _make_handler(stream: io.StringIO) -> logging.StreamHandler:
    """logging_config.configure_logging 과 동일한 formatter + filter 조립."""
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s "
        "%(module)s %(funcName)s %(lineno)d",
        rename_fields={
            "asctime": "ts",
            "levelname": "level",
            "name": "logger",
            "otelTraceID": "trace_id",
            "otelSpanID": "span_id",
        },
    )
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    handler.addFilter(OtelTraceContextFilter())
    return handler


def _emit_and_capture(stream: io.StringIO, record: logging.LogRecord) -> str:
    """handler 에 record 를 흘려 출력 한 줄 캡쳐 + 마지막 KeyError 흔적 검출."""
    handler = _make_handler(stream)
    handler.handle(record)
    return stream.getvalue()


def _record(*, attrs: dict | None = None) -> logging.LogRecord:
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="hello %s", args=("world",), exc_info=None,
    )
    if attrs:
        for k, v in attrs.items():
            setattr(rec, k, v)
    return rec


def test_filter_sets_empty_when_missing():
    """Filter 통과 후 두 attribute 가 빈 문자열로 보장돼야."""
    rec = _record()
    OtelTraceContextFilter().filter(rec)
    assert rec.otelTraceID == ""
    assert rec.otelSpanID == ""


def test_filter_preserves_existing_values():
    """LoggingInstrumentor 가 이미 채운 값은 덮어쓰지 않는다."""
    rec = _record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"})
    OtelTraceContextFilter().filter(rec)
    assert rec.otelTraceID == "abc123"
    assert rec.otelSpanID == "def456"


def test_emit_no_otel_attrs_does_not_raise():
    """회귀 가드: LoggingInstrumentor 가 attribute 를 안 박은 record 도
    handler.handle 이 KeyError 없이 통과해 JSON 한 줄을 stream 에 떨군다.

    이 검증이 깨지면 prod 의 uvicorn access log 가 다시 traceback 으로 망가짐.
    """
    stream = io.StringIO()
    out = _emit_and_capture(stream, _record())
    assert out.strip().startswith("{")
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["trace_id"] == ""
    assert payload["span_id"] == ""
    assert payload["message"] == "hello world"


def test_emit_with_otel_attrs_renames_to_trace_span():
    """LoggingInstrumentor 가 채운 값은 rename_fields 를 거쳐 `trace_id`/`span_id`
    키로 JSON 에 노출."""
    stream = io.StringIO()
    rec = _record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"})
    out = _emit_and_capture(stream, rec)
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["trace_id"] == "abc123"
    assert payload["span_id"] == "def456"
    # 원본 키 (otelTraceID/otelSpanID) 는 출력에서 사라져야 — rename 의 의도.
    assert "otelTraceID" not in payload
    assert "otelSpanID" not in payload


def test_emit_with_printf_args_does_not_raise():
    """uvicorn access logger 처럼 args tuple 을 받는 record 도 동일하게 안전."""
    stream = io.StringIO()
    rec = logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname=__file__, lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("10.42.0.1:51136", "GET", "/health", "1.1", 200),
        exc_info=None,
    )
    out = _emit_and_capture(stream, rec)
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["message"] == '10.42.0.1:51136 - "GET /health HTTP/1.1" 200'
    assert payload["trace_id"] == ""
