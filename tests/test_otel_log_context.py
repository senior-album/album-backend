"""
T-318: OtelTraceContextFilter + 전체 logging 설정 회귀 테스트.

핵심 회귀: jsonlogger 의 `rename_fields={"otelTraceID": "trace_id", ...}` 가
record 에 source attribute 가 없을 때 KeyError 를 던지면서 StreamHandler.emit
이 `handleError` 로 빠져 access log 가 traceback 으로 stderr 에 dump 되던
사고. uvicorn access logger 는 trace context 가 종료된 뒤 호출돼 LoggingInstrumentor
가 두 attribute 를 setattr 하지 않는 케이스.

검증 전략: Filter 가 record 에 두 attribute 를 빈 문자열로 채우는지 +
filter 를 거친 record 가 `JsonFormatter.format()` 호출에서 raise 하지 않는지.

stream 출력 형식이나 handler.handle pipeline 까지 가지 않는 이유 — python-json-logger
2.0.7 (prod / CI) 와 ≥3.x (로컬 dev) 의 emit/output path 차이가 있어 stream
직접 검증이 brittle 했다 (PR #139 첫 commit 의 사고). format() 직접 호출이
회귀의 본질 ("rename 단계 KeyError") 을 가장 좁게 잡는다.
"""

from __future__ import annotations

import logging

from pythonjsonlogger import jsonlogger

from app.core.logging_filters import OtelTraceContextFilter


_RENAME_FIELDS = {
    "asctime": "ts",
    "levelname": "level",
    "name": "logger",
    "otelTraceID": "trace_id",
    "otelSpanID": "span_id",
}

_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s %(message)s "
    "%(module)s %(funcName)s %(lineno)d"
)


def _formatter() -> jsonlogger.JsonFormatter:
    return jsonlogger.JsonFormatter(_FORMAT, rename_fields=_RENAME_FIELDS)


def _record(*, attrs: dict | None = None, msg: str = "hello %s", args=("world",)) -> logging.LogRecord:
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=None,
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


def test_format_raises_without_filter_when_otel_attrs_missing():
    """회귀 재현 가드: filter 를 거치지 않은 record 는 prod 와 동일한
    KeyError 가 raise 되어야 한다. fix 가 실효 있다는 증거.

    python-json-logger ≥3.x 는 rename 에 missing-key 가드를 추가해 raise
    하지 않을 수 있다 — 그 경우엔 skip (가드의 존재가 우리 fix 의 필요성
    자체를 약화하지만 prod 의 2.0.7 동작은 변하지 않음).
    """
    formatter = _formatter()
    rec = _record()  # no filter applied — otelTraceID/otelSpanID 미주입
    try:
        formatter.format(rec)
    except KeyError as e:
        assert "otelTraceID" in str(e), f"unexpected KeyError: {e!r}"
    else:
        # ≥3.x: missing 가드로 통과 — fix 가 본질적으로 영향 없음을 확인하고 skip
        import pytest
        pytest.skip("python-json-logger 가 missing key 가드를 갖고 있어 회귀 재현 불가 (로컬 dev 환경)")


def test_format_succeeds_with_filter_when_otel_attrs_missing():
    """본 회귀 fix 의 핵심: filter 가 attribute 를 빈 문자열로 채우면
    formatter.format() 이 raise 없이 통과한다."""
    formatter = _formatter()
    rec = _record()
    OtelTraceContextFilter().filter(rec)
    formatter.format(rec)  # raises 면 fail


def test_format_succeeds_with_otel_attrs_present():
    """LoggingInstrumentor 가 채운 값이 있는 record 도 동일하게 안전."""
    formatter = _formatter()
    rec = _record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"})
    OtelTraceContextFilter().filter(rec)
    formatter.format(rec)  # raises 면 fail


def test_format_succeeds_with_printf_args():
    """uvicorn access logger 처럼 args tuple 을 받는 record 도 안전.
    실제 prod 회귀가 발생한 패턴 — `'%s - "%s %s HTTP/%s" %d'` + tuple args.
    """
    formatter = _formatter()
    rec = _record(
        msg='%s - "%s %s HTTP/%s" %d',
        args=("10.42.0.1:51136", "GET", "/health", "1.1", 200),
    )
    OtelTraceContextFilter().filter(rec)
    formatter.format(rec)  # raises 면 fail


def test_filter_attached_to_handler_not_logger():
    """문서화 가드: configure_logging 이 OtelTraceContextFilter 를 StreamHandler
    에 attach 했는지 확인. root.addFilter 면 propagate 된 child record 안 잡혀
    회귀 재발 — 이 검증으로 패턴 의도를 묶어둔다.
    """
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
        assert "OtelTraceContextFilter" in handler_filters, (
            "OtelTraceContextFilter 가 StreamHandler 에 attach 안 됨 — "
            "root.addFilter 로 잘못 붙으면 propagate 된 child record 에 적용되지 않아 회귀 재발."
        )
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
