"""
T-318: OtelTraceContextFilter + 전체 logging 설정 회귀 테스트.

핵심 회귀: jsonlogger 의 `rename_fields={"otelTraceID": "trace_id", ...}` 가
record 에 source attribute 가 없을 때 KeyError 를 던지면서 StreamHandler.emit
이 `handleError` 로 빠져 access log 가 traceback 으로 stderr 에 dump 되던
사고. uvicorn access logger 는 trace context 가 종료된 뒤 호출돼 LoggingInstrumentor
가 두 attribute 를 setattr 하지 않는 케이스.

OtelTraceContextFilter 가 Handler 에 attach 된 상태에서, 두 attribute 가
없는 record 도 emit 이 KeyError 없이 끝나야 한다 (= Handler.handleError 가
호출되지 않아야 한다).

검증 전략은 출력 stream 포맷 비교가 아니라 **handleError 미호출** 로 둔다 —
python-json-logger 2.0.7 (prod / CI) 와 ≥3.x (로컬 dev) 의 emit path 가
출력 형식 면에서 다른데, 회귀의 본질은 "rename 단계 KeyError 로 emit 실패"
이고 그건 handleError 호출 여부로 정확히 잡힌다.
"""

from __future__ import annotations

import io
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


def test_emit_no_otel_attrs_does_not_trigger_handleError(monkeypatch):
    """회귀 가드: LoggingInstrumentor 가 attribute 를 안 박은 record 도
    `Handler.handleError` 호출 없이 emit 통과해야 한다.

    이 검증이 깨지면 prod 의 uvicorn access log 가 다시 traceback 으로 망가짐.
    출력 stream 의 형식은 검증하지 않는다 — jsonlogger 2.0.7 / ≥3.x 사이에
    extras 처리 path 가 달라서 출력이 비어 보일 수 있다. 회귀의 본질은
    "rename 단계에서 KeyError 가 나서 emit 이 fallback 으로 빠진다" 이고
    그건 handleError 호출 여부로 정확히 잡힌다.
    """
    called: list[logging.LogRecord] = []
    monkeypatch.setattr(
        logging.Handler, "handleError",
        lambda self, record: called.append(record),
    )

    handler = _make_handler(io.StringIO())
    handler.handle(_record())  # raises 또는 handleError 호출되면 fail

    assert not called, (
        "Handler.handleError 가 호출됐다 — emit 단계 예외 (KeyError 등) 가 났다는 신호. "
        "OtelTraceContextFilter 가 Handler 에 attach 안 됐거나, filter 가 record 의 "
        "otelTraceID/otelSpanID 를 채우지 못한 것."
    )


def test_emit_with_otel_attrs_does_not_trigger_handleError(monkeypatch):
    """LoggingInstrumentor 가 채운 값이 있는 record 도 동일하게 안전."""
    called: list[logging.LogRecord] = []
    monkeypatch.setattr(
        logging.Handler, "handleError",
        lambda self, record: called.append(record),
    )

    handler = _make_handler(io.StringIO())
    handler.handle(_record(attrs={"otelTraceID": "abc123", "otelSpanID": "def456"}))

    assert not called


def test_emit_with_printf_args_does_not_trigger_handleError(monkeypatch):
    """uvicorn access logger 처럼 args tuple 을 받는 record 도 동일하게 안전.

    실제 prod 회귀가 발생한 패턴 — `'%s - "%s %s HTTP/%s" %d'` + tuple args.
    """
    called: list[logging.LogRecord] = []
    monkeypatch.setattr(
        logging.Handler, "handleError",
        lambda self, record: called.append(record),
    )

    handler = _make_handler(io.StringIO())
    handler.handle(_record(
        msg='%s - "%s %s HTTP/%s" %d',
        args=("10.42.0.1:51136", "GET", "/health", "1.1", 200),
    ))

    assert not called


def test_filter_attached_to_handler_not_logger():
    """문서화 가드: configure_logging 이 OtelTraceContextFilter 를 StreamHandler
    에 attach 했는지 확인. root.addFilter 면 propagate 된 child record 안 잡혀
    회귀 재발 — 이 검증으로 패턴 의도를 묶어둔다.
    """
    # logging 을 격리하기 위해 fresh root 처럼 보이게 모든 handler/filter 제거 후
    # configure_logging 재호출. test 간 부작용을 최소화하기 위해 finalize 단계에서
    # 원래 상태로 복원.
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
