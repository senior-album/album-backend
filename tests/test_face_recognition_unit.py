"""
T-124 PR2: app.services.face_recognition.FaceService 단위 테스트.

실제 insightface 모델 로딩은 비싸고 환경 의존적이라 (300MB 모델 다운로드, ONNX
런타임), `_get_app` 결과를 mock 으로 갈아끼워 비즈니스 로직 분기만 검증한다:
- 모델이 사용 불가능할 때의 fallback (빈 결과)
- 임베딩 L2 정규화
- 가장 큰 얼굴 선택 로직
- det_score 누락 안전 처리

class-level cache (`FaceService._app`) 가 다른 테스트로 새지 않도록 매번
초기화한다.
"""

import numpy as np
import pytest

from app.services import face_recognition as face_module
from app.services.face_recognition import FaceService


@pytest.fixture(autouse=True)
def _reset_faceservice_state():
    """class-level _app cache 가 테스트 간 새지 않도록."""
    FaceService._app = None
    FaceService._embedding_dim = 512
    yield
    FaceService._app = None
    FaceService._embedding_dim = 512


class _FakeFace:
    """insightface Face 객체와 동일한 attr 만 흉내."""

    def __init__(self, bbox, embedding, det_score=0.99):
        self.bbox = np.array(bbox, dtype=float)
        self.embedding = np.array(embedding, dtype=float) if embedding is not None else None
        self.det_score = det_score


class _FakeApp:
    """FaceAnalysis 앱 — `.get(image)` 가 미리 준비한 얼굴 리스트를 반환."""

    def __init__(self, faces):
        self._faces = faces
        self.last_input = None

    def get(self, image):
        self.last_input = image
        return self._faces


def _zeros_image(h: int = 64, w: int = 64) -> np.ndarray:
    return np.zeros((h, w, 3), dtype=np.uint8)


# ---------------------------------------------------------------------------
# is_available / 모델 미로딩 시 fallback
# ---------------------------------------------------------------------------


def test_is_available_reflects_module_flag(monkeypatch):
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    assert FaceService.is_available() is True
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", False)
    assert FaceService.is_available() is False


def test_detect_faces_returns_empty_when_insightface_disabled(monkeypatch):
    """insightface 자체가 안 깔린 환경에선 모델을 만들지 않고 즉시 [] 반환."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", False)
    out = FaceService.detect_faces(_zeros_image())
    assert out == []


def test_detect_faces_returns_empty_when_app_failed_to_load(monkeypatch):
    """insightface 는 깔렸지만 모델 로딩이 None 으로 끝난 경우."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: None))
    assert FaceService.detect_faces(_zeros_image()) == []


def test_extract_single_embedding_returns_none_when_no_faces(monkeypatch):
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: _FakeApp([])))
    assert FaceService.extract_single_embedding(_zeros_image()) is None


# ---------------------------------------------------------------------------
# detect_faces — 정상 동작 + 정규화
# ---------------------------------------------------------------------------


def test_detect_faces_normalizes_embedding(monkeypatch):
    """insightface 출력이 정규화되어 있어도 한 번 더 L2 정규화 (norm=1) 보장."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    raw = [3.0, 4.0]  # ||raw|| = 5
    fake = _FakeApp([_FakeFace([0.0, 0.0, 10.0, 10.0], raw, det_score=0.95)])
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: fake))

    out = FaceService.detect_faces(_zeros_image())
    assert len(out) == 1
    emb = out[0]["embedding"]
    assert pytest.approx(emb[0], rel=1e-6) == 0.6  # 3/5
    assert pytest.approx(emb[1], rel=1e-6) == 0.8  # 4/5
    # 정규화 결과 norm = 1
    assert pytest.approx(float(np.linalg.norm(emb)), rel=1e-6) == 1.0


def test_detect_faces_handles_zero_norm_embedding(monkeypatch):
    """zero-vector 임베딩도 ZeroDivision 없이 그대로 list 로 반환되어야 한다."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    fake = _FakeApp([_FakeFace([0.0, 0.0, 5.0, 5.0], [0.0, 0.0, 0.0])])
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: fake))

    out = FaceService.detect_faces(_zeros_image())
    assert out[0]["embedding"] == [0.0, 0.0, 0.0]


def test_detect_faces_handles_missing_det_score(monkeypatch):
    """일부 모델 변종이 det_score 를 안 노출해도 0.0 으로 채워서 통과해야."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)

    class _NoScoreFace:
        bbox = np.array([0, 0, 1, 1], dtype=float)
        embedding = np.array([1.0, 0.0])

    fake = _FakeApp([_NoScoreFace()])
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: fake))
    out = FaceService.detect_faces(_zeros_image())
    assert out[0]["det_score"] == 0.0


def test_detect_faces_returns_empty_on_app_exception(monkeypatch):
    """앱이 예외를 던지면 (예: ONNX 런타임 오류) 호출자에 None 대신 [] 반환."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)

    class _Boom:
        def get(self, _):
            raise RuntimeError("onnx kaboom")

    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: _Boom()))
    assert FaceService.detect_faces(_zeros_image()) == []


# ---------------------------------------------------------------------------
# extract_single_embedding — 가장 큰 얼굴 선택
# ---------------------------------------------------------------------------


def test_extract_single_embedding_picks_largest_face_by_bbox_area(monkeypatch):
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    small = _FakeFace([0, 0, 10, 10], [1.0, 0.0])  # area 100
    big = _FakeFace([0, 0, 50, 50], [0.0, 1.0])  # area 2500
    medium = _FakeFace([0, 0, 30, 30], [1.0, 1.0])  # area 900

    fake = _FakeApp([small, big, medium])
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: fake))

    emb = FaceService.extract_single_embedding(_zeros_image())
    # 가장 큰 얼굴(big)의 정규화된 embedding == [0, 1]
    assert pytest.approx(emb[0], abs=1e-9) == 0.0
    assert pytest.approx(emb[1], rel=1e-6) == 1.0


# ---------------------------------------------------------------------------
# get_embedding_dim
# ---------------------------------------------------------------------------


def test_get_embedding_dim_returns_512_when_app_unavailable(monkeypatch):
    """모델 로딩 안 된 환경에서도 안전하게 512 디폴트 반환."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", False)
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: None))
    assert FaceService.get_embedding_dim() == 512


def test_get_embedding_dim_returns_512_when_app_loaded(monkeypatch):
    """app 이 로딩됐을 때도 insightface buffalo 는 항상 512."""
    monkeypatch.setattr(face_module, "INSIGHTFACE_AVAILABLE", True)
    monkeypatch.setattr(FaceService, "_get_app", classmethod(lambda cls: _FakeApp([])))
    assert FaceService.get_embedding_dim() == 512
