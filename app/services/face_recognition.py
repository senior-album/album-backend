"""
얼굴 인식 서비스 — insightface (Buffalo) 기반
- 얼굴 감지 + 랜드마크 정렬 + 임베딩 추출을 한 번에 처리
- 상용 수준의 정확도 (LFW 99.8%+)
- 512차원 임베딩, 코사인 유사도로 비교

pip install insightface onnxruntime
"""

import os
import logging
from typing import Optional, List

import numpy as np

logger = logging.getLogger(__name__)

# insightface 로드
INSIGHTFACE_AVAILABLE = False
try:
    from insightface.app import FaceAnalysis
    INSIGHTFACE_AVAILABLE = True
except ImportError:
    logger.warning("insightface not available — pip install insightface onnxruntime")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")


class FaceService:
    """insightface 기반 얼굴 감지 + 임베딩 추출"""

    _app = None
    _embedding_dim = 512  # insightface buffalo 기본 512차원

    @classmethod
    def is_available(cls) -> bool:
        return INSIGHTFACE_AVAILABLE

    @classmethod
    def _get_app(cls):
        """insightface FaceAnalysis 앱 초기화 (최초 1회)"""
        if cls._app is None and INSIGHTFACE_AVAILABLE:
            try:
                # buffalo_l = 가장 정확한 모델 (~300MB, 자동 다운로드)
                # buffalo_s = 경량 모델 (~30MB)
                # buffalo_sc = 초경량 모델
                cls._app = FaceAnalysis(
                    name="buffalo_l",
                    root=MODEL_DIR,
                    providers=["CPUExecutionProvider"],
                )
                # det_size: 감지 해상도. 높을수록 작은 얼굴도 감지 (느려짐)
                cls._app.prepare(ctx_id=-1, det_size=(640, 640))
                logger.info("insightface buffalo_l model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load insightface model: {e}")
                # buffalo_l 실패 시 buffalo_s로 폴백
                try:
                    logger.info("Trying buffalo_s (smaller model)...")
                    cls._app = FaceAnalysis(
                        name="buffalo_s",
                        root=MODEL_DIR,
                        providers=["CPUExecutionProvider"],
                    )
                    cls._app.prepare(ctx_id=-1, det_size=(640, 640))
                    logger.info("insightface buffalo_s model loaded successfully")
                except Exception as e2:
                    logger.error(f"Failed to load fallback model: {e2}")
                    cls._app = None
        return cls._app

    @classmethod
    def get_embedding_dim(cls) -> int:
        """임베딩 차원 반환 (insightface는 항상 512)"""
        app = cls._get_app()
        if app:
            cls._embedding_dim = 512
        return cls._embedding_dim

    @classmethod
    def detect_faces(cls, image_array: np.ndarray) -> List[dict]:
        """
        이미지에서 얼굴 감지 + 정렬 + 임베딩 추출

        insightface가 자동으로:
        1. 얼굴 감지 (RetinaFace)
        2. 5-point 랜드마크 검출
        3. 랜드마크 기반 얼굴 정렬 (alignment)
        4. ArcFace 임베딩 추출 (512차원)

        Args:
            image_array: RGB numpy 배열 (H, W, 3)

        Returns:
            [{"bbox": [x1,y1,x2,y2], "embedding": [floats...], "det_score": float}, ...]
        """
        if not INSIGHTFACE_AVAILABLE:
            logger.warning("Face detection skipped — insightface not available")
            return []

        app = cls._get_app()
        if app is None:
            return []

        try:
            # insightface는 BGR 입력을 기대하지만,
            # 내부적으로 RGB도 잘 처리함. 명시적으로 변환.
            image_bgr = image_array[:, :, ::-1].copy()

            faces = app.get(image_bgr)

            if not faces:
                logger.debug("No faces detected")
                return []

            results = []
            for face in faces:
                bbox = face.bbox.astype(float).tolist()  # [x1, y1, x2, y2]
                embedding = face.embedding  # numpy array (512,)
                det_score = float(face.det_score) if hasattr(face, 'det_score') else 0.0

                # L2 정규화 (insightface는 이미 정규화되어 있지만 확실히)
                if embedding is not None:
                    norm = np.linalg.norm(embedding)
                    if norm > 0:
                        embedding = (embedding / norm).tolist()
                    else:
                        embedding = embedding.tolist()

                results.append({
                    "bbox": bbox,
                    "embedding": embedding,
                    "det_score": det_score,
                })

            logger.info(f"Detected {len(results)} face(s) with insightface")
            return results

        except Exception as e:
            logger.error(f"Face detection failed: {e}", exc_info=True)
            return []

    @classmethod
    def extract_single_embedding(cls, image_array: np.ndarray) -> Optional[list]:
        """이미지에서 가장 큰 얼굴의 임베딩 추출"""
        faces = cls.detect_faces(image_array)
        if not faces:
            return None

        # 가장 큰 얼굴 선택 (바운딩박스 면적 기준)
        best_face = max(faces, key=lambda f: (
            (f["bbox"][2] - f["bbox"][0]) * (f["bbox"][3] - f["bbox"][1])
        ))

        embedding = best_face.get("embedding")
        if embedding is None:
            logger.warning("Face detected but embedding extraction failed")
            return None

        return embedding
