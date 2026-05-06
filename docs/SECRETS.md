# Secrets — 인벤토리 & Rotation

이 프로젝트가 다루는 시크릿이 어떤 것들이 있는지, 어디에 저장되고, 어떻게
rotation 하는지 정리한다. 원칙: **시크릿은 절대 repo 에 커밋하지 않는다**.

## 방어 레이어 (지금 돌고 있는 것)

| 계층 | 도구 | 설정 파일 |
|---|---|---|
| 로컬 커밋 직전 | pre-commit + gitleaks | `.pre-commit-config.yaml`, `.gitleaksignore` |
| CI push/PR | gitleaks-action | `.github/workflows/gitleaks.yml` |
| 의존성 취약점 | pip-audit, trivy | `.github/workflows/{pip-audit,trivy}.yml` |
| 배포 시 암호화 | Bitnami Sealed Secrets | `album-deploy/k8s/sealed/` |

개발자는 처음 clone 후:
```bash
pip install pre-commit
pre-commit install
```
한 번만 하면 이후 `git commit` 마다 자동으로 gitleaks 가 돈다.

## 시크릿 인벤토리

### Internal (우리가 직접 생성)

| 이름 | 용도 | 생성 방법 | 저장소 |
|---|---|---|---|
| `JWT_SECRET` | access token 서명 | `python -c "import secrets; print(secrets.token_urlsafe(48))"` | `.env`(dev), `backend-secret`(prod) |
| `JWT_REFRESH_SECRET` | refresh token 서명 (별도로 관리 — 탈취 시 영향 격리) | 위와 동일 | 위와 동일 |
| `POSTGRES_PASSWORD` | DB 접속 | 임의 랜덤 문자열 32+ char | 위와 동일 |
| `MINIO_ACCESS_KEY` | 오브젝트 스토리지 access | 임의 | 위와 동일 |
| `MINIO_SECRET_KEY` | 오브젝트 스토리지 secret | 임의 | 위와 동일 |

### External (외부 서비스에서 발급)

| 이름 | 발급처 | 담당 계정 | 저장소 |
|---|---|---|---|
| `KAKAO_CLIENT_ID` | developers.kakao.com → 앱 → 앱 키 | 프로젝트 소유자 | `.env`(dev), `backend-secret`(prod) |
| `KAKAO_CLIENT_SECRET` | developers.kakao.com → 앱 → 보안 탭 | 동일 | 동일 |
| `TUNNEL_TOKEN` | Cloudflare Zero Trust → Networks → Tunnels | 동일 | `cloudflared-secret`(prod only) |
| `COOLSMS_API_KEY` | coolsms.co.kr → 대시보드 → API keys | 동일 | `.env`(dev), `backend-secret`(prod) — SMS_PROVIDER=coolsms 일 때만 |
| `COOLSMS_API_SECRET` | 위와 동일 | 동일 | 동일 |
| `BIZZTALK_SENDER_KEY` | Kakao 비즈채널 신청 후 발급 | 동일 | 동일 |

### 저장 위치 요약

| 환경 | 위치 | 형식 |
|---|---|---|
| 로컬 dev | `src/backend/.env` (gitignored) | 평문 |
| Production K8s | `album-deploy/k8s/sealed/backend-secret.yaml` | SealedSecret (암호화 — 공개저장소에 올려도 안전) |
| Cloudflare Tunnel | `album-deploy/k8s/sealed/cloudflared-secret.yaml` | SealedSecret |

## Rotation 절차

### 언제 rotate 해야 하는가?
- **즉시**: 실수로 공개 repo / 채팅 / 티켓에 노출된 경우
- **직원 이탈 시**: rotation 권장 (특히 JWT — 유효한 세션 전체 무효화)
- **정기**: 알파 단계에서는 연 1회 또는 incident 기반. 베타 전환 시 90일 주기 도입 검토.

### JWT 키 회전 (T-055 rolling key)

T-055 이후 JWT 회전은 **재로그인 없이** 진행 가능하다. 토큰 헤더의 `kid` 로
키 lookup 하므로 옛 토큰과 새 토큰이 한 동안 공존할 수 있다. 자세한 절차는
`album-deploy/docs/JWT_KEY_ROTATION.md` 참고. 요약:

1. **새 kid 추가**: `JWT_KEY_V<N+1>` / `JWT_REFRESH_KEY_V<N+1>` 추가, ACTIVE
   는 아직 V<N> 유지 → 모든 backend pod 가 새 키 인식하지만 발급은 옛 키.
2. **활성 kid 전환**: `JWT_ACTIVE_KID=v<N+1>` / `JWT_REFRESH_ACTIVE_KID=v<N+1>`
   → 신규 발급 토큰부터 새 kid. 옛 kid 토큰은 검증 keyset 에 남아있어 그대로 유효.
3. **Grace 대기**: refresh 만료(14일) + access 만료(60분) 기다림.
4. **옛 kid 제거**: `JWT_KEY_V<N>` / `JWT_REFRESH_KEY_V<N>` SealedSecret 에서 삭제.

### 그 외 내부 시크릿 (DB / MinIO)

```bash
# 1. 새 값 생성
openssl rand -base64 32                                       # POSTGRES_PASSWORD
# MinIO 키: mc admin user add myminio <new-access-key> <new-secret-key>

# 2. SealedSecret 재생성 (album-deploy 레포에서) — 변경할 키만 새 값으로,
# 나머지는 기존 값 그대로 유지하기 위해 항목별 reseal 권장.
cd album-deploy
echo -n "$NEW_DB_PASS" | kubectl create secret generic backend-secret \
  --namespace=senior-album --dry-run=client \
  --from-file=POSTGRES_PASSWORD=/dev/stdin -o yaml \
  | kubeseal --format yaml --merge-into k8s/sealed/backend-secret.yaml

# 3. 커밋 + push → GitOps 가 apply
git add k8s/sealed/backend-secret.yaml
git commit -m "chore(secret): rotate POSTGRES_PASSWORD"
git push

# 4. 롤아웃 트리거 (SealedSecret 변경은 Pod 재시작 안 시키므로 수동)
kubectl -n senior-album rollout restart deploy/backend
kubectl -n senior-album rollout restart deploy/minio  # MinIO 키 바뀐 경우
kubectl -n senior-album rollout restart statefulset/postgres  # DB 비번 바뀐 경우

# 5. 로컬 .env 도 동기화 (선택 — 개발자 본인만)
```

### 외부 시크릿 (Kakao / Cloudflare / SMS)

해당 벤더 콘솔에서 **먼저** 새 값 발급 → 구 값 무효화 **전** SealedSecret 업데이트
→ rollout → 앱 정상 동작 확인 → 콘솔에서 구 값 revoke. 순서 중요 — 구 값
먼저 죽이면 다운타임 발생.

### Rotation 후 체크리스트
- [ ] 앱 로그에 auth 오류 없는지 (JWT 회전은 T-055 rolling key 로 재로그인 불요. 다른 시크릿 회전은 해당 서비스 재기동 후 정상 동작 확인)
- [ ] 카카오 로그인 정상 동작
- [ ] 사진 업로드 (MinIO) 정상
- [ ] DB 연결 정상 (`/health` 200)

## 절대 하지 말 것

- ❌ `.env` 를 `git add -f` 로 강제 스테이징
- ❌ Slack / 이슈 / PR 본문에 실시크릿 붙여넣기 (허용: placeholder `***` 또는 앞 4자리만)
- ❌ SealedSecret 대신 평문 `Secret` manifest 를 커밋
- ❌ `.env.example` 에 실시크릿 넣기 (꼭 빈 값 또는 `CHANGE-ME`)
- ❌ JWT 서명용 Secret 을 `.env` 에 하드코딩된 예시 그대로 사용 (프로덕션)

## 유출 감지 시 대응 순서

1. **막기**: 해당 시크릿 즉시 rotate (위 절차)
2. **흔적 제거**: git history 에 커밋된 경우 `git filter-repo` 또는 BFG 로 제거. **force push 가 공개저장소에서는 효과가 제한적** — 유출된 값은 rotate 를 먼저 하는 것이 본질.
3. **영향 파악**: 해당 시크릿으로 가능했던 동작 (DB 덤프, 토큰 발급, MinIO 읽기 등) 을 로그에서 역추적
4. **보고**: 이슈로 postmortem 남김 (label: `incident`)

## 관련 파일

- `.env.example` — 필드 목록 (값 비워둠)
- `.gitleaksignore` — test fixture 등 false positive 면제 리스트
- `.pre-commit-config.yaml` — 로컬 hook 설정
- `.github/workflows/gitleaks.yml` — CI 스캔
- `album-deploy/k8s/sealed/` — SealedSecret manifest
