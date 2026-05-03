# omemo-rs

XMPP를 위한 **OMEMO 2** (XEP-0384 v0.9) 의 순수 Rust · MIT 라이선스 구현입니다.
런타임 의존성 그래프에 AGPL 코드를 끌어들이지 않으면서, XMPP 기반 봇 오케스트레이터
([nan-curunir](https://github.com/Rockheung/nan-curunir)의 후속 프로젝트)의 E2EE
계층으로 사용하기 위해 만들었습니다.

다른 언어로 보기: [English](README.md)

## 왜 만들었나

Rust 생태계에서 Signal 계열 E2EE의 레퍼런스는 `signalapp/libsignal`인데
**AGPL-3.0**입니다. OMEMO 0.3.0 (`oldmemo`) 구현체도 libsignal에서 파생되어
같은 라이선스를 전이적으로 상속받습니다. 이 프로젝트는 양쪽 모두 우회하기 위해
permissive 라이선스인 [Syndace Python 스택](https://github.com/Syndace)을
[RustCrypto](https://github.com/RustCrypto) 프리미티브 위에 Rust로 포팅하고,
OMEMO 2 만 구현합니다.

전체 라이선스 체인 분석과 ADR-002는 `docs/architecture.md` §3 참조.

## 진행 현황

| 단계 | 크레이트 | 상태 | 게이트 테스트 |
|---|---|---|---|
| 0 | 워크스페이스 + replay 파이프라인 | ✅ | `kdf_hkdf` |
| 1.1 | `omemo-xeddsa` | ✅ | `xeddsa` (104 assertion) |
| 1.2 | `omemo-doubleratchet` | ✅ | DH 스텝 + skip + OOO 포함 4-msg 라운드트립 |
| 1.3 | `omemo-x3dh` | ✅ | active+passive 번들 교환 byte-equal |
| 1.4 | `omemo-twomemo` | ✅ | 1 KEX + 3 message 의 protobuf byte-equal |
| 2 | `omemo-stanza` | ✅ | XEP-0384 §3+§5 라운드트립 + 3-수신자 케이스 |
| 3 | `omemo-session` | ✅ | identity + 번들 + 영속 + 재시작, re-key 없음 |
| 4 | `omemo-pep` | ✅ | alice ↔ bob 가 진짜 Prosody 위에서 3 메시지 교환 (`gate.rs`) |
| 5 | 그룹 OMEMO (MUC) | ✅ | 3 omemo-pep 클라이언트 그룹 채팅 라운드트립 (`tests/muc.rs`) |
| 6.1 | python-omemo cross-impl | ✅ | omemo-rs ↔ Syndace python-omemo 양방향 (`tests/python_interop.rs`) |
| 6.2 | Conversations / Dino | ⏳ | manual; 같은 Prosody에 `omemo-rs-cli` 사용 |
| 7.1 | `omemo-oldmemo` 스캐폴드 | ✅ | DR 세션 라운드트립 포함 10개 단위 테스트 |
| 7.2 | `gen_oldmemo.py` + replay | ✅ | Syndace python-oldmemo 와 byte-equal (KEX + 3 메시지) |
| 7.3 | `omemo-stanza` axolotl 네임스페이스 | ✅ | `eu.siacs.conversations.axolotl` 라운드트립 + AES-128-GCM body |
| 7.4 | `omemo-pep` dual-backend | ✅ | 평행 `*_oldmemo` 플로우 + 듀얼 네임스페이스 `wait_for_encrypted_any` |
| 7.5 | oldmemo cross-impl 게이트 | ✅ | `python_interop --backend oldmemo` 양방향 (실제 Prosody) |
| 8 | Converse.js E2E rig | ✅ | 멀티 세션 브라우저 ↔ CLI E2E (`docs/converse-e2e.md`) |

암호 계층은 모든 픽스처에서 Syndace Python 스택과 byte-equal 로 검증됩니다.
`cargo test --workspace` 는 64개의 unit/replay 테스트를 통과하며,
추가로 10개의 integration 테스트가 로컬 Prosody 컨테이너 위에서 XMPP 경로를
게이트합니다 (`-- --ignored` 로 실행). Stage 4 + Stage 5 + Stage 6.1 +
4-FU.1~4-FU.4 + 5-FU.1~5-FU.4 완료: alice ↔ bob 1:1 *및* alice →
bob+carol 그룹 채팅 라운드트립이 실제 Prosody MUC 위에서 동작하며,
**omemo-rs ↔ Syndace 의 python-omemo cross-implementation interop 이
양방향 모두 통과**합니다 (Stage 6.1). 게이트는 `omemo-session` SQLite
스토어를 단일 진실 공급원으로 사용합니다. 메시지 본문은 XEP-0420 SCE
봉투에 감싸서 inbound 시 `<to>` 검증 (DM 은 peer bare, groupchat 은
room bare), 모든 피어 디바이스는 TOFU 혹은 Manual trust 정책 하에
IK-drift 탐지와 함께 기록됩니다. 프로덕션 배포는 `connect_starttls`
(rustls + aws-lc-rs + 네이티브 인증서 검증) 로 StartTLS 를 사용합니다.
`omemo-rs-cli` 바이너리 (`crates/omemo-rs-cli/`) 가 production API 를
실제 CLI 클라이언트로 시연하며 Stage 6.2 (Conversations / Dino) manual
검증의 driver 입니다.

## 워크스페이스 레이아웃

```
omemo-rs/
├── crates/
│   ├── omemo-xeddsa/          # XEdDSA + Curve25519/Ed25519 + X25519
│   ├── omemo-doubleratchet/   # Signal 스펙 Double Ratchet
│   ├── omemo-x3dh/            # X3DH 키 합의
│   ├── omemo-twomemo/         # OMEMO 2 백엔드 (twomemo.proto)
│   ├── omemo-stanza/          # XEP-0384 v0.9 스탠자 인코드/파싱
│   ├── omemo-session/         # SQLite 기반 영속 저장
│   ├── omemo-pep/             # XEP-0163 PEP 통합 (Stage 4)
│   └── omemo-test-harness/    # 크로스-언어 픽스처 replay (cargo test 전용)
├── docs/                      # 아키텍처, 파이프라인, ADR, stages
├── test-vectors/
│   ├── fixtures/              # 커밋된 JSON 픽스처 (Stage 3 시점 10개)
│   ├── scripts/gen_*.py       # 재생성 스크립트
│   └── reference/             # 클론된 upstream Python repo (gitignored)
└── TODO.md                    # 실시간 태스크 리스트 (docs/stages.md 의 미러)
```

## 테스트 방법론

모든 Rust 암호 프리미티브는 대응되는 Syndace Python 구현과 **바이트 단위로 동일한**
출력을 내야 합니다. Python 구현체를 결정적 오라클로 사용합니다:
생성기 스크립트(`scripts/gen_*.py`)가 결정적 입력을 Python 레퍼런스에 넣고
`(입력, 기대 출력)` 쌍을 `fixtures/<primitive>.json` 으로 직렬화합니다.
Rust replay 테스트는 그 JSON 을 로드해 동일 입력으로 우리 구현을 돌리고
저장된 출력과 `assert_eq!` 합니다.

픽스처는 커밋되어 있어서 Python venv 없이도 `cargo test` 만으로 검증 가능합니다.
자세한 내용과 픽스처 인벤토리는 `docs/pipeline.md` 참조.

## 빠른 시작

```bash
git clone https://github.com/Rockheung/omemo-rs.git
cd omemo-rs
cargo test --workspace
```

upstream Python 패키지 버전이 올라간 뒤 픽스처를 재생성하려면:

```bash
cd test-vectors
git clone --depth 1 https://github.com/Syndace/python-doubleratchet.git reference/python-doubleratchet
git clone --depth 1 https://github.com/Syndace/python-x3dh.git           reference/python-x3dh
git clone --depth 1 https://github.com/Syndace/python-xeddsa.git         reference/python-xeddsa
git clone --depth 1 https://github.com/Syndace/python-twomemo.git        reference/python-twomemo
git clone --depth 1 https://github.com/Syndace/python-oldmemo.git        reference/python-oldmemo
git clone --depth 1 https://github.com/Syndace/python-omemo.git          reference/python-omemo

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install doubleratchet==1.3.0 x3dh==1.3.0 xeddsa==1.2.0 twomemo==2.1.0 oldmemo==2.1.0 'omemo>=2,<3' \
            cryptography pydantic

for s in scripts/gen_*.py; do python "$s"; done
git diff fixtures/   # upstream 가 표류하지 않았다면 빈 출력이어야 함
```

## 라이선스

MIT (`LICENSE` 파일이 있으면 그것, 없으면 `Cargo.toml`의 `[workspace.package]` 참조).

런타임 크레이트 그래프는 MIT/Apache/BSD 코드만 포함합니다:

* `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `hmac`,
  `sha2`, `aes`, `cbc` — RustCrypto, BSD/MIT/Apache
* `prost` — Apache-2.0
* `quick-xml` — MIT
* `rusqlite` (번들 SQLite 포함) — MIT / public-domain SQLite 소스

Python 레퍼런스 패키지들은 **픽스처 생성 시점에만** 쓰이고 런타임 크레이트 그래프에는
포함되지 않습니다. AGPL-3.0인 `libsignal` (Rust) 과 `python-oldmemo` 는 의도적으로
의존하지 **않습니다**.

## 문서

* [`docs/architecture.md`](docs/architecture.md) — 최상위 설계, 크레이트 책임 분배,
  OMEMO 2 알고리즘 선택지.
* [`docs/pipeline.md`](docs/pipeline.md) — 픽스처 replay 인프라 + 프리미티브별
  인벤토리.
* [`docs/stages.md`](docs/stages.md) — 단계별 개발 계획과 게이트 기준.
* [`docs/decisions.md`](docs/decisions.md) — 아키텍처 결정 로그
  (ADR-001 ~ ADR-006).
* [`TODO.md`](TODO.md) — 체크박스 형태의 실시간 태스크 리스트.

## 범위 외 (Out of scope)

* 하드웨어 토큰 / 스마트카드 기반 identity key.
* Wasm 빌드 (저장 계층이 파일시스템 + SQLite 를 가정).
* Megolm 스타일 그룹 암호화 최적화 (OMEMO 2 의 디바이스별 팬아웃은
  본 프로젝트의 타깃인 봇 규모 룸에서는 충분).

OMEMO 0.3.0 (`oldmemo` / siacs axolotl 네임스페이스) 은 원래
"libsignal AGPL 체인" 을 이유로 여기 있었습니다. ADR-009 (2026-05-02)
에서 그 전제를 다시 검토했습니다 — `python-oldmemo` 는 런타임에
libsignal 에 의존하지 않으며, 그 AGPL 은 Syndace 자체의 라이선스
선택입니다. OMEMO 0.3 은 Stage 7 으로 다시 범위 안에 들어왔습니다 —
XEP-0384 v0.3 + 기존 MIT 프리미티브 위에 clean-room 으로 구현하고,
python-oldmemo 는 **외부 픽스처 오라클로만** 사용합니다 (링크하지도,
복사하지도 않음). 자세히는 `docs/decisions.md` ADR-009 참조.
