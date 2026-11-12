# SN-002 — решения Q-01–Q-09 и согласование

Дата: 12 ноября 2026. **Проект спецификации для обсуждения, не реализация vault.**
Основание: задание владельца SN-002; SN-001 в текущем рабочем дереве; HEAD
`6904096d875510ae9117012c9df53fb9b6e0bf55`; ADR 0001–0006 и восстановленная база знаний.
Исторические материалы не отменяют новые прямые решения владельца.

## Подтверждено и не запрашивается повторно

Самостоятельный local-first SafeNook без импорта PasswordGeneratorCLI; M1/0.1 — local core,
CLI и recovery; M2/0.2 — SSH/age/files и типы; согласованная последовательность M0–M4;
NSec/libsodium Argon2id p1/salt16/min64MiB/t3, AES-256-GCM, каталог с файлами записей,
Native AOT и независимость Core от UI. Recovery key обязателен с init в M1.

ADR 0006 содержит более раннюю оговорку о предложенных milestones. Последующее прямое
подтверждение владельца в задании SN-002 является основанием scope выше; принятый ADR
не переписан. Аналогично F-12 не помечена завершённой: согласование Proposed ADR ещё впереди.

## Результат проектирования

| Q | Рекомендуемое решение | Документ / статус |
|---|---|---|
| Q-01 | Offline confidentiality/integrity; явные пределы unlocked/same-user, доступности и rollback | [Threat model](threat-model.md), T01–T15; проект |
| Q-02 | Бинарные authenticated header/envelopes, bounded JSON wrapper/payloads, точные AAD/offsets/limits | [Vault format](vault-format.md); проект |
| Q-03 | VK256, независимый RK256, ровно два slots, подтверждённая выдача, отдельный full rekey | [Recovery](recovery-and-io.md), [ADR 0007](adr/0007-recovery-key-slots.md); Proposed |
| Q-04 | Сохранить минимум; ceilings1GiB/t10, локальный budget, calibration и killable KDF deadline | [KDF](recovery-and-io.md); численные budgets и worker требуют утверждения/замеров |
| Q-05 | Точный Tink RAW AES-GCM-HKDF Streaming profile, ciphertext segments64KiB, <=25MiB, verify-all-before-output | [ADR 0009](adr/0009-streaming-aead-profile.md); Proposed, review gate |
| Q-06 | COW файлы + encrypted manifest + один root, lock, previous root, explicit restore | [Storage](storage-protocol.md), [ADR 0008](adr/0008-generation-commit.md); Proposed |
| Q-07 | SSH/age как непреобразуемые opaque bytes с честной маркировкой unvalidated | [Payloads](vault-format.md); M2 без agent/generation/engine |
| Q-08 | No secret argv/env; framed handles/TTY; reveal allowlist; authenticated bounded-memory export | [I/O](recovery-and-io.md); предложенный контракт, команды не реализованы |
| Q-09 | Typed DTO/schema1, immutable write IDs, previous hashes/tombstones, bounded inventory | [Items/manifest](vault-format.md); revision/time не разрешают sync-конфликты |

Q-01–Q-09 покрыты проектированием; это не утверждение выбранных решений и не разрешение SN-003.
[План проверок](SN-002-VERIFICATION.md) отделяет будущие tests от проверок документации.

## Решения, требующие утверждения владельца

| ID | Конкретный выбор | Рекомендация и цена |
|---|---|---|
| D01 | Принять ADR 0007 и wire header/slot lifecycle? | Два независимых slots, Base32 RK и явное подтверждение; слот нельзя удалить без замены; old backup не отзывается |
| D02 | Принять ADR 0008, новый physical layout и ограничения writable FS? | COW/root; один previous snapshot, serial access, fail closed на unqualified storage; дополнительное место/GC |
| D03 | Принять ADR 0009 как blob profile либо выбрать whole-object/secretstream? | Рекомендуется точный опубликованный AES-GCM streaming profile, но M2 нельзя выпускать без reviewed implementation/interop; random nonce и смысл64KiB в ADR0003 уточняются явно |
| D04 | Утвердить resource/UX budgets? | KDF1GiB/t10, default256MiB и10s, max30s/worker; item64KiB, blob25MiB, active items10k и metadata256MiB; значения требуют hardware validation |
| D05 | Утвердить M2 opaque SSH/age и правила output? | Точные bytes, без обещаний usability/validation; отдельный защищённый recovery output; file export без stdout и plaintext spool |
| D06 | Утвердить утечки и границы гарантий? | Видны type/size/IDs/связь поколений; нет полного rollback detection, host-compromise защиты или криптографического отзыва старых копий |

До утверждения не менять статусы новых ADR на Accepted и не помечать старые Superseded.
Отдельного согласования уже подтверждённых продуктовых приоритетов не требуется.

## Альтернативы и оставшиеся инженерные gates

- Binary authenticated header вместо canonical JSON: точные bytes и простой bounded parser;
  payload JSON остаётся source-generated. Цена — ручной wire parser и независимые vectors.
- Slot vs full VK rotation: первая дешёвая, но не защищает future objects от сохранённого VK;
  вторая дороже и требует credentials обоих slots/доставки новых и места для двух эпох.
- Journal против COW и full-directory copy сравниваются в [ADR 0008](adr/0008-generation-commit.md).
- Stream library/port, whole-object GCM и secretstream сравниваются в [ADR 0009](adr/0009-streaming-aead-profile.md).
- В M1/M2 encrypted backup — проверенный каталог; single-file packaging не специфицировано
  как неявный формат и не является необходимостью для восстановления.
- До кода: проверить exact crypto vectors независимо; до M1 — worker/AOT и OS filesystem
  adapter; до M2 — stream implementation review. .NET библиотека для Tink не выбрана.
- Full rollback protection с внешним anchor, multi-device causal metadata, conflict policy,
  transport/auth, archive packaging и полноценная history/clipboard — отдельные будущие ADR.
- Старый `CLAUDE.md` явно актуализирован на System.CommandLine3.0.0 по разрешению SN-002:
  в коде остаются Command, Option<T>, SetAction и ParseResult.GetValue.

## Граница завершения SN-002

Документы должны быть внутренне согласованы, ссылки и размеры проверены, работа SN-001
сохранена. Ни криптографическая безопасность, ни power-loss durability не устанавливаются
этим ревью. Исходники, тесты, версии пакетов и CI не меняются. Следующий шаг владельца —
обсудить D01–D06 и отдельно утвердить/скорректировать Proposed ADR.
