# SN-002 — решения Q-01–Q-09 после SN-002-R2

Дата: 12 ноября 2026. Статус: архитектурное согласование, не реализация vault.
R2 основан на сохранённых результатах SN-001/SN-002/R1 в коммите
`3bd58c053bfba5c81ec0a3223b6e570e39e9a774`. Последующие прямые решения владельца имеют
приоритет над историческими предложениями. [R1](SN-002-STREAMING-RESEARCH.md) сохранён
как исследование: его Proposed-формулировки описывают состояние на момент исследования.

## Подтверждённые решения

Самостоятельный local-first SafeNook, без импорта PasswordGeneratorCLI. M1/0.1 — local core,
CLI и обязательный recovery; M2/0.2 — SSH/age/files; M0–M4 согласованы. Core независим от UI,
.NET 10 и Native AOT сохраняются. NSec/libsodium для Argon2id/Ed25519 — ADR 0002.

В SN-002-R2 приняты ADR 0007 (два независимых slots) и ADR 0008 (COW, immutable objects,
authenticated manifest, единый commit root). Для файлов до 25 МиБ выбран whole-object
AES-256-GCM через BCL, отдельные буферы с явной очисткой, без обязательного ArrayPool.
SSH/age сохраняются и возвращаются как исходные bytes; agent/engine/генерация не требуются.
Не обещается защита от скомпрометированной ОС, полного rollback без внешнего доверенного
состояния или криптографический отзыв уже скопированных старых версий.

## Q-01–Q-09: действующий результат

| Q | Решение / контракт | Источник и граница утверждения |
|---|---|---|
| Q-01 | Threat model с границами unlocked/same-user, availability и rollback | [Threat model](threat-model.md); ограничения подтверждены |
| Q-02 | Бинарные authenticated структуры и bounded JSON, точный AAD | [Vault format](vault-format.md); рабочая спецификация, vectors/review впереди |
| Q-03 | VK256/RK256, два независимых slots, подтверждённая выдача RK, отдельный full rekey | [ADR 0007](adr/0007-recovery-key-slots.md) Accepted; смена пароля сохраняет recovery slot |
| Q-04 | p1/salt16, min64MiB/t3, max1GiB/t10, цель0.5–1s | [KDF](recovery-and-io.md); рабочие числа требуют hardware validation; worker/deadline не утверждены |
| Q-05 | Whole-object BCL AES-GCM для blob<=25MiB, nonce12/tag16, verify-all-before-output | Выбор владельца; [новая редакция ADR 0009](adr/0009-streaming-aead-profile.md) Proposed до согласования текста |
| Q-06 | COW, encrypted manifest, single root, lock, explicit restore | [ADR 0008](adr/0008-generation-commit.md) Accepted; платформенные гарантии ещё проверяются |
| Q-07 | SSH/age opaque bytes и точный round-trip | Подтверждено для M2; [payloads](vault-format.md), без обещания usability/agent/engine |
| Q-08 | No secret argv/env, allowlisted reveal/JSON, authenticated bounded-memory export | [I/O](recovery-and-io.md); детальный UX не равен реализации |
| Q-09 | Typed DTO/schema, immutable write IDs, previous hashes/tombstones | [Items/manifest](vault-format.md); revision/time не выбирают sync-победителя |

## Реестр D01–D06

| ID | Состояние после R2 | Что остаётся |
|---|---|---|
| D01 | Архитектура ADR 0007 принята | Проверка точных кодировок/UX/vectors; не повторное согласование независимых slots |
| D02 | Архитектура ADR 0008 принята | OS adapters, failure injection, durability/backup qualification |
| D03 | Whole-object BCL и 25 МиБ выбраны | Согласовать новую редакцию ADR 0009; затем отдельно перевести её в Accepted |
| D04 | Лимиты v1 сохранены как рабочие | Аппаратная проверка KDF/RAM/counts; worker и hard deadline требуют отдельного решения |
| D05 | Точное хранение/восстановление SSH/age bytes подтверждено | Детальный UX, ошибки и экспортные ограничения проверяются перед реализацией |
| D06 | Ограничения host compromise/full rollback/old-copy revocation подтверждены | Документированные metadata leaks не превращаются в обещание полной конфиденциальности метаданных |

ADR 0001–0008 приняты; ADR 0004 частично заменён принятым ADR 0008.
Attachment STREAM-решение ADR 0003 заменено прямым выбором владельца в R2;
ADR 0009 фиксирует новую редакцию и пока не Accepted. Остальные назначения AES-GCM
не отменены. Это согласование не является разрешением SN-003.

## Рабочие лимиты и инженерные риски

- Argon2id: минимум 64 МиБ/3 прохода, максимум 1 ГиБ/10 проходов, p=1, salt16,
  цель калибровки 0,5–1 с. Проверять на представительных устройствах; ошибки не снижают
  параметры автоматически. Worker, 10/30-секундные hard deadlines и IPC не приняты.
- Blob<=25 МиБ; до 10 000 активных записей. Остальные размеры и budgets из спецификации
  сохранены, но не доказывают практическую производительность. Отдельные blob buffers
  требуют до 50 МиБ payload RAM плюс runtime/provider/metadata/concurrency.
- Independent crypto/envelope vectors, parser limits и review ещё нужны. R1 — изолированный
  Windows PoC, не доказательство интегрированного vault и не кроссплатформенный тест.
- Filesystem atomicity/durability, memory pressure/cancellation, backup/restore, GC и
  symlink/reparse защита требуют испытаний. Old backup продолжает открываться старым ключом.
- Single-file backup packaging, полноценные history/clipboard/agent и sync остаются отдельно.

## План первого этапа SN-003 — только после отдельного разрешения

1. Зафиксировать согласованную редакцию ADR 0009 и scope первого изменения. Отдельно решить,
   нужен ли KDF worker/hard deadline; не включать его в реализацию по умолчанию.
2. Подготовить независимые synthetic vectors AES-GCM, HKDF, Argon2id p1/salt16/output32,
   slot/AAD/header/envelope; документировать происхождение и ожидаемые промежуточные bytes.
3. Реализовать ограниченные parsers/encoders и криптопримитивы в Core без Console/UI/сети:
   checked bounds, exact lengths/EOF, unknown-format refusal, source-generated DTOs.
4. Реализовать wrap/unwrap и whole-object codec с per-write HKDF/nonce и явным владением
   буферами. Проверить empty/max/oversize/tamper/AAD/context и отсутствие раннего plaintext.
5. Проверить lifecycle slots: оба unwrap дают один VK; password change оставляет recovery
   slot byte-identical; failure/cancel не удаляет действующий путь восстановления.
6. Выполнить build/tests и Native AOT на доступных платформах, затем матрицу Windows/Linux/
   macOS; проверить memory pressure и независимые vectors. Не объявлять непроверенные RID.

Результат первого этапа — проверяемые primitives/format contracts. Файловые транзакции,
команды vault и интеграция COW идут следующими отдельно очерченными изменениями после
этих проверок. В R2 код/тесты/зависимости/CI не меняются, этап SN-003 не начат.

## История и завершение

SN-001 задал вопросы; SN-002 предложил wire format, recovery/COW и Tink profile;
R1 сохранил исследование трёх вариантов; R2 принял recovery/COW и применил выбор BCL
к действующей документации. Исторические альтернативы в ADR и R1 сохранены.
F-12 не закрывается автоматически до согласования редакции ADR 0009 и review спецификации.
[План проверок](SN-002-VERIFICATION.md) описывает будущие тесты, а не выполненную реализацию.
