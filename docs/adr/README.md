# Architecture Decision Records

Короткие записи о решениях, которые сложно или дорого поменять потом.

Формат имени: `NNNN-короткое-название.md`. Статусы: **Предложено** → **Принято** → (**Заменено** NNNN | **Отклонено**).
Принятое решение не редактируется по существу: если оно меняется, пишется новый ADR, а старый помечается «Заменено».

| # | Решение | Статус |
|---|---|---|
| [0001](0001-name.md) | Имя проекта SafeNook, команда `nook` | Принято |
| [0002](0002-crypto-library.md) | NSec (libsodium) для Argon2id и Ed25519 | Принято |
| [0003](0003-aead-cipher.md) | AES-256-GCM как AEAD | Принято; attachment STREAM заменён решением R2, текст 0009 на согласовании |
| [0004](0004-vault-layout.md) | Хранилище как каталог с файлом на запись | Принято; layout частично заменён 0008 |
| [0005](0005-console-ui.md) | Spectre.Console для консольного UI | Принято |
| [0006](0006-product-scope.md) | Самостоятельный local-first vault и приоритет developer secrets | Принято |

Шаблон — [`template.md`](template.md).

## SN-002-R2 — состояния решений, 2026-11-12

| # | Решение | Статус |
|---|---|---|
| [0007](0007-recovery-key-slots.md) | Независимые password/recovery slots, обязательный recovery | Принято (Accepted) |
| [0008](0008-generation-commit.md) | COW версии, manifest и единый root commit | Принято (Accepted); частично заменяет 0004 |
| [0009](0009-streaming-aead-profile.md) | Whole-object BCL AES-256-GCM для вложений до 25 МиБ | Предложено (Proposed), новая редакция на согласовании |

[Спецификация](../vault-format.md), [модель угроз](../threat-model.md),
[реестр решений владельца](../SN-002-DECISIONS.md) и [план проверок](../SN-002-VERIFICATION.md).
Приняты ADR 0001–0008. ADR 0008 частично заменяет layout ADR 0004. Выбор whole-object
вместо attachment STREAM из ADR 0003 подтверждён владельцем; редакция ADR 0009 ещё Proposed.
KDF worker и жёсткий deadline не входят в автоматически утверждённые решения.
