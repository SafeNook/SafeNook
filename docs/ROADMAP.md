# SafeNook Roadmap

> Статус: рабочий план, октябрь 2026.
> Направление: **CLI/TUI-хранилище секретов для разработчиков → собственная экосистема.** Сначала локальное хранилище паролей, SSH-ключей, `.env`-наборов, файлов и заметок с удобным CLI и синхронизацией через git. Затем собственный self-hosted сервер и GUI-клиенты (десктоп + мобильные) на общем ядре.
>
> SafeNook — новый проект, а не продолжение [PasswordGeneratorCLI](https://github.com/algmironov/PasswordGeneratorCLI). Обратной совместимости с ним нет; записи переносятся одноразовым импортом.

---

## Содержание

1. [Цели и не-цели](#1-цели-и-не-цели)
2. [Уроки PasswordGeneratorCLI](#2-уроки-passwordgeneratorcli)
3. [Решения](#3-решения)
4. [Целевая архитектура](#4-целевая-архитектура)
5. [Формат хранилища и криптография](#5-формат-хранилища-и-криптография)
6. [Модель данных](#6-модель-данных)
7. [Этапы](#7-этапы)
   - [Этап 0. Фундамент](#этап-0-фундамент)
   - [Этап 1. CLI и интерактивный режим](#этап-1-cli-и-интерактивный-режим)
   - [Этап 2. Дистрибуция](#этап-2-дистрибуция)
   - [Этап 3. Секреты для разработчиков и фоновый агент](#этап-3-секреты-для-разработчиков-и-фоновый-агент)
   - [Этап 4. Синхронизация и self-hosted сервер](#этап-4-синхронизация-и-self-hosted-сервер)
   - [Этап 5. GUI: десктоп и мобильные](#этап-5-gui-десктоп-и-мобильные)
   - [Организационные задачи](#организационные-задачи)
8. [Сквозные требования](#8-сквозные-требования)
9. [Версии и вехи](#9-версии-и-вехи)
10. [Риски](#10-риски)

---

## 1. Цели и не-цели

**Цели**

- Безопасное локальное хранилище с современной криптографией и версионируемым форматом.
- Типизированные записи: логины, заметки, SSH-ключи, `.env`-наборы, небольшие файлы, TOTP.
- Удобный CLI для скриптов и приятный интерактивный режим для людей.
- Один бинарник без установленного .NET, пакеты для основных менеджеров.
- Синхронизация между устройствами: сначала git/папка, затем свой zero-knowledge сервер.
- GUI-клиенты на общем ядре.

**Не-цели (по крайней мере до этапа 5)**

- Расширение для браузера и автозаполнение в браузере.
- Командный/организационный шаринг секретов.
- Совместимость с форматами других менеджеров на уровне хранилища (только импорт/экспорт).

---

## 2. Уроки PasswordGeneratorCLI

Аудит версии 2.1.1 определил требования к SafeNook с первого дня:

| Что было | Что делаем |
|---|---|
| Один класс смешивал крипто, файлы, логику и консоль | `SafeNook.Core` без единой ссылки на консоль; UI — тонкие фронтенды |
| AES-CBC без аутентификации | Только AEAD (AES-256-GCM) |
| PBKDF2, 10 000 итераций | Argon2id с калибровкой и параметрами в заголовке |
| Нет версии формата | Magic + версия во всех файлах |
| Неатомарная запись | temp-файл → `fsync` → atomic rename + бэкапы |
| Очистка буфера в fire-and-forget задаче, которая умирала вместе с процессом | Очистка — ответственность живого процесса (интерактивный режим, агент, отсоединённый helper) |
| Пароль печатался в консоль | Секреты не выводятся без явного `--reveal` |
| Генератор молча обрезал длину, не гарантировал классы символов | Явная политика генерации с валидацией и гарантиями |
| `Console.ReadKey` не работал без TTY | Отдельные пути ввода для TTY и скриптов |
| Нет тестов и CI | CI на трёх ОС с первого коммита |

---

## 3. Решения

Каждое решение фиксируется ADR в [`docs/adr/`](adr/).

| # | Вопрос | Статус | ADR |
|---|---|---|---|
| D-1 | Имя проекта и команды | **Принято:** SafeNook, команда `nook` | [0001](adr/0001-name.md) |
| D-2 | Библиотека для Argon2id и Ed25519 | **Принято:** NSec (libsodium), статическая линковка; Argon2id только с p=1 | [0002](adr/0002-crypto-library.md) |
| D-3 | AEAD-шифр | **Принято:** AES-256-GCM из BCL | [0003](adr/0003-aead-cipher.md) |
| D-4 | Один файл или каталог | **Принято:** каталог, файл на запись | [0004](adr/0004-vault-layout.md) |
| D-5 | Консольная UI-библиотека | **Принято:** Spectre.Console; Terminal.Gui v2 — только при необходимости полноэкранного TUI | [0005](adr/0005-console-ui.md) |
| D-6 | GUI-фреймворк | Предложено: Avalonia | этап 5 |
| D-7 | Лицензия сервера | Открыто: MIT как у клиента или AGPL | этап 4 |

---

## 4. Целевая архитектура

### Структура решения

```
/
├─ src/
│  ├─ SafeNook.Core/          # модели, крипто, формат, сервисы. БЕЗ Console, БЕЗ UI
│  ├─ SafeNook.Core.Sync/     # движок синхронизации (git, HTTP-клиент сервера)   (этап 4)
│  ├─ SafeNook.Agent/         # фоновый агент: сессия, ssh-agent, буфер обмена    (этап 3)
│  ├─ SafeNook.Cli/           # команда `nook`: System.CommandLine 2.0 + Spectre.Console
│  ├─ SafeNook.Server/        # ASP.NET Core minimal API + SQLite                 (этап 4)
│  └─ SafeNook.Desktop/       # Avalonia, затем Android/iOS                        (этап 5)
├─ tests/
│  ├─ SafeNook.Core.Tests/
│  ├─ SafeNook.Cli.Tests/
│  └─ SafeNook.Server.Tests/
├─ docs/
│  ├─ ROADMAP.md
│  ├─ adr/
│  ├─ vault-format.md         # спецификация формата
│  └─ threat-model.md
├─ packaging/                 # nfpm, homebrew, scoop, winget, aur
├─ Directory.Build.props      # общие настройки, Nullable, анализаторы, TreatWarningsAsErrors
├─ Directory.Packages.props   # central package management
├─ global.json                # закреплён SDK .NET 10
└─ SafeNook.slnx
```

### Правила зависимостей

```
Cli ──► Agent ──► Core.Sync ──► Core
Desktop ─────────► Core.Sync ──► Core
Server  ─────────► (только контракты DTO, общие с Core.Sync)
```

- `Core` не знает о консоли, файловой системе пользователя (только через абстракции), буфере обмена и сети.
- Сервер **никогда** не ссылается на криптографию расшифровки.
- Все проекты, кроме сервера и GUI, обязаны быть AOT-совместимыми (`IsAotCompatible`).

### Основные абстракции `SafeNook.Core`

```csharp
// Хранилище байтов. Реализации: FileSystemVaultStore, InMemoryVaultStore (тесты)
public interface IVaultStore
{
    Task<VaultHeader?> ReadHeaderAsync(CancellationToken ct);
    Task WriteHeaderAsync(VaultHeader header, CancellationToken ct);       // атомарно
    IAsyncEnumerable<EncryptedObject> ReadItemsAsync(CancellationToken ct);
    Task WriteItemAsync(EncryptedObject item, CancellationToken ct);       // атомарно
    Task<IAsyncDisposable> AcquireLockAsync(CancellationToken ct);         // межпроцессная блокировка
}

public interface IKeyDerivation   // Argon2id
{
    void DeriveKey(ReadOnlySpan<byte> password, KdfParameters p, Span<byte> output);
}

public interface IAeadCipher      // AES-256-GCM
{
    byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad);
    byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> aad);
}

// Разблокированная сессия. Держит Vault Key, зануляет его в Dispose
public sealed class VaultSession : IDisposable
{
    public IReadOnlyList<VaultItem> Items { get; }
    public Task<VaultItem> AddAsync(VaultItem item, CancellationToken ct);
    public Task UpdateAsync(VaultItem item, CancellationToken ct);   // кладёт старый пароль в историю
    public Task DeleteAsync(Guid id, CancellationToken ct);          // tombstone, не физическое удаление
    public IEnumerable<VaultItem> Search(string query);              // нечёткий поиск по имени, тегам, URL
}

public static class VaultOpener
{
    public static Task CreateAsync(IVaultStore store, ReadOnlyMemory<byte> masterPassword, ...);
    public static Task<VaultSession> UnlockAsync(IVaultStore store, ReadOnlyMemory<byte> masterPassword, ...);
}

public interface IPasswordGenerator
{
    string Generate(PasswordPolicy policy);        // длина, классы, исключения, «без похожих символов»
    string GeneratePassphrase(PassphrasePolicy p); // diceware, EFF wordlist
    double EstimateEntropyBits(PasswordPolicy p);
}

public interface IClipboard   // реализация живёт в Cli/Agent, не в Core
{
    Task SetAsync(string text, CancellationToken ct);
    Task ClearIfEqualsAsync(string expectedHash, CancellationToken ct);
}
```

---

## 5. Формат хранилища и криптография

Полная спецификация выносится в `docs/vault-format.md` (задача F-12). Здесь — суть.

### Расположение

| ОС | Данные | Конфиг |
|---|---|---|
| Linux | `$XDG_DATA_HOME/safenook/` (`~/.local/share/safenook/`) | `$XDG_CONFIG_HOME/safenook/config.toml` |
| macOS | `~/Library/Application Support/SafeNook/` | там же |
| Windows | `%APPDATA%\SafeNook\` | там же |

Переопределение: `--vault <path>` и переменная окружения `SAFENOOK_VAULT`. Поддерживаются несколько хранилищ (личное, рабочее).

Права: каталог `0700`, файлы `0600` (на Windows — ACL только для текущего пользователя).

### Структура каталога

```
vault/
├─ vault.json            # заголовок (открытый текст, целостность защищена)
├─ items/
│  └─ <uuid>.item        # одна зашифрованная запись
├─ blobs/
│  └─ <uuid>.blob        # зашифрованные вложения (потоковое шифрование)
├─ .lock                 # межпроцессная блокировка
└─ .backup/              # N последних версий изменённых файлов
```

### Иерархия ключей

```
мастер-пароль ──Argon2id(salt, m, t, p)──► KEK (256 бит)
                                            │ unwrap (AES-GCM)
                                            ▼
                         Vault Key (VK, случайные 256 бит, генерируется при init)
                                            │ HKDF-SHA256 (info = "item" / "blob" / "auth")
                       ┌────────────────────┼────────────────────┐
                       ▼                    ▼                    ▼
                   Item Key             Blob Key           Auth Key (этап 4)
```

- Смена мастер-пароля = перешифровать только VK, записи не трогаются.
- **Key slots**: VK может быть обёрнут несколькими способами — пароль, ключ восстановления (показывается при `init`), позже — биометрия/OS keychain на устройстве.

### `vault.json`

```json
{
  "format": "safenook-vault",
  "formatVersion": 1,
  "vaultId": "7c3e…",
  "createdAt": "2026-11-01T10:00:00Z",
  "cipher": "AES-256-GCM",
  "keySlots": [
    {
      "id": "pwd-1",
      "type": "password",
      "kdf": { "alg": "argon2id", "memoryKiB": 65536, "iterations": 3, "parallelism": 1, "salt": "base64…" },
      "wrappedKey": "base64(nonce‖ciphertext‖tag)"
    },
    { "id": "rec-1", "type": "recovery", "kdf": { "alg": "hkdf-sha256", "salt": "…" }, "wrappedKey": "…" }
  ]
}
```

- AAD при обёртке VK = `vaultId ‖ slotId ‖ formatVersion` — слот нельзя переставить в другое хранилище.
- Параметры Argon2id калибруются на `init` (цель ~0.5–1 с на машине пользователя, не ниже `m=64 MiB, t=3`) и хранятся в слоте → их можно поднимать позже командой `nook passwd --rekey`.
- Калибровка: целевое время достигается сначала увеличением памяти, затем числа проходов; потоков всегда 1 (libsodium поддерживает только `p=1`, соль ровно 16 байт — см. [ADR 0002](adr/0002-crypto-library.md)).

### Файл записи `<uuid>.item`

```
magic "SNI1" (4) | version (1) | nonce (12) | ciphertext (…) | tag (16)
AAD = vaultId ‖ itemId
```

- Внутри — JSON записи (см. §6), сериализация через **source-generated** `JsonSerializerContext` (обязательно для Native AOT).
- Случайный 96-битный nonce на каждую запись файла. Лимит ~2³² шифрований на ключ недостижим для личного хранилища; при необходимости — ротация Item Key.

### Вложения `<uuid>.blob`

- Magic `SNB1`. Потоковое AEAD: чанки по 64 KiB, nonce = префикс ‖ номер чанка, флаг последнего чанка в AAD (конструкция STREAM). Защищает от обрезки и перестановки чанков.
- Лимит размера по умолчанию 25 MiB, настраивается.

### Надёжность записи

1. Пишем во временный файл в том же каталоге.
2. `fsync` файла.
3. Атомарный `rename` поверх старого (на Windows — `File.Replace`).
4. Старую версию кладём в `.backup/` (ротация, последние N).

### Работа с секретами в памяти

- Ключи — только `byte[]`/`Span<byte>`, после использования `CryptographicOperations.ZeroMemory`.
- Мастер-пароль читается в `byte[]`, а не в `string`.
- Ограничения .NET (строки для отображения, GC-копии) честно описываем в `threat-model.md`.

### Импорт из PasswordGeneratorCLI

- `nook import pwgen-v2 [PATH]` — по умолчанию ищет `~/.config/pwgen/storage.cpwgen` / `%APPDATA%\pwgen\storage.cpwgen`.
- Расшифровка старым алгоритмом (AES-CBC + PBKDF2-SHA256, 10 000 итераций), перенос: Service → name, Login → username, Url → urls[0], Note → notes.
- Код чтения старого формата изолирован в `Import/PwgenV2Reader`, только для чтения. Старый файл не изменяется.

---

## 6. Модель данных

Общие поля любой записи:

```json
{
  "id": "uuid",
  "type": "login | note | ssh-key | file | env",
  "name": "GitHub",
  "tags": ["work", "dev"],
  "favorite": false,
  "notes": "",
  "createdAt": "…",
  "updatedAt": "…",
  "revision": 7,
  "deleted": false,
  "customFields": [{ "name": "PIN", "value": "1234", "hidden": true }],
  "data": { /* зависит от типа */ }
}
```

| Тип | `data` |
|---|---|
| `login` | `username`, `password`, `urls[]`, `totp` (otpauth URI), `passwordHistory[]` (`value`, `changedAt`) |
| `note` | `body` (markdown) |
| `ssh-key` | `keyType` (ed25519 / rsa / ecdsa), `privateKey` (OpenSSH), `publicKey`, `comment`, `agent` (`enabled`, `confirmOnUse`), `hosts[]` |
| `file` | `blobId`, `fileName`, `size`, `sha256`, `mime` |
| `env` | `variables[]` (`key`, `value`), `description` |

- Удаление — tombstone (`deleted: true`), окончательная очистка через `nook purge` после N дней. Это нужно для синхронизации.
- `revision` растёт при каждом изменении — основа для разрешения конфликтов.

---

## 7. Этапы

Формат задачи: `ID` — описание. Внутри этапа задачи идут примерно в порядке выполнения.

### Этап 0. Фундамент

Цель: ядро с форматом хранилища, покрытое тестами. Выпуск **0.1.0**.

**Инфраструктура**

- [x] F-1 Принять D-1, D-3, D-4, D-5, записать ADR. D-2 — после F-4.
- [x] F-2 Структура решения (`src/`, `tests/`), `global.json` с .NET 10, `Directory.Build.props`, `Directory.Packages.props`, `SafeNook.slnx`.
- [x] F-3 CI в GitHub Actions: build + test на Windows, Linux, macOS, AOT smoke-публикация. Dependabot.
- [ ] F-3a CodeQL, защита ветки `main`, обязательный зелёный CI для merge.
- [x] F-4 Спайк: NSec + Native AOT на трёх ОС (результат → ADR 0002).

**Ядро**

- [ ] F-5 `IAeadCipher` (AES-GCM), `IKeyDerivation` (Argon2id), HKDF. Тесты на известных векторах (libsodium `pwhash_argon2id` для Argon2 — RFC 9106 требует p=4, см. ADR 0002; NIST для GCM, RFC 5869 для HKDF).
- [ ] F-6 `VaultHeader`, key slots, wrap/unwrap VK, калибровка Argon2id.
- [ ] F-7 `FileSystemVaultStore`: атомарная запись, `.backup/`, межпроцессная блокировка, права файлов.
- [ ] F-8 Модели записей (§6) + source-generated JSON-контекст.
- [ ] F-9 `VaultSession`: CRUD, история паролей, tombstones, поиск.
- [ ] F-10 `PasswordGenerator`: политика (длина 8–128, классы символов с гарантией каждого, исключение похожих `0O1lI`), passphrase по EFF wordlist, оценка энтропии.
- [ ] F-11 `PwgenV2Reader` + импорт.
- [ ] F-12 `docs/vault-format.md` и `docs/threat-model.md`.

**Тесты (минимум)**

- round-trip шифрования; неверный пароль; подмена одного байта в любом файле → ошибка; перестановка файла записи в другое хранилище → ошибка;
- прерванная запись не повреждает хранилище;
- импорт из PasswordGeneratorCLI на эталонном файле (сгенерировать старой версией и положить в `tests/fixtures`);
- статистические тесты генератора (наличие классов, распределение);
- fuzz-тест парсера заголовка и файлов записей.

**Готово, когда:** ядро проходит тесты на трёх ОС, формат описан, AOT-спайк закрыт.

### Этап 1. CLI и интерактивный режим

Цель: выпуски **0.2** (команды) и **0.3** (интерактивный режим).

#### Команды

```
nook                                   интерактивный режим (если TTY), иначе справка
nook gen [-l 20] [--no-symbols] [--exclude-similar] [--passphrase --words 5] [--copy]
nook init [--vault PATH]
nook add login|note|ssh|file|env [--name ..] [--username ..] [--url ..] [--generate]
nook ls [QUERY] [--type T] [--tag T] [--json]
nook show QUERY [--reveal] [--field F] [--json]
nook copy QUERY [--field password|username|totp|<custom>] [-t 30]
nook edit QUERY
nook rm QUERY                          (tombstone; purge — отдельно)
nook history QUERY
nook totp QUERY
nook passwd [--rekey]                  смена мастер-пароля / параметров KDF
nook import pwgen-v2|bitwarden|keepass-csv FILE
nook export --encrypted FILE           (открытый экспорт — только с явным флагом и предупреждением)
nook doctor                            слабые, повторяющиеся, старые пароли
```

- `QUERY` — нечёткий поиск. Если совпадений несколько: в TTY — выбор стрелками, без TTY — ошибка с кодом 2 и списком.

#### Скриптовый режим

- `--json` для всех команд чтения, стабильная схема вывода.
- Мастер-пароль: TTY-prompt; `--password-stdin`; `SAFENOOK_PASSWORD_FILE`. Никогда — аргументом командной строки.
- Коды выхода: `0` ок, `1` ошибка, `2` неоднозначность/не найдено, `3` неверный пароль, `4` хранилище заблокировано.
- Уважать `NO_COLOR`, `--no-color`, отсутствие TTY.

#### Буфер обмена

- В интерактивном режиме — таймер внутри живого процесса.
- В одноразовой команде: запускается отсоединённый дочерний процесс `nook __clip-clear --after 30 --hash <sha256>`, который очищает буфер **только если там всё ещё наш пароль** (сравнение хэша).
- Linux: проверить X11 и Wayland (`wl-copy`), понятная ошибка, если утилит нет.

#### Интерактивный режим

```
┌ SafeNook · personal ───────────────────── 🔓 автоблок через 4:52 ┐
│ Поиск: git▌                                                       │
│ › 🔑 GitHub            alex@example.com     github.com    work    │
│   🔑 GitLab (work)     a.mironov            gitlab.corp   work    │
│   🗝  github-deploy     ed25519                           dev     │
└ ↑↓ выбор · Enter действия · / поиск · n новая · q выход ──────────┘
```

- [ ] I-1 Цикл: разблокировка → поиск с фильтрацией → меню действий записи (копировать пароль/логин/TOTP, показать, редактировать, удалить).
- [ ] I-2 Автоблокировка по бездействию. Стандартные prompt'ы Spectre блокирующие → нужен свой цикл ввода с опросом `Console.KeyAvailable` и таймером. Технический риск, делать первым спайком этапа.
- [ ] I-3 Мастера создания записей по типам с генерацией пароля «на месте».
- [ ] I-4 Единая тема: цвета только через палитру Spectre, без жёстких фонов, проверка в светлой и тёмной теме; иконки типов с ASCII-фолбэком.

#### Задачи

- [ ] C-1 Слой команд как тонкая обёртка над `SafeNook.Core` — без логики в обработчиках.
- [ ] C-2 Все команды из списка выше, кроме `import bitwarden|keepass-csv` и `doctor` (их можно в 0.4).
- [ ] C-3 Буфер обмена (см. выше).
- [ ] C-4 Интерактивный режим I-1 … I-4.
- [ ] C-5 Тесты CLI: `Spectre.Console.Testing` + snapshot-тесты вывода, тесты кодов выхода и JSON-схемы.
- [ ] C-6 README с GIF/asciinema.

**Готово, когда:** вы перенесли свои записи импортом и пользуетесь `nook` каждый день вместо старой утилиты.

### Этап 2. Дистрибуция

Цель: выпуск **0.4**, затем **1.0** — установка одной командой без .NET на всех основных платформах.

#### Сборка

- Native AOT, `InvariantGlobalization`, trimming; без рефлексии (source-gen JSON, System.CommandLine 2.0 AOT-совместим).
- Матрица: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `linux-musl-x64`, `osx-arm64`, `osx-x64`. AOT собирается на родной ОС → матрица runner'ов GitHub Actions.

#### Релизный pipeline (по тегу `v*`)

1. Сборка и тесты на всех RID.
2. Архивы `.tar.gz` / `.zip`, `SHA256SUMS`.
3. Подпись: GitHub artifact attestations (Sigstore) и/или minisign.
4. GitHub Release с changelog из `CHANGELOG.md`.
5. Публикация в каналы ниже.

#### Каналы

| Канал | Что сделать |
|---|---|
| Homebrew | tap `SafeNook/homebrew-tap`, формула обновляется из CI |
| Scoop | bucket `SafeNook/scoop-bucket` |
| winget | манифест `SafeNook.SafeNook`, PR в `microsoft/winget-pkgs` |
| AUR | пакет `safenook-bin` (команда `nook`) |
| deb / rpm | пакет `safenook` через `nfpm`, позже — свой apt/rpm-репозиторий |
| install.sh / install.ps1 | `curl -fsSL https://safenook.dev/install.sh \| sh` с проверкой SHA256 и подписи |
| NuGet dotnet tool | `SafeNook.Cli` как дополнительный канал |

Пакеты называются `safenook`, бинарник — `nook`. Перед публикацией проверить, что `nook` не конфликтует с бинарниками в репозиториях дистрибутивов.

- [ ] R-1 AOT-сборка проходит без предупреждений trimming.
- [ ] R-2 Release workflow.
- [ ] R-3 Homebrew + Scoop + install-скрипты.
- [ ] R-4 winget + AUR + deb/rpm.
- [ ] R-5 Проверка «чистой установки» на свежих VM/контейнерах в CI.

**Готово, когда:** на чистой машине любой ОС ставится одной командой и работает без .NET. После этого — **1.0**: формат хранилища заморожен, дальнейшие изменения только с миграциями.

### Этап 3. Секреты для разработчиков и фоновый агент

Цель: выпуск **1.1** — то, что делает SafeNook инструментом разработчика.

#### Фоновый агент

Один долгоживущий процесс на пользователя, который:

- держит разблокированный VK с автоблокировкой (по таймеру, по команде `nook lock`, позже — при сне/блокировке экрана);
- обслуживает CLI через локальный сокет → `nook unlock` один раз, дальше команды без пароля;
- работает как **ssh-agent**;
- отвечает за очистку буфера обмена.

Транспорт и защита:

- Linux/macOS: Unix socket в `$XDG_RUNTIME_DIR` с правами `0600`, проверка UID собеседника (`SO_PEERCRED` / `getpeereid`).
- Windows: named pipe с ACL текущего пользователя.
- Команды: `nook unlock [--timeout 15m]`, `nook lock`, `nook agent status|start|stop`, автозапуск через systemd user unit / launchd / Task Scheduler (опционально).

#### SSH-ключи

- [ ] S-1 `nook ssh gen [--type ed25519|rsa] --name …`, `nook ssh import FILE`, `nook ssh pub QUERY`, `nook ssh export QUERY` (с предупреждением).
- [ ] S-2 Парсинг/запись формата OpenSSH private key. Импорт зашифрованных ключей требует `bcrypt_pbkdf` — реализовать или запрашивать расшифрованный ключ.
- [ ] S-3 Протокол ssh-agent: `REQUEST_IDENTITIES`, `SIGN_REQUEST` для ed25519 (NSec), `rsa-sha2-256/512`, ECDSA (встроенные в .NET).
- [ ] S-4 Windows: pipe `\\.\pipe\openssh-ssh-agent` (конфликтует со службой Windows OpenSSH agent — понятная диагностика).
- [ ] S-5 Подтверждение использования ключа (`confirmOnUse`) через prompt/уведомление.

#### Файлы, `.env`, TOTP

- [ ] E-1 `nook file add PATH [--name …]`, `nook file get QUERY -o PATH` (создаётся с правами `0600`), потоковое шифрование blob'ов.
- [ ] E-2 `nook env set NAME KEY=VALUE…`, `nook env import .env`, `nook env show`.
- [ ] E-3 `nook run --env NAME [--env NAME2] -- команда args…` — секреты передаются только в окружение дочернего процесса.
- [ ] E-4 TOTP (RFC 6238): `nook totp QUERY`, копирование кода, импорт из `otpauth://` URI и QR-картинки (опционально).

**Готово, когда:** можно хранить SSH-ключ в SafeNook и делать `git push` без файла ключа на диске; `nook run` подставляет секреты в окружение.

### Этап 4. Синхронизация и self-hosted сервер

#### 4a. Синхронизация через git или папку (выпуск 1.2)

Каталог с файлом на запись (D-4) делает это почти бесплатным.

- [ ] Y-1 `nook sync init git REMOTE` — инициализирует git в каталоге хранилища, `.gitignore` для `.lock` и `.backup/`.
- [ ] Y-2 `nook sync` = `commit` → `pull --rebase` → разрешение конфликтов → `push`. Используем установленный `git` (без LibGit2Sharp, чтобы не тащить нативные зависимости).
- [ ] Y-3 Разрешение конфликтов на уровне записей в `SafeNook.Core.Sync`: расшифровать обе версии, побеждает бо́льшая `revision`, при равенстве — более поздний `updatedAt`; проигравшая версия пароля уходит в `passwordHistory`, для остальных полей — запись-копия «(конфликт)».
- [ ] Y-4 Режим «папка» для Syncthing/Dropbox/Nextcloud: обнаружение и разрешение файлов-конфликтов, которые создают эти сервисы.

#### 4b. SafeNook Server (выпуск 1.3)

**Принцип zero-knowledge:** сервер хранит только зашифрованные объекты и не может их расшифровать. Компрометация сервера раскрывает только метаданные (количество и размеры объектов, время изменений).

**Аутентификация**

- Клиент выводит `AuthKey = HKDF(KEK, "auth")` и отправляет его серверу; сервер хранит `Argon2id(AuthKey)`. Ни KEK, ни VK сервер не видит.
- Устройства регистрируются, получают access token (короткий) + refresh token (отзывной). Список устройств и отзыв — в CLI.
- Регистрация только по приглашению (команда администратора на сервере), rate limiting на логин. 2FA — позже.

**API v1**

```
POST   /api/v1/auth/prelogin        → kdf-параметры и salt по логину
POST   /api/v1/auth/login           → токены
POST   /api/v1/auth/refresh
GET    /api/v1/devices  · DELETE /api/v1/devices/{id}

GET    /api/v1/vault/header
PUT    /api/v1/vault/header         If-Match: <revision>

GET    /api/v1/items?since=<seq>    → изменения после серверного номера seq (включая tombstones)
PUT    /api/v1/items/{id}           If-Match: <revision>  → 409 Conflict при гонке
DELETE /api/v1/items/{id}           → tombstone

PUT    /api/v1/blobs/{id}  · GET /api/v1/blobs/{id}

GET    /health
```

- Синхронизация инкрементальная: клиент помнит последний `seq`, сервер выдаёт монотонно растущий номер каждому изменению.
- Конфликты разрешает клиент тем же кодом, что и в 4a.

**Сервер**

- [ ] V-1 ASP.NET Core minimal API, SQLite (одна таблица объектов + пользователи + устройства), миграции схемы.
- [ ] V-2 Docker-образ `ghcr.io/safenook/server` + пример `docker-compose.yml` с Caddy для HTTPS; также AOT-бинарник.
- [ ] V-3 Админ-CLI: `safenook-server user invite`, `user disable`, `backup` (онлайн-копия SQLite).
- [ ] V-4 Ограничения: квоты на размер хранилища и blob'ов, rate limiting, CORS закрыт.
- [ ] V-5 Клиент: `nook sync init server URL`, `nook sync login`, `nook sync`, `nook sync devices`.
- [ ] V-6 Интеграционные тесты клиент ↔ сервер (`WebApplicationFactory`), сценарии конфликтов двух устройств.
- [ ] V-7 Документация по развёртыванию и бэкапам.

Позже: WebDAV/S3 как «немой» бэкенд с той же раскладкой объектов; защита от отката версий (подписанный журнал ревизий).

**Готово, когда:** два устройства синхронизируются через свой сервер, развёрнутый одной командой `docker compose up`.

### Этап 5. GUI: десктоп и мобильные

Цель: выпуск **2.0**. Ядро к этому моменту стабильно, GUI — ещё один фронтенд.

- [ ] G-1 Avalonia-приложение для Windows/macOS/Linux: список, поиск, просмотр/редактирование всех типов записей, генератор, синхронизация, автоблокировка. MVVM на CommunityToolkit.Mvvm.
- [ ] G-2 Интеграция с агентом: если агент разблокирован, GUI работает через него (одна сессия на систему).
- [ ] G-3 Android и iOS из того же кода; разблокировка биометрией через key slot, обёрнутый ключом Android Keystore / iOS Keychain.
- [ ] G-4 Автозаполнение: Android `AutofillService`; iOS Credential Provider Extension — вероятно, отдельный небольшой нативный модуль (риск, требует исследования).
- [ ] G-5 Распространение: подписанные инсталляторы (MSIX, `.dmg` с нотаризацией, AppImage/Flatpak), Google Play / F-Droid, App Store (требует Apple Developer аккаунт).

### Организационные задачи

- [x] O-1 GitHub-организация `SafeNook`, репозиторий `SafeNook/safenook`.
- [ ] O-2 Установить Claude GitHub App на организацию (для работы с репозиторием из сессий Claude).
- [ ] O-3 Настройки организации: обязательная 2FA, private vulnerability reporting, защита `main`.
- [ ] O-4 Зарегистрировать домен `safenook.dev` (проверено: в реестре не найден на 21.10.2026).
- [ ] O-5 Зарезервировать префикс `SafeNook.*` в NuGet (до первой публикации пакетов).
- [ ] O-6 После выпуска 0.3: архивировать PasswordGeneratorCLI — ссылка на SafeNook в README, пометить NuGet-пакет `PasswordGenCLI` как deprecated с альтернативой.

---

## 8. Сквозные требования

**Безопасность**

- Ни одного секрета в логах, исключениях, `ToString()`, выводе без явного `--reveal`.
- Все форматы версионированы и аутентифицированы; парсеры покрыты fuzz-тестами.
- [`SECURITY.md`](../SECURITY.md) с порядком сообщения об уязвимостях; `threat-model.md` обновляется на каждом этапе.
- Зависимости — минимум, версии закреплены через central package management, Dependabot.
- Перед 1.3 (сервер) — внешний взгляд на криптографию (хотя бы ревью сообществом / знакомым специалистом).

**Качество**

- xUnit v3, покрытие ядра ≥ 80 %, CI на трёх ОС обязателен для merge.
- Conventional Commits, `CHANGELOG.md` в формате Keep a Changelog, SemVer.
- Ветка `main` защищена; работа через PR.

**UX**

- Любая деструктивная операция требует подтверждения (`--yes` для скриптов).
- Ошибки сообщают, что делать дальше («хранилище не найдено → `nook init`»).
- Локализация: английский по умолчанию, русский через ресурсы (опционально, после 1.0).

---

## 9. Версии и вехи

| Версия | Содержимое | Этапы |
|---|---|---|
| 0.1 | ядро, формат хранилища, импорт из PasswordGeneratorCLI | 0 |
| 0.2 | команды CLI | 1 |
| 0.3 | интерактивный режим | 1 |
| 0.4 | AOT-бинарники, пакетные менеджеры, `import bitwarden/keepass`, `doctor` | 2 |
| **1.0** | формат заморожен, стабильный CLI, установка одной командой | 2 |
| 1.1 | фоновый агент, ssh-agent, файлы, `.env`, `run`, TOTP | 3 |
| 1.2 | синхронизация git / папка | 4a |
| 1.3 | SafeNook Server | 4b |
| 2.0 | десктопный и мобильный GUI | 5 |

До 1.0 формат может меняться без миграций (в README предупреждение «pre-alpha, не храните настоящие секреты»).

---

## 10. Риски

| Риск | Вероятность | Что делаем |
|---|---|---|
| Ошибка в криптографии/формате | средняя | только стандартные примитивы, тест-векторы, fuzz, ревью, спецификация формата до кода |
| NSec/libsodium плохо дружит с AOT на какой-то платформе | средняя | спайк F-4 до основной работы; запасной вариант — managed Argon2id + встроенные примитивы |
| Автоблокировка в интерактивном режиме с блокирующими prompt'ами | высокая | свой цикл ввода, спайк в начале этапа 1 |
| Команда `nook` совпадает с чем-то в репозиториях дистрибутивов | низкая | проверить перед этапом 2; запасной вариант — `snook` или алиас |
| ssh-agent на Windows конфликтует со службой OpenSSH | средняя | диагностика и документация, опционально Pageant-протокол |
| iOS-автозаполнение на Avalonia | высокая | отдельное исследование на этапе 5, допускаем нативный модуль |
| Объём работ для одного человека | высокая | каждый этап выпускается и полезен сам по себе; этапы 4b и 5 можно отложить без ущерба для предыдущих |
