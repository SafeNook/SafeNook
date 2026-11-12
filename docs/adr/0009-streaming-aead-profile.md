# 0009. Конкретный AES-GCM-HKDF Streaming профиль для вложений

- **Статус:** Предложено (Proposed)
- **Дата:** 2026-11-12
- **Scope:** SN-002, Q-05, вложения M2.
- **При принятии:** заменяет правило случайного nonce для каждого chunk в ADR 0003
  на профиль nonce из выбранной STREAM-конструкции; AES-256-GCM остаётся.

## Контекст

ADR 0003 выбирает STREAM/GCM и 64 KiB, но не задаёт полноценный wire protocol.
Самостоятельная конкатенация GCM chunks не доказывает защиту от truncation/reordering.
Различаются аутентификация отдельного префикса и проверка целого файла до выдачи plaintext.

## Предлагаемое решение

Взять опубликованную RAW encryption function AES-GCM-HKDF Streaming из Tink с SHA256,
AES256 и ciphertext segment 65,536 bytes. Контекст SafeNook передаётся AssociatedData;
фиксированная спецификация оболочки и длины — [vault-format](../vault-format.md).
Уменьшенная ёмкость первого сегмента и счётчик/final marker являются частью профиля,
а не неявными деталями реализации. Новый случайный write ID и stream randomness на
каждое шифрование, включая повтор после неудачи. Максимум 25 MiB / 401 segments.

Сначала аутентифицировать весь файл в ограниченной памяти, только затем публиковать
plaintext. Не отдавать прошедший проверку префикс до проверки final segment и EOF.

## Альтернативы

| Вариант | Плюсы | Цена / решение |
|---|---|---|
| Готовая reviewed реализация выбранного профиля | Есть спецификация, анализ, interop target | Сначала подтвердить .NET/AOT support, зависимости и происхождение; предпочтительна |
| Собственный порт точного профиля | BCL AES/HKDF, единый формат | Не считается audited; независимый review и vectors до M2 обязательны |
| libsodium secretstream XChaCha20-Poly1305 | Готовая высокоуровневая streaming API | Нужны новый выбор AEAD вместо ADR 0003 для blobs, binding/AOT review; резервная альтернатива |
| Whole-object AES-GCM для <=25 MiB | Проще композиция и уже нужна память до output | Отменяет STREAM ADR 0003, нужен отдельный выбор владельца; не внедрять молча |
| Самодельные независимые AES-GCM chunks | Кажется просто | Не выбран: легко потерять final/ordering/domain guarantees |

## Источники и ограничения

[Tink formal profile](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming)
ссылается на анализ [Hoang–Shen 2020](https://eprint.iacr.org/2020/1019).
[libsodium secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream)
даёт готовую альтернативу с XChaCha20-Poly1305. Анализ конструкции не доказывает безопасность
нового порта, SafeNook envelope, парсера или filesystem adapter.

Библиотека не выбрана и зависимости не добавлены. При отсутствии подходящей reviewed
реализации выпуск M2 блокируется до review порта либо явно утверждённой альтернативы.
Принятый ADR 0003 сейчас не изменён; этот ADR не принят автоматически.
