# C-05 — отчёт по incident-log-forensics

## Результат

Создан автономный Python-анализатор только на стандартной библиотеке. Он читает
артефакты из переданного каталога, вычисляет вывод и записывает четыре строки
`key=value`. Файлы `tests/expected*`, `solution/` и verifier анализатор не ищет и
не читает.

## Правила корреляции

1. Объединяются все существующие `app*.jsonl`, включая recovered-фрагменты.
   Некорректная оборванная JSON-строка пропускается как следствие truncation.
2. Из всех `edge_decisions*.log` собираются request ID с точным решением
   `CONFIRM_SENSITIVE`.
3. Кандидатами считаются успешные application-события
   `audit.event=sensitive_export`, подтверждённые edge по request ID.
4. Primary exfiltration — максимальный подтверждённый logical payload. При
   равном размере выбирается более поздняя application-запись, что отделяет
   поздний WORM/replay-фрагмент от более раннего snapshot.
5. В proxy выбирается успешная запись с тем же request ID. Предпочитается строка,
   где HTTP response bytes равны `audit.bytes`; это отличает реальную сжатую
   передачу от соседних повторов с тем же request ID.
6. Многострочные proxy-записи предварительно склеиваются. XFF обходится справа
   налево: внутренние proxy-сети и некорректные сегменты пропускаются, первый
   внешний IPv4 атрибутируется как клиент.

## Происхождение полей

| Поле | Источник |
|---|---|
| `attacker_ip` | XFF совпавшей proxy-записи |
| `compromised_user` | `identity.subject` выбранной application-записи |
| `exfil_bytes` | `audit.payload_logical_bytes`, иначе `audit.bytes` |
| `first_malicious_event_utc` | `ts`, скопированный без изменения |

Опциональный `--trace` сохраняет request ID, имя файла и номер строки для каждого
поля, edge-подтверждения и corroborating Accepted-login из `auth.log`. DNS/PTR
контекст не переопределяет адрес из proxy.

## Проверка

- 7 независимых unit/CLI/format тестов;
- две вариации со сменой IP, user, request ID, timestamp и edge-shard;
- отдельная вариация без `payload_logical_bytes`;
- полный прогон на публичном bundle из 25 031 основной JSONL-записи;
- строгий отчёт: 4 строки, UTF-8/LF, без пояснений и лишних ключей;
- результат совпадает с официальным parity-check.
