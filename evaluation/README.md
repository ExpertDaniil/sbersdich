# Evaluation

Здесь находится локальный контур оценки: результаты прогонов, дополнительные
задачи и автоматический разбор причин провалов C-11. Генерируемое содержимое
`results/` не коммитится.

## C-11: failure journal

Анализатор принимает отдельные файлы или каталоги с `JSON`, `JSONL`, `NDJSON`,
`.log` и `.txt`:

```bash
python3 -m evaluation.failure_analysis path/to/traces.json \
  --output evaluation/results/failure_journal.json \
  --strict
```

| Категория | Что означает | Следующий владелец |
|---|---|---|
| `launch` | Не запустились runtime, entrypoint или конфигурация | блок B, runtime/entrypoint |
| `format` | Не выполнен контракт пути, схемы или артефакта | блок C, validation/output |
| `hypothesis` | Не подтверждена выбранная находка или трактовка | блок C, security strategies |
| `execution` | Упало действие или инструмент | блок A, agent core/tools |
| `timeout` | Истёк deadline | блок A, orchestration |
| `budget` | Исчерпаны шаги, повторы, контекст или токены | блок A, agent loop |
| `regression` | Не прошли тесты или security-check | блок C, regression verification |
| `unknown` | Данных в логе недостаточно | общий ручной triage |

Каждая запись содержит исходный файл и JSON-path доказательства, краткую
причину, владельца и следующее действие. Evidence ограничено по размеру и
очищается от API-ключей, bearer-токенов, паролей и секретов.

Коды возврата CLI:

- `0` — журнал создан; в `--strict` нет неизвестных причин;
- `1` — журнал создан, но `--strict` нашёл `unknown`;
- `2` — вход повреждён, небезопасен или не поддерживается.

Проверка модуля:

```bash
./evaluation/verify.sh
```

## C-12: portability/adversarial suite

C-12 проверяет реальные компоненты агента на изменённых входах и пограничных
условиях. Все fixtures создаются во временных каталогах, поэтому suite не
меняет рабочее дерево и не содержит ответов публичных задач.

```bash
python3 -m evaluation.portability \
  --output evaluation/results/c12_portability.json
```

Проверяются девять областей:

- точный формат результата при LF/CRLF, лишнем newline и пробелах;
- три SQL-вариации с другими именами, Unicode и разными окончаниями строк;
- обязательный rescan, который обнаруживает частичное исправление SQLi;
- атомарность patch при неверном втором файле, traversal и плохом hunk;
- пустые JSONL, BOM, большие строки и несколько forensics log-shard;
- отсутствующие артефакты и неполная evidence-цепочка;
- объединение нескольких C-11 run-log файлов;
- ограничение большого stdout, timeout зависшей команды и неверный cwd;
- работа runtime-модулей без сторонних зависимостей и сетевых обращений suite.

Код возврата `0` означает, что все проверки прошли; `1` — хотя бы одна
проверка провалена, но JSON-отчёт сохранён; `2` — отчёт записать не удалось.

Подробности: [`../docs/C12_REPORT.md`](../docs/C12_REPORT.md).

## C-13: generated CTF variations

C-13 добавляет отдельный `ctf`-режим и проверяет его на трёх независимых
задачах, которые создаются только во временных каталогах:

- Base64 → ROT13 для текстового артефакта;
- чтение бинарного файла → hex → repeating XOR;
- unpadded Base64URL → ограниченная gzip-распаковка.

```bash
python3 -m evaluation.ctf_suite \
  --output evaluation/results/c13_ctf.json
```

Suite прогоняет настоящий classifier, task contract, режимный tool registry,
agent loop и validator. Внутренний validator проверяет создание только
заявленного output; внешний exact-verifier отдельно сравнивает байты ответа с
эталоном. Ответ не передаётся pipeline-driver и не помещается в workspace.

Код возврата `0` означает 3/3; `1` — хотя бы одна задача не решена; `2` —
невозможно безопасно записать JSON-отчёт. Подробности:
[`../docs/C13_REPORT.md`](../docs/C13_REPORT.md).
