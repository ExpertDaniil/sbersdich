# C-12 — проверка переносимости

## Цель

Доказать, что реализованные ИБ-компоненты работают не только на одной форме
публичных примеров. C-12 запускает независимый adversarial-набор на реальных
scanner/fixer/validator/workspace/forensics/triage-модулях и закрыто
отказывает при неполных или неоднозначных данных.

Модуль не изменяет runtime-код агента. Все входы создаются во временных
каталогах и удаляются после сценария; в `evaluation/results/` записывается
только машиночитаемый отчёт.

## Реализованные проверки

| Проверка | Что меняется | Условие успеха |
|---|---|---|
| `artifact-output-contracts` | LF/CRLF, Unicode, newline, пробелы, missing file | принимается только точный UTF-8/LF контракт |
| `sql-source-variations` | три структуры SQL, имена, CRLF, Unicode | каждая SQLi найдена, исправлена и исчезла после rescan |
| `partial-security-fix` | исправлена одна из двух SQLi | оставшаяся SQLi обязательно видна; полный fix даёт ноль findings |
| `atomic-workspace-patch` | неверный второй файл, traversal, bad hunk | ни один плохой patch не делает частичную запись |
| `forensics-log-shards` | empty JSONL, BOM/CRLF, пробелы, Unicode, большая строка, shard | evidence из разных файлов даёт одну подтверждённую цепочку |
| `missing-inputs-fail-closed` | нет artifact/run/proxy evidence | результат не угадывается, возвращается явная ошибка |
| `failure-journal-shards` | несколько run-файлов, CRLF, Unicode, большой log | ровно три провала и правильные категории без `unknown` |
| `bounded-processes` | 50 KB stdout, зависание, внешний cwd | stdout ограничен, процесс остановлен по timeout, escape запрещён |
| `stdlib-runtime-dependencies` | runtime imports и `run.sh` | нет установки пакетов и сторонних Python-зависимостей |

В каждом ключевом классе есть не менее трёх вариаций. Имена, значения и
структуры fixtures не зависят от названий публичных задач, `solution` или
`expected` организаторов.

## Offline-проверка

Во время suite распространённые in-process socket entrypoints заблокированы.
Отдельно AST-проверка импортов подтверждает, что 11 проверяемых runtime-модулей
используют только стандартную библиотеку и локальные пакеты. `run.sh` также
проверяется на отсутствие команд скачивания и установки зависимостей.

Guard относится к Python-процессу suite. Реальная изоляция финального запуска
по-прежнему обеспечивается контейнером организаторов.

## Формат результата

```json
{
  "schema_version": 1,
  "suite": "c12-portability-adversarial",
  "offline_parent_network_guard": true,
  "passed": true,
  "check_count": 9,
  "passed_count": 9,
  "failed_count": 0,
  "checks": []
}
```

Каждый элемент `checks` содержит имя, область, статус и конкретную причину.
Если один сценарий падает, остальные продолжают выполняться, а итоговый JSON
всё равно сохраняется. Текст исключений проходит C-11 redaction перед записью.

Коды возврата:

- `0` — все зарегистрированные проверки прошли;
- `1` — хотя бы одна проверка не прошла;
- `2` — не удалось безопасно записать отчёт.

Пустой registry не может считаться успешным.

## Запуск

Из корня репозитория:

```bash
python3 -m evaluation.portability \
  --output evaluation/results/c12_portability.json
```

Полная проверка C-11/C-12:

```bash
./evaluation/verify.sh
```

Все остальные regression-тесты проекта:

```bash
./scripts/check_all.sh
```

На Windows PowerShell:

```powershell
& "C:\Program Files\Git\bin\bash.exe" "./evaluation/verify.sh"
& "C:\Program Files\Git\bin\bash.exe" "./scripts/check_all.sh"
```

## Граница интеграции

C-12 остаётся в `evaluation/` и не добавляется в action catalog LLM. Он нужен
до сборки submission и после изменений команды, чтобы быстро обнаруживать
зависимость от формата, ОС или одного примера. В финальный ZIP тестовый suite
включать необязательно.
