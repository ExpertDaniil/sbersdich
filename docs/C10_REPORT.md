# C-10 — безопасные filesystem/process-инструменты

## Результат

Будущий LLM-драйвер получил структурированный набор рабочих инструментов вместо
неограниченного shell. Инструменты подключены к C-09 loop через режимный каталог
и возвращают bounded observations, которые можно безопасно помещать в следующий
LLM-запрос.

## Доступные действия

| Action | Назначение | Audit | Fix | Forensics | General |
|---|---|---:|---:|---:|---:|
| `list_files` | Ограниченный список обычных файлов | да | да | да | да |
| `read_file` | UTF-8 строки с pagination | да | да | да | да |
| `read_bytes` | Ограниченный hex/ASCII диапазон | да | да | да | да |
| `search_text` | Literal search с glob и лимитами | да | да | да | да |
| `apply_patch` | Strict unified diff существующих файлов | нет | да | нет | да |
| `run_command` | Allowlisted test/check без shell | нет | да | нет | да |

Специализированные C-06/C-07 actions остаются в том же registry и выдаются
только подходящим режимам.

## Инварианты безопасности

1. Каждый путь канонизируется и должен остаться внутри workdir; `/app/...`
   платформенно-независимо переводится в фактический каталог задачи.
2. Read/list/search не открывают `.git`, `solution`, `expected` и `verifier`.
3. Patch не может создавать, удалять, переименовывать или изменять tests,
   answer-файлы, dependency manifests и symlink-цели.
4. Все файлы и hunks проверяются до первой записи. Контекст должен точно
   совпадать с текущим содержимым.
5. Сохраняются исходные LF/CRLF и executable mode.
6. Process запускается через argv с `shell=False`; shell, `python -c`,
   destructive git и выход через `..` запрещены.
7. Команда ограничена 120 секундами, а observation — 12 КБ; stdout продолжает
   дренироваться, не раздувая память агента.
8. `OPENAI_API_KEY`, model endpoint и переменные с token/password/secret не
   передаются дочернему процессу.
9. Audit/forensics не получают mutating actions. Итоговый diff по-прежнему
   независимо контролирует C-08 validator.

## Проверка

```bash
./agent/verify.sh
./scripts/check_all.sh
./scripts/run_c10_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

В C-10 добавлено 32 теста: path containment, answer exclusion, text/binary
limits, search budget, malformed/multi-file/CRLF/symlink patch, process success,
failure, timeout, capped output, credentials и сквозной loop с ручным patch.

Публичный runner читает только `environment/`, выполняет read-only audit и
forensics, генерирует generic unified diff из детерминированного преобразования
двух SQL-fixture и применяет его только к отдельным временным копиям. Исходный
репозиторий организаторов не изменяется, `solution`/`expected` не читаются.

## Граница C-10

Process allowlist предназначен для project tests/checks, а не является отдельной
ОС-песочницей. Основная изоляция обеспечивается runtime-контейнером соревнования;
внутри агента дополнительно действуют mode permissions, путь/argv-фильтры,
timeout и финальный C-08 diff validator.
