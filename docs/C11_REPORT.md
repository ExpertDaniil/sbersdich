# C-11 — автоматический разбор причин провалов

## Результат

Реализован независимый post-run анализатор `evaluation.failure_analysis`.
Он не меняет проект задачи и не вмешивается в работу агента: после прогона
получает сохранённый trace или лог и формирует единый JSON-журнал.

Критерий C-11 закрывается так:

1. Провалы разделяются на `launch`, `format`, `hypothesis`, `execution`,
   `timeout`, `budget` и `regression`.
2. У каждой записи есть evidence непосредственно из входного файла:
   `source`, `json_path` и ограниченный `excerpt`.
3. У каждой записи есть понятные `reason`, `cause`, `owner` и `next_action`.
4. Недостаточно доказанные случаи получают `unknown`, а `--strict` завершает
   команду кодом `1`. Такой случай нельзя молча считать разобранным.

## Поддерживаемые входы

- полный `AgentRunResult.as_payload()`;
- `summary.json` и `traces.json` публичных C-09/C-10 прогонов;
- массивы и словари результатов нескольких задач;
- построчный `JSONL`/`NDJSON`;
- обычные UTF-8 `.log` и `.txt` с признаками ошибки.

Успешный итоговый статус имеет приоритет над промежуточными retry-событиями:
успешно восстановившийся прогон не попадает в журнал как провал.

## Формат результата

Основные поля файла `failure_journal.json`:

```json
{
  "schema_version": 1,
  "failure_count": 1,
  "unknown_failure_count": 0,
  "category_counts": {"timeout": 1},
  "failures": [
    {
      "task_id": "fix-sqli-login",
      "category": "timeout",
      "confidence": "high",
      "reason": "...",
      "cause": "deadline exceeded",
      "owner": {"block": "A", "component": "orchestration-and-deadlines"},
      "next_action": "...",
      "evidence": [
        {"source": "traces.json", "json_path": "$.fix-sqli-login.reason", "excerpt": "deadline exceeded"}
      ]
    }
  ]
}
```

Счётчики для всех категорий присутствуют всегда, в том числе с нулевыми
значениями. В отчёт намеренно не добавляется текущее время, поэтому одинаковый
вход создаёт побайтно стабильное содержимое.

## Безопасность и ограничения

- только стандартная библиотека Python, без установки зависимостей;
- максимум 256 файлов, 8 МиБ на файл и 10 000 run-records;
- входные symlink-файлы не читаются;
- результат записывается атомарно;
- собственный output исключается при анализе каталога;
- evidence ограничено тремя фрагментами по 500 символов;
- значения полей API key/token/password/secret/authorization/cookie и
  распространённые секреты внутри строк редактируются до сохранения.

## Запуск

Из корня проекта:

```bash
python3 -m evaluation.failure_analysis \
  evaluation/results/c09_public/traces.json \
  --output evaluation/results/failure_journal.json \
  --strict
```

Можно передать несколько файлов или целый каталог:

```bash
python3 -m evaluation.failure_analysis evaluation/results/run-01/ run-02.log --strict
```

Для PowerShell с установленным Python:

```powershell
python -m evaluation.failure_analysis evaluation/results/c09_public/traces.json --strict
```

## Проверка

```bash
./evaluation/verify.sh
./scripts/check_all.sh
```

Тесты покрывают все обязательные категории, C-09 mapping, успешный retry,
JSONL и текстовые логи, unknown fail-closed, CLI-коды, стабильность результата,
повреждённый/слишком большой вход, исключение output и удаление секретов.

## Граница интеграции

C-11 — диагностический слой разработки, а не новый инструмент, доступный LLM.
Агент или внешний runner сохраняет trace; анализатор читает его после
завершения. Поэтому модуль не меняет `agent/core`, `agent/local_agent.py`,
`run.sh` и runtime-контракт команды. В финальный submission этот модуль
добавлять необязательно: он нужен команде для улучшения агента между прогонами.
