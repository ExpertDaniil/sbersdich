# Sber SDI Challenge — автономный ИБ-агент

Командный репозиторий решения для хакатона: автономный агент анализирует
задание и файлы в изолированном окружении, обращается к локальной LLM,
выполняет разрешённые действия и принимает результат только после проверки.

## Что уже есть

- `run.sh` и `agent/local_agent.py` — точка входа и подключение локальной модели;
- `agent/core/` — контракты, автономный цикл, бюджеты и безопасные инструменты;
- `agent/playbooks/` — инструкции для audit, fix и forensics;
- `agent/tools/` — анализ кода, SQL-fix и обработка incident-данных;
- `agent/validators.py` — проверка артефактов, изменений, синтаксиса и тестов;
- `security/tasks/` — локальные учебные ИБ-решения и regression-проверки;
- `evaluation/` — тестовый контур и C-11 журнал причин провалов;
- `scripts/` — повторяемые локальные и публичные проверки.

Архитектура описана в [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), отчёты
по этапам находятся в `docs/` и `security/tasks/`.

## Быстрая проверка

Нужны Bash и Python 3.12+. Из корня репозитория:

```bash
./scripts/check_all.sh
./evaluation/verify.sh
```

В Windows PowerShell те же проверки можно запустить через Git Bash:

```powershell
& "C:\Program Files\Git\bin\bash.exe" "./scripts/check_all.sh"
& "C:\Program Files\Git\bin\bash.exe" "./evaluation/verify.sh"
```

## Запуск агента

Runtime передаёт `LOCAL_AGENT_MODEL`, `OPENAI_BASE_URL` и `OPENAI_API_KEY`.
После их настройки агент запускается одной инструкцией:

```bash
./run.sh 'Проверь проект в /app и выполни требования задания.'
```

Публичные задачи организаторов используются только для локальной проверки.
Скрипты `run_c*_public.sh` работают с временными копиями и не изменяют
исходный репозиторий.

## Разбор неудачного прогона (C-11)

```bash
python3 -m evaluation.failure_analysis \
  evaluation/results/c09_public/traces.json \
  --output evaluation/results/failure_journal.json \
  --strict
```

Журнал разделяет причины на запуск, формат, гипотезу, исполнение, timeout,
бюджет и регрессию. Для каждого провала сохраняются evidence из исходного
лога, причина, следующий владелец и действие. Подробности:
[`docs/C11_REPORT.md`](docs/C11_REPORT.md).

`evaluation/`, тестовые задачи и отчёты нужны в репозитории для разработки.
В финальный архив до 10 МБ должны попасть только runtime-файлы, необходимые
`run.sh`; состав архива проверяется отдельно перед отправкой.
