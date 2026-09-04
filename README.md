# Sber SDI Challenge — автономный ИБ-агент

Командный репозиторий решения для универсального автономного агента по кибербезопасности, работающего в изолированном контуре с локальной LLM.

Сейчас в репозитории находятся проверенные учебные решения:

- **C-03** — минимальное исправление SQL-инъекции в `POST /login`;
- **C-04** — security/regression-проверка исправленного FastAPI-приложения;
- **C-05** — независимый анализатор incident-логов с evidence trace;
- **C-06** — переносимые audit/fix-стратегии, AST-аудитор и безопасный
  параметризатор SQL;
- **C-07** — универсальная forensics-стратегия, inventory и evidence graph.

Публичный репозиторий организаторов не изменяется. Он используется только как источник учебных задач; Docker-проверка создаёт временную копию исходного commit.

## Структура

```text
agent/                    код, который позже войдёт в submission
  core/                   цикл агента, бюджет и контекст
  tools/                  файловые и процессные инструменты
  playbooks/              audit, fix, forensics и CTF-стратегии
security/tasks/           учебные ИБ-разборы C-03, C-04, C-05...
evaluation/               тестовый стенд, дополнительные задачи и результаты
docs/                     архитектура, допущения и дорожная карта
scripts/                  единые команды проверки
```

Подробности: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Быстрая проверка без Docker

Требуются Bash и Python 3.12+.

Из корня репозитория:

```bash
chmod +x scripts/check_all.sh
./scripts/check_all.sh
```

Команда выполняет:

- 5 unit/security-тестов C-03;
- 4 теста проверяющего контура C-04;
- 11 HTTP-проверок на безопасном fake API;
- отрицательный тест на намеренно уязвимом login;
- проверку обработки провала project pytest;
- 7 unit/CLI/format-тестов C-05 с изменяемыми incident-данными;
- 12 unit/CLI/behavior-тестов C-06 для классификатора, аудитора и исправителя;
- 12 вариативных тестов C-07 для inventory, корреляции, XFF, evidence graph и
  строгого отчёта.

## Проверка C-03 отдельно

```bash
cd security/tasks/c03_fix_sqli_login
chmod +x verify.sh
./verify.sh
```

Готовый безопасный файл: `security/tasks/c03_fix_sqli_login/routers/auth.py`.

Отчёт: [`security/tasks/c03_fix_sqli_login/C03_REPORT.md`](security/tasks/c03_fix_sqli_login/C03_REPORT.md).

## Проверка C-04 отдельно

```bash
cd security/tasks/c04_regression_verification
chmod +x verify_package.sh
./verify_package.sh
```

Отчёт: [`security/tasks/c04_regression_verification/C04_REPORT.md`](security/tasks/c04_regression_verification/C04_REPORT.md).

## Проверка C-05 отдельно

```bash
cd security/tasks/c05_incident_forensics
chmod +x verify.sh
./verify.sh
```

Анализатор: `security/tasks/c05_incident_forensics/analyze_incident.py`.

Отчёт: [`security/tasks/c05_incident_forensics/C05_REPORT.md`](security/tasks/c05_incident_forensics/C05_REPORT.md).

## Проверка C-06 отдельно

```bash
chmod +x agent/verify.sh
./agent/verify.sh
```

Инструменты C-06 работают на стандартной библиотеке Python и не содержат
ответов публичных задач. Отчёт: [`docs/C06_REPORT.md`](docs/C06_REPORT.md).

## Проверка C-07 отдельно

Тесты C-07 входят в общий пакет агента:

```bash
./agent/verify.sh
```

Пример запуска forensics-профиля:

```bash
python3 -m agent.tools.forensics analyze /app \
  --output /app/incident_report.txt \
  --trace /tmp/evidence_graph.json
```

Отчёт этапа: [`docs/C07_REPORT.md`](docs/C07_REPORT.md).

## Полная ручная проверка в Docker

Нужны Docker, Git, Bash, `patch` и локальная копия публичного репозитория организаторов.

```bash
git clone https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic.git
./scripts/run_c03_c04_docker.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Скрипт:

1. проверяет, что передан Git-репозиторий;
2. экспортирует его текущий commit во временный каталог;
3. применяет исправление C-03 только к временной копии;
4. собирает образ на основе `secureintelligent/acp`;
5. запускает C-04 с новой PostgreSQL и новым Uvicorn-процессом;
6. сохраняет журналы в `evaluation/results/c04_manual/`;
7. удаляет временную копию.

Исходный публичный репозиторий и его remote не меняются.

Успешный результат заканчивается строкой:

```text
C-04 PASSED: project tests and HTTP checks succeeded
```

Публичную C-05 можно проверить отдельно, также без изменения исходного
репозитория организаторов:

```bash
./scripts/run_c05_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Отчёт и evidence trace сохранятся в `evaluation/results/c05_public/`.

Audit/fix-инструменты C-06 можно прогнать на одноразовых копиях трёх публичных
SQL-задач:

```bash
./scripts/run_c06_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Скрипт проверяет отсутствие изменений в исходном публичном репозитории,
находит уязвимость в audit-задаче и исправляет обе fix-задачи только во
временном каталоге. Результаты сохраняются в
`evaluation/results/c06_public/`.

Forensics-инструмент C-07 проверяется без чтения публичных expected/solution:

```bash
./scripts/run_c07_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Исходные артефакты копируются во временный каталог. Строгий отчёт, evidence
graph и техническая сводка сохраняются в `evaluation/results/c07_public/`.

## Следующий этап

Следующая задача — **C-08: универсальные валидаторы артефактов и результата**. Статус и критерии находятся в [`docs/ROADMAP.md`](docs/ROADMAP.md).
