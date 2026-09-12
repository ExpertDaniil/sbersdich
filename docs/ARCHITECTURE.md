# Архитектура репозитория

## 1. `agent/` — production submission-код

Только содержимое этой зоны и корневой `run.sh`, который появится после интеграции, должны рассматриваться как кандидаты на включение в финальный ZIP.

Компоненты:

- `strategies.py` — реализованная детерминированная классификация задачи;
- `tools/security_scan.py` — реализованный AST-аудитор source-to-SQL-sink;
- `tools/audit_signals.py` — консервативные non-SQL audit leads с source lines;
- `tools/fix_guard.py` — instruction-derived post-edit security properties;
- `tools/ctf.py`, `tools/binary_records.py` — byte-safe scalar/batch transforms
  и binary carving;
- `tools/dns_exfil.py` — bounded DNS sequence/decode/inventory/process correlation;
- `tools/sql_parameterize.py` — реализованный ограниченный asyncpg-fixer;
- `tools/forensics.py` — реализованные inventory, incident-profile и evidence
  graph;
- `playbooks/audit.md`, `playbooks/fix.md`, `playbooks/forensics.md` —
  реализованные стратегии;
- `validators.py` — реализованные baseline snapshot, режимные политики,
  форматы артефактов, syntax и команды с timeout;
- `core/loop.py` — реализованный цикл «инструкция → действие → наблюдение →
  проверка», retry и ограничение бюджета;
- `core/config.py`, `core/llm.py` — проверка настроек, ограниченный запрос к
  локальной модели, учёт токенов и преобразование ответа в одно действие;
- `core/contracts.py`, `core/playbooks.py`, `core/models.py` — task contract,
  безопасная загрузка стратегий и структурированный action-протокол;
- `core/tools.py` — режимный allowlist и каталог action-схем для драйвера;
- `core/workspace.py` — bounded list/read/search, безопасный unified patch и
  allowlisted process runner с timeout и ограничением observation.
- `scaffold/kernel.py` — единственный production bounded loop;
- `scaffold/planner.py` — deterministic fast path и локальная LLM policy;
- `scaffold/context_compiler.py` — semantic namespace и trusted source windows;
- `scaffold/registry.py`, `scaffold/providers.py` — capability/mode ToolBus;
- `scaffold/verifier.py` — freshness, mode policy, frozen tests, scanners и
  instruction-derived final gate.

Корневой `run.sh` запускает `agent.scaffold.cli`. Общую Harbor-обёртку `agent.py`
организаторы добавляют или перезаписывают сами, поэтому собственная логика не
зависит от её модификации.

`agent/core/loop.py` сохраняется для совместимости и независимых regressions.
Он не запускается параллельно со scaffold и не владеет вторым production state.

## 2. `security/tasks/` — учебные ИБ-разборы

Здесь лежат независимые решения этапов командного трекера:

- `c03_fix_sqli_login/` — безопасный `auth.py`, patch, тесты и отчёт;
- `c04_regression_verification/` — runner, HTTP-проверки и матрица регрессии;
- `c05_incident_forensics/` — независимый анализатор, formatter, validator и
  вариативные тесты корреляции логов.

Эти материалы обучают и проверяют метод решения. Публичные ответы нельзя переносить в system prompt или боевую логику агента.

## 3. `evaluation/` — внутренний стенд

- `results/` — локальные результаты прогонов, не коммитятся;
- `extra_tasks/` — независимые вариации задач без доступного агенту эталона;
- позднее здесь появятся `run_suite.py`, `summarize.py` и журнал причин провалов.

## 4. `docs/` и `scripts/`

- `docs/` фиксирует решения команды и критерии готовности;
- `scripts/check_all.sh` проверяет автономные пакеты;
- `scripts/run_c03_c04_docker.sh` проводит Docker-проверку C-03/C-04 во
  временной копии публичной задачи;
- `scripts/run_c05_public.sh`, `scripts/run_c06_public.sh` и
  `scripts/run_c07_public.sh` проверяют C-05…C-07 на одноразовых копиях;
- `scripts/run_c08_public.sh` применяет единые validation policies к публичным
  audit/fix/forensics-копиям.
- `scripts/run_c09_public.sh` прогоняет единый агентный цикл по всем шести
  публичным instruction на одноразовых рабочих каталогах.
- `scripts/run_c10_public.sh` проверяет read-only анализ и generic patch/process
  на публичных environment-копиях без чтения answer-файлов.

## Поток разработки

```text
instruction → router/contract → context compiler → planner → ToolBus
            → trusted observation → deterministic verifier → result
```

Принцип разделения важен: verifier, expected-значения и учебные reference solution не должны попадать в `agent/` и финальный ZIP.
