# Agent source

Здесь находится переносимая часть будущего автономного агента. На этапах
C-06/C-07 реализованы:

- детерминированная классификация задач `audit`, `fix`, `forensics` и `general`;
- AST-аудитор Python-кода для поиска tainted SQL-конструкций;
- ограниченный исправитель SQL-инъекций для поддерживаемых вызовов asyncpg;
- playbook для режима аудита без изменения проекта;
- playbook для минимального security-fix с обязательной проверкой;
- forensics inventory, корреляционный профиль и evidence graph;
- playbook для анализа инцидента без изменения доказательств;
- общий validation engine с baseline, режимными политиками, проверкой
  артефактов, Python-синтаксиса и команд с timeout;
- основной автономный цикл с action-протоколом, бюджетами, режимным allowlist,
  повторной валидацией и детерминированным fallback-драйвером.

Проверка компонентов:

```bash
./agent/verify.sh
```

Классификатор можно вызвать отдельно:

```bash
python3 -m agent.strategies "Find security vulnerabilities and write a report"
python3 -m agent.tools.forensics inventory /app/incident
python3 -m agent.tools.forensics analyze /app
python3 -m agent.validators snapshot /app --output /tmp/task-baseline.json
python3 -m agent.core.loop 'Audit /app and write security_report.json' --workdir /app
```

Адаптер локальной LLM, общие ограниченные файловые/process-инструменты и
финальный `run.sh` будут добавлены на следующих этапах. Учебные решения из
`security/tasks/` не копируются в submission.
