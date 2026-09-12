# Agent source

Здесь находится переносимая production-часть автономного агента:

- детерминированная классификация задач `audit`, `fix`, `forensics`, `ctf` и `general`;
- AST-аудитор Python-кода для поиска tainted SQL-конструкций;
- ограниченный исправитель SQL-инъекций для поддерживаемых вызовов asyncpg;
- playbook для режима аудита без изменения проекта;
- playbook для минимального security-fix с обязательной проверкой;
- forensics inventory, корреляционный профиль и evidence graph;
- playbook для анализа инцидента без изменения доказательств;
- общий validation engine с baseline, режимными политиками, проверкой
  артефактов, Python-синтаксиса и команд с timeout;
- основной автономный цикл с action-протоколом, бюджетами, режимным allowlist,
  повторной валидацией и детерминированным fallback-драйвером;
- bounded `list/read/read-bytes/search`, безопасный unified patch и allowlisted
  process runner без shell-интерпретации.
- instruction-native JSON contracts, включая exact nested item schema;
- semantic Repository Distiller/ACI, SHA-guarded checked edits и Candidate Arena;
- non-SQL audit leads и instruction-derived post-edit security guards;
- binary carving, structured JWT transforms, ordered batch shards и DNS
  exfiltration correlation;
- автоматическая финальная проверка после подтверждённой mutation/artifact write.

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
python3 -m agent.scaffold.cli 'Audit /app and write security_report.json' --workdir /app
```

Корневой `run.sh` запускает этот scaffold независимо от текущего cwd. Учебные решения из
`security/tasks/` не копируются в submission.
