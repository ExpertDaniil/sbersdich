# Tools

Реализованные переносимые ИБ-инструменты:

- `security_scan.py` — AST-анализ Python-кода от пользовательского ввода к
  SQL-sink; формирует отчёт совместимого audit-формата;
- `sql_parameterize.py` — консервативно заменяет только поддерживаемую
  интерполяцию SQL-значений на позиционные параметры asyncpg;
- `forensics.py` — инвентаризирует incident-артефакты, запускает поддерживаемый
  профиль корреляции, строит evidence graph и валидирует строгий отчёт.

Примеры:

```bash
python3 -m agent.tools.security_scan ./project --output ./security_report.json
python3 -m agent.tools.sql_parameterize ./project --check
python3 -m agent.tools.sql_parameterize ./project --apply
python3 -m agent.tools.forensics inventory /app/incident
python3 -m agent.tools.forensics analyze /app --output /app/incident_report.txt
python3 -m agent.tools.forensics validate /app/incident_report.txt
```

`--check` ничего не записывает и возвращает код `1`, если найдены автоматически
исправимые конструкции. Имена таблиц/столбцов и неоднозначные динамические
запросы инструмент намеренно не переписывает: их должен обработать основной
агент с последующей проверкой.

Forensics-анализатор автоматически принимает как `/app/incident`, так и его
родительский `/app`, читает все подходящие shards и не записывает результат
внутрь evidence-каталога. Встроенный профиль покрывает подтверждённые
`sensitive_export`; неизвестные схемы остаются LLM, которой inventory даёт
ограниченную карту файлов без чтения каталогов answer/test.

Общие файловые и process-инструменты находятся в `agent/core/workspace.py` и
вызываются только через режимный registry. Они ограничивают пути, размеры
файлов/ответов, число результатов и timeout; process runner не использует shell
и удаляет LLM credentials из окружения дочерней команды.
