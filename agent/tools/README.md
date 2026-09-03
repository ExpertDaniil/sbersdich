# Tools

Реализованные переносимые ИБ-инструменты:

- `security_scan.py` — AST-анализ Python-кода от пользовательского ввода к
  SQL-sink; формирует отчёт совместимого audit-формата;
- `sql_parameterize.py` — консервативно заменяет только поддерживаемую
  интерполяцию SQL-значений на позиционные параметры asyncpg.

Примеры:

```bash
python3 -m agent.tools.security_scan ./project --output ./security_report.json
python3 -m agent.tools.sql_parameterize ./project --check
python3 -m agent.tools.sql_parameterize ./project --apply
```

`--check` ничего не записывает и возвращает код `1`, если найдены автоматически
исправимые конструкции. Имена таблиц/столбцов и неоднозначные динамические
запросы инструмент намеренно не переписывает: их должен обработать основной
агент с последующей проверкой.

Файловые и process-инструменты с timeout появятся вместе с основным циклом
агента.
