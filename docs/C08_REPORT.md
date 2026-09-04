# C-08 — общий validation engine

## Результат

`agent/validators.py` предоставляет единый программный и CLI-интерфейс проверки
результата задачи. Валидатор не пытается решить задачу: он независимо отвечает,
может ли агент безопасно завершить работу.

Жизненный цикл состоит из двух действий:

```bash
python3 -m agent.validators snapshot /app --output /tmp/task-baseline.json
python3 -m agent.validators validate /app \
  --mode MODE \
  --baseline /tmp/task-baseline.json [RULES]
```

Baseline и validation report запрещено сохранять внутри проверяемого проекта.

## Политики изменений

| Режим | Разрешено | Запрещено |
|---|---|---|
| `audit` | только объявленные deliverables | исходники и остальные файлы |
| `forensics` | только объявленные deliverables | evidence и остальные файлы |
| `fix` | минимальные project-файлы | tests, expected, solution, verifier, зависимости |
| `general` | project-файлы | защищённые пути и зависимости |

Dependency changes можно разрешить только явным флагом политики. Snapshot
учитывает содержимое, размер, обычный файл/symlink и permission mode; кэши Python
и тестовых раннеров исключаются.

## Артефакты и проверки

Поддержаны типы:

- `file`, `text`, `exact-text`;
- произвольный `json`;
- строгий `security-report`;
- строгий `incident-report`.

Python проверяется через `ast.parse`, без импорта приложения и побочных
эффектов. Test/lint-команды передаются как JSON argv, запускаются без shell,
имеют timeout до 120 секунд и ограниченный диагностический вывод.

## Проверка

Добавлено 17 тестов:

- add/modify/delete и исключение runtime caches;
- валидация и защита baseline JSON;
- security/incident/exact-text/JSON/UTF-8 артефакты;
- audit no-write и разрешённый отчёт;
- fix source change, запрет изменения tests и dependencies;
- forensics report и запрет изменения evidence;
- Python syntax без импортов;
- успешная, упавшая и зависшая команды;
- CLI lifecycle и корректные exit codes.

Публичный runner проверяет четыре одноразовые копии и не читает expected или
solution:

```bash
./scripts/run_c08_public.sh /path/to/UniversalAgenticCompetitionPublic
```
