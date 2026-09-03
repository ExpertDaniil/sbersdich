# Пакет C-04: проверка SQLi fix и регрессии

Пакет не изменяет публичный GitHub и предназначен для проверки решения C-03 в отдельной учебной среде.

Состав:

- `run_in_acp.sh` — полный запуск в `secureintelligent/acp`;
- `scripts/http_regression.py` — 11 HTTP security/regression-проверок;
- `tests/test_http_regression.py` — автономная проверка runner на безопасном и намеренно уязвимом fake API;
- `verify_package.sh` — проверка пакета без Docker и внешних Python-зависимостей;
- `C04_REPORT.md` — матрица тестов, порядок запуска и критерий готовности.

Быстрая автономная проверка:

```bash
chmod +x verify_package.sh
./verify_package.sh
```

Полная проверка после применения C-03 внутри runtime:

```bash
chmod +x run_in_acp.sh
C04_RESET_DB=1 ./run_in_acp.sh /app
```

Дополнительные настройки:

- `C04_OUTPUT_DIR` — каталог журналов и JSON-отчёта;
- `C04_PORT` — порт нового Uvicorn-процесса, по умолчанию `8000`;
- `DATABASE_URL` — строка подключения к тестовой PostgreSQL;
- `C04_RESET_DB=1` — пересоздать базу; использовать только в одноразовом контейнере от root.
