# Evaluation

Здесь находится локальный контур оценки: результаты прогонов, дополнительные
задачи и автоматический разбор причин провалов C-11. Генерируемое содержимое
`results/` не коммитится.

## C-11: failure journal

Анализатор принимает отдельные файлы или каталоги с `JSON`, `JSONL`, `NDJSON`,
`.log` и `.txt`:

```bash
python3 -m evaluation.failure_analysis path/to/traces.json \
  --output evaluation/results/failure_journal.json \
  --strict
```

| Категория | Что означает | Следующий владелец |
|---|---|---|
| `launch` | Не запустились runtime, entrypoint или конфигурация | блок B, runtime/entrypoint |
| `format` | Не выполнен контракт пути, схемы или артефакта | блок C, validation/output |
| `hypothesis` | Не подтверждена выбранная находка или трактовка | блок C, security strategies |
| `execution` | Упало действие или инструмент | блок A, agent core/tools |
| `timeout` | Истёк deadline | блок A, orchestration |
| `budget` | Исчерпаны шаги, повторы, контекст или токены | блок A, agent loop |
| `regression` | Не прошли тесты или security-check | блок C, regression verification |
| `unknown` | Данных в логе недостаточно | общий ручной triage |

Каждая запись содержит исходный файл и JSON-path доказательства, краткую
причину, владельца и следующее действие. Evidence ограничено по размеру и
очищается от API-ключей, bearer-токенов, паролей и секретов.

Коды возврата CLI:

- `0` — журнал создан; в `--strict` нет неизвестных причин;
- `1` — журнал создан, но `--strict` нашёл `unknown`;
- `2` — вход повреждён, небезопасен или не поддерживается.

Проверка модуля:

```bash
./evaluation/verify.sh
```
