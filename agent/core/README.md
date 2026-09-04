# Core agent loop

C-09 реализует управляющую часть автономного агента:

- `loop.py` — состояния «действие → валидация → повтор/завершение», лимиты
  шагов, времени, повторов и validation attempts;
- `models.py` — структурированный протокол `AgentAction`, observations и
  итогового машиночитаемого результата;
- `contracts.py` — обязательные артефакты и exact-text контракт из instruction;
- `playbooks.py` — ограниченная загрузка только Markdown playbook из `agent/`;
- `tools.py` — режимный allowlist для C-06/C-07 инструментов и безопасной
  записи exact-text файла.

Любой action driver реализует один метод:

```python
def next_action(context: DriverContext) -> AgentAction: ...
```

Сейчас `DeterministicDriver` без LLM полностью выполняет поддерживаемые
audit/fix/forensics/exact-file профили. OpenAI-compatible LLM adapter будет
реализовывать тот же интерфейс на следующем интеграционном этапе, поэтому
validation и safety-логика не будут дублироваться.

Локальный запуск:

```bash
python3 -m agent.core.loop \
  'Create a file at `/app/result.txt` whose content is exactly `done`.' \
  --workdir /tmp/example-app
```

Код возврата `0` выдаётся только после успешной C-08 валидации. Неизвестная
задача, провал инструмента, теста или лимита завершается кодом `1`.
