# Validation protocol

Общий validator работает только при наличии baseline, снятого до первого
изменения. Baseline и validation report хранить вне `/app`, например в `/tmp`.

```bash
python3 -m agent.validators snapshot /app --output /tmp/task-baseline.json
```

Перед завершением выбрать режим и обязательные артефакты:

```bash
python3 -m agent.validators validate /app \
  --mode audit \
  --baseline /tmp/task-baseline.json \
  --artifact security-report=security_report.json

python3 -m agent.validators validate /app \
  --mode forensics \
  --baseline /tmp/task-baseline.json \
  --artifact incident-report=incident_report.txt
```

Для project tests передавать argv как JSON-массив: команда запускается без
shell-интерпретации и с timeout.

```bash
python3 -m agent.validators validate /app \
  --mode fix \
  --baseline /tmp/task-baseline.json \
  --command-json '["python3","-m","pytest","tests/"]' \
  --command-timeout 120
```

Код возврата `0` означает, что все проверки прошли; `1` — корректно выполненная
валидация нашла проблему; `2` — неверный запрос или внутренняя ошибка. Агент не
должен завершать задачу при любом ненулевом коде.
