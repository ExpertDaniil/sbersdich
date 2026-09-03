# C-05 — incident log forensics

Независимый анализатор коррелирует application JSONL, все edge-shard'ы,
многострочный proxy access log и вспомогательный auth log. В коде нет
заранее заданных IP, пользователя, request ID, времени или размера выгрузки.

## Локальная проверка пакета

```bash
./verify.sh
```

Проверяются изменённые значения полей, другое имя edge-shard, приоритет
`payload_logical_bytes`, fallback на `audit.bytes`, CLI, evidence trace и строгий
формат отчёта.

## Запуск анализатора

```bash
python3 analyze_incident.py /path/to/incident \
  --output /path/to/incident_report.txt \
  --trace /path/to/evidence_trace.json
```

Если `--output` не передан, результат записывается рядом с каталогом incident:
`INCIDENT_DIR/../incident_report.txt`. Параметр `--trace` предназначен только для
разработки и не входит в обязательный deliverable.

Проверка готового отчёта:

```bash
python3 validate_report.py /path/to/incident_report.txt
```

Для публичного bundle используйте корневой скрипт:

```bash
./scripts/run_c05_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Исходный репозиторий организаторов не изменяется. Результат появляется в
`evaluation/results/c05_public/`.
