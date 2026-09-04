# C-09 — основной цикл автономного агента

## Результат

Реализована первая сквозная исполняемая система в `agent/core/`. Она получает
instruction, до изменений снимает C-08 baseline, выбирает стратегию, загружает
playbook, выполняет структурированные действия через режимный allowlist и
завершается успешно только после независимой валидации.

## Компоненты

| Файл | Назначение |
|---|---|
| `agent/core/models.py` | Action, observation, context, result и driver protocol |
| `agent/core/contracts.py` | Обязательные audit/forensics/exact-text артефакты |
| `agent/core/playbooks.py` | Загрузка только доверенных playbook внутри `agent/` |
| `agent/core/tools.py` | Адаптеры scanner, SQL parameterizer, forensics и exact write |
| `agent/core/loop.py` | State machine, бюджеты, retry, validation и CLI |
| `agent/tests/test_agent_loop.py` | 19 сквозных и отрицательных тестов |
| `scripts/run_c09_public.py` | Прогон шести публичных instruction на временных копиях |

## Инварианты безопасности

1. Baseline снимается до вызова driver и до первого изменения.
2. Audit разрешает только scanner/report, fix — scanner/parameterizer,
   forensics — correlator/report, general exact-file — только точную запись.
3. Все переданные пути после раскрытия symlink должны оставаться внутри workdir.
4. Tests, expected, solution, verifier и dependency manifests нельзя перезаписать
   через доступный write action.
5. `finish` не является доверием к драйверу: C-08 повторно проверяет артефакты,
   синтаксис, команды и diff-policy.
6. Fix дополнительно требует реального изменения и чистого post-fix scan.
7. Неизвестный deterministic-профиль завершается fail-closed, а не ложным
   успехом.
8. Step, deadline, validation и repeated-action budgets исключают бесконечный
   цикл.

## Проверка

Только unit/CLI/regression:

```bash
./agent/verify.sh
./scripts/check_all.sh
```

Все шесть публичных задач, без Docker и без изменения исходного репозитория:

```bash
./scripts/run_c09_public.sh /absolute/path/to/UniversalAgenticCompetitionPublic
```

Runner читает и хеширует только `instruction.md` и `environment/`, создаёт
одноразовый workdir и подтверждает неизменность этих входов. Файлы
`tests/expected*` и `solution/` не открываются и не используются.

## Граница C-09

`DeterministicDriver` уже выполняет известные поддерживаемые профили без расхода
LLM-токенов. Интерфейс `ActionDriver.next_action(context)` подготовлен для
локальной OpenAI-compatible модели, но сам сетевой адаптер намеренно относится к
C-11: перед ним C-10 добавит безопасные универсальные read/search/patch/process
инструменты. Поэтому C-09 является рабочим циклом и fallback, но ещё не финальным
`submission.zip`.
