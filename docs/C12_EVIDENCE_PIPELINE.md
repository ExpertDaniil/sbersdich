# C-12 — Evidence-Gated Hypothesis Pipeline

## Цель

C-12 переводит LLM-часть агента из линейного `prompt -> action -> observation`
в управляемый исследовательский цикл. Изменение намеренно не переписывает
`AgentLoop`, C-08 validation и C-10 workspace safety: новый слой живёт внутри
LLM-драйвера и использует существующие `AgentAction`, `ToolResult`,
`DriverContext` и режимный каталог инструментов.

## Пайплайн

```text
instruction
   |
   v
specialist policy (audit / remediation / forensics / general)
   |
   v
Hypothesis Graph ---- backtrack / branch <------------------+
   |                                                         |
   v                                                         |
Capability Ladder -> cheapest falsifying probe               |
   |                                                         |
   v                                                         |
existing ToolRegistry -> real ToolResult                     |
   |                                                         |
   v                                                         |
Evidence Gate -> Evidence Ledger -> progress/stagnation -----+
   |
   v
existing independent validator
   |
   +-- fail -> new evidence -> hypothesis revision
   `-- pass -> success
```

## 1. Hypothesis Graph

Модель может вернуть необязательный объект `reasoning`:

```json
{
  "hypothesis": "user input reaches a SQL query unsafely",
  "confidence": 0.68,
  "expected_evidence": "string interpolation near the database call",
  "strategy": "branch"
}
```

Это **не факт**. Гипотеза хранится отдельно, имеет bounded confidence/status,
родительскую ветку и список evidence ID. Поддерживаются стратегии `continue`,
`branch`, `backtrack`, `verify`, `escalate`.

## 2. Evidence Gate

LLM не может записать evidence напрямую. В `Evidence Ledger` попадают только:

- реальные `ToolResult` из существующего registry;
- реальные результаты deterministic validation.

Каждая запись содержит source, action, краткое summary, bounded preview,
digest данных и ID гипотезы, которую проверяло действие. Поэтому
model-generated `observation` не становится источником истины.

## 3. Capability Ladder

Существующие действия распределяются по цене эскалации:

- level 0 — `list/read/search`;
- level 1 — специализированный статический анализ;
- level 2 — активные project checks;
- level 3 — зарезервирован под persistent debugger/network sessions;
- level 4 — mutation (`patch`, fixer, artifact write).

Лестница не заменяет C-10 allowlist. Это подсказка reasoning-слою: сначала
выбирать самый дешёвый probe, который способен опровергнуть текущую гипотезу.

## 4. Progress / Recovery

Новая уникальная evidence запись сбрасывает stagnation. Повтор уже известного
результата или failed probe увеличивает stagnation. После двух stagnating шагов
в prompt появляется `recovery_required=true` и рекомендуемый следующий уровень
capability ladder. System policy требует не повторять текущий подход, а
`backtrack`, `branch` или `escalate`.

Существующий `max_repeated_action` остаётся последним hard-stop: C-12 не
ослабляет fail-closed поведение ядра.

## 5. Bounded context

Reasoning state ограничен по числу гипотез, evidence и длине preview. Окно
сырых recent events уменьшено; долгоживущие выводы сохраняются в компактном
Evidence Ledger, а не в бесконечной истории stdout.

## Совместимость

- deterministic публичные задачи продолжают обходить LLM полностью;
- `AgentLoop`, validators и workspace tools не меняются;
- старый LLM JSON без поля `reasoning` остаётся валидным;
- неправильный `reasoning.strategy` или тип поля завершается fail-closed;
- следующий логичный этап — level-3 persistent interactive sessions для
  debugger/server connection без расширения полномочий существующих режимов.
