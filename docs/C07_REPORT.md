# C-07 — универсальная forensics-стратегия

## Результат

В `agent/tools/forensics.py` создан runtime-инструмент на стандартной библиотеке
Python. Он поддерживает три CLI-команды:

```bash
python3 -m agent.tools.forensics inventory TARGET [--output inventory.json]
python3 -m agent.tools.forensics analyze TARGET [--output report] [--trace graph]
python3 -m agent.tools.forensics validate REPORT
```

`TARGET` может указывать непосредственно на evidence-каталог или на родителя с
подкаталогом `incident/`.

## Безопасность доказательств

- inventory ограничен 256 файлами;
- каталоги `.git`, `solution`, `tests` и скрытые пути исключаются;
- небольшие/средние артефакты получают SHA-256;
- отчёт и trace запрещено записывать внутрь evidence-каталога;
- до и после анализа сравнивается digest инвентаря;
- публичный runner дополнительно сравнивает полный digest исходного bundle.

## Поддерживаемый профиль

Профиль `confirmed-sensitive-export-v1`:

1. читает все `app*.jsonl`, включая recovered fragments;
2. собирает `CONFIRM_SENSITIVE` из всех `edge_decisions*.log`;
3. выбирает максимальную подтверждённую logical payload;
4. связывает export с успешным `proxy_access*.log` по request ID и wire bytes;
5. атрибутирует XFF справа налево, поддерживая IPv4 и IPv6;
6. добавляет corroboration из всех `auth*.log`;
7. строит evidence graph и строгий четырёхстрочный результат.

Если схема неизвестна, инструмент не угадывает поля: основной агент использует
inventory и forensics playbook для ручной корреляции.

## Проверки

Добавлено 12 тестов:

- два разных набора IP/user/request ID/time/bytes;
- fallback с logical bytes на wire bytes;
- отбрасывание неподтверждённой крупной выгрузки;
- recovered JSONL, sharded edge и многострочный proxy log;
- IPv6 и right-to-left XFF attribution;
- полнота связей evidence graph;
- строгие мутации формата отчёта;
- CLI analyze/validate и неизменность evidence;
- запрет записи результата в каталог доказательств;
- лимит inventory и исключение answer/test-каталогов;
- разрешение родительского `/app` и default output;
- детерминированный выбор более позднего события при равном размере.

Публичный прогон выполняется без чтения `solution` и expected-файлов:

```bash
./scripts/run_c07_public.sh /path/to/UniversalAgenticCompetitionPublic
```
