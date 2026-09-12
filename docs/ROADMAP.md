# Дорожная карта ИБ-блока

> Актуальное состояние: этапы C-01…C-16 интегрированы. Production entrypoint —
> `agent.scaffold.cli`; таблица ниже сохраняет последовательность появления
> компонентов, а не список будущих работ.

| ID | Статус | Результат |
|---|---|---|
| C-01 | готово аналитически | карта шести публичных задач |
| C-02 | готово по допущениям | `docs/ASSUMPTIONS.md` |
| C-03 | готово | SQLi-разбор, минимальный patch и 5 тестов |
| C-04 | runner готов; нужен реальный Docker-прогон | project pytest + 11 HTTP-проверок |
| C-05 | готово | независимый анализатор, validator, trace и 7 тестов |
| C-06 | готово | audit/fix playbooks, AST-аудитор, asyncpg-fixer и 12 тестов |
| C-07 | готово | inventory, forensics profile, evidence graph и 12 тестов |
| C-08 | готово | baseline, policy engine, artifact/syntax/command checks и 18 тестов |
| C-09 | готово | основной цикл, action protocol, бюджеты, retry и fail-closed |
| C-10 | готово | bounded filesystem, unified patch, process allowlist и 32 теста |
| C-11 | готово | адаптер локальной OpenAI-compatible LLM и usage accounting |
| C-12 | готово | prompt policy, bounded state и mode guidance |
| C-13 | готово | portability/adversarial evaluation |
| C-14 | готово | CTF contract, byte-safe tools и completion guard |
| C-15 | готово | frozen project checks и test-integrity gate |
| C-16 | готово | production scaffold, diagnostics и reproducible ZIP |

## Выполнено в C-05

Создан `security/tasks/c05_incident_forensics/`:

- независимый Python-анализатор на стандартной библиотеке;
- строгий formatter четырёх строк `key=value`;
- тестовые вариации с другими IP, request ID, временем и log-shard;
- валидатор формата;
- отчёт с трассировкой происхождения каждого поля.

Анализатор вычисляет результат из логов и не читает публичный expected-файл.

## Выполнено в C-06

Созданы универсальные компоненты в `agent/`:

- классификатор режима задачи без расхода LLM-токенов;
- AST-аудитор tainted SQL для Python-проектов;
- консервативный asyncpg-параметризатор поддерживаемых SQL-значений;
- отдельные audit/fix playbook с разными правилами изменения проекта;
- 12 тестов, включая поведенческие SQLi-проверки и CLI-контракты;
- runner публичных SQL-задач на одноразовых копиях.

Инструменты не содержат IP, логины, request ID или готовые ответы публичного
набора.

## Выполнено в C-07

Созданы универсальные компоненты в `agent/`:

- ограниченная инвентаризация incident-каталога с типами, размерами и SHA-256;
- автоматическое разрешение `/app` или `/app/incident`;
- профиль подтверждённой утечки с application/edge/proxy/auth-корреляцией;
- объединение усечённых JSONL и многострочных/sharded логов;
- разбор IPv4/IPv6 XFF от доверенной proxy-стороны;
- evidence graph с файлами и номерами строк;
- строгий validator четырёхстрочного отчёта;
- 12 независимых unit/CLI/contract-тестов.

Публичный runner читает только `environment/`, работает на временной копии и
проверяет неизменность evidence и исходного репозитория.

## Выполнено в C-08

Создан `agent/validators.py`:

- SHA-256 snapshot содержимого, типа и Unix mode файлов;
- обнаружение добавленных, изменённых и удалённых путей;
- строгие политики `audit`, `fix`, `forensics` и `general`;
- защита tests/expected/solution/verifier и dependency manifests;
- проверки exact text, JSON, security report и incident report;
- AST-проверка Python без импорта проекта;
- команды без shell-интерпретации, с timeout и ограничением вывода;
- машиночитаемый validation report и коды возврата `0/1/2`;
- нормализация symlink и Windows 8.3-путей.

Добавлено 18 тестов, включая Windows-regression для ещё не созданных путей, и
публичный runner на временных audit/fix/forensics-копиях.

## Выполнено в C-09

Создан `agent/core/`:

- цикл снимает baseline до первого action, классифицирует instruction и загружает
  режимный playbook;
- драйвер возвращает только структурированные действия без shell-строк;
- режимный tool registry соединяет C-06/C-07 инструменты, не разрешая audit
  менять код или general-задаче запускать fix;
- `finish` всегда вызывает C-08 validator; провал возвращается драйверу для
  исправления, а не маскируется успешным завершением;
- лимиты шагов, времени, validation attempts и одинаковых действий останавливают
  зацикливание;
- deterministic fallback решает поддерживаемые профили без LLM-токенов и
  закрыто отказывает на неизвестной задаче;
- 19 сценарных/CLI/security-тестов проверяют успех, retry, провал tests,
  containment путей и бюджеты;
- публичный runner прогоняет все шесть instruction на временных копиях без
  чтения `solution`/`expected` и без изменения репозитория организаторов.

## Выполнено в C-10

Создан `agent/core/workspace.py` и расширен режимный registry:

- bounded list, UTF-8 line read, hex/ASCII byte read и literal search;
- пропуск `.git`, dependency caches и answer/verifier-каталогов;
- единая безопасная обработка `/app`, Windows absolute/8.3 и relative paths;
- strict unified diff только для существующих UTF-8 source-файлов;
- запрет patch для tests, expected/solution/verifier, dependency manifests и
  symlink-целей;
- предварительная проверка всех patch hunks до первой записи, сохранение LF/CRLF
  и file mode;
- process allowlist для project checks без shell, с timeout, capped output и
  удалением LLM credentials из child environment;
- отдельный каталог action-схем в `DriverContext`, различный для каждого режима;
- 32 security/integration-теста и публичный runner на временных копиях.

## Текущий цикл улучшения

Следующие изменения принимаются только через независимые regressions и полный
benchmark: расширение intent routing, instruction-native artifact schemas,
property-based non-SQL guards, compositional CTF/forensics dataflow и снижение
ложных внутренних success/failure. Hidden answers и task-name branches в runtime
не допускаются.
