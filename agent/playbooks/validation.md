# Validation protocol

Общий validator принадлежит runtime. Baseline снимается ядром до первого
изменения, хранится вне task workspace и автоматически используется при
`finish` либо сразу после подтверждённой transactional mutation/записи
объявленного артефакта.

Планировщик не должен:

- запускать `python -m agent.validators` или искать файлы внутреннего агента;
- придумывать `/tmp` baseline и validation report;
- создавать `security_report.json`, если такого deliverable нет в
  `artifact_rules`;
- повторно запускать pytest только для подтверждения уже успешного
  `checked_edit`: runtime сам выполняет frozen project checks.

Если автоматическая проверка не прошла, использовать только её
`failed_checks` как новую информацию и исправить конкретную причину. Нельзя
обходить gate другим режимом, лишним файлом или самостоятельным заявлением об
успехе.

Для audit/forensics схема в `artifact_rules` извлечена непосредственно из
instruction и имеет приоритет над любыми generic-примерами. Поля нельзя
переименовывать. Для fix проверяются syntax, неизменность тестов и dependency
manifests, frozen project suite, поддерживаемые scanners и явно извлечённые из
instruction security properties.
