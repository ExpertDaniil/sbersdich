# C-12 portability/adversarial fixtures

Сценарии C-12 не хранят готовые task-environment или expected-ответы. Модуль
`evaluation.portability` при каждом запуске создаёт новые временные каталоги и
проверяет настоящие компоненты из `agent/` и `evaluation/`.

Матрица вариаций:

| Класс | Положительные варианты | Отрицательные варианты |
|---|---|---|
| Артефакт | точный LF, UTF-8/Unicode | CRLF, лишний newline, пробелы, отсутствующий файл |
| SQL | CRLF и Unicode, LIKE, числовой контекст | частично исправлена только одна из двух SQLi |
| Patch | один корректный CRLF-файл | неверный второй hunk, traversal, неверные счётчики |
| Forensics | BOM/CRLF, пробелы вокруг `=`, несколько shard | пустой JSONL, большая noise-строка, нет proxy evidence |
| Failure journal | четыре shard, Unicode task ID | пустой shard и большой regression-log |
| Process | большой stdout с успешным exit | зависание и cwd за пределами workspace |

Expected-условия находятся только в коде проверяющего контура и не копируются
в каталог, доступный агенту во время решения задачи.
