# C-07 forensics variations

Тесты C-07 создают incident bundles во временных каталогах со сменой IP,
пользователя, request ID, времени, размера, shard-имён и наличия logical bytes.

Expected-результаты задаются только внутри unit-тестов и не копируются в
runtime-каталог агента или финальный submission.
