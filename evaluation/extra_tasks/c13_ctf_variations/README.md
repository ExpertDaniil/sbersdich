# C-13 generated CTF variations

Каталог не содержит статических environment, solution или expected-файлов.
`evaluation.ctf_suite` детерминированно создаёт каждый challenge во временном
workspace и удаляет его после проверки.

| Задача | Доступные evidence/clues | Проверяемая цепочка |
|---|---|---|
| `layered-text` | UTF-8-файл в пути с пробелом и Unicode | Base64 → ROT13 → flag |
| `binary-xor` | бинарный файл и явный repeating key | bounded byte read → hex → XOR → flag |
| `compressed-base64url` | unpadded Base64URL token | Base64URL → bounded gzip → flag |

Для каждой задачи pipeline использует только runtime actions из `ctf`-режима.
После `finish` внешний verifier проверяет точные байты результата и неизменность
evidence. Хеш результата можно записать в отчёт, само значение флага — нельзя.

Негативные тесты отдельно проверяют malformed transforms, compression bomb,
неявный/внешний output path, изменение лишнего файла, старый артефакт и
правдоподобный, но неверный флаг.
