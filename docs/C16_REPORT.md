# C16 — проверка submission ZIP оригинальными локальными тестами

C16 добавляет воспроизводимый Docker-прогон шести публичных задач организаторов.
Его назначение — проверить собранный архив, запуск агента, PostgreSQL/API и
результат исправлений вместе. Самостоятельно написанные unit-тесты проверяют
раннер, а оценку задач выставляют исходные проверяющие скрипты организаторов.

Рабочая ветка: `security/c15-fix-validation`. Новая ветка для C16 не создаётся.
Изменения ограничены новым раннером, его тестами, новым workflow и этим отчётом.
Runtime агента, инструменты команды, прежние workflow и `run.sh` не изменяются.

## Что запускается

Используется публичный репозиторий
[UniversalAgenticCompetitionPublic](https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic/tree/b95c62fec81656e338af54045efa688fd4979615)
на фиксированном коммите `b95c62fec81656e338af54045efa688fd4979615`.

| Задача | Что проверяют организаторы |
| --- | --- |
| `hello-file` | Создан файл с точным содержимым Hello |
| `bye-file` | Создан файл с точным содержимым Bye |
| `find-sqli-login` | Правильно указан уязвимый участок входа |
| `fix-sqli-login` | Исправлена SQL-инъекция входа; HTTP-поведение проходит suite |
| `fix-sqli-search` | Исправлена SQL-инъекция поиска; HTTP-поведение проходит suite |
| `incident-log-forensics` | Из журналов получены четыре требуемых факта |

`local_task/insecure-api-app` — общий пример приложения, а не седьмая задача.

## Подтверждённый официальный публичный прогон

7 сентября 2026 года [GitHub Actions run 34161140173](https://github.com/ExpertDaniil/sbersdich/actions/runs/34161140173)
на коммите `ca6e87bf46039bb84ac5974d7d2564e805a7683d` завершился успешно.
Это финальный прогон с прямым запуском `./run.sh`.
Все шесть задач получили `reward = 1` от оригинальных verifier. В скачанном
artifact дополнительно проверены контрольная сумма ZIP, agent.log и вывод pytest:

| Задача | Оригинальный verifier | Время процесса агента, с |
| --- | --- | ---: |
| hello-file | reward 1 | 7.478 |
| bye-file | reward 1 | 7.428 |
| find-sqli-login | 3/3 pytest, reward 1 | 8.881 |
| fix-sqli-login | 9/9 pytest, reward 1 | 18.399 |
| fix-sqli-search | 8/8 pytest, reward 1 | 18.048 |
| incident-log-forensics | reward 1 | 7.577 |

Суммарное время процессов агента — 67.811 с (без подготовки контейнеров и
верификации). Во всех шести agent.log: 0 запросов к модели, 0 модельных токенов.
ZIP: 130 552 байта, SHA256
`6aa087528fcec147980a25d2e06371ce1cd8ce78a49401e37dbf117228ad94bf`.
ACP digest:
`sha256:1324d7bb140422a9929f5bc538f55ec0480d2731742effee02bf67604130c8a3`.

В обеих fix-задачах C15 также запустил настоящие `pytest tests/` внутри приложения:
15/15 обычных тестов успешно, затем официальный verifier независимо проверил
защиту от инъекций на перезапущенном API. Тесты и их настройки агентом не менялись.

Предыдущий [run 34160635991](https://github.com/ExpertDaniil/sbersdich/actions/runs/34160635991)
тоже дал 6/6 для того же ZIP. В нём использовался `sh ./run.sh`; финальный запуск
дополнительно проверил shebang и исполняемость entrypoint. Разницу времени между
двумя CI-машинами нельзя считать оптимизацией агента: runtime ZIP идентичен.
Результаты и логи финального запуска доступны в artifact
[`c16-official-public-ca6e87b`](https://github.com/ExpertDaniil/sbersdich/actions/runs/34161140173/artifacts/10032691042).

## Как устроен прогон

1. Существующий сборщик создаёт ZIP с production `run.sh`. C16 проверяет размер
   до 10 000 000 байт, контрольную сумму, пути, отсутствие тестов, секретных файлов
   и CRLF в entrypoint. Сам архив раннер не исправляет и не пересобирает.
2. Команда `prepare` экспортирует исходные файлы через `git archive` из указанного
   коммита. Она не меняет checkout организаторов. Это также сохраняет исходные LF
   независимо от `core.autocrlf` и Windows-настроек рабочей копии.
3. Пока сеть доступна, загружается ACP, сохраняется его digest, собираются образы
   задач. В отдельной копии build context заменяется только `FROM ...:latest`
   на этот digest. Экспортированные исходники и оригинальные tests не меняются.
4. Команда `run` запускает каждую задачу в новом контейнере по сохранённому image ID
   с `--pull=never`, `--network none`, CPU/RAM из `task.toml`. Порты, каталоги хоста
   и Docker socket не пробрасываются. PostgreSQL и API работают внутри контейнера.
5. Архив устанавливается в `/opt/harbor/local-agent`. Рядом кладётся оригинальный
   `agent.py`, как в установке Harbor. `run.sh` получает исходный текст инструкции
   одним аргументом; рабочий каталог задачи выбирает существующий launcher.
6. Только после успешного завершения агента загружается оригинальный `/tests`.
   Старый каталог результатов verifier очищается. Выполняется `bash /tests/test.sh`.
   В SQL-задачах этот скрипт сам перезапускает API на исправленном коде и готовит БД.
7. Результат берётся из `/logs/verifier/reward.txt`: допустимы только `0` и `1`.
   Падение или timeout агента/проверяющего процесса не может стать успехом.
   Контейнер удаляется по уникальному имени даже после ошибки.

Подготовка образов требует интернет. Во время выполнения задач зависимости не
устанавливаются, внешний интернет контейнерам недоступен; loopback остаётся
доступным для API/БД. См. [Docker network none](https://docs.docker.com/engine/network/drivers/none/).

## Что содержат результаты

`prepared/prepared.json` хранит SHA исходного репозитория, digest ACP, image ID,
лимиты и контрольные суммы. `run/summary.json` содержит SHA ZIP, результаты каждой
задачи, число решённых задач и `all_passed`. Для каждой задачи сохраняются вывод
агента, оригинального verifier, контейнера, reward и сведения о timeout/exit code.

`run/traces.json` совместим с разбором C11:

```sh
python -m evaluation.failure_analysis evaluation/results/c16/run/traces.json --output evaluation/results/c16/failure_journal.json --strict
```

Код возврата `prepare`: 0 — образы готовы, 2 — подготовка заблокирована.
Код возврата `run`: 0 — все выбранные задачи прошли, 1 — есть провалы,
2 — запуск заблокирован, например, нет Docker или изменились исходники.
Пустой прогон не считается успешным. Каталог результатов должен быть новым:
повторный запуск не перезаписывает предыдущий отчёт.

## Запуск из PowerShell

Нужны Python 3.12, Git и запущенный Docker Desktop в режиме Linux containers.
Это требования к машине разработчика; агент внутри ACP ничего не устанавливает.
Клонировать оригинальный репозиторий достаточно один раз вне командного проекта:

```powershell
git clone https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic.git ..\UniversalAgenticCompetitionPublic
if ($LASTEXITCODE -ne 0) { throw "Не удалось получить публичные задачи" }
```

Из корня `sbersdich`:

```powershell
$C16Run = "evaluation/results/c16-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
python scripts/build_scaffold_submission.py --output "$C16Run/submission.zip"
if ($LASTEXITCODE -ne 0) { throw "Сборка ZIP не прошла" }
python -m evaluation.official_public prepare --public-root "../UniversalAgenticCompetitionPublic" --output "$C16Run/prepared"
if ($LASTEXITCODE -ne 0) { throw "Подготовка Docker не прошла: смотри prepared.json и логи" }
python -m evaluation.official_public run --prepared "$C16Run/prepared" --submission "$C16Run/submission.zip" --output "$C16Run/run"
if ($LASTEXITCODE -ne 0) { throw "Есть провал или блокировка: смотри summary.json и логи задачи" }
Get-Content "$C16Run/run/summary.json" -Encoding UTF8
```

Для повторной проверки готового ZIP можно использовать те же prepared-образы и
новый каталог `--output`. `--task fix-sqli-login --task fix-sqli-search` ограничивает
прогон двумя задачами; отчёт явно перечисляет выбранные задачи.

На Linux доступны те же Python-команды и обёртка `bash scripts/run_c16_public.sh`.
Ветка также получает отдельный workflow `.github/workflows/security-c16.yml`:
push изменений кода в ветку C15 запускает проверки, сборку и шесть задач. В GitHub
Actions сохраняется artifact с ZIP и логами, в том числе при неудаче подготовки.

## Границы проверки

- Это Docker-раннер оригинальных публичных verifier, а не запуск самого Harbor.
  Установочный путь, соседний wrapper, инструкция и окружения воспроизводятся;
  управление контейнером и сбор результатов выполняет C16.
- Проверка идёт без LLM: три переменные подключения очищаются, используются
  готовые детерминированные стратегии. `real_llm_tested` всегда `false`.
  Работу настоящего endpoint и расход модельных токенов нужно проверять отдельно.
- CPU/RAM и timeout берутся из задач. Дисковая квота `storage_mb` этим раннером
  не устанавливается; доступное место зависит от Docker-хоста.
- Исходники и образ ACP фиксируются, но apt/pip-зависимости при подготовке образов
  зависят от доступных внешних репозиториев. Готовые image ID повторно используются
  без сети; для полного воспроизведения следует сохранять подготовленные образы.
- Успех на шести открытых задачах не гарантирует результат на 15 закрытых.
  Зелёные unit-тесты раннера также не являются результатом этих шести задач.

## Проверки самого C16

Локально на Linux/Python 3.12: C03 — 5, C04 — 4, C05 — 7,
agent — 212 (211 успешно, один Windows-only пропуск), evaluation — 73 успешно,
включая 22 новых проверки C16. Итого 301 обнаруженный тест: 300 успешных,
один платформенный пропуск. Portability: 9/9. Это проверки разработки.
Docker в среде этой локальной проверки отсутствует, поэтому она сама по себе
не подтверждает результат официальных задач. Их результат фиксируется отдельно.

```sh
python -m unittest evaluation.tests.test_official_public -v
bash scripts/check_all.sh
bash evaluation/verify.sh
```

Unit-тесты используют явно обозначенный FakeDocker. Они проверяют порядок
установки verifier, обработку reward/timeout, изоляцию запуска, очистку контейнера,
целостность fixtures, небезопасные ZIP, UTF-8 и отказ при отсутствии Docker.
Реальные результаты Docker-прогона следует смотреть в artifact конкретного CI run
или в созданном на своей машине `summary.json`.
