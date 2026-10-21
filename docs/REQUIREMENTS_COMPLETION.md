# Проверка требований практической работы 4

## Изменения 21 октября 2026 года

1. `go/scanner/main.go` запускает Nmap, Masscan и Nikto в трёх goroutine.
   Go управляет процессами, журналами и таймаутами. Python вызывает этот
   сборщик, затем выполняет нормализацию, объединение и анализ. Оба входа
   — API и `run_system.sh` — используют один конвейер.
2. Java поддерживает `add`, `listRules`, `findByCategory`, `snapshot`,
   `restore` и `list`. Добавление и выбор правил выполняются в Java.
   Python используется только для чтения/записи YAML и общей валидации.
   Добавление проверяет весь итоговый набор, отклоняет повтор имени,
   сохраняет резервную копию и атомарно заменяет активный YAML.
   Файловая блокировка защищает от одновременных команд менеджера.

## Соответствие заданию

| Требование | Реализация | Проверка |
| --- | --- | --- |
| Анализ SDL_Moskalev | docs/ORIGINAL_PROJECT_ANALYSIS.md | Статический разбор шести исходных файлов |
| Архитектура и общие данные | README, normalize_*, merge_scans.py | Демо объединяет три источника |
| C++ Nmap XML → JSON | cpp/nmap_parser.cpp, libxml2 | run_demo.sh |
| Python Masscan/Nikto | normalize_masscan.py, normalize_nikto.py | Демо и лабораторный конвейер |
| Правила и дерево | expert_system.py, decision_tree.py | evaluate.py, train_tree.py |
| Go API и конкурентность | go/api.go, go/scanner/main.go | Go race-тесты, затем сканирование в VM |
| JavaScript-визуализация | web/index.html | Карточки, таблица и распределение severity |
| Java-правила и версии | java/RuleManager.java | Тесты add/find/restore и конкурентного добавления |
| Интеграция Linux | run_system.sh, setup_lab.sh | Проверка сохранённого живого отчёта |
| Precision/Recall/F1 | evaluate.py, train_tree.py | Размеченные синтетические сценарии |

## Сборка и автоматические проверки

Нужны Go 1.20+, JDK 17+, C-компилятор для Go race и установленная `.venv`.
Команды выполнять из корня проекта. Перед заменой бинарных файлов дождаться
конца сканирования и остановить API через Ctrl+C.

```bash
bash verify_requirements.sh
```

Скрипт собирает Go и Java, выполняет Go-тесты и шесть Python/Java-тестов.
Java-тесты работают в отдельном временном каталоге: активные правила проекта
не меняются. Go-тесты проверяют одновременный старт, отказ одного сканера,
код завершения, журнал и таймаут процесса с дочерним процессом.

## Использование Java

```bash
java -cp build/java RuleManager listRules
java -cp build/java RuleManager findByCategory unauthorized_access
java -cp build/java RuleManager snapshot before-custom-rule
java -cp build/java RuleManager add /path/to/new-rule.yaml
java -cp build/java RuleManager restore before-custom-rule
```

Имя снимка должно быть новым. `list` показывает версии; `listRules` — активные
правила. Кандидат — один YAML-объект, без внешнего ключа `rules`. Например:

```yaml
name: Open RDP lab example
category: unauthorized_access
risk_score: 8.5
conditions:
  - field: port
    operator: eq
    value: 3389
  - field: state
    operator: eq
    value: open
recommendations:
  - Verify the service and restrict access through a VPN.
version: '1.0'
```

Добавление изменяет активные правила. Учебный пример не добавляется при
установке автоматически. Правила и дерево — независимые методы; новое правило
не обучает дерево автоматически. Ручное редактирование YAML не использует
блокировку Java: не редактировать файл параллельно с командами менеджера.

## Подтверждение в Ubuntu VM

Автоматические тесты нового кода прошли в среде подготовки на Linux.
Исторические скриншоты от 19 октября относятся к прежнему Python-сборщику.
Новый Go-сборщик требуется отдельно проверить в пользовательской VM:

1. Подготовить/запустить лабораторию по `docs/LIVE_SCAN.md`.
2. Если отсутствует модель или C++-бинарный файл, выполнить `bash run_demo.sh`.
3. В другом терминале запустить:

```bash
bash run_system.sh > results/requirements-live.json
.venv/bin/python python/verify_live_report.py results/requirements-live.json
```

4. Для проверки API запустить `./build/api`, открыть существующий SSH-туннель
   и нажать **Start lab scan** в браузере. Не запускать CLI и API-сканы одновременно.
5. Сохранить снимки успешной автоматической проверки, нового живого отчёта и
   дашборда. Количество находок может измениться; значение 16 не зафиксировано в тесте.

После проверок изменения можно сохранить одним коммитом и отправить в GitHub:

```bash
git diff --check
git add .gitignore README.md docs/LIVE_SCAN.md docs/REQUIREMENTS_COMPLETION.md \
  go/scanner java/RuleManager.java python/live_scan.py python/rule_codec.py \
  python/verify_live_report.py tests/test_live_scan.py tests/test_rule_manager.py \
  verify_requirements.sh
git commit -m "Complete Go scanner concurrency and Java rule management"
git push
```

Небольшой синтетический датасет и отсутствие проверки установки на чистой VM
остаются ограничениями доказательств, а не отсутствующими функциями прототипа.
Сравнительная скорость C++ не измерялась. В задании нет обязательства доказать
производственную точность или установить систему на второй чистой VM.
