# Antigravity Patcher — отключение региональных ограничений

Патчер для Google Antigravity: нейтрализует **локальные** проверки доступности
(eligibility), из-за которых клиенты показывают «not available in your location».
Написан на базе [QNIX-Dev/eligibility-antigravity-patcher](https://github.com/QNIX-Dev/eligibility-antigravity-patcher) (MIT),
с проверенной поддержкой **Antigravity IDE 2.6.0**.

> Патч меняет только локальную логику клиентов. Он **не** создаёт серверных прав,
> не обходит серверную авторизацию и не открывает платные функции: доступность
> моделей по-прежнему определяют ответы серверов Google. Ошибки вида
> HTTP 400 «User location is not supported for the API use» — серверные,
> локальным патчем не лечатся.

## Что патчится

| Цель | Файл | Что меняется |
|---|---|---|
| `ide` | `resources/app/out/main.js` в папке IDE | Auth-гейт: `resetIsTierGCPTos(),this.<svc>.isGoogleInternal` → `resetIsTierGCPTos(),true` |
| `agy` | `~/.gemini/bin/agy[.exe]` | Бинарные гейты Go-бэкенда (`hasValidAuth` / экран eligibility). **Для IDE 2.6.0 обязательная пара к `ide`** — см. ниже |
| `cli` | `agy[.exe]` из PATH | Экран eligibility в Antigravity CLI (x64 и arm64) |
| `manager` | `resources/bin/language_server[.exe]` в Antigravity 2.0 | Гейт `hasValidAuth` (x64 и arm64) |

### Особенность IDE 2.6.0

В IDE 2.6.0 языковой сервер **больше не лежит внутри папки IDE** (в официальном
linux-x64 пакете 2.6.0 нет ни одного `language_server`): расширение
`google-antigravity` скачивает бинарник при первом запуске IDE в
`%USERPROFILE%\.gemini\bin\agy.exe` (Linux/macOS: `~/.gemini/bin/agy`).
Поэтому:

- полный патч IDE 2.6.0 = `patch ide` **плюс** `patch agy` (или просто `patch` — все цели сразу);
- если `agy` ещё не скачан, патчер прямо скажет: запустите IDE один раз и повторите `patch`.

## Быстрый старт

Требуется Python 3.8+, сторонние пакеты не нужны. Перед патчем закройте Antigravity.

```bash
python3 antigravity_patcher.py status          # что найдено и в каком состоянии
python3 antigravity_patcher.py patch           # пропатчить всё найденное
python3 antigravity_patcher.py patch ide agy   # только IDE 2.6.0 (main.js + языковой сервер)
python3 antigravity_patcher.py restore         # откатить всё из бэкапов
```

Windows — то же самое с `python` вместо `python3`. Для нестандартных путей:

```bash
python3 antigravity_patcher.py --path-ide "/opt/Antigravity IDE/resources/app/out/main.js" patch ide
python3 antigravity_patcher.py --path-agy ~/.gemini/bin/agy patch agy
```

Дополнительно: `--json` (статус в JSON), `--dry-run` (для IDE: показать, что изменится, ничего не записывая).

## Безопасность патча

- Сигнатуры ищутся регулярными выражениями по машинному коду / минифицированному JS,
  а не по фиксированным смещениям; бинарные сигнатуры — **только внутри исполняемых
  секций** PE/ELF/Mach-O, с определением архитектуры (x64/arm64).
- Патч применяется только при **ровно одном** однозначном совпадении. Ноль, два и более,
  а также смешанное состояние «половина пропатчено» — отказ без записи.
- Перед записью создаётся бэкап `<файл>.agybak`, который проверяется как чистый оригинал;
  цель перечитывается перед записью; результат проверяется после записи;
  при любой ошибке — автоматический откат из бэкапа.
- `restore` принимает бэкап, только если он сам распознаётся как чистый оригинал,
  и проверяет результат восстановления.
- Для IDE после патча сбрасывается JS-кэш (`CachedData`, `Code Cache/js`),
  чтобы IDE не подхватила старую скомпилированную копию `main.js`.

### macOS: автоматическая подпись

На macOS подпись обрабатывается автоматически, как в апстриме:

- перед первым патчем внутри `.app` исходное состояние подписи бандла
  (главный executable, `Contents/_CodeSignature`, `Contents/CodeResources`)
  сохраняется в соседний каталог `<App>.app.agysignbak` с манифестом дайджестов;
- перед записью проверяется Electron Library Validation: если она включена и
  entitlement-исключения нет, патч останавливается. Флаг
  `--macos-disable-library-validation` добавляет исключение
  `com.apple.security.cs.disable-library-validation` **только** главному
  executable выбранного приложения;
- после патча изменённые бинарники переподписываются ad-hoc изнутри наружу,
  затем сам бандл (с сохранением identifier/entitlements/flags/runtime),
  результат проверяется `codesign --verify`, карантин (`com.apple.quarantine`)
  рекурсивно снимается. Ошибка подписи откатывает пропатченные файлы из бэкапов;
- при `restore`, когда восстановлена последняя пропатченная цель в бандле,
  оригинальная подпись бандла возвращается из `.agysignbak` и проверяется;
  если в бандле остались пропатченные цели — бандл переподписывается вокруг них;
- одиночные бинарники (`~/.gemini/bin/agy`, CLI) переподписываются ad-hoc на месте;
  отдельный бэкап подписи им не нужен — `restore` возвращает исходные байты,
  а с ними и исходную подпись;
- запись в подписанные Mach-O на macOS идёт не на месте, а атомарной заменой
  через соседний временный файл.

Честная оговорка: живой `codesign` прогнать негде (нет Mac), поэтому логика
подписи покрыта юнит-тестами с моком codesign (`tests_macos.py`: снапшот/восстановление
подписи, порядок подписи «бинарник → бандл», откат при ошибке подписи, префлайт
Library Validation, полный цикл patch→sign→restore на фейковом `.app`).
Сама схема и код адаптированы из апстрима QNIX, где она проверена на реальном железе.

## Проверка поддержки IDE 2.6.0 (факты)

Проверено 2026-11-06 на официальном билде **2.6.0-5526304964083712** (linux-x64;
пакет получен из официального CDN-набора версий, контрольная сумма пакета сверена):

- `product.json`: `ideVersion = 2.6.0` (патчер читает версию именно оттуда);
- `resources/app/out/main.js`: 12 946 363 байта,
  SHA-256 `d84ad79f5634d3ba544a939533e75ec197240a21047e3a01b9160cfd980e04ff`;
- гейт найден **ровно один**, смещение `0xbf13cb`:
  `if(this._authActor.send({type:t.isGcpTos?"GCP_SIGN_IN":"SIGN_IN"}),this._cloudCodeMainService.resetIsTierGCPTos(),this._productService.isGoogleInternal){...}`;
- остальных вхождений `isGoogleInternal` в файле 63 — это флаги продукта для UI/обновлений,
  патч их не трогает;
- `main.js` **нет** в `checksums` файла `product.json` — патч не триггерит проверку целостности VS Code-ядра;
- сквозной тест на копии реального файла: `patch` → ровно одна замена (−33 байта),
  повторный `patch` → «already patched», `restore` → SHA-256 совпал с оригиналом байт-в-байт;
- бинарные гейты `agy` прогнаны на PE-фикстурах (гейт CLI и гейт hub/`hasValidAuth`):
  status/patch/restore работают, сигнатура в неисполняемой секции корректно не находится.

Подробный протокол: `VERIFICATION.md`.

## Файлы

- `antigravity_patcher.py` — сам патчер (один файл, стандартная библиотека Python).
- `tests_macos.py` — тесты логики macOS-подписи (codesign замокирован).
- `VERIFICATION.md` — протокол проверки на IDE 2.6.0.

## Лицензия и кредиты

Гейт-сигнатуры, сканирование исполняемых диапазонов и модель бэкап/откат —
из [QNIX-Dev/eligibility-antigravity-patcher](https://github.com/QNIX-Dev/eligibility-antigravity-patcher) (MIT).
Факт о скачивании языкового сервера IDE 2.6.0 в `~/.gemini/bin` впервые задокументирован
в релизе v2.28.2 проекта confeden/Antigravity и подтверждён здесь по официальному пакету 2.6.0.
