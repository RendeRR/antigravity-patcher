# Протокол проверки поддержки Antigravity IDE 2.6.0

Дата: 2026-11-06 (МСК). Проверяющий: Муся Третья, в этой сессии.

## Источник билда

- Официальная страница antigravity.google/download показывает IDE v2.6.0.
- Официальный updater-эндпоинт `antigravity-ide-auto-updater-974169037036.us-central1.run.app/releases`
  первой записью отдаёт `{"version":"2.6.0","execution_id":"5526304964083712"}`.
- Официальный linux-x64 URL: `https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.6.0-5526304964083712/linux-x64/Antigravity%20IDE.tar.gz`.
  Прямая загрузка с этой машины была недоступна (egress-прокси режет edgedl, браузерная
  загрузка не подтвердилась), поэтому тот же официальный билд 2.6.0-5526304964083712
  получен в виде .deb из репозитория X3M Antigravity Packagers
  (`apt.x3m.industries`, пакет `antigravity-ide 2.6.0-5526304964083712`):
  размер 141 328 300 байт, SHA-256 пакета
  `d7534a15e8672e08fae87c2ba0fd4d5711d91f3be320a1bbbc189b3940b48cbf` —
  совпал с опубликованным в Packages-индексе репозитория.
  Пакет лишь переупаковывает официальный tar.gz Google (структура и даты файлов —
  2026-10-26, commit IDE 9e3a5da5d6731effd57d47d88bbe5df14ac6ccdd).

## Структура пакета 2.6.0 (linux-x64, 18 636 записей)

- `resources/app/out/main.js` — есть, 12 946 363 байта.
- `resources/app/product.json`: `ideVersion = 2.6.0`, `version = 1.107.0` (ядро VS Code),
  `isGoogleInternal = False`, `languageServerCL = 1007378935`.
- Ни одного файла `language_server*` в пакете нет — подтверждение, что IDE 2.6.0
  не поставляет языковой сервер внутри установки.
- Единственный agy-артефакт — встроенное расширение `resources/app/extensions/agy`
  (`google-antigravity`, dist/extension.js): оно и скачивает сервер в `~/.gemini/bin`
  при первом запуске (путь вне пакета; на Windows — `%USERPROFILE%\.gemini\bin\agy.exe`,
  как задокументировано в релизе confeden/Antigravity v2.28.2).

## Гейт в main.js

- SHA-256 оригинального main.js:
  `d84ad79f5634d3ba544a939533e75ec197240a21047e3a01b9160cfd980e04ff`
- Сигнатура апстрима `(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal`:
  **ровно 1 совпадение**, смещение 0xbf13cb. Контекст:
  `async confirmUserForService(t){if(this._authActor.send({type:t.isGcpTos?"GCP_SIGN_IN":"SIGN_IN"}),this._cloudCodeMainService.resetIsTierGCPTos(),this._productService.isGoogleInternal){try{await this._cloudCodeMainService.loadCodeAssist(t);...`
- Маркер пропатченного состояния `resetIsTierGCPTos(),true` в оригинале отсутствует.
- Всего вхождений `isGoogleInternal`: 64; 63 из них — чтение флага продукта
  (`this._productService.isGoogleInternal`, `Io().product` и т.п.) для UI, обновлений
  и метаданных клиента. Патчится только auth-гейт в `confirmUserForService`.
- `out/main.js` отсутствует в словаре `checksums` внутри product.json
  (там 11 записей, включая `jetskiAgent/main.js` и `workbench.desktop.main.js`),
  т.е. замена не конфликтует с проверкой целостности ядра.

## Сквозные тесты патчера (на копии реального main.js 2.6.0)

1. `status ide` → `unpatched`, версия определена как IDE 2.6.0, `verified: true` (JSON).
2. `--dry-run patch ide` → сообщение о точке патча, файл не изменён (SHA-256 прежний).
3. `patch ide` → `main.js.agybak` создан; результат равен оригиналу с ровно одной
   заменой `resetIsTierGCPTos(),this._productService.isGoogleInternal` →
   `resetIsTierGCPTos(),true` (размер −33 байта); `status` → `patched`.
4. Повторный `patch ide` → `already patched`, файл не тронут.
5. `restore ide` → SHA-256 снова `d84ad79f…04ff` (байт-в-байт), `status` → `unpatched`.
6. Негативный тест: файл с двумя гейтами → отказ «signature is not unique»,
   код выхода 1, файл не изменён.

## Тесты бинарной цели agy (фикстуры)

Минимальные PE x64 с байтами гейтов в исполняемой секции `.text`:

- гейт CLI (eligibility screen, agy 1.4.0 x64): status `unpatched` → patch
  (`eligibility screen off (x64) @ 0x209`) → status `patched` → restore → `unpatched`;
- гейт hub (hasValidAuth=true, x64): аналогично, патч по смещению 0x200;
- те же байты гейта только в неисполняемой секции `.data` → status `unknown`,
  patch отклонён (код 1) — поиск идёт только по исполняемым диапазонам;
- случайный файл → `unknown`; отсутствующий `~/.gemini/bin/agy` → подсказка
  «запустите IDE один раз» вместо ошибки.

## macOS: автоматическая подпись (добавлено 2026-11-07)

По замечанию пользователя в патчер добавлена автоматическая подпись для macOS
(в первой версии был только warning с ручной инструкцией). Реализовано по модели
апстрима: снапшот оригинальной подписи бандла в `<App>.app.agysignbak`,
префлайт Electron Library Validation (стоп без флага
`--macos-disable-library-validation`), ad-hoc переподпись бинарников изнутри
наружу и затем бандла с `--preserve-metadata=identifier,entitlements,flags,runtime`,
верификация `codesign --verify --deep --strict`, снятие карантина, откат файлов
при ошибке подписи, восстановление оригинальной подписи бандла при restore
последней пропатченной цели.

Проверка — `tests_macos.py`, 7 тестов, все проходят (на Linux, codesign замокирован):
снапшот/восстановление состояния подписи байт-в-байт; создание `.agysignbak`;
порядок подписи «бинарник → бандл»; откат байтов бинарника при ошибке codesign;
Library Validation блокирует без флага и даёт entitlement-исключение с флагом;
полный цикл patch→sign→restore на фейковом `.app` (файл пропатчен, бандл подписан,
бэкап подписи создан; после restore файл и состояние — исходные).
Регрессия Linux-путей после изменения: реальный main.js 2.6.0 (patch/restore,
SHA-256 исходный) и PE-фикстуры agy (оба гейта) — без изменений.

## Что не проверялось вживую

- Реальный скачанный IDE 2.6.0 бинарник `~/.gemini/bin/agy` (для этого нужен первый
  запуск IDE с аккаунтом): патчер перебирает оба известных семейства гейтов
  (CLI и hub) и требует ровно одно однозначное совпадение; при несовпадении честно
  скажет «unsupported version», ничего не записав.
- Windows- и macOS-сборки IDE 2.6.0: main.js у VS Code-форков общий для платформ
  (JS архитектурно независим; апстрим подтверждал ту же сигнатуру на macOS arm64 2.5.5),
  но хэш выше — именно linux-x64.
- Живой `codesign` на настоящем Mac: логика подписи покрыта тестами с моком
  (см. раздел выше), на реальном железе не прогонялась — нет доступного Mac.
