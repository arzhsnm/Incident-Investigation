# Отчёт по расследованию компьютерного вторжения
## Incident Investigation — Forensics Linear Quest: Task 2

**Дата анализа:** 29–30 июня 2026 г.  
**Анализируемый образ:** rd01-triage.vhdx  
**Инструменты:** PECmd, AppCompatCacheParser, AmcacheParser, MFTECmd (Eric Zimmerman Tools)  
**Операционная система образа:** Windows 10/11 (22000)

---

## Раздел 1. Анализ артефактов

### Вопрос 1. Приложения, релевантные для расследования вторжения

В ходе анализа prefetch-файлов были выявлены следующие приложения, представляющие интерес для расследования:

| № | Приложение | Путь | Причина интереса |
|---|-----------|------|-----------------|
| 1 | **PowerShell.exe** ⭐ | C:\Windows\System32\WindowsPowerShell\v1.0\ | Основной инструмент атакующих, living-off-the-land |
| 2 | **CMD.exe** ⭐ | C:\Windows\System32\ | Запуск команд, скриптов, разведка |
| 3 | **EdgeUpdater.exe** ⭐ | C:\Windows\Update\ | Подозрительное расположение, маскировка |
| 4 | **STUN.exe** ⭐ | C:\Windows\System32\ | Нестандартный инструмент, переименован |
| 5 | **MSTSC.exe** | C:\Windows\System32\ | RDP клиент — боковое перемещение |
| 6 | **NET.exe** | C:\Windows\System32\ | Управление пользователями и сетью |
| 7 | **CSCRIPT.exe** | C:\Windows\System32\ | Запуск вредоносных скриптов |
| 8 | **WMIC.exe** | C:\Windows\System32\ | WMI — разведка и выполнение команд |
| 9 | **SCHTASKS.exe** | C:\Windows\System32\ | Создание задач для закрепления |
| 10 | **NOTEPAD.exe** | Program Files\WindowsApps\ | Открытие подозрительных файлов |
| 11 | **WHERE.exe** | C:\Windows\System32\ | Поиск файлов в системе |
| 12 | **SHUTDOWN.exe** | C:\Windows\System32\ | Выключение/перезагрузка системы |
| 13 | **WSMPROVHOST.exe** | C:\Windows\System32\ | WS-Management — удалённое управление |

**Приоритетные для анализа:**
- **EdgeUpdater.exe** — находится в нестандартной папке `C:\Windows\Update\`, является переименованным инструментом BrowsingHistoryView
- **PowerShell.exe** — запускался пользователем wacsvc и tdungan, наличие транскриптов
- **STUN.exe** — нестандартный инструмент в System32, исходный файл переименованного EdgeUpdater
- **MSTSC.exe** — запущен сразу после Notepad, указывает на RDP-подключение к другому хосту

---

### Вопрос 2. Сколько раз выполнялся PowerShell?

**Ответ: 16 раз**

Источник: prefetch-файл `POWERSHELL.EXE-59FC8F3D.pf`, поле RunCount = 16

---

### Вопрос 3. Когда первый раз выполнялся PowerShell?

**Ответ: 2023-01-17 19:04:19 UTC**

Prefetch хранит до 8 последних временных меток. Самая ранняя из сохранённых: `PreviousRun7 = 2023-01-17 19:04:19`. Учитывая что RunCount = 16, более ранние запуски не сохранились в prefetch.

---

### Вопрос 4. Когда последний раз выполнялся PowerShell?

**Ответ: 2023-01-25 14:57:21 UTC**

Источник: поле LastRun в prefetch-файле PowerShell.

---

### Вопрос 5. Какой пользователь запускал PowerShell?

**Ответ: два пользователя**

- **wacsvc** — транскрипты PowerShell в `C:\Users\wacsvc\Documents\20230117\` (17 января 2023)
- **tdungan** — транскрипты PowerShell в `C:\Users\tdungan\Documents\20230125\` (25 января 2023)

Источник: FilesLoaded в prefetch-файле PowerShell содержат пути к транскриптам обоих пользователей.

---

### Вопрос 6. Анализ CMD.exe

| Параметр | Значение |
|---------|---------|
| Количество запусков | **49** |
| Первый запуск (из сохранённых) | **2023-01-23 18:16:17 UTC** |
| Последний запуск | **2023-01-25 15:07:50 UTC** |
| Пользователь | **wacsvc** |

Источник: prefetch-файл `CMD.EXE-89305D47.pf`  
Пользователь определён по FilesLoaded: файлы в `C:\Users\wacsvc\AppData\Local\Temp\` и в `C:\Windows\Update\`

---

### Вопрос 7. Файлы и директории в CMD.EXE prefetch

Анализ `CMD.EXE-89305D47.pf` показал следующие интересные файлы, затронутые в течение 10 секунд от запуска:

**Подозрительные/интересные файлы:**
- `NET.EXE` — управление пользователями и сетевыми ресурсами (разведка)
- `CSCRIPT.EXE` — запуск скриптов (возможно вредоносных)
- `WHERE.EXE` — поиск файлов в системе
- `SHUTDOWN.EXE` — выключение/перезагрузка системы
- `C:\Windows\Update\WERFAULT.EXE` — **критически подозрительно**: файл в нестандартной папке
- `C:\Windows\Update\WERFAULT.EXE:SMARTSCREEN` — ADS (Alternate Data Stream)
- `C:\Windows\Update\WERFAULT.EXE:ZONE.IDENTIFIER` — маркер загрузки из интернета

**Вывод:** CMD использовался для выполнения системных команд разведки и запуска инструментов из нестандартной папки `C:\Windows\Update\`

---

### Вопрос 8. Файл в неожиданном месте

**Ответ: `C:\Windows\Update\WERFAULT.EXE`**

Настоящий `WerFault.exe` (Windows Error Reporting) должен находиться в `C:\Windows\System32\`. Наличие файла с таким же именем в `C:\Windows\Update\` является явной попыткой маскировки вредоносного файла под легитимный системный процесс.

Дополнительно обнаружены ADS (Alternate Data Streams):
- `WERFAULT.EXE:SMARTSCREEN` — проверка SmartScreen
- `WERFAULT.EXE:ZONE.IDENTIFIER` — файл был загружен из интернета (Zone 3)

---

### Вопрос 9. Все файлы в необычной папке C:\Windows\Update\

Анализ prefetch timeline выявил следующие файлы в `C:\Windows\Update\`:

| Файл | Обнаружен в prefetch |
|------|---------------------|
| `EdgeUpdater.exe` | EDGEUPDATER.EXE.pf |
| `EdgeUpdater.cfg` | EDGEUPDATER.EXE.pf |
| `WerFault.exe` | CMD.EXE.pf |
| `DATA.BAT` | NOTEPAD.EXE.pf |
| `DC01.SHIELDBASE.COM.TXT` | NOTEPAD.EXE.pf, POWERSHELL.EXE.pf |
| `DEV01.SHIELDBASE.COM.TXT` | NOTEPAD.EXE.pf |
| `RD09-HISTORY.CSV` | EDGEUPDATER.EXE.pf |
| `RD03-HISTORY.CSV` | EDGEUPDATER.EXE.pf |
| `RD02-HISTORY.CSV` | EDGEUPDATER.EXE.pf |
| `RD04-HISTORY.CSV` | EDGEUPDATER.EXE.pf |
| `RD04_HISTORY.CSV` | (удалён, найден в Recycle Bin) |

---

### Вопрос 10. Количество записей в AppCompatCache (ShimCache)

**Ответ: 1024 записи**

Команда: `AppCompatCacheParser.exe -f D:\C\Windows\system32\config\SYSTEM --csv ...`  
ControlSet001, Windows10C_11

---

### Вопрос 11. Дополнительные файлы в необычной папке (ShimCache)

Анализ `appcompatcache.csv` с фильтром по `C:\Windows\Update\` выявил:

| Файл | Примечание |
|------|-----------|
| `c:\windows\update\svchost.exe` | **Критически подозрительно!** Настоящий svchost в System32 |
| `c:\windows\update\werfault.exe` | Маскировка под системный процесс |
| `C:\Windows\Update\EdgeUpdater.exe` | Основной инструмент атакующего |
| `C:\Windows\Update\rd01\EdgeUpdater.exe` | Копия в подпапке |

**Вывод:** ShimCache подтвердил наличие ещё одного замаскированного файла — `svchost.exe` в нестандартной папке, который не был виден в prefetch.

---

### Вопрос 12. Доказательства подключений к другим системам

**Ответ:** В prefetch-файлах NOTEPAD.EXE и POWERSHELL.EXE обнаружены файлы:
- `C:\Windows\Update\DC01.SHIELDBASE.COM.TXT` — указывает на хост **DC01** в домене **SHIELDBASE.COM**
- `C:\Windows\Update\DEV01.SHIELDBASE.COM.TXT` — указывает на хост **DEV01** в том же домене

Эти текстовые файлы содержат информацию о других системах в сети и были созданы инструментом BrowsingHistoryView/EdgeUpdater как результат разведки.

Дополнительно: prefetch MSTSC.EXE подтверждает использование RDP для подключения к другим хостам.

---

### Вопрос 13. Создание CSV файла AmCache

Команда выполнена успешно:
```
AmcacheParser.exe -i -f D:\C\Windows\AppCompat\Programs\Amcache.hve --csv C:\DFIR\assignment1 --csvf amcache.csv
```
Результат: найдено 242 unassociated file entries, 253 program file entries (139 программ), 383 drive binaries.

---

### Вопрос 14. Хэш EdgeUpdater в VirusTotal

| Параметр | Значение |
|---------|---------|
| Файл | `c:\windows\update\edgeupdater.exe` |
| SHA-1 | `324fe86872000b7566a818e5825fd4af77f40cb4` |
| Обнаружений | 1/70 |
| Название | **BrowsingHistoryView.exe** |
| Threat label | `pua.browserhistoryview` |
| Производитель | NirSoft |
| Malwarebytes | RiskWare.BrowserHistoryView |

**Вывод:** `EdgeUpdater.exe` является переименованным инструментом **BrowsingHistoryView** от NirSoft — утилита для просмотра и сбора истории браузеров. Атакующий переименовал её под легитимное название для маскировки своей деятельности по сбору данных.

---

### Вопрос 15. Неподписанные драйверы (AmCache)

В `amcache_DriveBinaries.csv` обнаружены 3 неподписанных драйвера:

| Драйвер | Версия | Тип |
|---------|--------|-----|
| `btha2dp.sys` | 10.0.22000.653 | Bluetooth A2DP |
| `bthhfenum.sys` | 10.0.22000.653 | Bluetooth HFP |
| `bthmodem.sys` | 10.0.22000.1 | Bluetooth Modem |

Все три — Bluetooth драйверы. Отсутствие подписи может указывать на модифицированные или неофициальные версии.

---

## Раздел 2. Timeline анализ (2023-01-01 — 2023-01-27)

MFT Timeline создан командой:
```
MFTECmd.exe -f D:\C\$MFT --body C:\DFIR\assignment1 --bodyf mftecmd.body --blf --bdl C:
```
Обработано: 357 501 FILE записей, размер MFT: 379 MB

---

### T1/Q16. Когда создана директория C:\Windows\Update?

**Ответ: 2023-01-17 14:57:37 UTC**

Источник: MFT запись `282354`, поле Created (born time) = Unix timestamp `1673967457`

---

### T2/Q17. Какой пользователь создал C:\Windows\Update?

**Ответ: wacsvc**

Обоснование:
- Профиль пользователя `wacsvc` создан в `2023-01-17 14:43:03 UTC` (первый логон)
- Папка `C:\Windows\Update` создана в `2023-01-17 14:57:37 UTC` — через **14 минут** после логона wacsvc
- Никакой другой пользователь не был активен в этот временной период
- Все файлы в `C:\Windows\Update\` связаны с активностью wacsvc

---

### T3/Q18. Существует ли prefetch файл для STUN.exe?

**Ответ: Нет, prefetch файл для STUN.exe отсутствует.**

**Причина:** `STUN.exe` был переименован в `EdgeUpdater.exe` **перед** первым запуском. Windows создаёт prefetch файл по имени исполняемого файла в момент запуска. Поскольку файл уже имел имя `EdgeUpdater.exe` при запуске, prefetch был создан как `EDGEUPDATER.EXE-39C2713A.pf`.

Доказательство: `STUN.exe` присутствует в MFT (`C:\Windows\System32\STUN.exe`, создан `2023-01-17 15:44:25 UTC`), но его prefetch отсутствует — значит он никогда не запускался под этим именем.

---

### T4/Q19. Когда EdgeUpdater.exe выполнился впервые?

**Ответ: примерно 2023-01-17 18:20:55 UTC**

Обоснование:
- Prefetch хранит временные метки последних запусков
- `PreviousRun3 = 2023-01-17 18:21:05` — самая ранняя из 5 сохранённых меток (RunCount = 5)
- По правилу **-10 секунд**: prefetch обновляется через ~10 сек после запуска
- Реальный первый запуск: **2023-01-17 18:21:05 − 10 сек ≈ 18:20:55 UTC**

---

### T5/Q20. Удалённый файл рядом с первым запуском EdgeUpdater.exe

**Ответ: `C:\Windows\Update\rd04_history.csv`**

Детали:
- В Recycle Bin найдена запись: `$R2T2A0E.csv` / `$I2T2A0E.csv`
- Время удаления: `2023-01-17 18:22:36 UTC` — через **~1.5 минуты** после первого запуска EdgeUpdater
- Содержимое `$I2T2A0E.csv` (метаданные): оригинальный путь = `C:\Windows\Update\rd04_history.csv`

**Вывод:** BrowsingHistoryView (EdgeUpdater) создал CSV файл с результатами сбора истории браузера, после чего атакующий удалил его для сокрытия следов.

---

### T6/Q21. Какой пользователь запускал EdgeUpdater.exe?

**Ответ: wacsvc**

Доказательства:
- Prefetch EdgeUpdater содержит файлы из `C:\Users\wacsvc\AppData\Local\Temp\` (CHIF3B6.TMP, SQPF434.TMP)
- Все CSV файлы результатов (`RD-HISTORY.CSV`) связаны с сессией wacsvc
- Временной период запусков совпадает с периодом активности wacsvc

---

### T7/Q22. В какой период wacsvc открывал файлы и папки?

**Ответ: с 2023-01-17 16:37:52 до 2023-01-17 18:59:09 UTC**

Метод: анализ LNK файлов в `C:\Users\wacsvc\AppData\Roaming\Microsoft\Windows\Recent\`
- Первый LNK файл создан: `1673973472` = **2023-01-17 16:37:52 UTC**
- Последний LNK файл (Office Recent): `1673981949` = **2023-01-17 18:59:09 UTC**

Среди открытых файлов: `g10`, `G10 (2)`, `2022-zero-dsr-x`, `Five Cases for Quantum Entanglement`, `Iceland`, `Intergalactic_Metal`, `rd03`, `rd09-history.csv` — файлы разведывательного характера.

---

### T8/Q23. Когда wacsvc впервые интерактивно вошёл в систему?

**Ответ: 2023-01-17 14:43:03 UTC**

Обоснование: Интерактивный логон (RDP) создаёт пользовательский профиль. MFT запись папки `C:\Users\wacsvc` имеет born time = `1673966583` = **2023-01-17 14:43:03 UTC**.

---

### T9/Q24. Какой файл вероятно последним открыт через Notepad.exe?

**Ответ: `C:\Windows\Update\DATA.BAT`**

Обоснование:
- Последний запуск Notepad: `2023-01-18 14:52:32 UTC`
- По правилу **-10 секунд**: файл открыт примерно в `14:52:22 UTC`
- Prefetch Notepad содержит файлы из `C:\Windows\Update\`: `DATA.BAT`, `DC01.SHIELDBASE.COM.TXT`, `DEV01.SHIELDBASE.COM.TXT`
- `DATA.BAT` наиболее вероятен как редактируемый файл (batch скрипт)

---

### T10/Q25. Какое интересное приложение запустили после Notepad?

**Ответ: MSTSC.EXE (Remote Desktop Connection), запускался 1 раз**

| Параметр | Значение |
|---------|---------|
| Приложение | MSTSC.EXE |
| Последний запуск | 2023-01-18 14:54:48 UTC |
| Количество запусков | **1** |
| Время после Notepad | ~2 минуты |

**Вывод:** После просмотра/редактирования `DATA.BAT` атакующий запустил RDP клиент для подключения к другому хосту в сети (DC01 или DEV01.SHIELDBASE.COM). Это классический паттерн бокового перемещения (lateral movement).

---

## Раздел 3. Реконструкция атаки (Timeline)

На основе всех собранных артефактов восстанавливается следующая хронология:

| Время (UTC) | Событие |
|------------|---------|
| **2023-01-17 14:43:03** | Первый интерактивный логон пользователя **wacsvc** (вероятно через RDP) |
| **2023-01-17 14:57:37** | Создание папки `C:\Windows\Update\` (staging directory) |
| **2023-01-17 15:44:25** | Появление `STUN.exe` в `C:\Windows\System32\` |
| **2023-01-17 16:37:52** | wacsvc начинает открывать файлы (LNK артефакты) |
| **2023-01-17 17:59:00** | `EdgeUpdater.exe` скопирован в `C:\Windows\Update\` |
| **2023-01-17 18:20:55** | **Первый запуск EdgeUpdater.exe** (BrowsingHistoryView) |
| **2023-01-17 18:21:05–18:58:55** | EdgeUpdater запускается ещё 4 раза — сбор истории браузеров |
| **2023-01-17 18:22:36** | Удаление `rd04_history.csv` из `C:\Windows\Update\` |
| **2023-01-17 18:59:09** | Последняя активность wacsvc (LNK файлы) |
| **2023-01-18 14:52:32** | Запуск **Notepad.exe** — открытие `DATA.BAT` |
| **2023-01-18 14:54:48** | Запуск **MSTSC.exe** — RDP подключение к другому хосту |
| **2023-01-23 18:16:17** | Первый из сохранённых запусков CMD.exe |
| **2023-01-25 14:57:21** | Последний запуск PowerShell |
| **2023-01-25 15:07:50** | Последний запуск CMD.exe |

---

## Раздел 4. Выводы

### Индикаторы компрометации (IOC)

| Тип | Значение |
|-----|---------|
| Файл | `C:\Windows\Update\EdgeUpdater.exe` |
| Файл | `C:\Windows\Update\svchost.exe` |
| Файл | `C:\Windows\Update\WerFault.exe` |
| Файл | `C:\Windows\Update\DATA.BAT` |
| SHA-1 | `324fe86872000b7566a818e5825fd4af77f40cb4` (BrowsingHistoryView) |
| Аккаунт | `wacsvc` (скомпрометированный/созданный атакующим) |
| Домен | `SHIELDBASE.COM` |
| Хосты | `DC01.SHIELDBASE.COM`, `DEV01.SHIELDBASE.COM` |

### Тактики ATT&CK

| Тактика | Техника | Описание |
|---------|---------|---------|
| Initial Access | T1078 — Valid Accounts | Использование аккаунта wacsvc |
| Execution | T1059.001 — PowerShell | Запуск PowerShell скриптов |
| Execution | T1059.003 — CMD | Выполнение команд через CMD |
| Defense Evasion | T1036.005 — Masquerading | EdgeUpdater.exe, svchost.exe, WerFault.exe |
| Collection | T1217 — Browser History | BrowsingHistoryView для сбора истории |
| Lateral Movement | T1021.001 — RDP | MSTSC.exe для перемещения |
| Discovery | T1083 — File Discovery | WHERE.exe, разведка файловой системы |

### Заключение

Расследование выявило целенаправленную атаку на систему RD01 в домене SHIELDBASE.COM. Атакующий получил доступ через аккаунт **wacsvc** (возможно, созданный или скомпрометированный), создал скрытую staging-директорию `C:\Windows\Update\`, разместил там инструменты под именами легитимных системных файлов, собрал историю браузеров с помощью переименованного **BrowsingHistoryView**, и использовал **RDP** для бокового перемещения на другие хосты сети.
