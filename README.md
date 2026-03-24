# html-inject-scan

Автоматизированный сканер отражённых HTML-инъекций и XSS. Обнаруживает параметры из нескольких источников, подставляет payload и проверяет, отражается ли маркер в ответе сервера.

<img width="1330" height="738" alt="image" src="https://github.com/user-attachments/assets/eb42c41f-b1bd-48e3-937e-b7b8288356af" />

## Установка

```bash
pip install requests
```

## Источники параметров

| Источник | Описание |
|----------|----------|
| **URL query** | Параметры из query string самого URL (`?id=1&type=osago` → `id`, `type`) |
| **HTML page** | Атрибуты `name=` из HTML-страницы (только `<input>` или все теги) |
| **Wordlist** | Пользовательский файл со списком параметров (`-w params.txt`) |
| **Extra/builtin** | Встроенный набор + пользовательские через `--extra` |

## Использование

### Базовый запуск

```bash
# Один URL — интерактивный выбор параметров
python3 html-inject-scan.py -u "https://target.com/page?id=1"

# Список URL-ов из файла
python3 html-inject-scan.py -l urls.txt
```

### Автоматический режим

```bash
# Автовыбор всех параметров, результаты в файл
python3 html-inject-scan.py -l urls.txt --auto -o reflected.txt
```

### Кастомный payload и маркер

```bash
python3 html-inject-scan.py -l urls.txt \
  -p '"><img src=x onerror=alert(1)>' \
  -m 'onerror=alert(1)'
```

Payload — строка, которая подставляется в параметр. Marker — подстрока, которую ищем в ответе сервера. Если marker найден в теле ответа, параметр помечается как `[REFLECTED]`.

### Авторизованная сессия

```bash
python3 html-inject-scan.py -l urls.txt \
  --cookie "PHPSESSID=abc123; BX_USER_ID=xyz" \
  --header "Authorization: Bearer eyJhbG..." \
  --auto
```

### Проксирование через Burp

```bash
python3 html-inject-scan.py -l urls.txt \
  --proxy http://127.0.0.1:8080 \
  --auto
```

### HTML-сканирование

```bash
# Только <input name=...> (по умолчанию)
python3 html-inject-scan.py -u https://target.com/form

# Все теги с name= (meta, select, textarea, etc.)
python3 html-inject-scan.py -u https://target.com/form --mode all

# Без HTML-сканирования (только URL query + wordlist + extra)
python3 html-inject-scan.py -l urls.txt --no-html-scan --auto
```

### POST-запросы

```bash
python3 html-inject-scan.py -u https://target.com/api --method POST --auto
```

## Все флаги

```
-u, --url           Один целевой URL
-l, --list          Файл со списком URL-ов (один на строку)
-p, --payload       Payload для инъекции (по умолчанию: '"><zxcasd>)
-m, --marker        Подстрока для поиска в ответе (по умолчанию: <zxcasd>)
-w, --wordlist      Файл с параметрами (один на строку)
--extra             Доп. параметры через запятую
--header            HTTP-заголовок (можно несколько раз): "Name: value"
--cookie            Cookie-строка: "name=val; name2=val2"
--proxy             HTTP-прокси: http://127.0.0.1:8080
--method            HTTP-метод: GET (по умолчанию) или POST
--threads           Потоков на URL (по умолчанию: 5)
--delay             Задержка между запросами в секундах
--mode              input (по умолчанию) — только <input>, all — все теги с name=
--auto              Без интерактивного выбора — берёт все параметры
--no-html-scan      Не загружать страницу для парсинга name= атрибутов
-o, --output        Сохранить результаты в файл
```

## Интерактивный выбор

Без `--auto` для каждого источника параметров выводится пронумерованный список:

```
[URL query] Found 3 params:
    0 id
    1 type
    2 region

  a = select all, n = select none, 0,1,5-10 = pick by index
  >
```

- `a` или Enter — выбрать все
- `n` — пропустить
- `0,2` — выбрать по индексу
- `3-7` — диапазон

## Вывод

```
[REFLECTED] coupon — 200 (45231 bytes)    ← payload отразился в ответе
[ ] utm_source — 200 (45102 bytes)        ← не отразился
```

Итоговая сводка:

```
============================================================
  REFLECTED: 2 hit(s)

  [+] coupon -> https://target.com/page?coupon=%27%22%3E%3Czxcasd%3E
  [+] redirect -> https://target.com/page?redirect=%27%22%3E%3Czxcasd%3E
```

При `-o reflected.txt` результаты сохраняются в формате TSV: `param \t status \t url`.
