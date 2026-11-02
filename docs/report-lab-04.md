# Звіт ЛР04. Авторизація, ролі, володіння ресурсом та IDOR/BOLA

**Виконав:** Воропаєв Артем Максимович, КБ-41.  
**Рівень:** Добре (із вимогами достатнього рівня).  
**Дата перевірки:** 02.11.2026.  
**Проєкт:** SecureLab, baseline 2-A; гілка lab/4-authorization.  
**Початковий тег:** v0.3.0, commit ef4a4646bcfa34bdd3b4a14811e808dd2cfacd4c.

## Мета та межі

Мета — перевірити, що автентифікований користувач може виконувати лише дозволені дії над конкретним ресурсом. Головна action — читання деталей Incident. Для рівня «Добре» додано централізовані правила списку, details, update, delete, triage та IncidentComment; перевірено горизонтальне й вертикальне підвищення привілеїв, підміну серверних полів і безпечний аудит.

Робота виконувалася на localhost зі штучними Alice/Bob/Morgan/Admin. Використано окрему базу securelab_lr04 в локальному PostgreSQL-контейнері; базу securelab попередніх робіт не очищали. Стан ЛР3 перед початком мав 68 успішних тестів.

## Матриця і серверне рішення

Повна матриця: [access-matrix.md](access-matrix.md). Чужий та неіснуючий ресурс повертають однаковий 404, а видимий ресурс із забороненою дією — 403. Анонім — 401 без HTML redirect.

- IncidentAccess отримує subject і ролі з verified HttpContext.User. Visible обмежує IQueryable до ToListAsync/SingleOrDefaultAsync.
- Reporter читає й редагує власні інциденти; видаляє лише власний New.
- Analyst читає інциденти для аналізу та виконує тільки New → Triaged. Це не право content update/delete.
- Administrator не отримує універсального доступу. Create з owner із principal збережено як успадкований контракт ЛР3 для автентифікованих користувачів.
- UpdateIncidentRequest містить тільки Title і Description. Вибрано A-08a: зайві поля ігноруються, успішний update повертає 204.
- Внутрішній коментар seed comment-3 належить інциденту Alice, автор Morgan. Reporter не бачить його ні в details, ні через прямий child id.

Місця реалізації: src/SecureLab.Api/Application/Incidents/IncidentAccess.cs; IncidentQueries.cs; Presentation/Endpoints/IncidentMutationEndpoints.cs; Presentation/Contracts/UpdateIncidentRequest.cs; Data/DbSeeder.cs.

## Вразливий стан та PoC

Контрольована копія початкового стану ізольована в C:/dev/lr04-local/vulnerable і запускалася лише на 127.0.0.1:5084. Початкова details-реалізація ЛР3 шукала за id без ownership. Для навчального PoC у цій копії додано authenticated PUT і triage без ресурсного/рольового рішення. Ці навмисно вразливі маршрути не входять у поточний fixed проєкт.

Фактично спостережено:

1. Alice → власні details: 200.
2. Alice → Bob details: 200, повернуто дані Bob замість очікуваного deny.
3. Alice → Bob update: 204; повторний read Bob підтвердив зміну Description.
4. Alice/Reporter → triage: 204; New змінився на Triaged без належної ролі.

Доказ: [vulnerable-evidence.json](evidence/lr04/vulnerable-evidence.json). Значень пароля, Cookie чи Set-Cookie немає. Першопричина — пошук ресурсу за id без перевірки права до повернення/збереження. Сам identifier у URL не є дефектом: дефектом є відсутність серверного рішення.

Вразливий стан збережено окремим commit `eec12cb0db64276a66615a622fcd50b9eadf75d6` — `lab4: record local authorization PoC`. Commit створено студентом власноруч. Виправлений стан збережено наступним commit `8daa3ca2da6061aac67a3ed5e97886c56d4df716` — `lab4: enforce incident authorization and regression tests`.

## Виправлення та retest

В основному проєкті list/details використовують Visible. Update/delete завантажують tracked entity, перевіряють доступ, потім змінюють/видаляють. Triage перевіряє Analyst і New та сам задає Triaged; історія записує verified Morgan як автора. Direct comment перевіряє parent і internal-visibility. Неіснуючі та невидимі ресурси використовують спільний NotFound helper.

Повторний HTTP-сценарій підтвердив: Alice → Bob details/update/delete — 404; Bob state не змінився; власний read — 200; власний update — 204; Reporter triage — 403 без зміни стану; Analyst triage — 204, повторна спроба — 403. DTO із forged owner/role/status/severity не змінює серверні поля.

## Доказова таблиця

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | Добре | Анонім | окремий client без cookie | protected GET/PUT/DELETE/triage/child | 401, без redirect | 401 | AuthorizationTests.A01; A01-anonymous.json |
| A-02 | Достатній | Owner read | Alice login | власні details | 200, правильний DTO | 200 | A02_A03_A03R test; A02-owner.json |
| A-03 | Достатній | Non-owner read | Alice login, Bob id | чужі details | 404, без даних Bob | 404 | A02_A03_A03R; A03-A10-foreign-unknown.json |
| A-03R | Достатній | Analyst read | Morgan login | details Alice | 200 для аналізу | 200 | A02_A03_A03R; A12-comments.json |
| A-04 | Добре | Non-owner mutation | окремий ресурс Bob | Alice PUT/DELETE | 404, state незмінний | 404, порівняння пройшло | A04 test; A04-update-delete.json |
| A-05 | Добре | List | Alice, seed | GET list | тільки її три seed записи | 200, тільки Alice | A05 test; A05-list.json |
| A-06 | Добре | Reporter transition | власний новий ресурс | forged role/status + triage | 403, state незмінний | 403 | A06 test; A06-A09-denied-triage.json |
| A-07 | Добре | Analyst transition | Morgan, новий ресурс | triage та повтор | 204, потім 403 | Triaged, серверна history | A07 test; A07-analyst-triage.json |
| A-08a | Добре | Overposting | Reporter-власник | PUT content + owner/role/status/severity | 204; тільки content/час змінені | підтверджено | A08a test; A08a-overposting.json |
| A-08b | Альтернатива | Не застосовується | обрано ignore-unknown A-08a | — | — | — | UpdateIncidentRequest |
| A-09 | Добре | Audit deny | authenticated Reporter | triage | без секретів, той самий trace | підтверджено | AuthorizationAuditTests; A09-audit.txt |
| A-10 | Добре | Foreign/unknown | той самий client | однакові GET/PUT/DELETE/triage з різними id | status/media/body однакові без traceId | підтверджено | A10 theory; A03-A10-foreign-unknown.json |
| A-11 | Відмінно | Search/summary scoping | поза обраним рівнем | не виконувалося | — | не заявляється | межі в access-matrix.md |
| A-12 | Добре | Child/internal | Alice і Morgan | прямий child id та details | Reporter deny internal/чужий; Analyst allow | 404 / 200 | A12 test; A12-comments.json |

Усі згадані JSON/TXT — у docs/evidence/lr04. Негативні mutation-тести читають стан до/після, включно з owner/status/severity/UpdatedAtUtc та кількістю history/comments. Позитивні mutation-тести створюють власний ресурс і очищають його в finally/DisposeAsync. Паралельність suite вимкнено через спільну навчальну БД.

## Browser flow

Перевірено в браузері: login Alice на auth-lab.html — 204, profile — 200/Reporter; головна сторінка показує три власні записи. Власні details містять public comment, але не internal comment. Введення identifier Bob у поле деталей показує «HTTP 404: Інцидент не знайдено».

Докази: [власні details](evidence/lr04/browser-own.png), [відмова](evidence/lr04/browser-denied.png). Поле identifier лише надсилає запит; дозволи перевіряє сервер. app.js використовує textContent/createTextElement/createTextNode, не виконує HTML із даних.

## Привілейована дія й аудит

POST /api/incidents/{id}/triage не приймає роль чи next status як дозвіл. CanTriage оцінює роль із principal і поточний стан із БД. На deny перед SaveChangesAsync формується authorization.denied з subject/action/resource/result/UTC/trace. Тест перевіряє точний дозволений набір структурованих полів та збіг traceId з Problem Details. Доказ A09-audit.txt містить один рядок саме відповідного запиту.

## Перевірки й відтворення

Windows, .NET SDK 10.0.402, target net10.0, PostgreSQL у secure-lab-postgres-1; локальний порт 55432; окрема securelab_lr04. Пароль seed читається з локального захищеного файла поза Git. API: http://localhost:5080.

02.11.2026 через Windows PowerShell виконано Test-Lab04.ps1: reset лише securelab_lr04 → build → повний dotnet test -c Release --no-restore. Результат: **82 passed, 0 failed, 0 skipped**. Попередня перевірка авторизації: 14 passed. Повторювані HTTP-докази: tests/http/lab-04-checks.py; запуск зовнішнім Check-Lab04.ps1 після Start-Lab04.ps1. Скрипт тримає cookie у пам’яті, виводить лише безпечні результати й очищає тільки створені ним fixtures.

Повторити: відкрити Docker Desktop; у PowerShell дозволити локальні сценарії лише для цього процесу; виконати C:/dev/lr04-local/Test-Lab04.ps1, потім Start-Lab04.ps1. В іншому вікні — Check-Lab04.ps1. Точні покрокові команди й скриншоти винесено до особистого screenshot-guide-lr04.md поза Git.

## Залишкові ризики

Це реалізація рівня «Добре», а не заява про production-ready захист усіх маршрутів. A-11 не виконано: search зберігає попередню видимість, summary не має owner scoping. CSRF для cookie mutation лишається навчальним боргом до ЛР6. Перехід не захищений optimistic concurrency; такого додаткового сценарію викладач не надав. Глобальна перевірка title перед записом не гарантує унікальність при concurrency. Сторонні системи не перевірялися.

## Git і подання

Репозиторій для подання: [artem77voropa-sudo/lr4](https://github.com/artem77voropa-sudo/lr4). Гілка: `lab/4-authorization`.

| Стан | Commit |
|---|---|
| Початкова ЛР3, v0.3.0 | `ef4a4646bcfa34bdd3b4a14811e808dd2cfacd4c` |
| Vulnerable: локальний PoC | `eec12cb0db64276a66615a622fcd50b9eadf75d6` |
| Fixed: авторизація та regression tests | `8daa3ca2da6061aac67a3ed5e97886c56d4df716` |

Обидва commits ЛР4 студент створив самостійно. Після fixed commit студент повторно запустив `Test-Lab04.ps1`. Збережений результат автоматизованої перевірки від 02.11.2026 — 82 passed, 0 failed, 0 skipped; він наведений у доказах. Окремий результат повторного ручного запуску потрібно звірити з підсумком у PowerShell.

Виправлений стан ЛР4 збережено в commit `8daa3ca2da6061aac67a3ed5e97886c56d4df716`. Реалізацію перевірено інтеграційними тестами та HTTP-сценаріями; результати наведено в доказовій таблиці. Окремий документаційний commit фіксує посилання на вразливий і виправлений стани.

Історія містить навмисно вразливий навчальний стан, тому подання здійснюється через приватний погоджений flow. Word-звіт, локальні helpers, пароль та особистий screenshot guide у Git не додаються.

## Використання ШІ

Для підготовки використано ChatGPT/Codex: пояснення вимог методички, розроблення коду й тестів відповідно до погодженої матриці, автоматизовані перевірки, підготовка звіту та покрокової інструкції. Згенеровані рішення адаптовано до власного кумулятивного проєкту SecureLab і baseline 2-A; результати перевірено тестами та HTTP-сценаріями.

Мій внесок: погодження правил доступу й рівня виконання, робота з проєктом за інструкцією, самостійне створення vulnerable та fixed commits, повторний запуск Test-Lab04.ps1 після збереження fixed стану. Матеріали для скриншотів і пояснення перевірок підготовлено окремо. Автоматизовану перевірку не видаю за власноручне написання всього коду; результат особистого запуску звіряю з фактичним виводом PowerShell. Паролі та cookie не включено до звіту чи Git.
