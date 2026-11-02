# Матриця доступу ЛР4 — baseline 2-A

Рівень: **Добре**. Головна action: GET /api/incidents/{id}; додатково перевірено update/delete/triage/child. Правила погоджено перед реалізацією.

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Значення owner/context | Реалізація й доказ |
|---|---|---|---|---|---|---|---|
| GET list | Добре | 401 | 200, тільки власні | 200, усі для аналізу | 200, порожній список | Reporter: OwnerUserId = verified subject | IncidentAccess.Visible; A-05 |
| GET details | Достатній | 401 | власні 200; чужі 404 | 200 для аналізу | 404, додаткового права немає | власник або Analyst; невідомий id 404 | Visible; A-02/A-03/A-03R |
| POST create | Успадкований ЛР3 | 401 | 201 для себе | 201 для себе | 201 для себе, лише успадкований create | id/owner/status/час серверні; чотири клієнтські поля ЛР2 | Lab02Endpoints; CreateIncidentTests |
| PUT content | Добре | 401 | власні 204; чужі 404 | 403 для видимого ресурсу | 404 | тільки Reporter-власник; лише Title/Description | CanUpdate; A-04/A-08a |
| DELETE | Добре | 401 | власний New — 204; власний інший стан — 403; чужий — 404 | 403 для видимого ресурсу | 404 | Reporter-власник і New | CanDelete; A-04, OwnerCannotDeleteNonNew |
| POST triage | Добре | 401 | власний — 403; чужий — 404 | New → Triaged: 204; інший стан: 403 | 404 | лише Analyst і поточний New; наступний стан серверний | CanTriage; A-06/A-07/A-09 |
| Зміна severity через PUT | Добре | 401 | не виконується, зайве поле ігнорується | content update заборонено | content update заборонено | окремої дії зміни severity немає | UpdateIncidentRequest; A-08a |
| GET public comment | Добре | 401 | власний parent — 200; чужий — 404 | 200 після перевірки parent | 404 | доступ через parent incident, не автора коментаря | CanReadComment; A-12 |
| GET internal comment | Добре | 401 | 404, навіть власник parent | 200 після перевірки parent | 404 | internal доступний тільки Analyst | CanReadComment; A-12 |
| Internal у details | Добре | 401 | виключений із comments | включений для аналізу | details 404 | видимість із verified principal | IncidentQueries; A-12 |

## Узгоджена політика відмов

- Анонім: 401 без переходу на HTML-сторінку.
- Чужий/невидимий і неіснуючий ресурс: однаковий 404 Problem Details «Інцидент не знайдено». Порівнюються status, media type і повне тіло, крім traceId; правило діє для details/update/delete/triage/child.
- Видимий ресурс, але заборонена дія або стан: 403 Problem Details «Дію не дозволено».
- Відмова передує змінам entity і SaveChangesAsync. Негативні тести перевіряють незмінність збереженого стану.
- Administrator не є універсальним обходом перевірок. Успадковане створення для себе не надає додаткових прав читання/оновлення/класифікації.

## Контракт update: A-08a

PUT приймає тільки UpdateIncidentRequest(Title, Description). Обидва поля потрібні: Trim, межі 160/4000, мінімум 40 символів опису для наявного High/Critical. Зайві ownerUserId/role/status/severity/updatedAtUtc ігноруються. Успіх — 204; змінюються Title, Description та серверний UpdatedAtUtc. Owner, role, severity, status не змінюються. Конфлікт незакритого title — 409. A-08b не застосовується.

## Централізація та аудит

IncidentAccess отримує subject і ролі лише з HttpContext.User. Visible додає умову до IQueryable перед матеріалізацією списку/деталей. CanUpdate/CanDelete/CanTriage/CanReadComment застосовуються до ресурсів до мутацій. Child не обходить parent-перевірку. Read DTO не серіалізує entity.

Відмова triage записує authorization.denied: SubjectId, Action, ResourceId, Result, UtcTime, TraceId. Trace = Activity.Current?.Id ?? context.TraceIdentifier, той самий, що у відповіді. Паролі, cookie, token, body і текст інциденту не входять у подію. A-09 перевіряє authenticated Reporter; анонім відхиляється middleware.

## Межа рівня та залишкові ризики

Search і scoping severity-summary належать до A-11 рівня «Відмінно» й не заявлені як виконані. Search з ЛР2 зберігає попередній контракт; summary в захищеній групі вимагає login, але рахує всі інциденти. Загальний захист усіх шляхів читання не заявляється. Перед production потрібно закрити й ці шляхи. Batch/export/audit API не створювалися.

CSRF для cookie mutation — навчальний борг до ЛР6. Concurrency-захист переходів не реалізований: для обраного рівня сценарію не надано. Перевірка title перед збереженням не є конкурентним UNIQUE constraint.
