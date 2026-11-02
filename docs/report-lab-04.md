# ЛР4: локальний стан до виправлення
Воропаєв Артем Максимович, КБ-41. Рівень Добре.
Baseline v0.3.0: ef4a4646bcfa34bdd3b4a14811e808dd2cfacd4c.
Лише штучні дані, локальний 127.0.0.1:5084, окрема securelab_lr04.
Фактично: Alice читає Bob (200), змінює його Description (204), Reporter виконує triage (204).
Доказ: docs/evidence/lr04/vulnerable-evidence.json. Першопричина: немає ownership/role decision до response/Save.
У цьому стані авторизацію ще НЕ виправлено. Цільова матриця — docs/access-matrix.md.
Commit створює студент самостійно. Цей стан не призначено для deployment чи публічного remote.
