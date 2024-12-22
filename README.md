# ValtDB

ValtDB - это современная, безопасная и высокопроизводительная база данных, написанная на Python. Она предоставляет интуитивно понятный API для работы с данными, поддерживает шифрование и предлагает широкие возможности для запросов.

## Особенности

- 🚀 Высокая производительность и оптимизация
- 🔒 Встроенное шифрование данных
- 🎯 Интуитивный и удобный API
- 📊 Продвинутый построитель запросов
- 🔄 Поддержка транзакций
- 📦 Простая установка и использование
- 🛡️ Безопасность и контроль доступа
- 🔍 Гибкие возможности поиска и фильтрации

## Установка

```bash
pip install valtdb
```

## Быстрый старт

### Инициализация и создание базы данных

```python
from valtdb.api import ValtDB

# Создание экземпляра ValtDB
db = ValtDB("./data")

# Создание базы данных
db.db("myapp")

# Создание зашифрованной базы данных
secure_db = db.db("secure_app", {
    "algorithm": "AES",
    "hash_algorithm": "SHA256"
})
```

### Создание и определение таблиц

```python
# Простая таблица
users = db.table("users", {
    "id": "int",
    "name": "str",
    "email": "str"
})

# Расширенное определение схемы
posts = db.table("posts", {
    "id": {"type": "int", "required": True, "unique": True},
    "title": {"type": "str", "required": True},
    "content": {"type": "str", "encrypted": True},
    "status": {"type": "str", "choices": ["draft", "published", "archived"]},
    "views": {"type": "int", "default": 0},
    "created_at": {"type": "datetime", "auto_now": True},
    "tags": {"type": "list", "item_type": "str"}
})
```

### Базовые операции с данными

```python
# Вставка одной записи
users.insert({
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com"
})

# Массовая вставка
users.bulk_insert([
    {"id": 2, "name": "Jane Doe", "email": "jane@example.com"},
    {"id": 3, "name": "Bob Smith", "email": "bob@example.com"}
])

# Обновление
users.query().where(id=1).update({"name": "John Smith"})

# Удаление
users.query().where(email="john@example.com").delete()
```

## Продвинутые возможности

### Построитель запросов

#### Базовые запросы

```python
# Простой поиск
active_users = users.query()\
    .where(status="active")\
    .get()

# Выбор полей
names = users.query()\
    .select("name", "email")\
    .where(status="active")\
    .get()

# Сортировка
sorted_users = users.query()\
    .order_by("name", SortOrder.ASC)\
    .get()
```

#### Сложные условия

```python
# Множественные условия
results = users.query()\
    .where(status="active")\
    .where_between("age", 18, 65)\
    .where_not_null("email")\
    .where_like("name", "%John%")\
    .get()

# OR условия
results = users.query()\
    .where(role="admin")\
    .or_where(status="premium")\
    .get()

# IN условия
results = users.query()\
    .where_in("status", ["active", "pending"])\
    .get()

# Сложные фильтры
premium_active_users = users.query()\
    .where(status="active")\
    .where(subscription="premium")\
    .where_greater("last_login", "2024-01-01")\
    .where_not_in("role", ["banned", "suspended"])\
    .get()
```

#### Агрегация и группировка

```python
# Подсчет
total = users.query().count()

# Среднее значение
avg_age = users.query()\
    .where(status="active")\
    .avg("age")

# Группировка
stats = users.query()\
    .select("country", db.raw("COUNT(*) as user_count"))\
    .group_by("country")\
    .having("user_count", ("GT", 100))\
    .get()

# Сложная агрегация
user_stats = users.query()\
    .select(
        "department",
        db.raw("AVG(salary) as avg_salary"),
        db.raw("COUNT(*) as employee_count")
    )\
    .group_by("department")\
    .having("employee_count", ("GT", 5))\
    .order_by("avg_salary", SortOrder.DESC)\
    .get()
```

#### Соединения таблиц

```python
# INNER JOIN
user_posts = users.query()\
    .select("users.name", "posts.title")\
    .join("posts", {"users.id": "posts.user_id"})\
    .where("posts.status", "published")\
    .get()

# LEFT JOIN с условиями
results = users.query()\
    .select("users.*", "orders.total")\
    .left_join("orders", {"users.id": "orders.user_id"})\
    .where("users.status", "active")\
    .where_greater("orders.total", 1000)\
    .get()
```

### Транзакции

```python
# Простая транзакция
with db.transaction():
    user_id = users.insert_get_id({
        "name": "New User",
        "email": "new@example.com"
    })
    posts.insert({
        "user_id": user_id,
        "title": "First Post"
    })

# Обработка ошибок в транзакции
try:
    with db.transaction():
        users.insert({"id": 1, "name": "Test"})
        posts.insert({"id": 1, "invalid": "data"})
except Exception:
    print("Транзакция отменена")
```

### Пагинация и чанки

```python
# Простая пагинация
posts, meta = posts.query()\
    .where(status="published")\
    .order_by("created_at", SortOrder.DESC)\
    .paginate(page=2, per_page=20)

print(f"Showing {meta['from']} to {meta['to']} of {meta['total']} entries")

# Обработка больших наборов данных
users.query()\
    .where(status="active")\
    .chunk(100, lambda batch: process_users(batch))
```

### Шифрование данных

```python
# Создание таблицы с шифрованием
secure_users = db.table("secure_users", {
    "id": "int",
    "name": "str",
    "email": {"type": "str", "encrypted": True},
    "ssn": {"type": "str", "encrypted": True},
    "notes": {"type": "str", "encrypted": True}
})

# Работа с зашифрованными данными
secure_users.insert({
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "ssn": "123-45-6789",
    "notes": "Конфиденциальная информация"
})
```

### Бэкапы и восстановление

```python
# Создание бэкапа
backup_file = db.backup("./backups")

# Восстановление из бэкапа
db.restore(backup_file)
```

### Сырые запросы

```python
# Выполнение сырого SQL
results = db.execute(
    "SELECT users.*, COUNT(orders.id) as order_count " +
    "FROM users " +
    "LEFT JOIN orders ON users.id = orders.user_id " +
    "GROUP BY users.id " +
    "HAVING order_count > :min_orders",
    {"min_orders": 5}
)
```

## Вклад в проект

Мы приветствуем вклад в развитие ValtDB! Пожалуйста, ознакомьтесь с [руководством по внесению изменений](CONTRIBUTING.md).

## Лицензия

ValtDB распространяется под лицензией MIT. Подробности в файле [LICENSE](LICENSE).

## Поддержка

- 💬 [Telegram](https://t.me/DevBenji)

## Авторы

ValtDB разрабатывается и поддерживается [командой разработчиков](https://github.com/valtdb/valtdb/graphs/contributors).
