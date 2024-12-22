# Contributing to ValtDB

Мы рады, что вы заинтересованы в улучшении ValtDB! Этот документ поможет вам начать работу.

## Содержание

- [Кодекс поведения](#кодекс-поведения)
- [Начало работы](#начало-работы)
- [Процесс разработки](#процесс-разработки)
- [Стиль кода](#стиль-кода)
- [Тестирование](#тестирование)
- [Документация](#документация)
- [Pull Requests](#pull-requests)
- [Сообщения о проблемах](#сообщения-о-проблемах)

## Кодекс поведения

Этот проект придерживается [Кодекса поведения контрибьюторов](CODE_OF_CONDUCT.md). Участвуя в проекте, вы соглашаетесь соблюдать его условия.

## Начало работы

1. Форкните репозиторий
2. Клонируйте свой форк:
   ```bash
   git clone https://github.com/DevsBenji/valtdb.git
   cd valtdb
   ```
3. Создайте виртуальное окружение:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```
4. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
5. Создайте новую ветку:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Процесс разработки

1. Убедитесь, что ваши изменения соответствуют целям проекта
2. Напишите тесты для новой функциональности
3. Убедитесь, что все тесты проходят
4. Обновите документацию
5. Создайте pull request

## Стиль кода

- Следуйте [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Используйте типизацию (type hints)
- Максимальная длина строки: 100 символов
- Документируйте все публичные методы и классы
- Используйте говорящие имена переменных и функций

### Примеры стиля кода

#### Базовый класс

```python
from typing import List, Optional, Dict, Any, Union, Tuple
from datetime import datetime

class QueryBuilder:
    """
    Построитель запросов с поддержкой цепочек методов.
    
    Attributes:
        table: Таблица для запросов
        query: Текущий объект запроса
    """
    
    def __init__(self, table: "Table") -> None:
        self._table = table
        self._query = Query()
        self._selected_fields: Set[str] = set()
        self._group_by: List[str] = []
        self._order_by: List[Tuple[str, str]] = []
        
    def select(self, *fields: str) -> "QueryBuilder":
        """
        Выбор полей для запроса.
        
        Args:
            *fields: Имена полей для выбора
            
        Returns:
            Self для цепочки методов
            
        Example:
            >>> query.select("name", "email").where(active=True)
        """
        self._selected_fields.update(fields)
        return self
```

#### Обработка условий

```python
def where(self, **conditions: Any) -> "QueryBuilder":
    """
    Добавляет условия WHERE к запросу.
    
    Args:
        **conditions: Условия в формате поле=значение или поле=(оператор, значение)
        
    Returns:
        Self для цепочки методов
        
    Examples:
        >>> query.where(status="active")
        >>> query.where(age=("GT", 18))
        >>> query.where(role="admin", active=True)
    """
    for field, value in conditions.items():
        if isinstance(value, tuple):
            operator, val = value
            self._query.filter(field, Operator[operator], val)
        else:
            self._query.filter(field, Operator.EQ, value)
    return self

def where_in(self, field: str, values: List[Any]) -> "QueryBuilder":
    """
    Добавляет условие WHERE IN.
    
    Args:
        field: Имя поля
        values: Список значений
        
    Returns:
        Self для цепочки методов
        
    Example:
        >>> query.where_in("status", ["active", "pending"])
    """
    self._query.filter(field, Operator.IN, values)
    return self
```

#### Агрегация и группировка

```python
def group_by(self, *fields: str) -> "QueryBuilder":
    """
    Добавляет GROUP BY к запросу.
    
    Args:
        *fields: Поля для группировки
        
    Returns:
        Self для цепочки методов
        
    Example:
        >>> query.group_by("department").select(
        ...     "department",
        ...     db.raw("COUNT(*) as employee_count")
        ... )
    """
    self._group_by.extend(fields)
    return self

def having(self, field: str, condition: Tuple[str, Any]) -> "QueryBuilder":
    """
    Добавляет условие HAVING.
    
    Args:
        field: Имя поля
        condition: Кортеж (оператор, значение)
        
    Returns:
        Self для цепочки методов
        
    Example:
        >>> query.group_by("department")\\
        ...     .having("employee_count", ("GT", 5))
    """
    operator, value = condition
    self._query.having(field, Operator[operator], value)
    return self
```

## Тестирование

### Структура тестов

```python
import pytest
from valtdb.api import ValtDB
from valtdb.exceptions import ValtDBError

@pytest.fixture
def db():
    """Create test database"""
    db = ValtDB("./test_data")
    yield db
    # Cleanup after tests
    shutil.rmtree("./test_data")

def test_query_builder(db):
    """Test query builder functionality"""
    # Setup
    users = db.db("test").table("users", {
        "id": "int",
        "name": "str",
        "age": "int",
        "status": "str"
    })
    
    # Insert test data
    users.insert([
        {"id": 1, "name": "John", "age": 30, "status": "active"},
        {"id": 2, "name": "Jane", "age": 25, "status": "active"},
        {"id": 3, "name": "Bob", "age": 35, "status": "inactive"}
    ])
    
    # Test basic query
    result = users.query()\
        .where(status="active")\
        .where_greater("age", 20)\
        .order_by("name")\
        .get()
        
    assert len(result) == 2
    assert result[0]["name"] == "Jane"
    
    # Test aggregation
    stats = users.query()\
        .select(
            "status",
            db.raw("COUNT(*) as count"),
            db.raw("AVG(age) as avg_age")
        )\
        .group_by("status")\
        .get()
        
    assert len(stats) == 2
    active_stats = next(s for s in stats if s["status"] == "active")
    assert active_stats["count"] == 2
    assert active_stats["avg_age"] == 27.5
```

### Тестирование ошибок

```python
def test_error_handling(db):
    """Test error handling"""
    users = db.db("test").table("users", {
        "id": {"type": "int", "unique": True},
        "email": {"type": "str", "unique": True}
    })
    
    # Test unique constraint
    users.insert({"id": 1, "email": "test@example.com"})
    
    with pytest.raises(ValtDBError) as exc:
        users.insert({"id": 1, "email": "other@example.com"})
    assert "unique constraint" in str(exc.value)
    
    # Test required fields
    with pytest.raises(ValtDBError) as exc:
        users.insert({"email": "missing.id@example.com"})
    assert "required field" in str(exc.value)
```

## Документация

### Docstring формат

```python
def paginate(
    self,
    page: int = 1,
    per_page: int = 10
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Возвращает страницу результатов с метаданными пагинации.
    
    Args:
        page: Номер страницы (начиная с 1)
        per_page: Количество записей на странице
        
    Returns:
        Tuple[List[Dict], Dict]: Кортеж из:
            - Список записей на текущей странице
            - Метаданные пагинации:
                - total: общее количество записей
                - per_page: записей на странице
                - current_page: текущая страница
                - last_page: последняя страница
                - from: номер первой записи
                - to: номер последней записи
        
    Raises:
        ValtDBError: Если page < 1 или per_page < 1
        
    Example:
        >>> results, meta = users.query()\\
        ...     .where(status="active")\\
        ...     .paginate(page=2, per_page=15)
        >>> print(f"Showing {meta['from']} to {meta['to']} of {meta['total']}")
    """
```

## Pull Requests

### Шаблон PR

```markdown
## Описание
Краткое описание изменений

## Тип изменений
- [ ] Новая функция
- [ ] Исправление бага
- [ ] Улучшение производительности
- [ ] Обновление документации

## Изменения
Подробное описание изменений:
1. Добавлен метод X для Y
2. Улучшена производительность Z
3. Исправлен баг в W

## Тесты
- [ ] Добавлены новые тесты
- [ ] Обновлены существующие тесты
- [ ] Все тесты проходят

## Документация
- [ ] Добавлена документация для новых функций
- [ ] Обновлены примеры кода
- [ ] Обновлен README

## Чеклист
- [ ] Код соответствует стилю проекта
- [ ] Добавлены типы данных (type hints)
- [ ] Добавлены docstrings
- [ ] Код отформатирован (black)
- [ ] Импорты отсортированы (isort)
```

## Сообщения о проблемах

### Шаблон бага

```markdown
## Описание бага
Краткое описание проблемы

## Как воспроизвести
1. Создать таблицу с X
2. Выполнить запрос Y
3. ...

## Ожидаемое поведение
Запрос должен вернуть Z

## Фактическое поведение
Запрос возвращает W или вызывает ошибку

## Код для воспроизведения
```python
from valtdb.api import ValtDB

db = ValtDB("./test")
users = db.db("test").table("users", {
    "id": "int",
    "name": "str"
})

# Код, вызывающий проблему
result = users.query()\\
    .where(id=1)\\
    .get()
```

## Окружение
- OS: Windows 10
- Python: 3.8.5
- ValtDB: 1.0.0
```

## Лицензия

Внося свой вклад в проект, вы соглашаетесь с тем, что ваши изменения будут распространяться под той же лицензией, что и проект (MIT).
