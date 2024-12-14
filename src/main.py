import streamlit as st
from dotenv import load_dotenv
import os, bcrypt, psycopg
import pandas as pd
from psycopg.rows import dict_row
import re, subprocess, datetime, tempfile
from datetime import timedelta

# Разница времени (+3 часа)
TIME_OFFSET = timedelta(hours=3)

load_dotenv()

def get_connection():
    conn = psycopg.connect(
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT"),
        row_factory=dict_row
    )
    return conn

# --------------------------------------------------------------------------------
# Инициализация: создаём / обновляем админа в таблице "User"
# --------------------------------------------------------------------------------
def init_admin_user():
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise ValueError("ADMIN_USERNAME или ADMIN_PASSWORD не определены в переменных окружения.")

    hashed_pass = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id, hashed_password FROM "User" WHERE username = %s', (ADMIN_USERNAME,))
            row = cur.fetchone()
            if row is None:
                # Нет админа - создаём
                cur.execute('''
                    INSERT INTO "User"(username, hashed_password, email, role, phone)
                    VALUES (%s, %s, %s, 'admin', %s)
                ''', (ADMIN_USERNAME, hashed_pass, None, None))
            else:
                # Обновляем пароль при каждом запуске
                cur.execute('''
                    UPDATE "User" SET hashed_password = %s WHERE username = %s
                ''', (hashed_pass, ADMIN_USERNAME))
            conn.commit()

# --------------------------------------------------------------------------------
# Функции для работы с пользователями (регистрация/авторизация)
# --------------------------------------------------------------------------------

# Проверка номера телефона
def validate_phone_number(phone):
    pattern = r"^(\+7|8)\d{10}$"
    return re.match(pattern, phone)

# Проверка сложности пароля
def validate_password(password):
    if len(password) < 8:
        return "Пароль должен быть не менее 8 символов."
    if not re.search(r"[A-Z]", password):
        return "Пароль должен содержать хотя бы одну заглавную букву."
    if not re.search(r"[a-z]", password):
        return "Пароль должен содержать хотя бы одну строчную букву."
    if not re.search(r"\d", password):
        return "Пароль должен содержать хотя бы одну цифру."
    if not re.search(r"[!@#$%^&*_(),.?\":{}|<>]", password):
        return "Пароль должен содержать хотя бы один специальный символ (!@#$%^&* и т.д.)."
    return None

def register_guest(username, plain_password, email=None, phone=None):
    """
    Регистрирует нового гостя. Поля email и phone необязательные.
    """
    # Нормализация значений email и phone (пустые строки заменяются на None)
    email = email.strip() if email else None
    phone = phone.strip() if phone else None

    # Валидация телефона, если указан
    if phone and not validate_phone_number(phone):
        st.error("Номер телефона должен быть в формате +7XXXXXXXXXX или 8XXXXXXXXXX.")
        return False

    # Проверка сложности пароля
    password_error = validate_password(plain_password)
    if password_error:
        st.error(password_error)
        return False

    # Хэширование пароля
    hashed_pass = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                # Проверка уникальности логина
                cur.execute('SELECT id FROM "User" WHERE username = %s', (username,))
                if cur.fetchone():
                    st.error("Логин уже существует!")
                    return False
                
                # Вставка нового пользователя
                cur.execute('''
                    INSERT INTO "User"(username, hashed_password, email, role, phone)
                    VALUES (%s, %s, %s, 'guest', %s)
                ''', (username, hashed_pass, email, phone))  # email и phone могут быть None
                conn.commit()
                st.success("Гость успешно зарегистрирован.")
                return True
    except Exception as e:
        st.error(f"Ошибка при регистрации: {e}")
        return False

def register_manager_by_admin(username, plain_password, email=None, phone=None):
    """
    Регистрирует менеджера. Поля email и phone обязательные.
    """
    # Нормализация значений email и phone (пустые строки заменяются на None)
    email = email.strip() if email else None
    phone = phone.strip() if phone else None

    # Проверка формата email
    if email and not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        st.error("Некорректный формат email. Ожидается формат xxx@xxx.xxx.")
        return False

    # Валидация телефона
    if not validate_phone_number(phone):
        st.error("Номер телефона должен быть в формате +7XXXXXXXXXX или 8XXXXXXXXXX.")
        return False

    # Проверка сложности пароля
    password_error = validate_password(plain_password)
    if password_error:
        st.error(password_error)
        return False

    # Хэширование пароля
    hashed_pass = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                # Проверка уникальности логина
                cur.execute('SELECT id FROM "User" WHERE username = %s', (username,))
                if cur.fetchone():
                    st.error("Логин уже существует!")
                    return False
                
                # Вставка нового менеджера
                cur.execute('''
                    INSERT INTO "User"(username, hashed_password, email, role, phone)
                    VALUES (%s, %s, %s, 'manager', %s)
                ''', (username, hashed_pass, email, phone))
                conn.commit()
                return True
    except Exception as e:
        st.error(f"Ошибка при создании менеджера: {e}")
        return False

def authenticate_user(username, plain_password):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id, hashed_password, role FROM "User" WHERE username = %s', (username,))
            row = cur.fetchone()
            if row:
                stored_hash = row['hashed_password']
                if bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash.encode('utf-8')):
                    return (row['id'], row['role'])
    return (None, None)

# --------------------------------------------------------------------------------
# Функции предметной области
# --------------------------------------------------------------------------------

def get_restaurants():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM Restaurant")
            return cur.fetchall()

def get_menu_for_restaurant(restaurant_id):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM MenuItem WHERE restaurant_id = %s", (restaurant_id,))
            return cur.fetchall()

def create_reservation(table_id, customer_id, reservation_datetime, duration):
    """
    Вызываем хранимую процедуру sp_create_reservation, которая вставляет запись в Reservation
    и Notification. table_id, customer_id -> 'id' из соответствующих таблиц.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("CALL sp_create_reservation(%s, %s, %s, %s)",
                        (table_id, customer_id, reservation_datetime, duration))
            conn.commit()

def update_reservation_status(res_id, new_status):
    """
    Вызываем хранимую процедуру sp_update_reservation_status, 
    где res_id соответствует полю 'id' в таблице Reservation
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("CALL sp_update_reservation_status(%s, %s)", (res_id, new_status))
            conn.commit()

def get_active_reservations():
    """
    SELECT * FROM v_active_reservations
    где view формирует поле reservation_id в SELECT, 
    хотя реальный PK = 'id' в Reservation. 
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM v_active_reservations")
            return cur.fetchall()

def get_tables_for_restaurant(restaurant_id):
    """
    Ищем столики в Table_Restaurant по foreign key restaurant_id -> Restaurant.id
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM Table_Restaurant WHERE restaurant_id = %s", (restaurant_id,))
            return cur.fetchall()

def insert_customer_if_not_exists(first_name, last_name, phone_number, email):
    """
    Если нет такой почты в Customer, создаём (возвращаем 'id'),
    иначе возвращаем существующий 'id'.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM Customer WHERE email = %s", (email,))
            row = cur.fetchone()
            if row:
                return row['id']  # уже есть запись
            else:
                cur.execute('''
                    INSERT INTO Customer (first_name, last_name, phone_number, email, registration_date)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                ''', (first_name, last_name, phone_number, email, datetime.date.today()))
                new_id = cur.fetchone()['id']
                conn.commit()
                return new_id

# --------------------------------------------------------------------------------
# Streamlit App
# --------------------------------------------------------------------------------

def main():
    st.set_page_config(layout='centered')  # Центрируем основной контент

    init_admin_user()  # создаём / обновляем админа (пароль из .env)

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "user_role" not in st.session_state:
        st.session_state.user_role = None
    if "user_id" not in st.session_state:
        st.session_state.user_id = None

    # Если не авторизован: показываем две большие кнопки «Авторизация» и «Регистрация»
    if not st.session_state.logged_in:
        st.title("🍽️ Добро пожаловать в сервис бронирования столиков!")
        st.markdown(
            """
            Выберите, что вы хотите сделать:
            - Войти, если вы уже зарегистрированы.
            - Зарегистрироваться, если вы новый пользователь.
            """
        )

        if "show_login_form" not in st.session_state:
            st.session_state.show_login_form = False

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### Авторизация 🔑")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Войти", key="login_button"):
                user_id, role = authenticate_user(username, password)
                if user_id is not None:
                    # Установка сессионных данных после успешной авторизации
                    st.session_state.logged_in = True
                    st.session_state.user_role = role
                    st.session_state.user_id = user_id
                    st.success(f"Успешный вход!")
                    st.rerun()
                else:
                    st.error("Неверный логин или пароль")

        with col2:
            st.markdown("### Регистрация 📝")
            new_username = st.text_input("Username", key="register_username")
            new_email = st.text_input("Email (optional)", key="register_email")
            new_phone = st.text_input("Phone (optional)", key="register_phone")
            new_password = st.text_input("Password", type="password", key="register_password")
            if st.button("Зарегистрироваться", key="register_button"):
                if register_guest(new_username, new_password, new_email, new_phone):
                    # Установка сессионных данных после успешной регистрации
                    st.session_state.logged_in = True
                    st.session_state.user_role = 'guest'
                    st.session_state.user_id = new_username 
                    st.success("Регистрация прошла успешно! Перенаправление...")
                    st.rerun()

    else:
        # Если пользователь авторизован
        st.sidebar.title("Навигация")
        role = st.session_state.user_role

        if role == "guest":
            actions = ["📝Гостевой функционал", "Выход"]
            choice = st.sidebar.selectbox("Выберите действие", actions)
            if choice == "📝Гостевой функционал":
                guest_dashboard()
            else:
                logout()

        elif role == "manager":
            actions = ["🛠️Просмотр и управление бронированиями", "📝Гостевой функционал", "Выход"]
            choice = st.sidebar.selectbox("Выберите действие", actions)
            if choice == "📝Гостевой функционал":
                guest_dashboard()
            elif choice == "🛠️Просмотр и управление бронированиями":
                manager_dashboard()
            else:
                logout()

        elif role == "admin":
            actions = ["⚙️Панель администрирования", "🛠️Просмотр и управление бронированиями", "📝Гостевой функционал","Выход"]
            choice = st.sidebar.selectbox("Выберите блок для работы", actions)
            if choice == "📝Гостевой функционал":
                guest_dashboard()
            elif choice == "🛠️Просмотр и управление бронированиями":
                manager_dashboard()
            elif choice == "⚙️Панель администрирования":
                admin_dashboard()
            else:
                logout()
        else:
            st.error("Неизвестная роль, доступ запрещён.")

def logout():
    st.session_state.logged_in = False
    st.session_state.user_role = None
    st.session_state.user_id = None
    st.rerun()

def guest_dashboard():
    st.header("🍽️Гостевой функционал")
    st.markdown("Гость может выбрать ресторан, посмотреть меню и сделать бронирование.")

    # Получаем рестораны
    restaurants = get_restaurants()
    if not restaurants:
        st.info("Нет ресторанов в базе.")
        return

    # Выбор ресторана
    st.markdown("### \U0001F374 Выберите ресторан")
    restaurant_options = {r["name"]: r["id"] for r in restaurants}
    choice = st.selectbox("Доступные рестораны", list(restaurant_options.keys()))
    chosen_restaurant_id = restaurant_options[choice]

    # Меню ресторана с использованием expander
    st.markdown("### 📜 Меню ресторана")
    menu = get_menu_for_restaurant(chosen_restaurant_id)
    if menu:
        with st.expander("Развернуть меню ресторана"):
            for item in menu:
                st.markdown(
                    f"**{item['name']} ({item['price']}$)**:\n\n{item['description']}\n"
                )
    else:
        st.info("Меню пустое.")

    # Выбор столика
    st.markdown("### \U0001F4CD Выбор столика")
    tables = get_tables_for_restaurant(chosen_restaurant_id)
    if not tables:
        st.info("Нет столиков в этом ресторане.")
        return

    table_map = {
        f"Столик №{t['id']} (Вместимость = {t['capacity']})": t['id'] for t in tables
    }
    chosen_table = st.selectbox("Выберите столик", list(table_map.keys()))
    chosen_table_id = table_map[chosen_table]

    # Данные пользователя
    st.markdown("### \U0001F464 Введите свои данные")
    first_name = st.text_input("Имя", "Иван")
    last_name = st.text_input("Фамилия", "Иванов")
    phone_number = st.text_input("Телефон", "+7-900-000-0000", help="Введите номер в формате +7XXXXXXXXXX")
    email = st.text_input("E-mail", "ivanov@example.com", help="Введите корректный email")

    # Проверка email
    if email and not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        st.error("Некорректный формат email. Ожидается формат xxx@xxx.xxx.")
        return

    # Проверка телефона
    if not phone_number.startswith("+"):
        st.error("Номер телефона должен начинаться с '+'.")
        return

    # Ввод времени бронирования
    st.markdown("### \U0001F4C5 Данные бронирования")
    reservation_date = st.date_input("Дата бронирования", value=datetime.date.today())
    reservation_time = st.time_input("Время бронирования", value=datetime.time(19, 0))
    duration = st.number_input("Продолжительность (мин.)", min_value=30, max_value=300, value=120)
    reservation_datetime = datetime.datetime.combine(reservation_date, reservation_time)

    # Проверка на корректное время бронирования
    current_time = datetime.datetime.now() + datetime.timedelta(hours=3)  # Учет смещения времени
    if reservation_datetime < current_time:
        st.error("Вы не можете забронировать столик на прошедшее время.")
        return

    # Кнопка для бронирования
    if st.button("\U0001F4E6 Забронировать"):
        if not (first_name and last_name and phone_number and email):
            st.error("Все поля обязательны к заполнению.")
            return

        customer_id = insert_customer_if_not_exists(first_name, last_name, phone_number, email)
        user_id = st.session_state.user_id  # ID текущего пользователя из "User"

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    # Устанавливаем сессионную переменную myapp.user_id через прямую подстановку
                    cur.execute(f"SET LOCAL myapp.user_id = '{user_id}'")

                    # Вызываем хранимую процедуру (или делаем INSERT Reservation)
                    cur.execute("CALL sp_create_reservation(%s, %s, %s, %s)",
                                (chosen_table_id, customer_id, reservation_datetime, duration))
                conn.commit()

            st.success("Бронь успешно создана (ожидает подтверждения).")
        except psycopg.Error as e:
            st.error(f"Ошибка при бронировании: {e}")


def manager_dashboard():
    # Заголовок панели
    st.markdown(
        "<h2 style='text-align: center; color: #4CAF50;'>🛠️ Функционал менеджера</h2>", 
        unsafe_allow_html=True
    )
    st.markdown("<p style='text-align: center;'>Просматривайте активные брони и управляйте их статусом.</p>", unsafe_allow_html=True)

    # Раздел: Активные бронирования
    st.markdown("---")
    st.subheader("📋 Активные бронирования")

    # Получение активных бронирований
    active_res = get_active_reservations()

    if active_res:
        import pandas as pd
        df = pd.DataFrame(active_res)

        # Подзаголовок и таблица
        st.write("📌 Список текущих бронирований:")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("🔍 Активных бронирований нет.")

    # Раздел: Обновление статуса бронирования
    st.markdown("---")
    st.subheader("🔄 Обновление статуса бронирования")

    # Поля для ввода
    res_id_to_update = st.number_input(
        "Введите ID бронирования для изменения", 
        min_value=1, 
        step=1,
        help="Укажите идентификатор бронирования, которое вы хотите изменить."
    )
    new_status = st.selectbox(
        "Выберите новый статус",
        ["подтверждена", "отменена"],
        help="Выберите новый статус для бронирования."
    )

    # Кнопка подтверждения
    if st.button("✅ Обновить статус"):
        user_id = st.session_state.user_id  # ID текущего пользователя
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    # Устанавливаем контекст пользователя
                    cur.execute(f"SET LOCAL myapp.user_id = '{user_id}'")

                    # Вызов хранимой процедуры для обновления статуса
                    cur.execute("CALL sp_update_reservation_status(%s, %s)", (res_id_to_update, new_status))

                conn.commit()
            st.success(f"✅ Статус бронирования с ID={res_id_to_update} успешно обновлён на '{new_status}'.")
        except psycopg.Error as e:
            st.error(f"❌ Ошибка при обновлении статуса: {e}")


def fetch_data(query, params=None):
    """Функция для выполнения SQL-запросов (SELECT/INSERT/UPDATE/DELETE)."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if query.strip().lower().startswith("select"):
                rows = cur.fetchall()
                cols = [desc[0] for desc in cur.description]
                return (rows, cols)
            conn.commit()
            return (None, None)

def edit_table(table_name):
    st.subheader(f"Таблица: {table_name}")

    data_query = f"SELECT * FROM {table_name}"
    data, columns = fetch_data(data_query)

    if data:
        df = pd.DataFrame(data, columns=columns)
        st.dataframe(df, use_container_width=True)

        # Удаление записи
        with st.expander("Удалить запись"):
            record_id = st.number_input("Введите ID записи для удаления", min_value=1, step=1)
            if st.button("Удалить запись"):
                delete_query = f"DELETE FROM {table_name} WHERE id = %s"
                fetch_data(delete_query, (record_id,))
                st.success(f"Запись с ID {record_id} удалена из таблицы {table_name}")

        # Добавление новой записи
        with st.expander("Добавить запись"):
            new_record = {}
            for col in columns:
                if col != "id":  # Поле "id" обычно автоинкрементное, не заполняем
                    new_record[col] = st.text_input(f"{col}")
            if st.button("Добавить запись"):
                columns_str = ", ".join([col for col in new_record.keys()])
                placeholders = ", ".join(["%s"] * len(new_record))
                insert_query = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})"
                fetch_data(insert_query, tuple(new_record.values()))
                st.success(f"Новая запись добавлена в таблицу {table_name}")

        # Редактирование записи
        with st.expander("Редактировать запись"):
            record_id = st.number_input("Введите ID записи для редактирования", min_value=1, step=1)
            updated_record = {}
            for col in columns:
                if col != "id":  
                    updated_record[col] = st.text_input(f"Новое значение для {col}")
            if st.button("Сохранить изменения"):
                set_clause = ", ".join([f"{col} = %s" for col in updated_record.keys()])
                update_query = f"UPDATE {table_name} SET {set_clause} WHERE id = %s"
                fetch_data(update_query, tuple(updated_record.values()) + (record_id,))
                st.success(f"Запись с ID {record_id} обновлена в таблице {table_name}")
    else:
        st.warning(f"Таблица {table_name} пуста или не существует.")

def create_backup():
    """
    Создает резервную копию базы данных PostgreSQL, подключаясь к контейнеру `db`,
    и сохраняет её в директорию /backups на хосте.
    """
    # Параметры подключения к базе данных
    db_host = os.getenv("POSTGRES_HOST", "db")  # Хост базы данных (имя контейнера)
    db_user = os.getenv("POSTGRES_USER", "postgre")
    db_name = os.getenv("POSTGRES_DB", "postgre")
    db_password = os.getenv("POSTGRES_PASSWORD", "postgre")
    backup_dir = "./backups"  # Локальная директория для резервных копий

    # Создаем имя резервного файла
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}.sql"
    backup_file_path = os.path.join(backup_dir, backup_filename)

    try:
        # Создаем локальную папку для резервных копий, если она не существует
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        # Устанавливаем пароль PostgreSQL через переменную окружения
        os.environ["PGPASSWORD"] = db_password

        # Команда для выполнения pg_dump из контейнера streamlit_app
        pg_dump_command = [
            "pg_dump", 
            "-h", db_host,         # Хост базы данных
            "-U", db_user,         # Пользователь
            "-F", "c",             # Формат: custom
            "-b",                  # Включение больших объектов
            "-v",                  # Подробный вывод
            "-f", backup_file_path, # Файл для сохранения резервной копии
            db_name                # Имя базы данных
        ]

        # Выполняем команду
        result = subprocess.run(pg_dump_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # Проверяем успешность выполнения команды
        if result.returncode == 0:
            # st.success(f"Резервная копия успешно создана: {backup_file_path}")
            return backup_file_path
        else:
            error_message = result.stderr.decode() if result.stderr else "Нет информации об ошибке"
            st.error(f"Ошибка при создании резервной копии базы данных: {error_message}")
            return None

    except Exception as e:
        st.error(f"Ошибка при создании резервной копии: {str(e)}")
        return None

def restore_db(uploaded_file):
    """
    Восстанавливает базу данных PostgreSQL из загруженного файла резервной копии.
    """
    # Параметры подключения к базе данных
    db_host = os.getenv("POSTGRES_HOST", "db")  # Хост базы данных (имя контейнера)
    db_user = os.getenv("POSTGRES_USER", "postgre")
    db_name = os.getenv("POSTGRES_DB", "postgre")
    db_password = os.getenv("POSTGRES_PASSWORD", "postgre")

    # Сохраняем загруженный файл во временную директорию
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".dump")
    temp_file_path = temp_file.name
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.read())
    temp_file.close()

    try:
        # Устанавливаем пароль PostgreSQL через переменную окружения
        os.environ["PGPASSWORD"] = db_password

        # Используем pg_restore с флагом --clean для очистки базы перед восстановлением
        restore_cmd = [
            "pg_restore",
            "--clean",             # Удаляет существующие объекты перед созданием
            "--if-exists",         # Удаляет объекты только если они существуют
            "-h", db_host,         # Хост базы данных
            "-U", db_user,         # Пользователь базы данных
            "-d", db_name,         # Имя базы данных
            "-v",                  # Подробный вывод
            temp_file_path         # Путь к файлу резервной копии
        ]

        # Выполнение команды восстановления
        result = subprocess.run(restore_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # if result.returncode == 0:
        #     # st.success("База данных успешно восстановлена из резервной копии.")
        # else:
        #     # Выводим сообщение об ошибке
        #     error_message = result.stderr.decode() if result.stderr else "Нет информации об ошибке"
        #     st.error(f"Ошибка при восстановлении базы данных: {error_message}")

    except Exception as e:
        st.error(f"Ошибка при восстановлении базы данных: {str(e)}")

    finally:
        # Удаляем временный файл
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def admin_dashboard():
    st.header("⚙️ Панель администрирования")
    submenu = st.sidebar.selectbox("Выберите действие", 
               ["📋 Управление таблицами", "👨‍💼 Зарегистрировать менеджера", "🔄 Сменить роль пользователя", "💾 Резервное копирование"])
    
    st.markdown("---")  # Разделитель для визуальной организации
    
    if submenu == "📋 Управление таблицами":
        st.subheader("📂 Управление таблицами")
        tables_to_view = st.selectbox("🔍Какую таблицу просмотреть?",
            ["Restaurant", "Table_Restaurant", "MenuItem", "Reservation", "\"User\"", "AuditLog", "Notification", "AppSetting"])
        edit_table(tables_to_view)

    elif submenu == "👨‍💼 Зарегистрировать менеджера":
        st.subheader("👨‍💼 Регистрация менеджера")
        with st.form("manager_registration_form"):
            manager_username = st.text_input("👤 Username менеджера")
            manager_email = st.text_input("📧 Email менеджера")
            manager_phone = st.text_input("📞 Телефон менеджера")
            manager_password = st.text_input("🔑 Пароль менеджера", type="password")
            submitted = st.form_submit_button("Зарегистрировать")
            if submitted:
                if not manager_username or not manager_email or not manager_phone or not manager_password:
                    st.error("❌ Все поля обязательны для заполнения.")
                else:
                    if register_manager_by_admin(manager_username, manager_password, manager_email, manager_phone):
                        st.success("✅ Менеджер успешно зарегистрирован.")


    
    elif submenu == "🔄 Сменить роль пользователя":
        st.subheader("🔄 Смена роли пользователя")
        with st.form("role_change_form"):
            user_to_update = st.text_input("👤 Username для изменения роли")
            new_role = st.selectbox("🛠️ Новая роль", ["guest", "manager", "admin"])
            submitted = st.form_submit_button("Применить роль")
            if submitted:
                if user_to_update == os.getenv("ADMIN_USERNAME"):
                    st.error("❌ Нельзя изменить свою собственную роль администратора.")
                else:
                    with get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute('UPDATE "User" SET role = %s WHERE username = %s', (new_role, user_to_update))
                            conn.commit()
                    st.success("✅ Роль успешно изменена.")

    elif submenu == "💾 Резервное копирование":
        st.markdown("### 📤 Создание резервной копии")
        if st.button("Создать резервную копию"):
            backup_file_path = create_backup()
            if backup_file_path:
                st.success(f"✅ Резервная копия успешно создана: {backup_file_path}")
            else:
                st.error("❌ Ошибка при создании резервной копии.")

        st.markdown("### 📥 Восстановление из резервной копии")
        uploaded_file = st.file_uploader("📁 Загрузите файл резервной копии (форматы: .sql, .dump)", type=["sql", "dump"])
        if uploaded_file:
            if st.button("Восстановить базу данных"):
                try:
                    restore_db(uploaded_file)
                    st.success("✅ База данных успешно восстановлена.")
                except Exception as e:
                    st.error(f"❌ Ошибка при восстановлении базы данных: {e}")

    st.markdown("---")  # Завершающий разделитель

if __name__ == "__main__":
    main()
