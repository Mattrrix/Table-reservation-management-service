-- ==============================================
-- DDL (Data Definition Language) для PostgreSQL
-- ==============================================

-- 1. Таблица Restaurant
CREATE TABLE IF NOT EXISTS Restaurant (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    address         VARCHAR(200) NOT NULL,
    phone_number    VARCHAR(20),
    description     TEXT
);

-- 2. Таблица Table_Restaurant (столики)
CREATE TABLE IF NOT EXISTS Table_Restaurant (
    id              SERIAL PRIMARY KEY,
    restaurant_id   INT NOT NULL,
    capacity        INT NOT NULL,
    location        VARCHAR(50),
    description     TEXT,
    CONSTRAINT fk_table_restaurant
        FOREIGN KEY (restaurant_id)
        REFERENCES Restaurant(id)
        ON DELETE CASCADE
);

-- 3. Таблица Customer
CREATE TABLE IF NOT EXISTS Customer (
    id              SERIAL PRIMARY KEY,
    first_name      VARCHAR(50) NOT NULL,
    last_name       VARCHAR(50) NOT NULL,
    phone_number    VARCHAR(20),
    email           VARCHAR(100),
    registration_date DATE
);

-- 4. Таблица Reservation (бронирование)
CREATE TABLE IF NOT EXISTS Reservation (
    id                  SERIAL PRIMARY KEY,
    table_id            INT NOT NULL,
    customer_id         INT NOT NULL,
    reservation_datetime TIMESTAMP NOT NULL,
    duration            INT NOT NULL,   -- продолжительность в минутах
    status              VARCHAR(50) NOT NULL,
    CONSTRAINT fk_reservation_table
        FOREIGN KEY (table_id)
        REFERENCES Table_Restaurant(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_reservation_customer
        FOREIGN KEY (customer_id)
        REFERENCES Customer(id)
        ON DELETE CASCADE
);

-- 5. Таблица MenuItem
CREATE TABLE IF NOT EXISTS MenuItem (
    id              SERIAL PRIMARY KEY,
    restaurant_id   INT NOT NULL,
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    price           NUMERIC(10, 2) NOT NULL,
    category        VARCHAR(50),
    CONSTRAINT fk_menuitem_restaurant
        FOREIGN KEY (restaurant_id)
        REFERENCES Restaurant(id)
        ON DELETE CASCADE
);

-- 6. Таблица "User"
CREATE TABLE IF NOT EXISTS "User" (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) NOT NULL UNIQUE,  
    hashed_password VARCHAR(100) NOT NULL,
    email           VARCHAR(100) DEFAULT NULL,  
    role            VARCHAR(20) NOT NULL,  -- admin/manager/guest
    phone           VARCHAR(15) DEFAULT NULL CHECK (phone IS NULL OR phone ~ '^(\+7|8)\d{10}$'), 
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);


-- 7. Таблица AuditLog (логирование)
CREATE TABLE IF NOT EXISTS AuditLog (
    id          SERIAL PRIMARY KEY,
    user_id     INT NOT NULL,
    action      TEXT NOT NULL,
    timestamp   TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address  VARCHAR(45),
    CONSTRAINT fk_auditlog_user
        FOREIGN KEY (user_id)
        REFERENCES "User"(id)
        ON DELETE CASCADE
);

-- 8. Таблица Notification
CREATE TABLE IF NOT EXISTS Notification (
    id              SERIAL PRIMARY KEY,
    reservation_id  INT NOT NULL,
    customer_id     INT NOT NULL,
    type            VARCHAR(50) NOT NULL,  -- email/SMS/push
    content         TEXT,
    status          VARCHAR(50),          -- sent/failed/pending
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_notification_reservation
        FOREIGN KEY (reservation_id)
        REFERENCES Reservation(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_notification_customer
        FOREIGN KEY (customer_id)
        REFERENCES Customer(id)
        ON DELETE CASCADE
);

-- 9. Таблица AppSetting (хранит настройки, напр. время работы)
CREATE TABLE IF NOT EXISTS AppSetting (
    setting_key   VARCHAR(100) PRIMARY KEY,
    setting_value VARCHAR(100) NOT NULL,
    description   TEXT
);

-- ==============================================
-- Представления (Views)
-- ==============================================

CREATE OR REPLACE VIEW v_active_reservations AS
SELECT
    r.id AS reservation_id,
    c.first_name,
    c.last_name,
    tr.id AS table_id,
    r.reservation_datetime,
    r.status
FROM Reservation r
JOIN Customer c ON c.id = r.customer_id
JOIN Table_Restaurant tr ON tr.id = r.table_id
WHERE r.status IN ('подтверждена', 'ожидает подтверждения');

CREATE OR REPLACE VIEW v_restaurant_tables AS
SELECT 
    rest.id AS restaurant_id,
    rest.name AS restaurant_name,
    tr.id AS table_id,
    tr.capacity,
    tr.location
FROM Restaurant rest
JOIN Table_Restaurant tr ON tr.restaurant_id = rest.id;

-- ==============================================
-- Функция (Functions)
-- ==============================================

CREATE OR REPLACE FUNCTION fn_calculate_end_time(
    p_start TIMESTAMP,
    p_duration INT
) 
RETURNS TIMESTAMP AS
$$
BEGIN
    RETURN p_start + (p_duration || ' minutes')::interval;
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- Хранимые процедуры (Stored Procedures)
-- ==============================================

-- Процедура sp_create_reservation: создаёт бронь
CREATE OR REPLACE PROCEDURE sp_create_reservation(
    IN p_table_id INT,
    IN p_customer_id INT,
    IN p_reservation_datetime TIMESTAMP,
    IN p_duration INT
)
LANGUAGE plpgsql
AS $$
DECLARE
    new_res_id INT;
BEGIN
    INSERT INTO Reservation (table_id, customer_id, reservation_datetime, duration, status)
    VALUES (p_table_id, p_customer_id, p_reservation_datetime, p_duration, 'ожидает подтверждения')
    RETURNING id INTO new_res_id;

    INSERT INTO Notification (reservation_id, customer_id, type, content, status)
    VALUES (
        new_res_id,
        p_customer_id,
        'email',
        CONCAT('Reservation #', new_res_id, ' created'),
        'pending'
    );
END;
$$;

-- Процедура sp_update_reservation_status: обновляет статус брони
CREATE OR REPLACE PROCEDURE sp_update_reservation_status(
    IN p_res_id INT,
    IN p_new_status VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE Reservation
       SET status = p_new_status
     WHERE id = p_res_id;  -- Primary key is "id"

    IF p_new_status = 'подтверждена' THEN
        UPDATE Notification
           SET status  = 'accept',
               content = CONCAT('Your reservation #', p_res_id, ' has been accepted')
         WHERE reservation_id = p_res_id;
    ELSIF p_new_status = 'отменена' THEN
        UPDATE Notification
           SET status  = 'cancel',
               content = CONCAT('Your reservation #', p_res_id, ' has been canceled')
         WHERE reservation_id = p_res_id;
    END IF;
END;
$$;

-- ==============================================
-- Триггеры (Triggers)
-- ==============================================

-- 1) AFTER INSERT ON Reservation
CREATE OR REPLACE FUNCTION trg_reservation_after_insert()
RETURNS TRIGGER AS $$
DECLARE
    v_user_id INT;
BEGIN
    -- Динамический user_id из сессии
    v_user_id := current_setting('myapp.user_id')::int;

    INSERT INTO AuditLog (user_id, action, ip_address)
    VALUES (
        v_user_id,
        CONCAT('Created reservation ', NEW.id),
        '127.0.0.1'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reservation_after_insert
AFTER INSERT ON Reservation
FOR EACH ROW
EXECUTE FUNCTION trg_reservation_after_insert();


-- 2) AFTER UPDATE ON Reservation
CREATE OR REPLACE FUNCTION trg_reservation_after_update()
RETURNS TRIGGER AS $$
DECLARE
    v_user_id INT;
BEGIN
    -- Аналогично получаем user_id
    v_user_id := current_setting('myapp.user_id')::int;

    INSERT INTO AuditLog (user_id, action, ip_address)
    VALUES (
        v_user_id,
        CONCAT('Updated reservation ', NEW.id,
               ' from status ', OLD.status, ' to ', NEW.status),
        '127.0.0.1'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reservation_after_update
AFTER UPDATE ON Reservation
FOR EACH ROW
EXECUTE FUNCTION trg_reservation_after_update();


-- 3) BEFORE INSERT ON Reservation (проверка рабочего времени)
CREATE OR REPLACE FUNCTION trg_reservation_before_insert()
RETURNS TRIGGER AS
$$
DECLARE
    v_open_time  TIME;
    v_close_time TIME;
    v_res_start  TIMESTAMP;
    v_res_end    TIMESTAMP;
BEGIN
    SELECT setting_value::time
      INTO v_open_time
      FROM AppSetting
     WHERE setting_key = 'open_time';

    SELECT setting_value::time
      INTO v_close_time
      FROM AppSetting
     WHERE setting_key = 'close_time';

    v_res_start := NEW.reservation_datetime;
    v_res_end   := fn_calculate_end_time(v_res_start, NEW.duration);

    IF v_res_start::time < v_open_time
       OR v_res_end::time > v_close_time THEN
       RAISE EXCEPTION 'Reservation outside working hours: from % to %',
                       v_open_time, v_close_time;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reservation_before_insert
BEFORE INSERT ON Reservation
FOR EACH ROW
EXECUTE FUNCTION trg_reservation_before_insert();

-- ==============================================
-- Роли (admin, manager, guest)
-- ==============================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin') THEN
        CREATE ROLE admin;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'manager') THEN
        CREATE ROLE manager;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guest') THEN
        CREATE ROLE guest;
    END IF;
END;
$$;
