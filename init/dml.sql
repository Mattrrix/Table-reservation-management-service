-- ==============================================
-- DML (Data Manipulation Language) для PostgreSQL
-- ==============================================

-- 1. Рестораны
INSERT INTO Restaurant (name, address, phone_number, description)
VALUES
    ('Italiano', '123 Main St', '+1-202-555-0147', 'Italian Cuisine'),
    ('SushiPlace', '456 Ocean Ave', '+1-202-555-0199', 'Japanese Sushi'),
    ('BBQ King', '789 Grill Road', '+1-202-555-0177', 'American BBQ');

-- 2. Столики для каждого ресторана
INSERT INTO Table_Restaurant (restaurant_id, capacity, location, description)
VALUES
    (1, 4, 'Main Hall', 'Corner table near window'),
    (1, 2, 'Main Hall', 'Cozy table for two'),
    (2, 6, 'Sushi Bar', 'Round table near the chef'),
    (2, 4, 'Balcony', 'Nice ocean view'),
    (3, 8, 'Main Hall', 'Large table for big group'),
    (3, 4, 'Terrace', 'Outdoor seating');

-- 3. Позиции меню (MenuItem)
INSERT INTO MenuItem (restaurant_id, name, description, price, category)
VALUES
    (1, 'Pizza Margherita', 'Tomato sauce, mozzarella, basil', 9.99, 'Pizza'),
    (1, 'Pasta Carbonara', 'Bacon, cheese, cream sauce', 12.50, 'Pasta'),
    (2, 'Nigiri Set', 'Assorted sushi nigiri', 15.00, 'Sushi'),
    (2, 'Miso Soup', 'Traditional Japanese soup', 3.50, 'Soup'),
    (3, 'BBQ Ribs', 'Pork ribs with signature sauce', 18.00, 'Main'),
    (3, 'Coleslaw', 'Homemade coleslaw', 3.00, 'Side');

-- 4. Настройки рабочего времени (AppSetting)
INSERT INTO AppSetting (setting_key, setting_value, description)
VALUES
    ('open_time', '10:00', 'Restaurant opens at 10 AM'),
    ('close_time', '22:00', 'Restaurant closes at 10 PM');

-- ==============================================
-- Пояснение:
--  - Мы НЕ вставляем здесь админа, т.к. админ создаётся/обновляется в main.py -> init_admin_user().
--  - Не добавляем гостей / клиентов — они будут регистрироваться сами 
--    (через Streamlit формы).
-- ==============================================
