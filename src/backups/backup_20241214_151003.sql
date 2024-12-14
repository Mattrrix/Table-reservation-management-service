PGDMP      
                |            postgre    17.2 (Debian 17.2-1.pgdg120+1)    17.2 (Debian 17.2-1.pgdg120+1) R    �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            �           1262    16384    postgre    DATABASE     r   CREATE DATABASE postgre WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.utf8';
    DROP DATABASE postgre;
                     postgre    false            �            1255    16535 ;   fn_calculate_end_time(timestamp without time zone, integer)    FUNCTION     �   CREATE FUNCTION public.fn_calculate_end_time(p_start timestamp without time zone, p_duration integer) RETURNS timestamp without time zone
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN p_start + (p_duration || ' minutes')::interval;
END;
$$;
 e   DROP FUNCTION public.fn_calculate_end_time(p_start timestamp without time zone, p_duration integer);
       public               postgre    false            �            1255    16536 M   sp_create_reservation(integer, integer, timestamp without time zone, integer) 	   PROCEDURE     �  CREATE PROCEDURE public.sp_create_reservation(IN p_table_id integer, IN p_customer_id integer, IN p_reservation_datetime timestamp without time zone, IN p_duration integer)
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
 �   DROP PROCEDURE public.sp_create_reservation(IN p_table_id integer, IN p_customer_id integer, IN p_reservation_datetime timestamp without time zone, IN p_duration integer);
       public               postgre    false            �            1255    16537 8   sp_update_reservation_status(integer, character varying) 	   PROCEDURE     	  CREATE PROCEDURE public.sp_update_reservation_status(IN p_res_id integer, IN p_new_status character varying)
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
 l   DROP PROCEDURE public.sp_update_reservation_status(IN p_res_id integer, IN p_new_status character varying);
       public               postgre    false            �            1255    16538    trg_reservation_after_insert()    FUNCTION     �  CREATE FUNCTION public.trg_reservation_after_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;
 5   DROP FUNCTION public.trg_reservation_after_insert();
       public               postgre    false            �            1255    16539    trg_reservation_after_update()    FUNCTION     �  CREATE FUNCTION public.trg_reservation_after_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;
 5   DROP FUNCTION public.trg_reservation_after_update();
       public               postgre    false            �            1255    16540    trg_reservation_before_insert()    FUNCTION     G  CREATE FUNCTION public.trg_reservation_before_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;
 6   DROP FUNCTION public.trg_reservation_before_insert();
       public               postgre    false            �            1259    16541    User    TABLE     6  CREATE TABLE public."User" (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    hashed_password character varying(100) NOT NULL,
    email character varying(100) DEFAULT NULL::character varying,
    role character varying(20) NOT NULL,
    phone character varying(15) DEFAULT NULL::character varying,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT "User_phone_check" CHECK (((phone IS NULL) OR ((phone)::text ~ '^(\+7|8)\d{10}$'::text)))
);
    DROP TABLE public."User";
       public         heap r       postgre    false            �            1259    16549    User_id_seq    SEQUENCE     �   CREATE SEQUENCE public."User_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public."User_id_seq";
       public               postgre    false    217            �           0    0    User_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public."User_id_seq" OWNED BY public."User".id;
          public               postgre    false    218            �            1259    16550 
   appsetting    TABLE     �   CREATE TABLE public.appsetting (
    setting_key character varying(100) NOT NULL,
    setting_value character varying(100) NOT NULL,
    description text
);
    DROP TABLE public.appsetting;
       public         heap r       postgre    false            �            1259    16555    auditlog    TABLE     �   CREATE TABLE public.auditlog (
    id integer NOT NULL,
    user_id integer NOT NULL,
    action text NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    ip_address character varying(45)
);
    DROP TABLE public.auditlog;
       public         heap r       postgre    false            �            1259    16561    auditlog_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auditlog_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.auditlog_id_seq;
       public               postgre    false    220            �           0    0    auditlog_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.auditlog_id_seq OWNED BY public.auditlog.id;
          public               postgre    false    221            �            1259    16562    customer    TABLE     �   CREATE TABLE public.customer (
    id integer NOT NULL,
    first_name character varying(50) NOT NULL,
    last_name character varying(50) NOT NULL,
    phone_number character varying(20),
    email character varying(100),
    registration_date date
);
    DROP TABLE public.customer;
       public         heap r       postgre    false            �            1259    16565    customer_id_seq    SEQUENCE     �   CREATE SEQUENCE public.customer_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.customer_id_seq;
       public               postgre    false    222            �           0    0    customer_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.customer_id_seq OWNED BY public.customer.id;
          public               postgre    false    223            �            1259    16566    menuitem    TABLE     �   CREATE TABLE public.menuitem (
    id integer NOT NULL,
    restaurant_id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    category character varying(50)
);
    DROP TABLE public.menuitem;
       public         heap r       postgre    false            �            1259    16571    menuitem_id_seq    SEQUENCE     �   CREATE SEQUENCE public.menuitem_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.menuitem_id_seq;
       public               postgre    false    224            �           0    0    menuitem_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.menuitem_id_seq OWNED BY public.menuitem.id;
          public               postgre    false    225            �            1259    16572    notification    TABLE     %  CREATE TABLE public.notification (
    id integer NOT NULL,
    reservation_id integer NOT NULL,
    customer_id integer NOT NULL,
    type character varying(50) NOT NULL,
    content text,
    status character varying(50),
    created_at timestamp without time zone DEFAULT now() NOT NULL
);
     DROP TABLE public.notification;
       public         heap r       postgre    false            �            1259    16578    notification_id_seq    SEQUENCE     �   CREATE SEQUENCE public.notification_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.notification_id_seq;
       public               postgre    false    226            �           0    0    notification_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.notification_id_seq OWNED BY public.notification.id;
          public               postgre    false    227            �            1259    16579    reservation    TABLE       CREATE TABLE public.reservation (
    id integer NOT NULL,
    table_id integer NOT NULL,
    customer_id integer NOT NULL,
    reservation_datetime timestamp without time zone NOT NULL,
    duration integer NOT NULL,
    status character varying(50) NOT NULL
);
    DROP TABLE public.reservation;
       public         heap r       postgre    false            �            1259    16582    reservation_id_seq    SEQUENCE     �   CREATE SEQUENCE public.reservation_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.reservation_id_seq;
       public               postgre    false    228            �           0    0    reservation_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.reservation_id_seq OWNED BY public.reservation.id;
          public               postgre    false    229            �            1259    16583 
   restaurant    TABLE     �   CREATE TABLE public.restaurant (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    address character varying(200) NOT NULL,
    phone_number character varying(20),
    description text
);
    DROP TABLE public.restaurant;
       public         heap r       postgre    false            �            1259    16588    restaurant_id_seq    SEQUENCE     �   CREATE SEQUENCE public.restaurant_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.restaurant_id_seq;
       public               postgre    false    230            �           0    0    restaurant_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.restaurant_id_seq OWNED BY public.restaurant.id;
          public               postgre    false    231            �            1259    16589    table_restaurant    TABLE     �   CREATE TABLE public.table_restaurant (
    id integer NOT NULL,
    restaurant_id integer NOT NULL,
    capacity integer NOT NULL,
    location character varying(50),
    description text
);
 $   DROP TABLE public.table_restaurant;
       public         heap r       postgre    false            �            1259    16594    table_restaurant_id_seq    SEQUENCE     �   CREATE SEQUENCE public.table_restaurant_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.table_restaurant_id_seq;
       public               postgre    false    232            �           0    0    table_restaurant_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.table_restaurant_id_seq OWNED BY public.table_restaurant.id;
          public               postgre    false    233            �            1259    16595    v_active_reservations    VIEW     �  CREATE VIEW public.v_active_reservations AS
 SELECT r.id AS reservation_id,
    c.first_name,
    c.last_name,
    tr.id AS table_id,
    r.reservation_datetime,
    r.status
   FROM ((public.reservation r
     JOIN public.customer c ON ((c.id = r.customer_id)))
     JOIN public.table_restaurant tr ON ((tr.id = r.table_id)))
  WHERE ((r.status)::text = ANY (ARRAY[('подтверждена'::character varying)::text, ('ожидает подтверждения'::character varying)::text]));
 (   DROP VIEW public.v_active_reservations;
       public       v       postgre    false    232    228    228    228    228    228    222    222    222            �            1259    16600    v_restaurant_tables    VIEW       CREATE VIEW public.v_restaurant_tables AS
 SELECT rest.id AS restaurant_id,
    rest.name AS restaurant_name,
    tr.id AS table_id,
    tr.capacity,
    tr.location
   FROM (public.restaurant rest
     JOIN public.table_restaurant tr ON ((tr.restaurant_id = rest.id)));
 &   DROP VIEW public.v_restaurant_tables;
       public       v       postgre    false    232    230    230    232    232    232            �           2604    16604    User id    DEFAULT     f   ALTER TABLE ONLY public."User" ALTER COLUMN id SET DEFAULT nextval('public."User_id_seq"'::regclass);
 8   ALTER TABLE public."User" ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    218    217            �           2604    16605    auditlog id    DEFAULT     j   ALTER TABLE ONLY public.auditlog ALTER COLUMN id SET DEFAULT nextval('public.auditlog_id_seq'::regclass);
 :   ALTER TABLE public.auditlog ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    221    220            �           2604    16606    customer id    DEFAULT     j   ALTER TABLE ONLY public.customer ALTER COLUMN id SET DEFAULT nextval('public.customer_id_seq'::regclass);
 :   ALTER TABLE public.customer ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    223    222            �           2604    16607    menuitem id    DEFAULT     j   ALTER TABLE ONLY public.menuitem ALTER COLUMN id SET DEFAULT nextval('public.menuitem_id_seq'::regclass);
 :   ALTER TABLE public.menuitem ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    225    224            �           2604    16608    notification id    DEFAULT     r   ALTER TABLE ONLY public.notification ALTER COLUMN id SET DEFAULT nextval('public.notification_id_seq'::regclass);
 >   ALTER TABLE public.notification ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    227    226            �           2604    16609    reservation id    DEFAULT     p   ALTER TABLE ONLY public.reservation ALTER COLUMN id SET DEFAULT nextval('public.reservation_id_seq'::regclass);
 =   ALTER TABLE public.reservation ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    229    228            �           2604    16610    restaurant id    DEFAULT     n   ALTER TABLE ONLY public.restaurant ALTER COLUMN id SET DEFAULT nextval('public.restaurant_id_seq'::regclass);
 <   ALTER TABLE public.restaurant ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    231    230            �           2604    16611    table_restaurant id    DEFAULT     z   ALTER TABLE ONLY public.table_restaurant ALTER COLUMN id SET DEFAULT nextval('public.table_restaurant_id_seq'::regclass);
 B   ALTER TABLE public.table_restaurant ALTER COLUMN id DROP DEFAULT;
       public               postgre    false    233    232                      0    16541    User 
   TABLE DATA           k   COPY public."User" (id, username, hashed_password, email, role, phone, created_at, updated_at) FROM stdin;
    public               postgre    false    217   Ms       �          0    16550 
   appsetting 
   TABLE DATA           M   COPY public.appsetting (setting_key, setting_value, description) FROM stdin;
    public               postgre    false    219   �s       �          0    16555    auditlog 
   TABLE DATA           P   COPY public.auditlog (id, user_id, action, "timestamp", ip_address) FROM stdin;
    public               postgre    false    220   *t       �          0    16562    customer 
   TABLE DATA           e   COPY public.customer (id, first_name, last_name, phone_number, email, registration_date) FROM stdin;
    public               postgre    false    222   Gt       �          0    16566    menuitem 
   TABLE DATA           Y   COPY public.menuitem (id, restaurant_id, name, description, price, category) FROM stdin;
    public               postgre    false    224   dt       �          0    16572    notification 
   TABLE DATA           j   COPY public.notification (id, reservation_id, customer_id, type, content, status, created_at) FROM stdin;
    public               postgre    false    226   _u       �          0    16579    reservation 
   TABLE DATA           h   COPY public.reservation (id, table_id, customer_id, reservation_datetime, duration, status) FROM stdin;
    public               postgre    false    228   |u       �          0    16583 
   restaurant 
   TABLE DATA           R   COPY public.restaurant (id, name, address, phone_number, description) FROM stdin;
    public               postgre    false    230   �u       �          0    16589    table_restaurant 
   TABLE DATA           ^   COPY public.table_restaurant (id, restaurant_id, capacity, location, description) FROM stdin;
    public               postgre    false    232   5v       �           0    0    User_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public."User_id_seq"', 1, true);
          public               postgre    false    218            �           0    0    auditlog_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.auditlog_id_seq', 1, false);
          public               postgre    false    221            �           0    0    customer_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.customer_id_seq', 1, false);
          public               postgre    false    223            �           0    0    menuitem_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.menuitem_id_seq', 6, true);
          public               postgre    false    225            �           0    0    notification_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.notification_id_seq', 1, false);
          public               postgre    false    227            �           0    0    reservation_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.reservation_id_seq', 1, false);
          public               postgre    false    229            �           0    0    restaurant_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.restaurant_id_seq', 3, true);
          public               postgre    false    231            �           0    0    table_restaurant_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.table_restaurant_id_seq', 6, true);
          public               postgre    false    233            �           2606    16613    User User_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public."User"
    ADD CONSTRAINT "User_pkey" PRIMARY KEY (id);
 <   ALTER TABLE ONLY public."User" DROP CONSTRAINT "User_pkey";
       public                 postgre    false    217            �           2606    16615    User User_username_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public."User"
    ADD CONSTRAINT "User_username_key" UNIQUE (username);
 D   ALTER TABLE ONLY public."User" DROP CONSTRAINT "User_username_key";
       public                 postgre    false    217            �           2606    16617    appsetting appsetting_pkey 
   CONSTRAINT     a   ALTER TABLE ONLY public.appsetting
    ADD CONSTRAINT appsetting_pkey PRIMARY KEY (setting_key);
 D   ALTER TABLE ONLY public.appsetting DROP CONSTRAINT appsetting_pkey;
       public                 postgre    false    219            �           2606    16619    auditlog auditlog_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.auditlog
    ADD CONSTRAINT auditlog_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.auditlog DROP CONSTRAINT auditlog_pkey;
       public                 postgre    false    220            �           2606    16621    customer customer_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.customer
    ADD CONSTRAINT customer_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.customer DROP CONSTRAINT customer_pkey;
       public                 postgre    false    222            �           2606    16623    menuitem menuitem_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.menuitem
    ADD CONSTRAINT menuitem_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.menuitem DROP CONSTRAINT menuitem_pkey;
       public                 postgre    false    224            �           2606    16625    notification notification_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.notification
    ADD CONSTRAINT notification_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.notification DROP CONSTRAINT notification_pkey;
       public                 postgre    false    226            �           2606    16627    reservation reservation_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.reservation
    ADD CONSTRAINT reservation_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.reservation DROP CONSTRAINT reservation_pkey;
       public                 postgre    false    228            �           2606    16629    restaurant restaurant_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.restaurant
    ADD CONSTRAINT restaurant_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.restaurant DROP CONSTRAINT restaurant_pkey;
       public                 postgre    false    230            �           2606    16631 &   table_restaurant table_restaurant_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.table_restaurant
    ADD CONSTRAINT table_restaurant_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.table_restaurant DROP CONSTRAINT table_restaurant_pkey;
       public                 postgre    false    232            �           2620    16632 (   reservation trg_reservation_after_insert    TRIGGER     �   CREATE TRIGGER trg_reservation_after_insert AFTER INSERT ON public.reservation FOR EACH ROW EXECUTE FUNCTION public.trg_reservation_after_insert();
 A   DROP TRIGGER trg_reservation_after_insert ON public.reservation;
       public               postgre    false    239    228            �           2620    16633 (   reservation trg_reservation_after_update    TRIGGER     �   CREATE TRIGGER trg_reservation_after_update AFTER UPDATE ON public.reservation FOR EACH ROW EXECUTE FUNCTION public.trg_reservation_after_update();
 A   DROP TRIGGER trg_reservation_after_update ON public.reservation;
       public               postgre    false    240    228            �           2620    16634 )   reservation trg_reservation_before_insert    TRIGGER     �   CREATE TRIGGER trg_reservation_before_insert BEFORE INSERT ON public.reservation FOR EACH ROW EXECUTE FUNCTION public.trg_reservation_before_insert();
 B   DROP TRIGGER trg_reservation_before_insert ON public.reservation;
       public               postgre    false    252    228            �           2606    16635    auditlog fk_auditlog_user    FK CONSTRAINT     �   ALTER TABLE ONLY public.auditlog
    ADD CONSTRAINT fk_auditlog_user FOREIGN KEY (user_id) REFERENCES public."User"(id) ON DELETE CASCADE;
 C   ALTER TABLE ONLY public.auditlog DROP CONSTRAINT fk_auditlog_user;
       public               postgre    false    220    3279    217            �           2606    16640    menuitem fk_menuitem_restaurant    FK CONSTRAINT     �   ALTER TABLE ONLY public.menuitem
    ADD CONSTRAINT fk_menuitem_restaurant FOREIGN KEY (restaurant_id) REFERENCES public.restaurant(id) ON DELETE CASCADE;
 I   ALTER TABLE ONLY public.menuitem DROP CONSTRAINT fk_menuitem_restaurant;
       public               postgre    false    230    3295    224            �           2606    16645 %   notification fk_notification_customer    FK CONSTRAINT     �   ALTER TABLE ONLY public.notification
    ADD CONSTRAINT fk_notification_customer FOREIGN KEY (customer_id) REFERENCES public.customer(id) ON DELETE CASCADE;
 O   ALTER TABLE ONLY public.notification DROP CONSTRAINT fk_notification_customer;
       public               postgre    false    226    3287    222            �           2606    16650 (   notification fk_notification_reservation    FK CONSTRAINT     �   ALTER TABLE ONLY public.notification
    ADD CONSTRAINT fk_notification_reservation FOREIGN KEY (reservation_id) REFERENCES public.reservation(id) ON DELETE CASCADE;
 R   ALTER TABLE ONLY public.notification DROP CONSTRAINT fk_notification_reservation;
       public               postgre    false    226    3293    228            �           2606    16655 #   reservation fk_reservation_customer    FK CONSTRAINT     �   ALTER TABLE ONLY public.reservation
    ADD CONSTRAINT fk_reservation_customer FOREIGN KEY (customer_id) REFERENCES public.customer(id) ON DELETE CASCADE;
 M   ALTER TABLE ONLY public.reservation DROP CONSTRAINT fk_reservation_customer;
       public               postgre    false    228    3287    222            �           2606    16660     reservation fk_reservation_table    FK CONSTRAINT     �   ALTER TABLE ONLY public.reservation
    ADD CONSTRAINT fk_reservation_table FOREIGN KEY (table_id) REFERENCES public.table_restaurant(id) ON DELETE CASCADE;
 J   ALTER TABLE ONLY public.reservation DROP CONSTRAINT fk_reservation_table;
       public               postgre    false    228    3297    232            �           2606    16665 $   table_restaurant fk_table_restaurant    FK CONSTRAINT     �   ALTER TABLE ONLY public.table_restaurant
    ADD CONSTRAINT fk_table_restaurant FOREIGN KEY (restaurant_id) REFERENCES public.restaurant(id) ON DELETE CASCADE;
 N   ALTER TABLE ONLY public.table_restaurant DROP CONSTRAINT fk_table_restaurant;
       public               postgre    false    232    3295    230               u   x�3�LL����T1JR14R���)sO)�vq�����/p����*M��(JOJ�J�r1*�32��L�r�(*qv��d����(�[��Z�ZX�X������ )�$1      �   H   x��/H͋/��M�44�20�J-.I,-J�+Q�J+$�((8�r%���B��)����r��qqq `�U      �      x������ � �      �      x������ � �      �   �   x�5��n�@Eמ�� ģTeY��*Q�%�nX`u`��H��A�Y���8��r��䧙���[(8T�Npq��l-%ؓ��:��2�Γ��ޭ�	ܚ�03k�ϴ� /�*; SB_2��8����G�Mg���@^�Y�����;�]��i� Qi񓮴F�ޔ�c�1��4��#����?�q�U��������njIV������n��^hd�I�xIF6��1�{e�      �      x������ � �      �      x������ � �      �   �   x�U̻�0���y
﨨IBǖB\��X�K!E���DH������P�@��$�:3�ɬ�Y�K��p3� ���v�r�J��4��Ӫ�=�)��������A�ܺ�m/!ൣ�:��{��5u[*��<�.�      �   �   x�Uͽ�0��~
?RK�������,n궑��)Qyz20����+� gv��<�p��%P�f���&,3,��g��Ns!)n3��>O����t��z*Bv�M�j��.�
���v�p[د�NzY}5��>���*K	���u���|����� �U0D�     