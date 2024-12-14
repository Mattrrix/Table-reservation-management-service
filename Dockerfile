FROM python:3.9-slim

# Установка рабочего каталога
WORKDIR /app

# Установка зависимостей PostgreSQL клиента (версии 17)
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    lsb-release

# Добавляем официальный репозиторий PostgreSQL 17
RUN echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add - && \
    apt-get update && apt-get install -y postgresql-client-17 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Копируем requirements.txt из папки src в текущую рабочую директорию контейнера
COPY src/requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт Streamlit
EXPOSE 8501

# Команда запуска приложения
CMD ["streamlit", "run", "main.py", "--server.address=0.0.0.0", "--server.fileWatcherType=poll"]

