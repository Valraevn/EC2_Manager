FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create data directory with proper permissions
RUN mkdir -p /app/data && chmod 777 /app/data

COPY . .

EXPOSE 5000

CMD ["python", "app.py"] 