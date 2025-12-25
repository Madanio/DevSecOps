FROM python:3.9-slim

# Create a non-root user
RUN useradd -m appuser

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY api/ .

# Switch to the non-root user
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]