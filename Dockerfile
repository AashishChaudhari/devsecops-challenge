# Start from an official lightweight Python image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy the rest of your app
COPY app.py .

# Tell Docker your app runs on port 5000
EXPOSE 5000

# Command to run your app
CMD ["python3", "app.py"]
