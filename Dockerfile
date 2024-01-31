#use an official Python runtime as a parent image
FROM python:3.9-slim
#set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
#set the working directory in the container
WORKDIR /app
#copy the current directory contents into the container at /app
COPY . /app
#Install any needed dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
#expose port 8000 to outside world
EXPOSE 8000
#run FastAPI app with uvicorn server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
