# fastapi_ba


locust starten: 
mit aktiver venv im verzeichnis fastapi_1: 
locust -f locustfile.py --host http://localhost:8000


docker: 
docker build -t fastapi_1 .
        
und 

docker run -p 8000:8000 fastapi_1
