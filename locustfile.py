from locust import HttpUser, task, between
import random
import uuid


class WebsiteUser(HttpUser):
    wait_time = between(1, 2)
    token = None

    def on_start(self):

        response = self.client.post("/login/", json={
            "username": "test",
            "password": "test"
        })
        if response.status_code == 200:
            self.token = response.json().get("access_token")
        else:
            self.token = None

    @task
    def service_b(self):
        kunden_id = random.randint(28, 800)
        headers = {
            "Authorization": f"Bearer {self.token}"
        }
        self.client.get(f"/service_b/{kunden_id}/", headers=headers)

    # @task
    # def service_a(self):

    #     header = {
    #          "Authorization":f"Bearer {self.token}"        
    #         }
    #     data = {
    #     "kunde":{
    #         "vorname":f"Max{uuid.uuid4().hex}",             # damit immer ein eindeutiger name vorliegt
    #         "nachname":"Mustermann-Engel",
    #         "strasse":"Musterstrasse",
    #         "plz":"12345",
    #         "ort":"Musterstadt",
    #         "vorwahl":"09999",
    #         "telefon":"1234567",
    #         "geburtsdatum":"1999-08-09",
    #         "ledig":"0",
    #         "rabatt":"0.02"
    #     },
    #     "auftrag":{
    #         "fk_shop":"667"
    #     },
    #     "bestellpositionen":[
    #     {    
    #     "fk_artikel":55,
    #         "position":1,
    #         "anzahl":1
    #     },
    #     {
    #     "fk_artikel":104,
    #         "position":2,
    #         "anzahl":3
    #     }
    #     ]
    #         }
    #     response = self.client.post("/service_a/", headers=header, json=data)          #headers = header,
    #     print(f"HttpStatus: {response.status_code}, Body: {response.text}")

        

        