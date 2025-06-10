from typing import Annotated, Optional, List
from datetime import datetime, date, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, status
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select
from pydantic import BaseModel
from typing import Annotated
from fastapi import Path, Request
from collections import defaultdict
from jwt.exceptions import InvalidTokenError
#from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
import requests

from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache

# ----------------------------------------
# Datenbankmodelle
# ----------------------------------------


class Kunde(SQLModel, table=True):
    kd_nr: int | None = Field(default=None, primary_key=True)
    vorname: str = Field(index=True)
    nachname: str = Field(index=True)
    strasse: str = Field(index=True)
    plz:str=Field(index=True)
    ort: str
    vorwahl: str
    telefon: str
    geburtsdatum: date
    ledig: int
    rabatt: float
    letzter_zugriff: datetime


class Auftrag(SQLModel, table=True):
    auft_nr: int | None = Field(default=None, primary_key=True)
    bestelldat: datetime
    lieferdat: datetime
    zahlungsziel: datetime
    zahlungseingang: datetime
    mahnung: int
    fk_kunde: int | None = Field(default=None, foreign_key="kunde.kd_nr")
    fk_shop: int


class Bestellposition(SQLModel, table=True):
    fk_auftrag: int | None = Field(default=None, primary_key=True)
    position: int
    fk_artikel: int
    anzahl: int

# ----------------------------------------
# Pydantic-Modelle für den Request
# ----------------------------------------



class KundeCreate(BaseModel):
    vorname: str
    nachname: str
    strasse: str
    plz: str  # Wird hier nicht gespeichert, aber akzeptiert
    ort: str
    vorwahl: str
    telefon: str
    geburtsdatum: date
    ledig: int
    rabatt: float


class AuftragCreate(BaseModel):
    fk_shop: int


class BestellpositionCreate(BaseModel):
    fk_artikel: int
    position: int
    anzahl: int


class BestellungRequest(BaseModel):
    kunde: KundeCreate
    auftrag: AuftragCreate
    bestellpositionen: List[BestellpositionCreate]


class Test_Auth(BaseModel):             # makes the http-Body matches the expected
    username : str
    password : str


# ----------------------------------------
# Datenbankverbindung und FastAPI-Setup
# ----------------------------------------

DATABASE_URL = "postgresql://postgres_user:postgres_pw@192.168.178.52:5432/postgres"
engine = create_engine(DATABASE_URL, echo=True)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"             # https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/#hash-and-verify-the-passwords
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()



# ----------------------------------------
# GET alle Kunden
# ----------------------------------------

# @app.get("/kunden_all/", response_model=List[Kunde])
# def get_users(session: Session = Depends(get_session)):
#     kunden = session.exec(select(Kunde)).all()
#     return kunden

# ----------------------------------------
# POST: Bestellung anlegen
# ----------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"sub":data.get("username"), "exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str) -> TokenData:                       #hier wird definiert, dass der Rückgabetyp vom Typ TokenData ist
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise ValueError("sub fehlt")
        return TokenData(username=username)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungültig oder abgelaufen",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        

@app.post("/login/")
async def login(data:Test_Auth):
    #user_data = request.json()
    #token:str=Depends(oauth2_scheme)
    username = data.username
    password = data.password
    data_dict = data.model_dump()                   # muss dict sein um in create_access_token() genutzt zu werden
    if username != 'test' or password != 'test':
        return status.HTTP_403_FORBIDDEN
    else:
        access_token = create_access_token(data_dict)
        return {"access_token":access_token, "token_type":"bearer"}




def get_session():
    with Session(engine) as session:
        yield session

@app.post("/service_a/", status_code=status.HTTP_201_CREATED)
def create_bestellung(
    bestellung: BestellungRequest,
    token: str = Depends(oauth2_scheme),         # Zugriffsschutz
    session: Session = Depends(get_session)      # DB-Verbindung
):
    current_user = verify_access_token(token)    # Token validieren
    
    bestehender_kunde = session.exec(
        select(Kunde).where(
            Kunde.vorname == bestellung.kunde.vorname,
            Kunde.nachname == bestellung.kunde.nachname,
            Kunde.geburtsdatum == bestellung.kunde.geburtsdatum
        )
    ).first()

    if bestehender_kunde:
        kunde = bestehender_kunde
    else:
        # Neue Kundennummer bestimmen
        max_kd = session.exec(select(Kunde.kd_nr).order_by(Kunde.kd_nr.desc())).first()
        neue_kd_nr = (max_kd or 0) + 1

        kunde = Kunde(
            kd_nr=neue_kd_nr,
            vorname=bestellung.kunde.vorname,
            nachname=bestellung.kunde.nachname,
            strasse=bestellung.kunde.strasse,
            plz=bestellung.kunde.plz,
            ort=bestellung.kunde.ort,
            vorwahl=bestellung.kunde.vorwahl,
            telefon=bestellung.kunde.telefon,
            geburtsdatum=bestellung.kunde.geburtsdatum,
            ledig=bestellung.kunde.ledig,
            rabatt=bestellung.kunde.rabatt,
            letzter_zugriff=datetime.now()
        )
        session.add(kunde)
        session.commit()
        session.refresh(kunde)

    # 2. Neue Auftragsnummer bestimmen
    max_auft = session.exec(select(Auftrag.auft_nr).order_by(Auftrag.auft_nr.desc())).first()
    neue_auft_nr = (max_auft or 0) + 1

    heute = datetime.now()
    neuer_auftrag = Auftrag(
        auft_nr=neue_auft_nr,
        bestelldat=heute,
        lieferdat=heute + timedelta(days=3),
        zahlungsziel=heute + timedelta(days=14),
        zahlungseingang=heute,
        mahnung=0,
        fk_kunde=kunde.kd_nr,
        fk_shop=bestellung.auftrag.fk_shop
    )
    session.add(neuer_auftrag)
    session.commit()
    session.refresh(neuer_auftrag)

    # 3. Bestellpositionen anlegen
    for pos in bestellung.bestellpositionen:
        neue_position = Bestellposition(
            fk_auftrag=neuer_auftrag.auft_nr,
            position=pos.position,
            fk_artikel=pos.fk_artikel,
            anzahl=pos.anzahl
        )
        session.add(neue_position)

    session.commit()

    return {
        "message": "Bestellung erfolgreich erstellt",
        "kunde_id": kunde.kd_nr,
        "auftrag_id": neuer_auftrag.auft_nr,
        "anzahl_positionen": len(bestellung.bestellpositionen),
        "hinweis": "Kunde wurde wiederverwendet" if bestehender_kunde else "Neuer Kunde angelegt"
    }



from fastapi import Path

from fastapi import Depends, HTTPException

@app.get("/service_b/{kd_nr}")
#cache(expire=60)
def get_auftraege_inkl_positionen(
    kd_nr: int = Path(..., ge=3, le=800),
    token: str = Depends(oauth2_scheme),  # 🔒 Token aus Authorization-Header holen
    session: Session = Depends(get_session)
):
    # Token prüfen (wirft automatisch 401 bei Fehler)
    current_user = verify_access_token(token)

    # Nur noch, wenn Token gültig ist:
    kunde = session.get(Kunde, kd_nr)
    if not kunde:
        raise HTTPException(status_code=404, detail=f"Kunde mit kd_nr={kd_nr} nicht gefunden.")

    auftraege = session.exec(select(Auftrag).where(Auftrag.fk_kunde == kd_nr)).all()
    if not auftraege:
        return []

    result = []
    for auftrag in auftraege:
        positionen = session.exec(select(Bestellposition).where(Bestellposition.fk_auftrag == auftrag.auft_nr)).all()
        auftrag_dict = {
            "datum": auftrag.bestelldat.strftime("%Y-%m-%d"),
            "fk_shop": auftrag.fk_shop
        }
        for pos in positionen:
            auftrag_dict[f"position {pos.position}"] = [{
                "Anzahl": pos.anzahl,
                "Artikel Nr.": pos.fk_artikel
            }]
        result.append({f"Auftrag {auftrag.auft_nr}": auftrag_dict})

    return result