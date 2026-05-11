from fastapi import FastAPI, Request
import sqlite3
import json

app = FastAPI()
SQLITE3 = "ip_reputations.sql3"
JSON_FILE = "../../core/databases/ip-reputation.json"

def InitDB():
    db_connect = sqlite3.connect(SQLITE3)
    cursor = db_connect.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reputations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            ip_address TEXT UNIQUE,
            score INTEGER
        )
    """)

    db_connect.commit()
    db_connect.close()

@app.on_event("startup")
async def startup():
    InitDB()

@app.get("/ip-reputations")
async def GetReputations():
    db_connect = sqlite3.connect(SQLITE3)
    cursor = db_connect.cursor()

    cursor.execute("SELECT name, ip_address, score FROM reputations")

    rows = cursor.fetchall()

    db_connect.close()

    return [
        {
        "name":row[0],
        "ip_address":row[1],
        "score":row[2],
        } for row in rows
    ]

@app.post("/ip-reputations")
async def PostReputations(request: Request):
    data = await request.json()

    db_connect = sqlite3.connect(SQLITE3)
    cursor = db_connect.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO reputations (name, ip_address, score) VALUES (?,?,?)",
        (data["name"],data["ip_address"],data["score"])
    )

    db_connect.commit()
    db_connect.close()

    return{
        "message":"Inersted Succesfully",
        "ip_address": data["ip_address"],
    }

@app.get("/convert")
async def Convert():
    db_connect = sqlite3.connect(SQLITE3)
    cursor = db_connect.cursor()

    cursor.execute("SELECT name, ip_address, score FROM reputations")
    rows = cursor.fetchall()

    data = [
        {
            "name":k,
            "ip_address":v,
            "score":m
        } for k,v,m in rows
    ]

    with open(JSON_FILE, "w") as file:
        json.dump(data, file, indent=4)
    
    return{
        "message": "Done converting SQLITE3 to JSON",
        "data":data
    }