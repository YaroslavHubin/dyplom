import base64
from pymongo import MongoClient
import pymongo
from cfg import name
import os

name_db = os.getenv("MONGO_URL", "mongodb://localhost:27017/solar_system")

def save_to_mongodb(encrypted_data):
    """
    Зберігає зашифровані дані у MongoDB.
    encrypted_data: байти (ciphertext із libsodium Box.encrypt)
    timestamp: рядок часу
    """
    # Підключення до MongoDB
    client = pymongo.MongoClient(name_db)
    db = client["solar_system"]
    collection = db["encrypted_data"]

    # Формуємо документ
    encrypted_doc = {
        "ciphertext": base64.b64encode(encrypted_data).decode()
    }

    # Запис у БД
    collection.insert_one(encrypted_doc)
    print("Збережено у БД:", encrypted_doc)
