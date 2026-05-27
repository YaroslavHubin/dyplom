from flask import Flask, render_template, redirect, url_for, request, session, Response
import base64, json, pymongo
from nacl.signing import VerifyKey, SigningKey
from nacl.public import PrivateKey, PublicKey, Box
from cfg import name
from datetime import datetime
import os
import pymongo

app = Flask(__name__)
app.secret_key = "supersecretkey"

mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/solar_system")
client = pymongo.MongoClient(mongo_url)
db = client["solar_system"]
collection = db["encrypted_data"]

USER_PUBLIC_KEY_HEX = "e31895b179f4718d4a79ec395d30385050afd2397b7d005b2f28bcaebf26e077"
verify_key = VerifyKey(bytes.fromhex(USER_PUBLIC_KEY_HEX))


@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form["password"]
        signature_hex = request.form["signature"]

        message = b"login_request"

        try:
            signature = bytes.fromhex(signature_hex)
            verify_key.verify(message, signature)
            if password == "securepass":
                session["user"] = "authorized"
                return redirect(url_for("index"))
            else:
                return "Невірний пароль"
        except Exception:
            return "Невірний цифровий підпис"
    return render_template("login.html")


@app.route("/set_keys", methods=["POST"])
def set_keys():
    if "user" not in session:
        return redirect(url_for("login"))

    server_public_hex = request.form["server_public_key"].strip()
    user_private_hex = request.form["user_private_key"].strip()

    # Зберігаємо ключі у сесії
    session["server_public_key"] = server_public_hex
    session["user_private_key"] = user_private_hex

    return redirect(url_for("index"))

@app.route("/export_logs", methods=["POST"])
def export_logs():
    if "user" not in session:
        return redirect(url_for("login"))

    user_private_hex = request.form.get("user_private_key")
    if not user_private_hex:
        return "Не задано приватний ключ для підпису"

    server_public_hex = session.get("server_public_key")
    user_private_hex_for_box = session.get("user_private_key")
    server_pk = PublicKey(bytes.fromhex(server_public_hex))
    user_sk_box = PrivateKey(bytes.fromhex(user_private_hex_for_box))
    box_user = Box(user_sk_box, server_pk)

    logs = []
    for doc in collection.find().sort("_id", -1).limit(50):
        ciphertext_bytes = base64.b64decode(doc["ciphertext"])
        try:
            decrypted = box_user.decrypt(ciphertext_bytes).decode()
            logs.append(json.loads(decrypted))
        except Exception:
            logs.append({"error": "Не вдалося розшифрувати запис"})

    content = json.dumps(logs, ensure_ascii=False, indent=2)

    try:
        user_sk = SigningKey(bytes.fromhex(user_private_hex))
        signature = user_sk.sign(content.encode()).signature.hex()
    except Exception:
        return "Помилка: ключ некоректний! Переконайтесь, що він має довжину 64 hex-символи (32 байти)."

    export_package = {
        "logs": logs,
        "signature": signature
    }

    response = Response(json.dumps(export_package, ensure_ascii=False, indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = "attachment; filename=logs.json"
    return response


@app.route("/verify_import", methods=["POST"])
def verify_import():
    file_content = request.form["file_content"]
    try:
        parsed = json.loads(file_content)
        logs = parsed["logs"]
        signature_hex = parsed["signature"]

        logs_json = json.dumps(logs, ensure_ascii=False, indent=2)

        verify_key = VerifyKey(bytes.fromhex(USER_PUBLIC_KEY_HEX))
        verify_key.verify(logs_json.encode(), bytes.fromhex(signature_hex))

        return "Файл автентичний. Підпис збігається."
    except Exception as e:
        return f"Підпис недійсний або файл змінено!"
    



@app.route("/stats", methods=["GET", "POST"])
def stats():
    if "user" not in session:
        return redirect(url_for("login"))

    sensor = request.args.get("sensor", "INA226")
    start_date_str = request.args.get("start_date", "")
    end_date_str = request.args.get("end_date", "")

    def parse_input_date(date_str):
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                return datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
            except ValueError:
                return None

    start_date = parse_input_date(start_date_str) if start_date_str.strip() else None
    end_date = parse_input_date(end_date_str) if end_date_str.strip() else None

    server_public_hex = session.get("server_public_key")
    user_private_hex = session.get("user_private_key")

    if not server_public_hex or not user_private_hex:
        return "Ключі не задані. Перейдіть на головну сторінку і введіть ключі."

    try:
        server_pk = PublicKey(bytes.fromhex(server_public_hex))
        user_sk = PrivateKey(bytes.fromhex(user_private_hex))
        box_user = Box(user_sk, server_pk)

        logs = []
        for doc in collection.find().sort("_id", -1):
            ciphertext_bytes = base64.b64decode(doc["ciphertext"])
            try:
                decrypted = box_user.decrypt(ciphertext_bytes).decode()
                parsed = json.loads(decrypted)

                def parse_ts(ts_str):
                    return datetime.strptime(ts_str, "%Y.%m.%d.%H.%M.%S")

                if sensor in parsed:
                    ts = parse_ts(parsed[sensor]["timestamp"])
                    if (not start_date or ts >= start_date) and (not end_date or ts <= end_date):
                        entry = parsed[sensor].copy()
                        entry["timestamp"] = parsed[sensor]["timestamp"]  # додаємо timestamp
                        logs.append(entry)

                elif isinstance(parsed, list):
                    for entry in parsed:
                        if sensor in entry:
                            ts = parse_ts(entry[sensor]["timestamp"])
                            if (not start_date or ts >= start_date) and (not end_date or ts <= end_date):
                                sensor_entry = entry[sensor].copy()
                                sensor_entry["timestamp"] = entry[sensor]["timestamp"]
                                logs.append(sensor_entry)

            except Exception:
                continue

        stats_data = {}
        if logs:
            for key in logs[0].keys():
                if key != "timestamp":
                    values = [entry[key] for entry in logs if key in entry]
                    stats_data[key] = {
                        "avg": round(sum(values) / len(values), 2),
                        "min": round(min(values), 2),
                        "max": round(max(values), 2)
                    }

    except Exception:
        return "Не вдалося розшифрувати дані. Перевірте ключі."

    return render_template("stats.html",sensor=sensor, stats_data=stats_data, logs=logs, start_date_str=start_date_str, end_date_str=end_date_str)

@app.route("/export_stats", methods=["POST"])
def export_stats():
    if "user" not in session:
        return redirect(url_for("login"))

    user_private_hex = request.form.get("user_private_key")
    if not user_private_hex:
        return "Не задано приватний ключ для підпису"

    server_public_hex = session.get("server_public_key")
    user_private_hex_for_box = session.get("user_private_key")

    if not server_public_hex or not user_private_hex_for_box:
        return "Ключі не задані. Перейдіть на головну сторінку і введіть ключі."

    try:
        server_pk = PublicKey(bytes.fromhex(server_public_hex))
        user_sk_box = PrivateKey(bytes.fromhex(user_private_hex_for_box))
        box_user = Box(user_sk_box, server_pk)

        # Беремо параметри з POST
        sensor = request.form.get("sensor", "INA226")
        start_date_str = request.form.get("start_date", "")
        end_date_str = request.form.get("end_date", "")

        def parse_input_date(date_str):
            try:
                return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
                except ValueError:
                    return None

        start_date = parse_input_date(start_date_str) if start_date_str.strip() else None
        end_date = parse_input_date(end_date_str) if end_date_str.strip() else None

        logs = []
        for doc in collection.find().sort("_id", -1):
            ciphertext_bytes = base64.b64decode(doc["ciphertext"])
            try:
                decrypted = box_user.decrypt(ciphertext_bytes).decode()
                parsed = json.loads(decrypted)

                def parse_ts(ts_str):
                    return datetime.strptime(ts_str, "%Y.%m.%d.%H.%M.%S")

                if sensor in parsed:
                    ts = parse_ts(parsed[sensor]["timestamp"])
                    if (not start_date or ts >= start_date) and (not end_date or ts <= end_date):
                        logs.append(parsed[sensor])
                elif isinstance(parsed, list):
                    for entry in parsed:
                        if sensor in entry:
                            ts = parse_ts(entry[sensor]["timestamp"])
                            if (not start_date or ts >= start_date) and (not end_date or ts <= end_date):
                                logs.append(entry[sensor])
            except Exception:
                continue

        stats_data = {}
        if logs:
            for key in logs[0].keys():
                if key != "timestamp":
                    values = [entry[key] for entry in logs if key in entry]
                    stats_data[key] = {
                        "avg": round(sum(values) / len(values), 2),
                        "min": round(min(values), 2),
                        "max": round(max(values), 2)
                    }

        stats_json = json.dumps(stats_data, ensure_ascii=False)
        user_sk = SigningKey(bytes.fromhex(user_private_hex))
        signature = user_sk.sign(stats_json.encode()).signature.hex()

        export_package = {"stats": stats_data, "signature": signature}
        response = Response(json.dumps(export_package, ensure_ascii=False, indent=2), mimetype="application/json")
        response.headers["Content-Disposition"] = "attachment; filename=stats.json"
        return response

    except Exception as e:
        return "Помилка експорту: " + str(e)

@app.route("/verify_stats_import", methods=["POST"])
def verify_stats_import():
    file_content = request.form["file_content"]
    try:
        parsed = json.loads(file_content)
        stats = parsed["stats"]
        signature_hex = parsed["signature"]

        stats_json = json.dumps(stats, ensure_ascii=False)
        verify_key.verify(stats_json.encode(), bytes.fromhex(signature_hex))
        return "Файл автентичний. Підпис збігається."
    except Exception:
        return "Підпис недійсний або файл змінено!"
    




@app.route("/monitor")
def monitor():
    if "user" not in session:
        return redirect(url_for("login"))

    server_public_hex = session.get("server_public_key")
    user_private_hex = session.get("user_private_key")

    if not server_public_hex or not user_private_hex:
        return "Ключі не задані. Перейдіть на головну сторінку і введіть ключі."

    try:
        server_pk = PublicKey(bytes.fromhex(server_public_hex))
        user_sk = PrivateKey(bytes.fromhex(user_private_hex))
        box_user = Box(user_sk, server_pk)

        docs = collection.find().sort("_id", -1).limit(20)
        data = []
        for doc in docs:
            ciphertext_bytes = base64.b64decode(doc["ciphertext"])
            decrypted = box_user.decrypt(ciphertext_bytes).decode()
            parsed = json.loads(decrypted)
            data.append(parsed)
    except Exception:
        return "Не вдалося розшифрувати дані. Перевірте ключі."

    return render_template("monitor.html", data=data)



@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))

    server_public_hex = session.get("server_public_key")
    user_private_hex = session.get("user_private_key")

    if not server_public_hex or not user_private_hex:
        return "Ключі не задані. Перейдіть на головну сторінку і введіть ключі."
    
    sort_by = request.args.get("sort_by", "timestamp")
    order = request.args.get("order", "asc")

    sensor_filter = request.args.get("sensor")

    try:
        server_pk = PublicKey(bytes.fromhex(server_public_hex))
        user_sk = PrivateKey(bytes.fromhex(user_private_hex))
        box_user = Box(user_sk, server_pk)

        logs = []
        for doc in collection.find().sort("_id", -1).limit(50):
            ciphertext_bytes = base64.b64decode(doc["ciphertext"])
            try:
                decrypted = box_user.decrypt(ciphertext_bytes).decode()
                parsed = json.loads(decrypted)

                if isinstance(parsed, list):
                    for entry in parsed:
                        for sensor, values in entry.items():
                            if sensor_filter and sensor != sensor_filter:
                                continue
                            logs.append({
                                "timestamp": values.get("timestamp"),
                                "sensor": sensor,
                                "data": {k: v for k, v in values.items() if k != "timestamp"}
                            })
                elif isinstance(parsed, dict):
                    for sensor, values in parsed.items():
                        if sensor_filter and sensor != sensor_filter:
                            continue
                        logs.append({
                            "timestamp": values.get("timestamp"),
                            "sensor": sensor,
                            "data": {k: v for k, v in values.items() if k != "timestamp"}
                        })
            except Exception:
                logs.append({"error": "Не вдалося розшифрувати запис"})

        reverse = (order == "desc")
        if sort_by == "timestamp":
            logs.sort(key=lambda x: x.get("timestamp", ""), reverse=reverse)
        elif sort_by == "sensor":
            logs.sort(key=lambda x: x.get("sensor", ""), reverse=reverse)
        elif sort_by == "data":
            logs.sort(key=lambda x: str(x.get("data", "")), reverse=reverse)

    except Exception:
        return "Не вдалося розшифрувати дані. Перевірте ключі."

    return render_template("logs.html", logs=logs, sort_by=sort_by, order=order, sensor_filter=sensor_filter)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5088, debug=True)
