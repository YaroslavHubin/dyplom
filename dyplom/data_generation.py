import time
import random
import datetime
import numpy as np

def generate_ina226_data():
    current_hour = datetime.datetime.now().hour
    
    params = {
        "Pmax": 211.8,
        "Vmp": 33.1,
        "Imp": 6.4,
        "Voc": 35.4,
        "Isc": 7.6
    }
    
    # Ніч: генерація = 0
    if current_hour >= 20 or current_hour < 8:
        data = {key: 0.0 for key in params}
    
    # Світанок: плавне зростання (08:00–09:00)
    elif 8 <= current_hour < 9:
        factor = (current_hour - 8) + datetime.datetime.now().minute/60.0
        factor = min(factor, 1.0)  # від 0 до 1
        data = {key: round(np.random.normal(loc=val*factor, scale=val*0.02), 2) for key, val in params.items()}
    
    # День: нормальна генерація (09:00–18:00)
    elif 9 <= current_hour < 18:
        data = {key: round(np.random.normal(loc=val, scale=val*0.02), 2) for key, val in params.items()}
    
    # Захід: плавне спадання (18:00–20:00)
    elif 18 <= current_hour < 20:
        factor = 1 - ((current_hour - 18) + datetime.datetime.now().minute/60.0)
        factor = max(factor, 0.0)  # від 1 до 0
        data = {key: round(np.random.normal(loc=val*factor, scale=val*0.02), 2) for key, val in params.items()}
    
    # Додаємо timestamp
    data["timestamp"] = datetime.datetime.now().strftime("%Y.%m.%d.%H.%M.%S")
    return data

def generate_pzem017_data():
    voltage = np.random.normal(loc=220, scale=5)
    current = np.random.normal(loc=5, scale=2)
    current = max(current, 0)
    power = voltage * current
    data = {
        "Voltage": round(voltage, 2),
        "Current": round(current, 2),
        "Power": round(power, 2),
        "timestamp": datetime.datetime.now().strftime("%Y.%m.%d.%H.%M.%S")
    }
    return data

if __name__ == "__main__":
    while True:
        ina_data = generate_ina226_data()
        pzem_data = generate_pzem017_data()
        
        print("INA226:", ina_data)
        print("PZEM017:", pzem_data)
        print("-"*50)
        
        time.sleep(random.randint(5, 10))
