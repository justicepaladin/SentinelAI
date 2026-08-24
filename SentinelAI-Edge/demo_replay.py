import pandas as pd
import requests
import time
import sys

# Configuración
API_URL = "http://localhost:8000/ingest"
# Ruta relativa a tu dataset del miércoles (que tiene ataques DoS)
CSV_FILE = "../SentinelAI-Model/data/Wednesday-workingHours.pcap_ISCX.csv" 

def main():
    print("[*] Cargando dataset para el Replay (Nivel 1)...")
    try:
        # Cargamos el CSV y limpiamos espacios en los nombres de las columnas
        df = pd.read_csv(CSV_FILE)
        df.columns = df.columns.str.strip()
    except FileNotFoundError:
        print(f"[!] Error: No se encontró el archivo {CSV_FILE}")
        print("[!] Chequeá que la ruta sea correcta según dónde estés ejecutando el script.")
        sys.exit(1)

    # Filtramos para tener una muestra desbalanceada realista (80 benignos, 20 ataques)
    try:
        benignos = df[df['Label'] == 'BENIGN'].sample(80, random_state=42)
        maliciosos = df[df['Label'] != 'BENIGN'].sample(20, random_state=42)
        # Unimos y mezclamos las filas aleatoriamente
        muestra = pd.concat([benignos, maliciosos]).sample(frac=1).reset_index(drop=True)
    except KeyError:
        print("[!] Error: No se encontró la columna 'Label'.")
        sys.exit(1)

    print("[+] Dataset preparado. Iniciando inyección de 100 flujos...")
    print("-" * 85)

    for index, fila in muestra.iterrows():
        etiqueta_real = fila['Label']
        
        # Extraemos IPs y puertos si el dataset los tiene, o usamos genéricos
        src_ip = fila.get('Source IP', '192.168.1.100')
        dst_ip = fila.get('Destination IP', '10.0.0.1')
        dst_port = int(fila.get('Destination Port', 80))

        # Quitamos la etiqueta para que el modelo no haga trampa
        features = fila.drop('Label').to_dict()
        
        payload = {
            "source_ip": str(src_ip),
            "destination_ip": str(dst_ip),
            "destination_port": dst_port,
            "features": features
        }

        try:
            r = requests.post(API_URL, json=payload, timeout=5)
            if r.status_code == 200:
                resultado = r.json()
                mse = resultado.get('mse_score', 0)
                es_anomalia = resultado.get('anomaly', False)

                # Formato visual para que se luzca en la consola
                if es_anomalia:
                    marca_ia = "🚨 ANOMALÍA DETECTADA"
                else:
                    marca_ia = "🟢 NORMAL"

                print(f"[{index+1:03d}] REAL: {etiqueta_real:<15} | IA: {marca_ia:<20} | MSE: {mse:.6f}")
            else:
                print(f"[-] Error HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[-] Error aislando el flujo {index}: {str(e)}")

        # Pausa para dar el efecto de flujo en tiempo real (regulalo a tu gusto)
        time.sleep(0.3)

if __name__ == "__main__":
    main()