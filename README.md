# SentinelAI

SentinelAI 🛡️🤖 Proyecto de Tesis: Detección de Intrusiones con Autoencoders y Deep Learning

Este repositorio contiene la arquitectura de entrenamiento e inferencia de SentinelAI. El sistema utiliza redes neuronales (Autoencoders) para aprender patrones de tráfico normal y detectar anomalías en tiempo real.

## 🛠️ Configuración del Entorno de Desarrollo

Para garantizar que el motor de IA utilice la aceleración por hardware (NVIDIA CUDA), el entorno corre dentro de un contenedor Docker.

### 1. Requisitos Previos
* **NVIDIA Driver:** Instalado y funcional en el host (`nvidia-smi`).
* **NVIDIA Container Toolkit:** Configurado para Docker.
* **Dataset:** Los archivos CSV del dataset CIC-IDS2017.

### 2. Preparación de los Datos
Debido a su peso, el dataset no está en el repo. Hay que descargar los archivos desde Kaggle - Network Intrusion Dataset.
Mové los CSV a la siguiente ruta dentro del repo: `SentinelAI/SentinelAI-Model/data/`

### 3. Ejecución del Laboratorio (Jupyter Lab)
Desde la carpeta raíz del proyecto, ejecutá el siguiente comando para levantar el entorno con soporte GPU:

```bash
docker run -it --rm --runtime=nvidia --gpus all \
  -v $(pwd)/SentinelAI-Model:/tf/notebooks \
  -p 8888:8888 \
  tensorflow/tensorflow:latest-gpu-jupyter
```

*(Nota: Si no tenés una GPU NVIDIA, podés usar la imagen `tensorflow/tensorflow:latest-jupyter` omitiendo los flags de runtime y gpus).*

## 🧠 Lógica del Modelo actual
El modelo aprende a reconstruir el tráfico benigno (lunes). La detección se basa en el Error de Reconstrucción. Si el error supera un umbral $\tau$, se considera tráfico anómalo:

$$L(x, \hat{x}) = \|x - \hat{x}\|^2 > \tau$$
