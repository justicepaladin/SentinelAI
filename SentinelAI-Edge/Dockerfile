FROM python:3.9-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev gcc
RUN pip install cicflowmeter requests scipy
WORKDIR /app
CMD ["tail", "-f", "/dev/null"]
