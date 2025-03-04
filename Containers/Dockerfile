# Usar la imagen base de Ubuntu
FROM ubuntu:latest

# Establecer el directorio de trabajo
WORKDIR /root

# Actualizar el sistema e instalar las dependencias necesarias
RUN apt-get update && apt-get install -y \
    sudo \
    wget \
    vim \
    nano \
    net-tools \
    curl \
    git \
    iputils-ping \
    software-properties-common \
    && sudo add-apt-repository ppa:deadsnakes/ppa \
    && sudo apt-get update \
    && sudo apt-get install -y \
    python3.9 \
    python3.9-dev \
    python3.9-distutils

# Descargar y ejecutar el script para instalar pip
RUN wget https://bootstrap.pypa.io/get-pip.py \
    && sudo python3.9 get-pip.py

# Instalar Mininet
RUN sudo apt-get install -y mininet

# Desinstalar eventlet y setuptools, luego instalar las versiones especificadas
RUN pip uninstall -y eventlet \
    && sudo pip uninstall -y setuptools \
    && pip install setuptools==67.6.1 \
    && pip install ryu \
    && pip install eventlet==0.30.2

# Limpiar el caché de apt y pip para reducir el tamaño de la imagen
RUN sudo apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm get-pip.py

# Exponer el puerto necesario (si es necesario para Mininet o ryu)
EXPOSE 6633

# Definir el comando predeterminado para el contenedor (puedes ajustarlo según tu caso)
CMD ["bash"]
