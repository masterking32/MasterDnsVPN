# 🚀 MasterDnsVPN

## [نسخه فارسی](https://github.com/masterking32/MasterDnsVPN/blob/main/README_FA.MD) | [English Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README.MD) | [Spanish Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README_ES.MD)


MasterDnsVPN es una herramienta de tunelización DNS de alto rendimiento diseñada para encapsular el tráfico VPN en consultas DNS. Este proyecto está diseñado específicamente para eludir la estricta censura de la red y los firewalls donde se bloquean los protocolos VPN tradicionales.

Cuenta con una implementación personalizada de **ARQ (solicitud de repetición automática)**, que garantiza una confiabilidad similar a la de TCP y un ordenamiento de paquetes a través del protocolo DNS basado en UDP, que es inherentemente poco confiable.

---

⭐ Si te parece útil o interesante este proyecto, ¡por favor apóyalo dándole una estrella al repositorio! ⭐

---

## ✨ Características principales
- 🛡️ **Elusión de censura:** Aprovecha el protocolo DNS para canalizar el tráfico a través de entornos restringidos.
- 🔐 **Seguridad robusta:** Admite múltiples métodos de cifrado, incluyendo XOR, AES-128-GCM, AES-192-GCM y AES-256-GCM.
- ⚙️ **Gestión inteligente de MTU:** Sondea y sincroniza automáticamente la unidad máxima de transmisión (MTU) óptima tanto para carga como para descarga.
- 🔄 **Protocolo ARQ personalizado:** Soluciona problemas de pérdida de paquetes y entrega desordenada con retransmisión dinámica y control de flujo.
- ⚡ **Balanceo de carga del solucionador:** Admite múltiples solucionadores DNS con estrategias de balanceo adaptativo (aleatorio, round-robin, mejor pérdida).
- 🌐 **Multiplexación TCP:** Permite multiplexar múltiples conexiones TCP locales en una sola sesión DNS.

---

## 🛠️ Network Prerequisites (DNS Configuration)

To make the tunnel functional, you must own a domain and configure the following records in your DNS management panel (e.g., Cloudflare):

1. **A Record:** Create an **A** record pointing to your server's public IP.
   - Example: `s.example.com` -> `1.2.3.4`
2. **NS Record:** Create an **NS** record for your tunnel subdomain pointing to the A record created above.
   - Example: `v.example.com` -> `s.example.com`

> 💡 **Pro Tip:** The shorter your domain and subdomain names are (e.g., `v.ex.com`), the more space remains for actual data payloads in each DNS packet, significantly increasing throughput.

---

## 📦 Requisitos

- 🐍 Python 3.7 o superior
- 🔐 cryptography  (Requerida para métodos de cifrado AES)
- 📝 loguru  (Para un registro mejorado)

---

## 🚀 Instalación y uso

### 1. Instalar dependencias

Clonar el repositorio e instalar las bibliotecas de Python necesarias:
```bash
git clone https://github.com/masterking32/MasterDnsVPN.git
cd MasterDnsVPN
pip install -r requirements.txt
```

### 2. Configuración del servidor

Copie la configuración de ejemplo:

```bash
cp server_config.py.simple server_config.py
```

Edite `server_config.py` para incluir su dominio y la IP/Puerto de reenvío de destino.
- Instale un servidor proxy (p. ej., SOCKS5, VLESS, VMESS, SSH, MTProto, OpenVPN TCP, etc.) en el servidor para reenviar el tráfico a internet.
- Configure `FORWARD_IP` y `FORWARD_PORT` en `server_config.py` para que apunten a su servidor proxy.
- Configure `DOMAIN` para que coincida con el subdominio que configuró en sus registros DNS (p. ej., `v.example.com`).
- Después de la primera ejecución, anote los valores óptimos de MTU para descarga y carga, y luego configure `MAX_UPLOAD_MTU` y `MAX_DOWNLOAD_MTU` en `server_config.py` según corresponda. Esto acelerará significativamente las ejecuciones posteriores.

### 3. Ejecutar el servidor

```bash
python server.py
```

En la primera ejecución, el servidor generará una clave de cifrado. Guarde esta clave; la necesitará para configurar el cliente.

### 4. Configurar el cliente

Copie la configuración de ejemplo del cliente:

```bash
cp client_config.py.simple client_config.py
```

Configure client_config.py:

- DOMAINS: Su subdominio de túnel (p. ej., v.example.com).

- ENCRYPTION_KEY: La clave proporcionada por su servidor.

- RESOLVER_DNS_SERVERS: Lista de resolvers DNS públicos (p. ej., 8.8.8.8, 1.1.1.1).

### 5. Ejecutar el cliente

```bash
python client.py
```

---

# 📝 Notas técnicas

- ⚡ Optimización de MTU: Al conectarse, el cliente realiza una búsqueda binaria para encontrar la MTU máxima posible para su ruta específica. Esto garantiza la máxima velocidad sin fragmentación de paquetes.

- 🔄 Sondeo adaptativo: El cliente utiliza mecanismos de retroceso inteligente y comprobación de inactividad para reducir la sobrecarga de DNS cuando no se transmite tráfico.

- 🔒 Cifrado: Si se utilizan métodos AES, se requiere la biblioteca de criptografía. Para dispositivos con recursos limitados, se recomienda XOR (Método 1).

---

## 🛠️ How It Works

```
┌────────────┐      DNS Queries     ┌────────────┐      ┌────────────┐
│  Client    │  <---------------->  │   Server   │ <--> │   Proxy    │
│ (Python)   │    (Encapsulated)    │  (Python)  │      │   Server   │
└────────────┘                      └────────────┘      └────────────┘
```

1. 🗝️ El cliente codifica y cifra los datos de la VPN en consultas DNS.
2. 🔓 El servidor decodifica, descifra y reenvía el tráfico a su servidor proxy local (VLESS/SOCKS5).
3. 🔁 Las respuestas se envían mediante respuestas DNS.

## 🤝 Contribuciones
¡Agradecemos sus contribuciones! Por favor, forkee el repositorio y cree una pull request con sus cambios.

--

## 📄 Licencia
Este proyecto está licenciado bajo la licencia MIT. Consulte el archivo de LICENCIA para obtener más información.

--

## 👨‍💻 Desarrollador
Desarrollado por [MasterkinG32](https://github.com/masterking32)
