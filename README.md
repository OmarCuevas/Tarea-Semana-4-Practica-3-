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

---

# Topología de laboratorio (VLANs, interfaces, direccionamiento)

> Ajusta esta sección a tu topología real en PNETLab (o Packet Tracer/GNS3).  
> Aquí te dejo una base **clara para documentar**.

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

