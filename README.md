# INFORME DE INTELIGENCIA DE AMENAZAS (CTI) - CAMPAÑA Gh0stRAT CONTRA CIUDADANOS CHINOS EN EL EXTRANJERO

**Fecha de producción:** 2 de septiembre de 2026  
**Clasificación:** TL:AMBER / CONFIDENCIAL  
**Estado:** Amenaza activa - nivel de campaña  
**Fuentes:** @OpcodeIntel, @Panda_Sec_Intel, VirusTotal Graph, Unit 42, AbuseIPDB, IPinfo, MalwareBazaar, CERT China, Trend Micro, Breakglass Intelligence  

---

## 1. RESUMEN EJECUTIVO

El 1 de septiembre de 2026, el investigador **@OpcodeIntel** publicó el hallazgo de un archivo RAR malicioso con nombre `Provided_for_Chinese_citizens_overseas_to_register_their_personal.rar`, observado desde **Corea**, que contenía un ejecutable con el mismo nombre temático. El señuelo imita el sistema oficial de registro voluntario de ciudadanos chinos en el extranjero del **Ministerio de Asuntos Exteriores de China** ("出国及海外中国公民自愿登记").

El análisis del **grafo de VirusTotal**, complementado con inteligencia de **Unit 42 (Palo Alto Networks)**, **AbuseIPDB** y **MalwareBazaar**, revela que **no es un caso aislado**. Se trata de una **campaña orquestada y a gran escala** que utiliza una infraestructura centralizada en torno a la IP `137.220.156.123` (Cloudbays, Hong Kong), con **múltiples dominios, variantes de droppers y una red de C2 dinámica** que incluye servicios No-IP.

El payload final es **Gh0stRAT** (también conocido como Farfli), un RAT de código abierto filtrado en 2008, ampliamente utilizado por actores **China-nexus** durante más de una década. El análisis de correlación sugiere vínculos con los grupos de amenazas **SilverFox** (también conocido como "游蛇"/"谷堕大盗") y **Dragon Breath (APT-Q-27 / GoldenEyeDog)**, ambos conocidos por utilizar Gh0stRAT y ValleyRAT (Winos4.0) contra objetivos de habla china.

**Evaluación de riesgo: CRÍTICO.** El señuelo es de alta credibilidad, el RAT proporciona control total del sistema y la infraestructura es resilientemente dinámica.

---

## 2. INDICADORES DE COMPROMISO (IOCs) - VOLCADO COMPLETO

### 2.1 Hashes (Fuente: @OpcodeIntel + Grafo VT)

| Tipo | Hash | Descripción |
|------|------|-------------|
| **MD5** | `9c6e7c81222c0b4f1fb04a6cbeb4c636` | RAR: `Provided_for_Chinese_citizens_overseas_to_register_their_personal.rar` |
| **MD5** | `8bd5c0ff6ac0491da96e078ca55a523b` | EXE: `Provided for Chinese citizens overseas to register their personal travel information.exe` |

**Hashes SHA256 de archivos que contactaron la IP o están en la cadena de dropeo (extraídos del grafo):**

```
012f336f87a96ee17687ae9563b5f60825245e10c6c0ef8fae5924cb3b0972fd
014ea1b9dc35bed386cee106b485def2d555cb7ce7dab1ef98ee117cd410d626
041b2f35494315269b51f983184e7623f8da91149a8d8cb8f15188956f360e2d
05ffb39604fab02c45993f1cc1d5c72ab76cf9f4c4a55573a7fd18f276103aa5
087aec8513f7403c824240f72c49252b7186d470556f39ef636f314530c4d5ac
09305dd1035cdf891888eab1ea84a2843a21a87118c59f4de767dd4861a082d3
0978f97be6140f69fde963bab9c3dbbfa7c19d8e20765fa180b61d6bc34a32d7
0b93c43de54d2fe4d870006860f20b2361316303433579ff842cb90f01bc563f
0dc6fad1746ee03fec1ec1244016fc2b9a61f4447e4d084282b59a069a769e10
0ff1fae41e00898c40d05e5a82bdb106da2b9d9fe1999fbef1a429fd5bc3024e
10a0dc2daf8a9dfc0d954b15bbed8eb7f395d8416cca09eb55b0149dd484ef80
12002bfac721b3b581fa05f35f25775fcfd016d047e3fa257dc7a4bd827ff48d
14873f36dffd266f571cdc79ffcfb94637232fe9694d4982c37cd09e2cb0ef86
183320ae79a0d4c2866cee39f5e6274320a78b01deb98022332589864bdd980c
1909ed1cb096be3a04c0c42db0c1d0817eb87421fc30249be05e8200d4e8b5a6
19b5b03fdb111d4d86e1cba228c6715b07d5bf794fd00b638319dbf42d64aa04
1c42d4909990237c77aec29ab9d834fa2d567f19bfde4b5577f1d22df6aafa68
1ce6e7eb6d19611daacf5747b6e47fef488e67d19fd3fb7d2eb79dbb96365875
1e57d53888a07044322e95af70f1c4e9332a7d0bad80bf48a844aafd56a68859
1e7a7cf87fad4c2fd29547514d3065311246037efbbb734bbef0e0f2fd85a73f  <-- MAIN DROPPER
7e05aa9dbd9bf463a6834302c32c52ae9f38336a2a6f0a4df67c6caeecc963dc
33c36482001685de57da8f9acfcedcfba0f907a2d877f5763bd86e32f68b2deb
69515318caceab8d0758fb7dfe708bb7014c3aae6ed403e0b1e23ad3c22959ad
be9a385ac36ec9104a3a74c6a2b58a333907e7836e5c7336531b77a0fa413a9b
6e31e8e4b914e4ef265c5be41ca2ecabfc71f2cd261004c47f14b570a8eef2a7
b671c247d7b2689b3dff360ef02afcb72dd796727b3a23bd2953bffb77aa7383
3858d50d83595b1148e6861679e5ec8b08afc7bd2bf65d43dc64139f94c30b48
bc5fa29bcccb9cb04f5506b1c134b30a33400a38384935ec30d6f73892087947
2c1b3d3e7e2c6a2cc21429b129b96d698d000b9c3ae3a2f6b2fbe38b4f46ae0d
9e954910fe2a146dd31e9f7303eb11e4a11cc35da74dd3dc371a88a75e22a0e1
```

### 2.2 IPs (Central + CDNs/Telemetría)

**IP C2 principal (CRÍTICA):**
- `137.220.156.123` (Cloudbays / BGPNET, AS4907, Hong Kong/Singapur)

**Otras IPs observadas en el grafo (CDNs, Azure, Akamai):**
- `162.159.36.2`, `224.0.0.251`, `23.195.81.59`, `23.195.81.73`, `20.101.57.9`
- `151.101.1.91`, `151.101.129.91`, `151.101.193.91`, `151.101.65.91`
- `104.40.149.189`, `23.55.236.132-143`, `13.107.226.57`, `13.107.253.57`
- `150.171.109.116/146/150`, `150.171.110.146/211`, `23.11.32.159`
- `13.107.226.69/70`, `13.107.253.70`, `150.171.109.115/184/73`
- `150.171.110.2/4`, `23.55.236.131/137/141`

### 2.3 Dominios (Completos, desde el grafo)

**Resuelven directamente a 137.220.156.123:**
```
babyy5.com
www.babyy5.com
babyyyi.com
336.fhshjw.cn
501.trslyw.cn
wap-dyh.fhshjw.cn
www.trslyw.cn
ybsktw.cn
rdsynw.cn
kkomok0m.ylsrfw.cn
jjl7.ylsrfw.cn
jhl1hhh7.ylsrfw.cn
o6kk.ylsrfw.cn
ljljll.ylsrfw.cn
984.jjswjw.cn
wap-crg.qsskhw.cn
4g-wc.qsskhw.cn
314.qsskhw.cn
wap-wt.qsskhw.cn
rrs.qsskhw.cn
```

**Dominios de collections (tu solicitud + otros del cluster):**
```
bhagavatirannade.org
ahmediye.net
afkootruegup.no-ip.org
4dexports.com
aanparshnh.com
aatcwo.biz
abbeveifep.no-ip.org
aewrhprres.com
againstshake.net
agreementsoup.info
aj.0x0x0x0x0.best
al-somow.com
althawry.org
amnsreiuojy.ru
amsamex.com
amuvicib.no-ip.org
anegafacolis.no-ip.org
animo.br
ankara-cambalkon.net
aocuoikhanhlinh.vn
api.cryptauth.net
a.ste-pdffiller.lat
adobeacrobat.portal-nota.sbs
aglobaconvite.com
api-metadata-v6.is
api.apimanagehost.com
api.paste.gg
api.rq-rp.com
api.wisemansupport.com
apple-pie.in
apzzls.biz
ara-photos.net
arthur.niria.biz
avonmiode.no-ip.org
apkafe.com
app-discorder.com
arimaexim.com
asruteiradicdap.no-ip.org
atepeget.no-ip.org
azurhay.shop
babeboru.no-ip.org
babyy2.com
banwyw.biz
beardiscovery.xyz
beliofifsalomu.no-ip.org
bettercapitalinc.com
betterservice.net
```

### 2.4 Nombres de Archivos (Indicios de Ingeniería Social)

- `Provided_for_Chinese_citizens_overseas_to_register_their_personal.rar`
- `Provided for Chinese citizens overseas to register their personal travel information.exe`

---

## 3. ANÁLISIS DE INFRAESTRUCTURA

### 3.1 IP 137.220.156.123

| Atributo | Detalle |
|----------|---------|
| **Rango** | 137.220.156.0/24 |
| **Proveedor** | Cloudbays, 15/F, Tower 1, New Town Central Plaza, 138 Shatin Rural Committee Road, Hong Kong |
| **ASN** | AS4907 - BGPNET PTE. LTD. |
| **Estado** | ALLOCATED NON-PORTABLE |
| **Email de abuso** | `abuse@cloudbays.com` (reportado como inválido) |
| **Uso** | Data Center/Web Hosting/Transit |

**Actividad maliciosa confirmada en el rango:**
- `137.220.158.188`: 15 reportes en AbuseIPDB (55% confianza), 116 escaneos de puertos, 32 ataques SSH.
- `137.220.136.161`: asociada a "Unknown RAT" en Maltiverse.

### 3.2 Estructura de C2

El grafo muestra una arquitectura jerárquica:
1. **Nivel 1:** IP central `137.220.156.123` (C2 principal).
2. **Nivel 2:** Dominios primarios que resuelven a esa IP (`babyy5.com`, `.cn`, etc.).
3. **Nivel 3:** Subdominios DDNS (`*.no-ip.org`) para failover y evasión.
4. **Nivel 4:** Collections que agrupan decenas de dominios adicionales, indicando un pool de infraestructura rotativa.

---

## 4. ANÁLISIS DEL MALWARE (Gh0stRAT)

### 4.1 Descripción

Gh0stRAT (Farfli) es un RAT de código abierto filtrado en 2008. Se ha utilizado extensivamente en espionaje (GhostNet) y cibercrimen. Sus capacidades incluyen:

- Control remoto completo (shell, ejecución de comandos)
- Keylogging y captura de pantalla
- Manipulación de archivos y procesos
- Persistencia (claves Run, servicios)
- Comunicación TCP cifrada (Zlib) y en variantes modernas, WebSocket.

### 4.2 Comportamiento del Dropper

El ejecutable de 21.39 MB está etiquetado en VT como `trojan`, `dropper`, `spreader`, `peexe`, `executes-dropped-file`, `overlay`. Detectado por 31/70 antivirus, con firmas como `TrojanDropper`, `Win64:MalwareX-gen`, `Trojan:Win32/Ravantar`. El dropper desempaqueta el payload de Gh0stRAT en el sistema.

### 4.3 TTPs (MITRE ATT&CK)

- **Entrega:** T1566 - Phishing de ingeniería social.
- **Ejecución:** T1059 - PowerShell no interactivo.
- **Persistencia:** T1547 - Claves de registro Run/RunOnce.
- **Evasión:** T1027 - Ofuscación, T1574.002 - DLL Side-loading.
- **C2:** T1095 - Protocolo de capa no-aplicación, uso de WebSocket en variantes.
- **Exfiltración:** T1048 - Exfiltración por C2.

---

## 5. ATRIBUCIÓN Y CORRELACIONES

### 5.1 Perfil del Actor

El patrón de infraestructura, señuelos en chino, uso de Gh0stRAT/ValleyRAT y ubicación en Hong Kong apunta a **SilverFox** (游蛇/谷堕大盗) o **Dragon Breath (APT-Q-27 / GoldenEyeDog)**.

**SilverFox:**
- **Operación:** Malware-as-a-Service (MaaS).
- **Tácticas:** Suplantación de marcas, SEO poisoning, phishing.
- **Malware:** Gh0stRAT, ValleyRAT (Winos4.0), HoldingHands, RustyStealer.
- **Infraestructura:** Múltiples cloud providers (Alibaba, Tencent, AWS HK, Vultr, Azure, Huawei), hub en Hong Kong.
- **Objetivos:** Usuarios de habla china, diáspora, organizaciones en Taiwán y Norteamérica.

**Dragon Breath (GoldenEyeDog):**
- **Operación:** APT de cibercrimen.
- **Tácticas:** DLL side-loading, firmas de código robadas (comprometieron DigiCert en abril 2026), PPL abuse.
- **Malware:** Gh0stRAT modificado, RONINGLOADER.
- **Infraestructura:** Certificados robados para firmar malware.
- **Objetivos:** Usuarios de habla china, juegos de azar, servicios financieros.

### 5.2 Evidencia de Correlación

| Evidencia | SilverFox | Dragon Breath | Esta campaña |
|-----------|-----------|---------------|--------------|
| Gh0stRAT/ValleyRAT | ✅ | ✅ | ✅ |
| Señuelos en chino | ✅ | ✅ | ✅ |
| Hong Kong como hub | ✅ | ❌ | ✅ |
| Múltiples dominios .cn | ✅ | ❌ | ✅ |
| DLL side-loading | ❌ | ✅ | Probable |
| WebSocket C2 | ❌ | ✅ | Posible |

### 5.3 Motivación

- Recolección de datos personales de la diáspora china.
- Vigilancia de actividades de la comunidad china en el extranjero.
- Acceso persistente a sistemas de valor (posible espionaje económico).
- Potencial extorsión o uso de datos para chantaje.

---

## 6. EVALUACIÓN DE RIESGO

| Factor | Nivel | Justificación |
|--------|-------|---------------|
| **Severidad** | **CRÍTICO** | Gh0stRAT proporciona control total del sistema |
| **Alcance** | **ALTO** | Dirigido a toda la diáspora china (millones) |
| **Credibilidad del señuelo** | **MUY ALTO** | Imita servicio legítimo del gobierno chino |
| **Detección** | **MEDIO** | 31/70 en VT (algunos AV no detectan) |
| **Persistencia** | **ALTO** | Establece persistencia en el sistema |
| **Resiliencia** | **ALTO** | Múltiples dominios, DDNS, multi-ASN |
| **Movimiento lateral** | **MEDIO** | Posible propagación en organizaciones |

**Riesgo general: CRÍTICO**

---

## 7. RECOMENDACIONES DE SEGURIDAD

### 7.1 Bloqueo Inmediato

**Nivel de Red (Firewall/Proxy/IDS/IPS):**
- Bloquear IP `137.220.156.123` y todo el rango `137.220.0.0/24`.
- Bloquear dominios: `babyy5.com`, `babyyyi.com`, `bhagavatirannade.org`, `ahmediye.net`, `afkootruegup.no-ip.org` y todos los listados en el punto 2.3.
- Bloquear todos los dominios `*.no-ip.org` y `*.ylsrfw.cn`, `*.qsskhw.cn`.

**Nivel de Endpoint (EDR/AV):**
- Bloquear hashes MD5: `9c6e7c81222c0b4f1fb04a6cbeb4c636`, `8bd5c0ff6ac0491da96e078ca55a523b`.
- Implementar reglas YARA para Gh0stRAT (incluidas en el apéndice).
- Monitorear creación de claves de registro `Run` y `RunOnce`, servicios de Windows, y procesos hijos de PowerShell.

### 7.2 Búsqueda Activa (Threat Hunting)

- **Archivos:** Nombre que contengan "register", "personal", "travel", "information", "Chinese", "citizens".
- **Red:** Conexiones a la IP/dominios listados, User-Agent "MSIE 7.0" en sistemas modernos.
- **Procesos:** PowerShell no interactivo, creación de EXEs en `%TEMP%` o `%APPDATA%`.
- **DNS:** Consultas a `*.no-ip.org`, `*.ylsrfw.cn`, `*.qsskhw.cn`.

### 7.3 Educación

- Advertir a usuarios sobre archivos que imiten trámites del Ministerio de Asuntos Exteriores de China o la APP "China Consular". El registro oficial es vía canales legítimos (`.gov.cn` o APP oficial), **nunca** mediante `.rar/.exe` no solicitados.

### 7.4 Respuesta a Incidentes

1. Aislar host de la red.
2. Recopilar memoria/disco.
3. Rotar credenciales del usuario afectado.
4. Notificar según procedimientos.
5. Analizar logs de red para identificar posibles conexiones a otros hosts.
6. Verificar persistencia (claves de registro, servicios, tareas programadas).

### 7.5 Compartición de Inteligencia

- Compartir IOCs con **MalwareBazaar**, **VirusTotal**, **MISP**.
- Reportar abuso a **Cloudbays** (`abuse@cloudbays.com`) aunque es inválido; reportar a registradores de dominios y a **CERT China/CNCERT**.

---

## 8. APÉNDICES

### Apéndice A: Reglas de Detección

**YARA (Gh0stRAT Dropper):**
```
rule Gh0stRAT_Dropper {
    meta:
        description = "Detects Gh0stRAT dropper"
        author = "CTI Team"
        date = "2026-09-02"
    strings:
        $s1 = "Gh0st" wide
        $s2 = "RAT" wide
        $s3 = "Register" wide
        $s4 = "Personal" wide
        $s5 = "Travel" wide
    condition:
        uint16(0) == 0x5A4D and (any of ($s*))
}
```

**Sigma (Conexión C2):**
```
title: Gh0stRAT C2 Connection
status: experimental
description: Detects connections to Gh0stRAT C2 infrastructure
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestinationIp:
            - "137.220.156.123"
            - "137.220.0.0/24"
        DestinationPort:
            - 6658
            - 6520
            - 3201
    condition: selection
```

### Apéndice B: Línea de Tiempo de la Campaña

| Fecha | Evento |
|-------|--------|
| 2008 | Código fuente de Gh0stRAT filtrado |
| Jun 2024 | Winos4.0 (ValleyRAT) documentado por Trend Micro |
| Feb-Mar 2025 | Campaña Trio: 2.000+ dominios suplantan 3 marcas |
| May 2025 | Campaña Chorus: suplantación de 40+ aplicaciones |
| Nov 2025 | RONINGLOADER desplegado por Dragon Breath |
| Abr 2026 | Dragon Breath compromete DigiCert |
| Abr 2026 | SilverFox expande campañas ValleyRAT/Gh0stRAT |
| 1 Sep 2026 | @OpcodeIntel publica hallazgo del señuelo chino |
| 2 Sep 2026 | Análisis del grafo revela infraestructura masiva |

---

## 9. CONCLUSIÓN

La campaña de Gh0stRAT identificada **no es un incidente aislado**, sino parte de un **ecosistema criminal maduro y bien organizado** que opera desde hace años contra objetivos de habla china. El uso de un señuelo de alta credibilidad (registro de ciudadanos chinos en el extranjero), combinado con una infraestructura **resiliente y dinámica** (múltiples dominios, DDNS, multi-ASN), demuestra un **nivel de sofisticación significativo**.

La correlación con los grupos **SilverFox** y **Dragon Breath (APT-Q-27)** sugiere que esta campaña podría ser operada por **el mismo ecosistema de actores** que han estado activos en 2025-2026.

**Recomendación final:** Tratar con **máxima prioridad**. Bloquear inmediatamente todos los IOCs, realizar búsqueda activa y compartir inteligencia con la comunidad.

---
