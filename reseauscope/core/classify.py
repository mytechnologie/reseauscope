"""Identification du type d'équipement à partir du fabricant MAC, des ports ouverts et du nom d'hôte."""
from __future__ import annotations

import re
from dataclasses import dataclass

CAMERA = "Caméra / NVR"
ACCESS = "Contrôle d'accès"
ALARM = "Alarme / intrusion"
INTERCOM = "Interphone / VoIP"
HOME = "Domotique / IoT"
NETWORK = "Réseau (routeur, switch, Wi-Fi)"
NAS = "Stockage (NAS)"
PRINTER = "Imprimante"
COMPUTER = "Ordinateur / serveur"
MOBILE = "Mobile / multimédia"
VIRTUAL = "Machine virtuelle"
INDUSTRIAL = "Automate / bâtiment"
UNKNOWN = "Inconnu"

CATEGORY_ICONS = {
    CAMERA: "📷", ACCESS: "🚪", ALARM: "🚨", INTERCOM: "📞", HOME: "🏠", NETWORK: "🌐", NAS: "💾",
    PRINTER: "🖨", COMPUTER: "💻", MOBILE: "📱", VIRTUAL: "🧊", INDUSTRIAL: "🏭", UNKNOWN: "❔",
}

# (motif regex sur le nom du fabricant IEEE, {catégorie: poids}, marque affichée)
VENDOR_RULES: list[tuple[str, dict[str, int], str]] = [
    # Vidéosurveillance
    (r"hikvision", {CAMERA: 10, ACCESS: 2, INTERCOM: 2}, "Hikvision"),
    (r"ezviz", {CAMERA: 10}, "Ezviz (Hikvision)"),
    (r"dahua", {CAMERA: 10, ACCESS: 2, INTERCOM: 2}, "Dahua"),
    (r"axis communications", {CAMERA: 10, ACCESS: 2, INTERCOM: 2}, "Axis"),
    (r"hanwha|samsung techwin", {CAMERA: 10}, "Hanwha Vision (Wisenet)"),
    (r"vivotek", {CAMERA: 10}, "Vivotek"),
    (r"uniview", {CAMERA: 10}, "Uniview"),
    (r"mobotix", {CAMERA: 10, INTERCOM: 3}, "Mobotix"),
    (r"i-pro co", {CAMERA: 10}, "i-PRO (Panasonic)"),
    (r"reolink", {CAMERA: 10}, "Reolink"),
    (r"amcrest", {CAMERA: 10}, "Amcrest"),
    (r"lorex", {CAMERA: 10}, "Lorex"),
    (r"tvt co", {CAMERA: 10}, "TVT"),
    (r"milesight", {CAMERA: 8, HOME: 3}, "Milesight"),
    (r"flir", {CAMERA: 9}, "FLIR"),
    (r"digital watchdog", {CAMERA: 10}, "Digital Watchdog"),
    (r"verkada", {CAMERA: 9, ACCESS: 4}, "Verkada"),
    (r"rhombus", {CAMERA: 10}, "Rhombus"),
    (r"geovision", {CAMERA: 10, ACCESS: 3}, "GeoVision"),
    (r"iqinvision", {CAMERA: 10}, "IQinVision"),
    (r"arecont", {CAMERA: 10}, "Arecont Vision"),
    (r"costar", {CAMERA: 8}, "Costar"),
    (r"speco", {CAMERA: 9}, "Speco"),
    (r"everfocus", {CAMERA: 10}, "EverFocus"),
    (r"idis co", {CAMERA: 10}, "IDIS"),
    (r"hunt electronic", {CAMERA: 9}, "Hunt"),
    (r"honeywell video", {CAMERA: 10}, "Honeywell Video"),
    (r"wyze", {CAMERA: 8, HOME: 4}, "Wyze"),
    (r"arlo technology", {CAMERA: 10}, "Arlo"),
    (r"blink by amazon", {CAMERA: 10}, "Blink"),
    (r"watchguard video", {CAMERA: 8}, "WatchGuard Video"),
    # Contrôle d'accès
    (r"hid corporation|hid global", {ACCESS: 10}, "HID"),
    (r"mercury security", {ACCESS: 10}, "Mercury Security"),
    (r"lenels2", {ACCESS: 10}, "LenelS2"),
    (r"genetec", {ACCESS: 6, CAMERA: 6}, "Genetec"),
    (r"suprema", {ACCESS: 10}, "Suprema"),
    (r"zkteco|zk tech", {ACCESS: 10}, "ZKTeco"),
    (r"paxton", {ACCESS: 10}, "Paxton"),
    (r"keyscan|dormakaba|dorma", {ACCESS: 10}, "dormakaba / Keyscan"),
    (r"rosslare", {ACCESS: 10}, "Rosslare"),
    (r"cdvi", {ACCESS: 10}, "CDVI"),
    (r"brivo", {ACCESS: 10}, "Brivo"),
    (r"openpath", {ACCESS: 10}, "Openpath (Avigilon Alta)"),
    (r"salto systems", {ACCESS: 10}, "SALTO"),
    (r"assa abloy", {ACCESS: 10}, "ASSA ABLOY"),
    (r"bosch access", {ACCESS: 10}, "Bosch Access"),
    (r"inner range", {ACCESS: 8, ALARM: 8}, "Inner Range"),
    (r"integrated control tech", {ACCESS: 8, ALARM: 8}, "ICT (Protege)"),
    (r"vanderbilt", {ACCESS: 8, ALARM: 6}, "Vanderbilt"),
    (r"doorking", {ACCESS: 10}, "DoorKing"),
    (r"chamberlain", {ACCESS: 7, HOME: 5}, "Chamberlain / LiftMaster"),
    (r"nuki", {ACCESS: 6, HOME: 6}, "Nuki"),
    (r"august home|yale", {ACCESS: 6, HOME: 6}, "August / Yale"),
    # Alarme
    (r"paradox security", {ALARM: 10}, "Paradox"),
    (r"^dsc corporation|digital security controls", {ALARM: 10}, "DSC"),
    (r"risco", {ALARM: 10}, "RISCO"),
    (r"ajax systems", {ALARM: 10}, "Ajax"),
    (r"napco", {ALARM: 10, ACCESS: 4}, "Napco"),
    (r"resideo|honeywell security|honeywell life", {ALARM: 9, HOME: 3}, "Honeywell / Resideo"),
    (r"alarm\.com", {ALARM: 9, HOME: 5}, "Alarm.com"),
    (r"qolsys", {ALARM: 10}, "Qolsys"),
    (r"2gig", {ALARM: 10}, "2GIG"),
    (r"nortek", {ALARM: 6, HOME: 6}, "Nortek"),
    (r"alula", {ALARM: 10}, "Alula"),
    (r"jablotron", {ALARM: 10}, "Jablotron"),
    (r"inim electronics", {ALARM: 10}, "INIM"),
    (r"bosch security", {CAMERA: 6, ALARM: 6, INTERCOM: 3}, "Bosch Security"),
    (r"somfy", {ALARM: 5, HOME: 7}, "Somfy"),
    (r"johnson controls", {ACCESS: 5, ALARM: 5, INDUSTRIAL: 5}, "Johnson Controls / Tyco"),
    (r"schneider electric fire", {ALARM: 8}, "Schneider Fire & Security"),
    # Interphones / VoIP
    (r"2n telekomunikace", {INTERCOM: 10, ACCESS: 5}, "2N"),
    (r"akuvox", {INTERCOM: 10, ACCESS: 4}, "Akuvox"),
    (r"aiphone", {INTERCOM: 10}, "Aiphone"),
    (r"comelit", {INTERCOM: 10, CAMERA: 3}, "Comelit"),
    (r"urmet", {INTERCOM: 9}, "Urmet"),
    (r"bticino", {INTERCOM: 9, HOME: 5}, "BTicino"),
    (r"fanvil", {INTERCOM: 10}, "Fanvil"),
    (r"grandstream", {INTERCOM: 10}, "Grandstream"),
    (r"yealink", {INTERCOM: 10}, "Yealink"),
    (r"polycom", {INTERCOM: 10}, "Polycom"),
    (r"skybell", {INTERCOM: 8, CAMERA: 6}, "SkyBell"),
    # Domotique / IoT
    (r"espressif", {HOME: 8}, "Espressif (ESP32/ESP8266 : Shelly, Sonoff…)"),
    (r"tuya", {HOME: 10}, "Tuya"),
    (r"signify|philips lighting", {HOME: 10}, "Philips Hue"),
    (r"sonos", {MOBILE: 6, HOME: 6}, "Sonos"),
    (r"nest labs", {HOME: 9, CAMERA: 3}, "Google Nest"),
    (r"ecobee", {HOME: 10}, "ecobee"),
    (r"netatmo", {HOME: 9, CAMERA: 3}, "Netatmo"),
    (r"tado", {HOME: 10}, "tado"),
    (r"crestron", {HOME: 10}, "Crestron"),
    (r"control4", {HOME: 10}, "Control4"),
    (r"savant", {HOME: 10}, "Savant"),
    (r"lutron electronics", {HOME: 10}, "Lutron"),
    (r"legrand", {HOME: 8}, "Legrand"),
    (r"hager", {HOME: 8}, "Hager"),
    (r"loxone", {HOME: 10}, "Loxone"),
    (r"nabu casa", {HOME: 10}, "Home Assistant (Nabu Casa)"),
    (r"knx", {HOME: 8, INDUSTRIAL: 4}, "KNX"),
    (r"gira", {HOME: 8}, "GIRA"),
    (r"albrecht jung", {HOME: 8}, "JUNG"),
    (r"xiaomi", {MOBILE: 5, HOME: 5}, "Xiaomi"),
    # Automates / bâtiment
    (r"wago", {INDUSTRIAL: 10}, "WAGO"),
    (r"beckhoff", {INDUSTRIAL: 10}, "Beckhoff"),
    (r"siemens", {INDUSTRIAL: 8}, "Siemens"),
    (r"^abb", {INDUSTRIAL: 8}, "ABB"),
    (r"schneider electric", {INDUSTRIAL: 8}, "Schneider Electric"),
    # Réseau
    (r"ubiquiti", {NETWORK: 9, CAMERA: 3, ACCESS: 2}, "Ubiquiti (UniFi)"),
    (r"cisco", {NETWORK: 10}, "Cisco"),
    (r"routerboard|mikrotik", {NETWORK: 10}, "MikroTik"),
    (r"tp-link", {NETWORK: 8, HOME: 3}, "TP-Link"),
    (r"netgear", {NETWORK: 9}, "Netgear"),
    (r"aruba", {NETWORK: 10}, "Aruba (HPE)"),
    (r"fortinet", {NETWORK: 10}, "Fortinet"),
    (r"juniper networks", {NETWORK: 10}, "Juniper"),
    (r"d-link", {NETWORK: 8, CAMERA: 3}, "D-Link"),
    (r"zyxel", {NETWORK: 10}, "Zyxel"),
    (r"ruckus", {NETWORK: 10}, "Ruckus"),
    (r"cambium", {NETWORK: 10}, "Cambium"),
    (r"sonicwall", {NETWORK: 10}, "SonicWall"),
    (r"watchguard tech", {NETWORK: 10}, "WatchGuard"),
    (r"sophos", {NETWORK: 10}, "Sophos"),
    (r"palo alto", {NETWORK: 10}, "Palo Alto"),
    (r"extreme networks", {NETWORK: 10}, "Extreme Networks"),
    (r"edgecore", {NETWORK: 10}, "Edgecore"),
    (r"teltonika", {NETWORK: 10}, "Teltonika"),
    (r"peplink", {NETWORK: 10}, "Peplink"),
    (r"draytek", {NETWORK: 10}, "DrayTek"),
    (r"eero", {NETWORK: 10}, "eero"),
    (r"arris|technicolor|sagemcom|vantiva|hitron|calix|fiberhome|sercomm", {NETWORK: 9}, "Box FAI"),
    (r"huawei", {NETWORK: 6, MOBILE: 5}, "Huawei"),
    (r"asustek|asus network", {NETWORK: 5, COMPUTER: 5}, "ASUS"),
    (r"linksys", {NETWORK: 10}, "Linksys"),
    # NAS / imprimantes
    (r"synology", {NAS: 10}, "Synology"),
    (r"qnap", {NAS: 10}, "QNAP"),
    (r"brother ind", {PRINTER: 10}, "Brother"),
    (r"seiko epson", {PRINTER: 10}, "Epson"),
    (r"xerox", {PRINTER: 10}, "Xerox"),
    (r"lexmark", {PRINTER: 10}, "Lexmark"),
    (r"ricoh", {PRINTER: 10}, "Ricoh"),
    (r"kyocera document", {PRINTER: 10}, "Kyocera"),
    (r"canon", {PRINTER: 7, CAMERA: 2}, "Canon"),
    # Ordinateurs / mobiles / VM
    (r"dell", {COMPUTER: 9}, "Dell"),
    (r"lenovo", {COMPUTER: 8}, "Lenovo"),
    (r"^hp inc|hewlett packard", {COMPUTER: 6, PRINTER: 5}, "HP"),
    (r"intel corp", {COMPUTER: 7}, "Intel"),
    (r"microsoft", {COMPUTER: 6}, "Microsoft"),
    (r"raspberry pi", {COMPUTER: 6, HOME: 5}, "Raspberry Pi"),
    (r"apple", {MOBILE: 6, COMPUTER: 5}, "Apple"),
    (r"samsung electronics", {MOBILE: 7}, "Samsung"),
    (r"google", {MOBILE: 6, HOME: 5}, "Google"),
    (r"amazon technologies|amazon\.com", {HOME: 7, MOBILE: 4}, "Amazon (Echo, Ring, Fire TV…)"),
    (r"vmware", {VIRTUAL: 10}, "VMware"),
    (r"proxmox", {VIRTUAL: 10}, "Proxmox"),
]
_COMPILED = [(re.compile(p, re.I), w, b) for p, w, b in VENDOR_RULES]

# Port ouvert -> indices
PORT_HINTS: dict[int, dict[str, int]] = {
    554: {CAMERA: 6, INTERCOM: 2}, 8554: {CAMERA: 5}, 10554: {CAMERA: 5},
    8000: {CAMERA: 3}, 37777: {CAMERA: 8}, 37778: {CAMERA: 6}, 34567: {CAMERA: 8}, 34599: {CAMERA: 6},
    6036: {CAMERA: 6}, 8899: {CAMERA: 4}, 1935: {CAMERA: 2},
    4370: {ACCESS: 9}, 4025: {ALARM: 9}, 10000: {ALARM: 2},
    5060: {INTERCOM: 5}, 5061: {INTERCOM: 5},
    1883: {HOME: 5}, 8883: {HOME: 4}, 8123: {HOME: 8}, 1880: {HOME: 6}, 6668: {HOME: 8},
    9999: {HOME: 4}, 1400: {MOBILE: 6}, 8008: {MOBILE: 3}, 8009: {MOBILE: 4},
    502: {INDUSTRIAL: 7}, 102: {INDUSTRIAL: 7}, 4840: {INDUSTRIAL: 7}, 47808: {INDUSTRIAL: 7},
    9100: {PRINTER: 9}, 515: {PRINTER: 6}, 631: {PRINTER: 5},
    5000: {NAS: 2}, 5001: {NAS: 4}, 548: {NAS: 3},
    3389: {COMPUTER: 7}, 445: {COMPUTER: 4}, 135: {COMPUTER: 4}, 5985: {COMPUTER: 5},
    62078: {MOBILE: 9}, 5555: {MOBILE: 5},
    8291: {NETWORK: 9}, 8728: {NETWORK: 8}, 7547: {NETWORK: 6}, 10001: {NETWORK: 3}, 53: {NETWORK: 3},
}

# Mots-clés dans le nom d'hôte, la bannière ou le titre web
TEXT_HINTS: list[tuple[str, dict[str, int]]] = [
    (r"\b(nvr|dvr|xvr|ipc|ipcam|network camera|webcam|ds-2cd|ds-7|ds-9|dh-ipc|ipc-h|netsurveillance|"
     r"web service|camera|caméra|hikvision|dahua|onvif|wisenet|axis)\b", {CAMERA: 7}),
    (r"\b(access|door|porte|zkteco|acs|controller|lenel|mercury|suprema|biostar|keyscan|paxton)\b", {ACCESS: 6}),
    (r"\b(alarm|alarme|paradox|ip150|envisalink|risco|ajax|panel|neo|powerseries)\b", {ALARM: 6}),
    (r"\b(intercom|interphone|doorbell|sip|voip|yealink|fanvil|2n)\b", {INTERCOM: 5}),
    (r"\b(home assistant|hassio|homeassistant|shelly|sonoff|tasmota|esphome|hue|tuya|zigbee|node-red)\b", {HOME: 7}),
    (r"\b(router|routeur|switch|unifi|mikrotik|routeros|openwrt|pfsense|opnsense|fortigate|gateway)\b", {NETWORK: 6}),
    (r"\b(synology|diskstation|qnap|nas)\b", {NAS: 7}),
    (r"\b(printer|imprimante|laserjet|officejet|deskjet|mfp|jetdirect)\b", {PRINTER: 7}),
    (r"\b(desktop-|laptop-|win-)\w|\b(ubuntu|debian|microsoft-iis)\b", {COMPUTER: 4}),
    (r"\b(iphone|ipad|android|galaxy|pixel|chromecast|roku|appletv|apple-tv)\b", {MOBILE: 7}),
]
_TEXT = [(re.compile(p, re.I), w) for p, w in TEXT_HINTS]


@dataclass
class Identification:
    category: str = UNKNOWN
    brand: str = ""
    confidence: str = ""      # Élevée / Moyenne / Faible
    reasons: str = ""

    @property
    def label(self) -> str:
        return f"{CATEGORY_ICONS.get(self.category, '')} {self.category}".strip()


def vendor_brand(vendor: str) -> tuple[str, dict[str, int]]:
    for rx, weights, brand in _COMPILED:
        if rx.search(vendor or ""):
            return brand, weights
    return "", {}


def identify(vendor: str = "", ports: list[int] | None = None, texts: list[str] | None = None,
             random_mac: bool = False) -> Identification:
    scores: dict[str, int] = {}
    reasons: list[str] = []

    def add(weights: dict[str, int], why: str):
        for cat, w in weights.items():
            scores[cat] = scores.get(cat, 0) + w
        reasons.append(why)

    brand, weights = vendor_brand(vendor)
    if weights:
        add(weights, f"MAC : {brand}")
    if random_mac:
        add({MOBILE: 4, COMPUTER: 2}, "MAC aléatoire")
    for p in ports or []:
        if p in PORT_HINTS:
            add(PORT_HINTS[p], f"port {p}")
    blob = " ".join(t for t in (texts or []) if t)
    if blob:
        for rx, w in _TEXT:
            m = rx.search(blob)
            if m:
                add(w, f"« {m.group(0)} »")
    if not scores:
        return Identification(UNKNOWN, brand, "", "")
    cat, best = max(scores.items(), key=lambda kv: kv[1])
    conf = "Élevée" if best >= 12 else "Moyenne" if best >= 7 else "Faible"
    return Identification(cat, brand, conf, ", ".join(dict.fromkeys(reasons)))
