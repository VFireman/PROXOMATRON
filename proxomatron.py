#!/usr/bin/env python3
# PROXOMATRON - дашборд-комбайн для Proxmox (Vitastor + Ceph + ZFS + VM/CT + сеть)
# Ребрендинг проекта VitaBOARD 0.0.49 -> PROXOMATRON 0.1.0 (2026-05-27)
# Single-file, stdlib only. Control plane, не data plane.
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
import threading
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VITASTOR_CLI = "/usr/bin/vitastor-cli"
VITASTOR_DISK = "/usr/bin/vitastor-disk"
VITA_PART_GUID = "e7009fac-a5a1-4d72-af72-53de13059903"
ETCDCTL = "/usr/bin/etcdctl"
ETCD_EP = "http://127.0.0.1:2379"
VITASTOR_CONF = "/etc/vitastor/vitastor.conf"
LSBLK = "/usr/bin/lsblk"
SMARTCTL = "/usr/sbin/smartctl"
ZPOOL = "/usr/sbin/zpool"
ZFS = "/usr/sbin/zfs"
CEPH = "/usr/bin/ceph"
PORT = 8080
CACHE_TTL = 2.0
SERIES_LEN = 60
SKIP = ("nbd", "loop", "zram", "ram", "dm-", "sr")
VERSION = "0.1.20"

_cache = {"ts": 0.0, "data": None}
_lock = threading.Lock()
_wiz_lock = threading.Lock()
_disk_cache = {"ts": 0.0, "data": None}
_disk_temp_cache = {"ts": 0.0, "data": {}}
_disk_temp_lock = threading.Lock()
_series = {}
_prev = {}
_series_lock = threading.Lock()
_arc_series = deque(maxlen=SERIES_LEN)
_osddisk = {"ts": 0.0, "map": {}}


# ---------- vitastor ----------
def cli_json(args, timeout=12):
    try:
        p = subprocess.run([VITASTOR_CLI] + args + ["--json"],
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            return None, (p.stderr.strip() or "cli rc=%d" % p.returncode)
        return json.loads(p.stdout or "null"), None
    except Exception as e:
        return None, str(e)


def pg_states_by_pool():
    # читает /vitastor/pg/state/<pool>/<pg> из etcd -> состояния PG по пулам
    res = {}
    try:
        env = dict(os.environ, ETCDCTL_API="3")
        p = subprocess.run([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                            "--prefix", "/vitastor/pg/state/", "-w", "json"],
                           capture_output=True, text=True, timeout=8, env=env)
        if p.returncode != 0:
            return res
        kvs = (json.loads(p.stdout or "{}") or {}).get("kvs") or []
        for kv in kvs:
            key = base64.b64decode(kv.get("key", "")).decode("utf-8", "ignore")
            parts = key.rsplit("/", 2)
            if len(parts) < 3:
                continue
            pool_id, pg = parts[1], parts[2]
            try:
                st = json.loads(base64.b64decode(kv.get("value", "")).decode("utf-8", "ignore"))
            except Exception:
                st = {}
            state = st.get("state") or []
            d = res.setdefault(pool_id, {"total": 0, "by_state": {}, "pgs": []})
            d["total"] += 1
            sk = "+".join(state) if state else "unknown"
            d["by_state"][sk] = d["by_state"].get(sk, 0) + 1
            d["pgs"].append({"pg": pg, "state": state, "primary": st.get("primary")})
        for d in res.values():
            d["pgs"].sort(key=lambda x: int(x["pg"]) if str(x["pg"]).isdigit() else 0)
    except Exception:
        pass
    return res


# ---------- диски ----------
def disks_info():
    try:
        p = subprocess.run([LSBLK, "-J", "-b", "-o",
                            "NAME,TYPE,SIZE,MODEL,TRAN,ROTA,FSTYPE,MOUNTPOINT,"
                            "PARTLABEL,PARTTYPE"],
                           capture_output=True, text=True, timeout=8)
        if p.returncode != 0:
            return None
        devs = json.loads(p.stdout).get("blockdevices", [])
        return [d for d in devs
                if d.get("type") == "disk"
                and not str(d.get("name", "")).startswith(SKIP)]
    except Exception:
        return None


def disks_info_cached():
    now = time.time()
    if _disk_cache["data"] is not None and (now - _disk_cache["ts"]) < 4:
        return _disk_cache["data"]
    d = disks_info()
    _disk_cache["ts"] = now
    _disk_cache["data"] = d
    return d


# SMART-атрибуты, ненулевой raw которых указывает на проблему диска
SMART_CRIT_IDS = {5, 10, 184, 187, 188, 196, 197, 198, 199, 201}


def smart_info(disk):
    """SMART-данные диска через `smartctl --json`: вердикт здоровья + атрибуты."""
    disk = (disk or "").strip()
    if not re.match(r"^[A-Za-z0-9]+$", disk):
        return {"error": "имя диска некорректно"}
    if not os.path.exists(SMARTCTL):
        return {"error": "smartctl не установлен — поставьте пакет smartmontools"}
    dev = "/dev/" + disk
    if not os.path.exists(dev):
        return {"error": "устройство %s не найдено" % dev}

    def probe(extra):
        p = subprocess.run([SMARTCTL, "--json=c", "-H", "-A", "-i"] + extra
                           + [dev], capture_output=True, text=True, timeout=25)
        try:
            return json.loads(p.stdout or "{}")
        except Exception:
            return None

    def has_data(j):
        return bool(j) and (("smart_status" in j)
                            or ("ata_smart_attributes" in j)
                            or ("nvme_smart_health_information_log" in j))

    try:
        j = probe([])
        if not has_data(j):
            j2 = probe(["-d", "sat"])
            if has_data(j2):
                j = j2
    except Exception as e:
        return {"error": "smartctl: " + str(e)}
    if not j:
        return {"error": "не удалось разобрать вывод smartctl"}

    msgs = [m.get("string", "") for m in
            (j.get("smartctl") or {}).get("messages", [])]
    info = {
        "disk": disk, "device": dev,
        "model": j.get("model_name") or j.get("scsi_model_name"),
        "serial": j.get("serial_number"),
        "firmware": j.get("firmware_version"),
        "capacity": (j.get("user_capacity") or {}).get("bytes"),
        "rotation": j.get("rotation_rate"),
        "is_ssd": j.get("rotation_rate") == 0,
        "smart_available": (j.get("smart_support") or {}).get("available"),
        "smart_enabled": (j.get("smart_support") or {}).get("enabled"),
        "health_passed": (j.get("smart_status") or {}).get("passed"),
        "temperature": (j.get("temperature") or {}).get("current"),
        "power_on_hours": (j.get("power_on_time") or {}).get("hours"),
        "power_cycles": j.get("power_cycle_count"),
        "messages": [m for m in msgs if m],
        "attributes": [],
    }
    for a in ((j.get("ata_smart_attributes") or {}).get("table")) or []:
        raw = a.get("raw") or {}
        info["attributes"].append({
            "id": a.get("id"), "name": a.get("name"),
            "value": a.get("value"), "worst": a.get("worst"),
            "thresh": a.get("thresh"),
            "raw": raw.get("string") if raw.get("string") is not None
                   else raw.get("value"),
            "when_failed": a.get("when_failed") or "",
            "crit": a.get("id") in SMART_CRIT_IDS,
        })
    nv = j.get("nvme_smart_health_information_log")
    if nv and not info["attributes"]:
        info["nvme"] = True
        for k, label, crit in (
                ("critical_warning", "Critical Warning", True),
                ("percentage_used", "Percentage Used (%)", False),
                ("available_spare", "Available Spare (%)", False),
                ("media_errors", "Media Errors", True),
                ("unsafe_shutdowns", "Unsafe Shutdowns", False),
                ("num_err_log_entries", "Error Log Entries", False)):
            if k in nv:
                info["attributes"].append({
                    "id": None, "name": label, "value": None,
                    "worst": None, "thresh": None, "raw": nv.get(k),
                    "when_failed": "", "crit": crit})
        if info["temperature"] is None:
            info["temperature"] = nv.get("temperature")
        if info["power_on_hours"] is None:
            info["power_on_hours"] = nv.get("power_on_hours")
    return info


# ---------- сборщик метрик дисков ----------
def read_diskstats():
    out = {}
    try:
        with open("/proc/diskstats") as f:
            for line in f:
                p = line.split()
                if len(p) < 13:
                    continue
                name = p[2]
                if name.startswith(SKIP):
                    continue
                if not os.path.isdir("/sys/block/" + name):
                    continue
                out[name] = {
                    "reads": int(p[3]), "rsect": int(p[5]),
                    "writes": int(p[7]), "wsect": int(p[9]),
                    "ioms": int(p[12]),
                }
    except Exception:
        pass
    return out


def read_arcstats():
    # /proc/spl/kstat/zfs/arcstats -> {name: int}
    out = {}
    try:
        with open("/proc/spl/kstat/zfs/arcstats") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        out[parts[0]] = int(parts[-1])
                    except ValueError:
                        pass
    except Exception:
        return None
    return out or None


def sampler_loop():
    while True:
        now = time.time()
        cur = read_diskstats()
        with _series_lock:
            for name, c in cur.items():
                prev = _prev.get(name)
                _prev[name] = (now, c)
                if name not in _series:
                    _series[name] = deque(maxlen=SERIES_LEN)
                if not prev:
                    continue
                dt = now - prev[0]
                if dt <= 0:
                    continue
                pc = prev[1]
                util = (c["ioms"] - pc["ioms"]) / (dt * 1000.0) * 100.0
                util = max(0.0, min(100.0, util))
                _series[name].append({
                    "t": round(now, 1),
                    "rbps": max(0, round((c["rsect"] - pc["rsect"]) * 512 / dt)),
                    "wbps": max(0, round((c["wsect"] - pc["wsect"]) * 512 / dt)),
                    "riops": max(0, round((c["reads"] - pc["reads"]) / dt)),
                    "wiops": max(0, round((c["writes"] - pc["writes"]) / dt)),
                    "util": round(util, 1),
                })
            for name in list(_series.keys()):
                if name not in cur:
                    _series.pop(name, None)
                    _prev.pop(name, None)
        arc = read_arcstats()
        if arc and "size" in arc:
            with _series_lock:
                _arc_series.append({"t": round(now, 1), "size": arc["size"]})
        time.sleep(1.0)


def diskmon():
    with _series_lock:
        series = {k: list(v) for k, v in _series.items()}
    raw = read_diskstats() or {}
    temps = _disk_temps()
    counters = {}
    for name, c in raw.items():
        counters[name] = {
            "read_bytes": (c.get("rsect") or 0) * 512,
            "write_bytes": (c.get("wsect") or 0) * 512,
            "read_ios": c.get("reads") or 0,
            "write_ios": c.get("writes") or 0,
            "ioms": c.get("ioms") or 0,
            "temp_c": temps.get(name),
        }
    return {"ts": time.time(), "version": VERSION,
            "disks": disks_info_cached(), "series": series,
            "counters": counters}


# ---------- zfs ----------
def _int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _diskname(dev):
    # '/dev/disk/by-id/...-part1' или '/dev/sde1' -> 'sde' (родительский диск)
    try:
        base = os.path.realpath(dev).rsplit("/", 1)[-1]
    except Exception:
        base = dev.rsplit("/", 1)[-1]
    try:
        if os.path.exists("/sys/class/block/%s/partition" % base):
            parent = os.path.basename(
                os.path.dirname(os.path.realpath("/sys/class/block/" + base)))
            if parent and parent != "block":
                return parent
    except Exception:
        pass
    return base


def zpool_topology():
    # парсит `zpool status -P` -> {pool: {type, disks[], vdev_count}}
    res = {}
    try:
        p = subprocess.run([ZPOOL, "status", "-P"],
                           capture_output=True, text=True, timeout=8)
        if p.returncode != 0:
            return res
    except Exception:
        return res
    cur = None
    in_cfg = False
    section = "data"
    for raw in (p.stdout or "").splitlines():
        s = raw.strip()
        if s.startswith("pool:"):
            cur = s.split(":", 1)[1].strip()
            res[cur] = {"vdevs": [], "disks": [], "dstate": {}}
            in_cfg = False
            section = "data"
            continue
        if s == "config:":
            in_cfg = True
            section = "data"
            continue
        if not in_cfg or cur is None:
            continue
        if not s:
            continue
        if raw[:1] not in (" ", "\t"):   # строка без отступа завершает config
            in_cfg = False
            continue
        parts = s.split()
        name = parts[0]
        if name == cur or name == "NAME":
            continue
        low = name.lower()
        if low in ("logs", "cache", "spares", "special", "dedup"):
            section = low
            continue
        if section != "data":
            continue
        state = parts[1] if len(parts) > 1 else ""
        if low.startswith(("mirror", "raidz", "draid")):
            res[cur]["vdevs"].append(low)
        else:
            dn = _diskname(name) if name.startswith("/") else name
            res[cur]["disks"].append(dn)
            res[cur]["dstate"][dn] = state
    szmap = {}
    for dd in (disks_info_cached() or []):
        n, sz = dd.get("name"), dd.get("size")
        if n and sz is not None:
            try:
                szmap[n] = int(sz)
            except (TypeError, ValueError):
                pass
    for d in res.values():
        vd = d["vdevs"]
        if any(v.startswith("mirror") for v in vd):
            d["type"] = "mirror"
        elif any(v.startswith("raidz3") for v in vd):
            d["type"] = "raidz3"
        elif any(v.startswith("raidz2") for v in vd):
            d["type"] = "raidz2"
        elif any(v.startswith("raidz") for v in vd):
            d["type"] = "raidz1"
        elif any(v.startswith("draid") for v in vd):
            d["type"] = "draid"
        elif len(d["disks"]) > 1:
            d["type"] = "stripe"
        elif len(d["disks"]) == 1:
            d["type"] = "single"
        else:
            d["type"] = "unknown"
        d["vdev_count"] = len(vd)
        d["disks"].sort()
        d["diskinfo"] = [{"name": dn, "size": szmap.get(dn),
                          "state": d["dstate"].get(dn, "")}
                         for dn in d["disks"]]
        d.pop("dstate", None)
    return res


def arc_info():
    # сводка кэша ZFS ARC + временной ряд размера
    cur = read_arcstats()
    if not cur or "size" not in cur:
        return {"present": False}
    hits = cur.get("hits", 0)
    misses = cur.get("misses", 0)
    tot = hits + misses
    with _series_lock:
        series = list(_arc_series)
    return {
        "present": True,
        "size": cur.get("size"),
        "c": cur.get("c"),
        "c_max": cur.get("c_max"),
        "c_min": cur.get("c_min"),
        "hits": hits,
        "misses": misses,
        "hit_ratio": round(hits / tot * 100.0, 1) if tot else None,
        "data_size": cur.get("data_size"),
        "metadata_size": cur.get("metadata_size"),
        "series": series,
    }


def zfs_info():
    res = {"installed": True, "pools": [], "datasets": []}
    try:
        p = subprocess.run([ZPOOL, "list", "-Hp", "-o",
                            "name,size,alloc,free,health,capacity,fragmentation"],
                           capture_output=True, text=True, timeout=8)
        for line in (p.stdout or "").strip().splitlines():
            f = line.split("\t")
            if len(f) >= 7:
                res["pools"].append({
                    "name": f[0], "size": _int(f[1]), "alloc": _int(f[2]),
                    "free": _int(f[3]), "health": f[4],
                    "capacity": f[5], "frag": f[6],
                })
    except FileNotFoundError:
        res["installed"] = False
        return res
    except Exception:
        pass
    try:
        p = subprocess.run([ZFS, "list", "-Hp", "-o",
                            "name,used,avail,refer,mountpoint,type,recordsize,volblocksize"],
                           capture_output=True, text=True, timeout=8)
        for line in (p.stdout or "").strip().splitlines():
            f = line.split("\t")
            if len(f) >= 8:
                res["datasets"].append({
                    "name": f[0], "used": _int(f[1]), "avail": _int(f[2]),
                    "refer": _int(f[3]), "mountpoint": f[4], "type": f[5],
                    "recordsize": _int(f[6]), "volblocksize": _int(f[7]),
                })
    except Exception:
        pass
    topo = zpool_topology()
    for pl in res["pools"]:
        pl["topology"] = topo.get(pl["name"]) or {}
    res["arc"] = arc_info()
    return res


# ---------- мастер пулов ZFS ----------
ZFS_MODES = {
    "single":    {"label": "Одиночный (страйп)", "min": 1, "exact": 0},
    "mirror":    {"label": "Зеркало (mirror)", "min": 2, "exact": 0},
    "zr1":       {"label": "RAIDZ1", "min": 3, "exact": 0},
    "zr2":       {"label": "RAIDZ2", "min": 4, "exact": 0},
    "mirror2+2": {"label": "Зеркало 2+2 (страйп из двух зеркал)",
                  "min": 4, "exact": 4},
}


def _zfs_vdev(mode, dpaths):
    """Аргументы vdev для `zpool create` по выбранному режиму избыточности."""
    if mode == "single":
        return list(dpaths)
    if mode == "mirror":
        return ["mirror"] + list(dpaths)
    if mode == "zr1":
        return ["raidz1"] + list(dpaths)
    if mode == "zr2":
        return ["raidz2"] + list(dpaths)
    if mode == "mirror2+2":
        return ["mirror", dpaths[0], dpaths[1],
                "mirror", dpaths[2], dpaths[3]]
    return None


def zfs_wizard_info():
    """Данные для Мастера пулов ZFS: свободные диски + имена существующих пулов."""
    zi = zfs_info()
    return {"installed": zi.get("installed", True),
            "free_disks": free_disks(),
            "pools": [p.get("name") for p in (zi.get("pools") or [])]}


def zfs_create_pool(name, mode, disks):
    """Создать ZFS-пул через `zpool create` в выбранном режиме избыточности."""
    name = (name or "").strip()
    mode = (mode or "").strip()
    disks = [str(d) for d in (disks or [])]
    if not _NAME_RE.match(name):
        return {"ok": False, "results": [],
                "msg": "имя пула: латиница/цифры/_/-, до 32 символов"}
    if name[0].isdigit():
        return {"ok": False, "results": [],
                "msg": "имя пула ZFS не может начинаться с цифры"}
    spec = ZFS_MODES.get(mode)
    if not spec:
        return {"ok": False, "results": [], "msg": "неизвестный режим пула"}
    if len(disks) < spec["min"]:
        return {"ok": False, "results": [],
                "msg": "режим %s требует не менее %d дисков" % (mode, spec["min"])}
    if spec["exact"] and len(disks) != spec["exact"]:
        return {"ok": False, "results": [],
                "msg": "режим %s требует ровно %d диска" % (mode, spec["exact"])}
    zi = zfs_info()
    if name in [p.get("name") for p in (zi.get("pools") or [])]:
        return {"ok": False, "results": [],
                "msg": "пул ZFS «%s» уже существует" % name}
    free = free_disks()
    fset = set(d["path"] for d in free) | set(d["name"] for d in free)
    dpaths = []
    for d in disks:
        p = d if d.startswith("/dev/") else "/dev/" + d
        if d not in fset and p not in fset:
            return {"ok": False, "results": [],
                    "msg": "диск %s занят или не найден среди свободных" % d}
        if p in dpaths:
            return {"ok": False, "results": [],
                    "msg": "диск %s выбран дважды" % d}
        dpaths.append(p)
    vdev = _zfs_vdev(mode, dpaths)
    if vdev is None:
        return {"ok": False, "results": [], "msg": "не удалось собрать vdev"}
    results = []
    r = run_cmd([ZPOOL, "create", "-f", "-o", "ashift=12", name] + vdev,
                timeout=120)
    ok = (r.get("rc") == 0)
    results.append({"title": "Создание пула " + name, "ok": ok,
                    "cmd": r.get("cmd"), "out": r.get("out"),
                    "err": r.get("err")})
    if not ok:
        return {"ok": False, "results": results,
                "msg": "zpool create завершился с ошибкой"}
    st = run_cmd([ZPOOL, "status", name], timeout=15)
    results.append({"title": "Состояние пула", "ok": True,
                    "cmd": st.get("cmd"), "out": st.get("out"), "err": ""})
    return {"ok": True, "results": results,
            "msg": "Пул ZFS «%s» создан — %s." % (name, spec["label"])}


# ---------- управление кэшем ZFS ARC ----------
ARC_MIN_BYTES = 128 * 1024 * 1024            # 128 MiB
ARC_MAX_BYTES = 256 * 1024 * 1024 * 1024     # 256 GiB
ZFS_ARC_MAX = "/sys/module/zfs/parameters/zfs_arc_max"
ZFS_ARC_MIN = "/sys/module/zfs/parameters/zfs_arc_min"
ZFS_MODPROBE = "/etc/modprobe.d/zfs.conf"


def _read_int_file(path):
    try:
        with open(path) as f:
            return int((f.read() or "0").strip())
    except Exception:
        return None


def _hbytes(n):
    n = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return ("%d %s" % (n, u)) if n == int(n) else ("%.1f %s" % (n, u))
        n /= 1024.0


def zfs_cache_info():
    """Состояние кэша ZFS ARC для панели управления."""
    arc = read_arcstats()
    present = bool(arc and "size" in arc) and os.path.exists("/sys/module/zfs")
    persist = None
    try:
        for ln in open(ZFS_MODPROBE):
            m = re.search(r"zfs_arc_max\s*=\s*(\d+)", ln)
            if m:
                persist = int(m.group(1))
    except Exception:
        pass
    try:
        total_ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except Exception:
        total_ram = 0
    return {
        "present": present,
        "size": (arc or {}).get("size", 0),
        "c": (arc or {}).get("c", 0),
        "c_max": (arc or {}).get("c_max", 0),
        "c_min": (arc or {}).get("c_min", 0),
        "arc_max_runtime": _read_int_file(ZFS_ARC_MAX) or 0,
        "arc_max_persist": persist,
        "total_ram": total_ram,
        "min_allowed": ARC_MIN_BYTES,
        "max_allowed": ARC_MAX_BYTES,
    }


def zfs_set_cache(bytes_val):
    """Установить максимальный размер кэша ZFS ARC (runtime + /etc/modprobe.d)."""
    try:
        b = int(bytes_val)
    except Exception:
        return {"ok": False, "results": [],
                "msg": "размер кэша должен быть числом"}
    if b < ARC_MIN_BYTES or b > ARC_MAX_BYTES:
        return {"ok": False, "results": [],
                "msg": "размер кэша вне диапазона 128 MiB – 256 GiB"}
    if not os.path.exists("/sys/module/zfs"):
        return {"ok": False, "results": [],
                "msg": "модуль ZFS не загружен — управление кэшем недоступно"}
    results = []

    def emit(title, ok, cmd="", out="", err=""):
        results.append({"title": title, "ok": ok, "cmd": cmd,
                        "out": out, "err": err})

    cur_min = _read_int_file(ZFS_ARC_MIN) or 0
    if cur_min and cur_min > b:
        try:
            with open(ZFS_ARC_MIN, "w") as f:
                f.write(str(b))
            emit("zfs_arc_min понижен до нового максимума", True,
                 "echo %d > %s" % (b, ZFS_ARC_MIN))
        except Exception as e:
            emit("Понижение zfs_arc_min", False, "", "", str(e))
            return {"ok": False, "results": results,
                    "msg": "не удалось понизить zfs_arc_min"}
    try:
        with open(ZFS_ARC_MAX, "w") as f:
            f.write(str(b))
        emit("Максимум ARC применён (действует сразу)", True,
             "echo %d > %s" % (b, ZFS_ARC_MAX), out=_hbytes(b))
    except Exception as e:
        emit("Применение максимума ARC", False, "", "", str(e))
        return {"ok": False, "results": results,
                "msg": "не удалось записать zfs_arc_max"}
    try:
        lines = []
        if os.path.exists(ZFS_MODPROBE):
            lines = open(ZFS_MODPROBE).read().splitlines()
        lines = [ln for ln in lines if "zfs_arc_max" not in ln]
        lines.append("options zfs zfs_arc_max=%d" % b)
        with open(ZFS_MODPROBE, "w") as f:
            f.write("\n".join(ln for ln in lines if ln.strip()) + "\n")
        emit("Сохранено в %s (вступит в силу после перезагрузки)" % ZFS_MODPROBE,
             True, "options zfs zfs_arc_max=%d" % b)
    except Exception as e:
        emit("Сохранение в zfs.conf", False, "", "", str(e))
        return {"ok": True, "results": results,
                "msg": "максимум кэша применён, но не сохранён в конфиг"}
    return {"ok": True, "results": results,
            "msg": "Максимум кэша ZFS ARC установлен: %s." % _hbytes(b)}


# ---------- ceph ----------
def ceph_info():
    res = {"installed": True, "configured": False}
    try:
        p = subprocess.run([CEPH, "-s", "--format", "json"],
                           capture_output=True, text=True, timeout=9)
        if p.returncode != 0:
            err = (p.stderr or "").strip().splitlines()
            res["error"] = err[-1] if err else "ceph status rc=%d" % p.returncode
            return res
        d = json.loads(p.stdout or "{}")
    except FileNotFoundError:
        res["installed"] = False
        return res
    except Exception as e:
        res["error"] = str(e)
        return res
    res["configured"] = True
    health = d.get("health") or {}
    mon = d.get("monmap") or {}
    osd = d.get("osdmap") or {}
    if isinstance(osd.get("osdmap"), dict):
        osd = osd["osdmap"]
    pg = d.get("pgmap") or {}
    res.update({
        "fsid": d.get("fsid"),
        "health": health.get("status"),
        "mon_num": mon.get("num_mons") if mon.get("num_mons") is not None
                   else len(mon.get("mons") or []),
        "quorum": len(d.get("quorum") or []),
        "osd_num": osd.get("num_osds"),
        "osd_up": osd.get("num_up_osds"),
        "osd_in": osd.get("num_in_osds"),
        "pg_num": pg.get("num_pgs"),
        "pools": pg.get("num_pools"),
        "pgs_by_state": pg.get("pgs_by_state") or [],
        "bytes_total": pg.get("bytes_total"),
        "bytes_used": pg.get("bytes_used"),
        "bytes_avail": pg.get("bytes_avail"),
    })
    return res


# ---------- osd -> диск ----------
def osd_disk_map():
    # {osd_num(str): имя диска} — по разделам с PARTTYPE Vitastor + read-sb
    now = time.time()
    if _osddisk["map"] and (now - _osddisk["ts"]) < 120:
        return _osddisk["map"]
    m = {}
    try:
        p = subprocess.run([LSBLK, "-J", "-b", "-o", "NAME,TYPE,PARTTYPE"],
                           capture_output=True, text=True, timeout=8)
        parts = []

        def walk(nodes):
            for n in nodes:
                if (n.get("parttype") or "").lower() == VITA_PART_GUID:
                    parts.append(n.get("name"))
                walk(n.get("children") or [])

        walk(json.loads(p.stdout or "{}").get("blockdevices", []))
        for part in parts:
            r = subprocess.run([VITASTOR_DISK, "read-sb", "/dev/" + part],
                               capture_output=True, text=True, timeout=6)
            try:
                sb = json.loads(r.stdout or "{}")
            except Exception:
                continue
            on = sb.get("osd_num")
            if on is not None:
                m[str(on)] = _diskname("/dev/" + part)
    except Exception:
        pass
    if m:
        _osddisk["ts"] = now
        _osddisk["map"] = m
    return m


# ---------- конфигурация ----------
def vitastor_conf():
    # /etc/vitastor/vitastor.conf -> сетевые настройки кластера
    try:
        with open(VITASTOR_CONF) as f:
            return json.load(f) or {}
    except Exception:
        return {}


_vita_ver = {"v": None}


def vitastor_version():
    # версия движка Vitastor — из объявленного состояния OSD в etcd (кэш на сессию)
    if _vita_ver["v"]:
        return _vita_ver["v"]
    try:
        env = dict(os.environ, ETCDCTL_API="3")
        p = subprocess.run([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                            "--prefix", "/vitastor/osd/state/", "-w", "json"],
                           capture_output=True, text=True, timeout=8, env=env)
        kvs = (json.loads(p.stdout or "{}") or {}).get("kvs") or []
        for kv in kvs:
            val = json.loads(base64.b64decode(kv.get("value", "")).decode("utf-8", "ignore"))
            if val.get("version"):
                _vita_ver["v"] = val["version"]
                break
    except Exception:
        pass
    return _vita_ver["v"]


def vitastorfs_mounts():
    """Карта: имя пула Vitastor -> точка монтирования VitastorFS.
    Источник — юниты /etc/systemd/system/vitastorfs-*.service."""
    res = {}
    try:
        units = [f for f in os.listdir("/etc/systemd/system")
                 if f.startswith("vitastorfs-") and f.endswith(".service")]
    except Exception:
        units = []
    mounted = set()
    try:
        with open("/proc/mounts") as fh:
            for ln in fh:
                parts = ln.split()
                if len(parts) >= 2:
                    mounted.add(parts[1])
    except Exception:
        pass
    for unit in units:
        try:
            txt = open("/etc/systemd/system/" + unit, "r", errors="ignore").read()
        except Exception:
            continue
        pool = path = img = None
        for ln in txt.splitlines():
            ln = ln.strip()
            if not ln.startswith("ExecStart="):
                continue
            toks = ln.split()
            for i, t in enumerate(toks):
                if t == "--pool" and i + 1 < len(toks):
                    pool = toks[i + 1]
                if t == "--fs" and i + 1 < len(toks):
                    img = toks[i + 1]
                if t == "mount" and i + 1 < len(toks):
                    path = toks[i + 1]
        if not pool or not path:
            continue
        active = False
        try:
            r = subprocess.run(["systemctl", "is-active", unit],
                               capture_output=True, text=True, timeout=4)
            active = (r.stdout.strip() == "active")
        except Exception:
            pass
        res[pool] = {"path": path, "unit": unit, "img": img,
                     "active": active, "mounted": path in mounted}
    return res


# ---------- overview ----------
def build_overview():
    status, e1 = cli_json(["status"])
    pools, e2 = cli_json(["df"])
    osds, e3 = cli_json(["osd-tree"])
    vols, e4 = cli_json(["ls"])
    if isinstance(osds, list):
        dm = osd_disk_map()
        for o in osds:
            if isinstance(o, dict) and o.get("type") == "osd":
                o["disk"] = dm.get(str(o.get("name")))
    if isinstance(pools, list):
        fsm = vitastorfs_mounts()
        for p in pools:
            if isinstance(p, dict):
                mi = fsm.get(p.get("name"))
                if mi:
                    p["mount"] = mi
    return {
        "ts": time.time(),
        "version": VERSION,
        "vitastor": {
            "installed": os.path.exists(VITASTOR_CLI),
            "cp": cp_info(),
            "status": status, "pools": pools, "osds": osds, "volumes": vols,
            "pg": pg_states_by_pool(),
            "config": vitastor_conf(),
            "engine": vitastor_version(),
            "errors": [x for x in (e1, e2, e3, e4) if x],
        },
        "zfs": zfs_info(),
        "ceph": ceph_info(),
    }


def overview_cached():
    now = time.time()
    with _lock:
        if _cache["data"] is not None and (now - _cache["ts"]) < CACHE_TTL:
            return _cache["data"]
    data = build_overview()
    with _lock:
        _cache["ts"] = time.time()
        _cache["data"] = data
    return data


def _os_codename():
    """VERSION_CODENAME из /etc/os-release (для apt-репозитория), по умолчанию trixie."""
    try:
        for ln in open("/etc/os-release", "r", errors="ignore"):
            if ln.startswith("VERSION_CODENAME="):
                cn = ln.strip().split("=", 1)[1].strip().strip('"')
                if cn:
                    return cn
    except Exception:
        pass
    return "trixie"


def vitastor_install():
    """Установка пакетов Vitastor: репозиторий vitastor.io + apt install.
    Кластер (etcd/монитор/OSD) НЕ разворачивается — только пакеты.
    Возвращает {ok, results, msg}."""
    results = []

    def step(title, r):
        ok = (r.get("rc") == 0)
        results.append({"title": title, "ok": ok, "cmd": r.get("cmd"),
                        "out": r.get("out"), "err": r.get("err")})
        return ok

    if os.path.exists(VITASTOR_CLI):
        return {"ok": True, "results": [],
                "msg": "vitastor-cli уже установлен — устанавливать нечего"}

    # 1) GPG-ключ репозитория
    r = run_cmd(["curl", "-fSsL", "https://vitastor.io/debian/pubkey.gpg",
                 "-o", "/etc/apt/trusted.gpg.d/vitastor.gpg"], timeout=60)
    if not step("GPG-ключ репозитория vitastor.io", r):
        return {"ok": False, "results": results,
                "msg": "не удалось скачать ключ репозитория — установка прервана"}

    # 2) apt-репозиторий
    codename = _os_codename()
    repo = "deb https://vitastor.io/debian %s main" % codename
    try:
        with open("/etc/apt/sources.list.d/vitastor.list", "w") as f:
            f.write(repo + "\n")
        results.append({"title": "apt-репозиторий vitastor", "ok": True,
                        "cmd": "write /etc/apt/sources.list.d/vitastor.list",
                        "out": repo, "err": ""})
    except Exception as e:
        results.append({"title": "apt-репозиторий vitastor", "ok": False,
                        "cmd": "write /etc/apt/sources.list.d/vitastor.list",
                        "out": "", "err": str(e)})
        return {"ok": False, "results": results,
                "msg": "не удалось записать файл репозитория — установка прервана"}

    apt_env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    # 3) apt-get update
    step("apt-get update", run_cmd(["apt-get", "update"],
                                   timeout=300, env=apt_env))

    # 4) установка пакетов (pve-storage-vitastor — только на Proxmox)
    pkgs = ["vitastor", "lp-solve", "etcd-server", "etcd-client"]
    if os.path.exists("/usr/bin/pveversion"):
        pkgs.append("pve-storage-vitastor")
    step("apt-get install " + " ".join(pkgs),
         run_cmd(["apt-get", "install", "-y"] + pkgs,
                 timeout=600, env=apt_env))

    # 5) проверка результата
    present = os.path.exists(VITASTOR_CLI)
    results.append({"title": "Проверка vitastor-cli", "ok": present,
                    "cmd": "test -x " + VITASTOR_CLI,
                    "out": (VITASTOR_CLI + " — установлен") if present else "",
                    "err": "" if present
                    else "vitastor-cli не появился после установки"})
    if present:
        return {"ok": True, "results": results,
                "msg": "Vitastor установлен. Пакеты на месте, но кластер "
                       "(etcd + монитор + OSD) ещё не развёрнут — настройте его "
                       "отдельно, затем создавайте пулы Мастером пулов."}
    return {"ok": False, "results": results,
            "msg": "установка завершилась с ошибками — см. лог шагов"}


def _primary_ip():
    """IP основного интерфейса (src маршрута по умолчанию)."""
    try:
        r = subprocess.run(["ip", "-j", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        for row in json.loads(r.stdout or "[]"):
            if row.get("prefsrc"):
                return row["prefsrc"]
    except Exception:
        pass
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True,
                           text=True, timeout=5)
        return (r.stdout or "").split()[0]
    except Exception:
        return ""


def cp_info():
    """Данные для мастера control plane: дефолты + наличие конфига Vitastor."""
    ip = _primary_ip()
    net = (ip.rsplit(".", 1)[0] + ".0/24") if ip.count(".") == 3 else ""
    try:
        node = os.uname().nodename
    except Exception:
        node = "vita"
    return {"node": node, "ip": ip, "network": net,
            "conf": os.path.exists("/etc/vitastor/vitastor.conf")}


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


def _etcd_default(node, ip, force=False):
    """Текст /etc/default/etcd для одноузлового etcd под Vitastor."""
    txt = (
        'ETCD_NAME="%s"\n'
        'ETCD_DATA_DIR="/var/lib/etcd/vitastor"\n'
        'ETCD_ADVERTISE_CLIENT_URLS="http://%s:2379"\n'
        'ETCD_LISTEN_CLIENT_URLS="http://%s:2379,http://127.0.0.1:2379"\n'
        'ETCD_INITIAL_ADVERTISE_PEER_URLS="http://%s:2380"\n'
        'ETCD_LISTEN_PEER_URLS="http://%s:2380"\n'
        'ETCD_INITIAL_CLUSTER="%s=http://%s:2380"\n'
        'ETCD_INITIAL_CLUSTER_TOKEN="vitastor-etcd"\n'
        'ETCD_INITIAL_CLUSTER_STATE="new"\n'
        'ETCD_AUTO_COMPACTION_RETENTION="10"\n'
        'ETCD_AUTO_COMPACTION_MODE="revision"\n'
        'ETCD_MAX_TXN_OPS="100000"\n'
        'ETCD_QUOTA_BACKEND_BYTES="2147483648"\n'
    ) % (node, ip, ip, ip, ip, node, ip)
    if force:
        txt += 'ETCD_FORCE_NEW_CLUSTER="true"\n'
    return txt


def control_plane_setup(node, ip, network):
    """Развернуть control plane Vitastor: одноузловой etcd + vitastor.conf +
    запуск vitastor-mon. Возвращает {ok, results, msg}."""
    node = (node or "").strip()
    ip = (ip or "").strip()
    network = (network or "").strip()
    if not _NODE_RE.match(node):
        return {"ok": False, "results": [], "msg": "имя узла некорректно"}
    if not _IP_RE.match(ip):
        return {"ok": False, "results": [], "msg": "IP-адрес узла некорректен"}
    if not _CIDR_RE.match(network):
        return {"ok": False, "results": [],
                "msg": "сеть OSD: формат X.X.X.X/NN"}
    if not os.path.exists(VITASTOR_CLI):
        return {"ok": False, "results": [],
                "msg": "пакеты Vitastor не установлены — сначала установка"}

    results = []

    def step(title, r):
        ok = (r.get("rc") == 0)
        results.append({"title": title, "ok": ok, "cmd": r.get("cmd"),
                        "out": r.get("out"), "err": r.get("err")})
        return ok

    def note(title, text, ok=True):
        results.append({"title": title, "ok": ok, "cmd": "",
                        "out": text if ok else "", "err": "" if ok else text})

    # 1) остановить стоковый etcd и очистить его данные
    run_cmd(["systemctl", "stop", "etcd"], timeout=60)
    step("Очистка данных etcd",
         run_cmd(["bash", "-c",
                  "rm -rf /var/lib/etcd/default /var/lib/etcd/vitastor && "
                  "mkdir -p /var/lib/etcd/vitastor && "
                  "(chown -R etcd:etcd /var/lib/etcd 2>/dev/null || true)"]))

    # 2) /etc/default/etcd — конфигурация под Vitastor
    try:
        with open("/etc/default/etcd", "w") as f:
            f.write(_etcd_default(node, ip))
        note("/etc/default/etcd", "конфигурация etcd под Vitastor записана")
    except Exception as e:
        note("/etc/default/etcd", str(e), ok=False)
        return {"ok": False, "results": results,
                "msg": "не удалось записать /etc/default/etcd"}

    # 3) /etc/vitastor/vitastor.conf
    try:
        os.makedirs("/etc/vitastor", exist_ok=True)
        with open("/etc/vitastor/vitastor.conf", "w") as f:
            f.write(json.dumps({"etcd_address": "http://%s:2379" % ip,
                                "osd_network": network}, indent=2) + "\n")
        note("/etc/vitastor/vitastor.conf",
             "etcd_address=http://%s:2379, osd_network=%s" % (ip, network))
    except Exception as e:
        note("/etc/vitastor/vitastor.conf", str(e), ok=False)
        return {"ok": False, "results": results,
                "msg": "не удалось записать vitastor.conf"}

    # 4) запуск etcd
    run_cmd(["systemctl", "daemon-reload"])
    step("systemctl enable etcd", run_cmd(["systemctl", "enable", "etcd"]))
    step("systemctl restart etcd",
         run_cmd(["systemctl", "restart", "etcd"], timeout=60))
    time.sleep(4)
    eh = run_cmd(["etcdctl", "--endpoints=http://127.0.0.1:2379",
                  "endpoint", "health"], env=_etcd_env())
    results.append({"title": "Проверка etcd (endpoint health)",
                    "ok": eh.get("rc") == 0, "cmd": eh.get("cmd"),
                    "out": eh.get("out"), "err": eh.get("err")})

    # 5) запуск монитора Vitastor
    step("systemctl enable vitastor-mon",
         run_cmd(["systemctl", "enable", "vitastor-mon"]))
    run_cmd(["systemctl", "reset-failed", "vitastor-mon"])
    step("systemctl restart vitastor-mon",
         run_cmd(["systemctl", "restart", "vitastor-mon"], timeout=60))
    time.sleep(5)
    mon_act = (run_cmd(["systemctl", "is-active",
                        "vitastor-mon"]).get("out") == "active")
    results.append({"title": "Монитор Vitastor активен", "ok": mon_act,
                    "cmd": "systemctl is-active vitastor-mon",
                    "out": "active" if mon_act else "",
                    "err": "" if mon_act
                    else "монитор не поднялся — журнал: journalctl -u "
                         "vitastor-mon"})

    ok = all(x["ok"] for x in results)
    return {"ok": ok, "results": results,
            "msg": ("Control plane развёрнут — etcd и монитор Vitastor "
                    "работают. Дальше добавьте диски как OSD и создайте пул "
                    "через Мастер пулов.") if ok
            else "развёртывание завершилось с ошибками — см. лог шагов"}


def _osd_units():
    """Инстансы vitastor-osd@N на узле (из systemd)."""
    r = run_cmd(["systemctl", "list-units", "--all", "--no-legend",
                 "--plain", "vitastor-osd@*.service"])
    units = []
    for ln in (r.get("out") or "").splitlines():
        tok = ln.strip().split()
        if tok and tok[0].startswith("vitastor-osd@") \
                and tok[0].endswith(".service"):
            units.append(tok[0])
    return units


def cluster_info():
    """Текущая конфигурация кластера для Мастера кластера."""
    conf = {}
    try:
        conf = json.loads(open("/etc/vitastor/vitastor.conf").read() or "{}")
    except Exception:
        pass
    ea = conf.get("etcd_address") or ""
    if isinstance(ea, list):
        ea = ea[0] if ea else ""
    net = conf.get("osd_network") or ""
    if isinstance(net, list):
        net = net[0] if net else ""
    m = re.search(r"https?://([0-9.]+):", str(ea))
    cur_ip = m.group(1) if m else ""
    node = ""
    try:
        for ln in open("/etc/default/etcd"):
            if ln.startswith("ETCD_NAME="):
                node = ln.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    if not node:
        try:
            node = os.uname().nodename
        except Exception:
            node = "vita"
    return {"node": node, "cur_ip": cur_ip, "host_ip": _primary_ip(),
            "etcd_address": str(ea), "osd_network": str(net),
            "conf": os.path.exists("/etc/vitastor/vitastor.conf"),
            "pools": len(pools_config()), "osds": len(_osd_set())}


def cluster_reconfigure(node, ip, network, mode):
    """Сменить IP узла / сеть OSD кластера. mode: preserve | reinit.
    Возвращает {ok, results, msg}."""
    node = (node or "").strip()
    ip = (ip or "").strip()
    network = (network or "").strip()
    if not _NODE_RE.match(node):
        return {"ok": False, "results": [], "msg": "имя узла некорректно"}
    if not _IP_RE.match(ip):
        return {"ok": False, "results": [], "msg": "IP-адрес узла некорректен"}
    if not _CIDR_RE.match(network):
        return {"ok": False, "results": [],
                "msg": "сеть OSD: формат X.X.X.X/NN"}
    if mode not in ("preserve", "reinit"):
        return {"ok": False, "results": [],
                "msg": "режим: preserve или reinit"}
    if not os.path.exists("/etc/vitastor/vitastor.conf"):
        return {"ok": False, "results": [],
                "msg": "vitastor.conf отсутствует — сначала Мастер control plane"}

    results = []

    def step(title, r):
        ok = (r.get("rc") == 0)
        results.append({"title": title, "ok": ok, "cmd": r.get("cmd"),
                        "out": r.get("out"), "err": r.get("err")})
        return ok

    def note(title, text, ok=True):
        results.append({"title": title, "ok": ok, "cmd": "",
                        "out": text if ok else "", "err": "" if ok else text})

    # 0) список OSD-юнитов (до остановки служб)
    osd_units = _osd_units()
    note("OSD-юниты узла", ", ".join(osd_units) or "нет")

    # 1) остановка служб
    for u in osd_units:
        run_cmd(["systemctl", "stop", u], timeout=60)
    run_cmd(["systemctl", "stop", "vitastor-mon"], timeout=60)
    run_cmd(["systemctl", "stop", "etcd"], timeout=60)
    note("Остановка служб", "etcd, vitastor-mon и OSD остановлены")

    # 2) vitastor.conf
    try:
        with open("/etc/vitastor/vitastor.conf", "w") as f:
            f.write(json.dumps({"etcd_address": "http://%s:2379" % ip,
                                "osd_network": network}, indent=2) + "\n")
        note("/etc/vitastor/vitastor.conf",
             "etcd_address=http://%s:2379, osd_network=%s" % (ip, network))
    except Exception as e:
        note("/etc/vitastor/vitastor.conf", str(e), ok=False)
        return {"ok": False, "results": results,
                "msg": "не удалось записать vitastor.conf"}

    # 3) etcd
    if mode == "reinit":
        run_cmd(["bash", "-c",
                 "rm -rf /var/lib/etcd/default /var/lib/etcd/vitastor && "
                 "mkdir -p /var/lib/etcd/vitastor && "
                 "(chown -R etcd:etcd /var/lib/etcd 2>/dev/null || true)"])
        note("Очистка данных etcd",
             "каталог данных etcd очищен (режим «начисто»)")
        try:
            with open("/etc/default/etcd", "w") as f:
                f.write(_etcd_default(node, ip))
            note("/etc/default/etcd", "записан (IP %s)" % ip)
        except Exception as e:
            note("/etc/default/etcd", str(e), ok=False)
            return {"ok": False, "results": results,
                    "msg": "не удалось записать /etc/default/etcd"}
        run_cmd(["systemctl", "daemon-reload"])
        step("Запуск etcd начисто",
             run_cmd(["systemctl", "restart", "etcd"], timeout=60))
    else:
        # preserve: один старт с force-new-cluster, затем штатный конфиг
        try:
            with open("/etc/default/etcd", "w") as f:
                f.write(_etcd_default(node, ip, force=True))
        except Exception as e:
            note("/etc/default/etcd", str(e), ok=False)
            return {"ok": False, "results": results,
                    "msg": "не удалось записать /etc/default/etcd"}
        run_cmd(["systemctl", "daemon-reload"])
        step("Запуск etcd (--force-new-cluster, данные сохраняются)",
             run_cmd(["systemctl", "restart", "etcd"], timeout=60))
        time.sleep(5)
        # снять force-флаг — иначе он сработает при каждом рестарте
        try:
            with open("/etc/default/etcd", "w") as f:
                f.write(_etcd_default(node, ip))
            note("/etc/default/etcd", "force-флаг снят, конфиг штатный")
        except Exception as e:
            note("/etc/default/etcd", str(e), ok=False)
        run_cmd(["systemctl", "daemon-reload"])
        step("Перезапуск etcd (штатный режим)",
             run_cmd(["systemctl", "restart", "etcd"], timeout=60))
    time.sleep(4)
    eh = run_cmd(["etcdctl", "--endpoints=http://127.0.0.1:2379",
                  "endpoint", "health"], env=_etcd_env())
    results.append({"title": "Проверка etcd (endpoint health)",
                    "ok": eh.get("rc") == 0, "cmd": eh.get("cmd"),
                    "out": eh.get("out"), "err": eh.get("err")})

    # 4) монитор
    run_cmd(["systemctl", "reset-failed", "vitastor-mon"])
    step("Запуск vitastor-mon",
         run_cmd(["systemctl", "restart", "vitastor-mon"], timeout=60))
    time.sleep(4)

    # 5) OSD
    for u in osd_units:
        run_cmd(["systemctl", "reset-failed", u])
        step("Запуск " + u,
             run_cmd(["systemctl", "restart", u], timeout=60))
    if osd_units:
        time.sleep(6)

    # 6) проверка
    mon_act = (run_cmd(["systemctl", "is-active",
                        "vitastor-mon"]).get("out") == "active")
    results.append({"title": "Монитор Vitastor активен", "ok": mon_act,
                    "cmd": "systemctl is-active vitastor-mon",
                    "out": "active" if mon_act else "",
                    "err": "" if mon_act else "монитор не поднялся"})
    st, se = cli_json(["status"])
    results.append({"title": "vitastor-cli status", "ok": st is not None,
                    "cmd": "vitastor-cli status",
                    "out": "кластер отвечает" if st is not None else "",
                    "err": "" if st is not None else (se or "нет ответа")})

    ok = all(x["ok"] for x in results)
    return {"ok": ok, "results": results,
            "msg": ("Кластер переконфигурирован на IP %s. etcd, монитор и OSD "
                    "перезапущены%s." % (ip, ", данные сохранены"
                    if mode == "preserve" else " (etcd начисто)")) if ok
            else "переконфигурация завершилась с ошибками — см. лог шагов"}


# ---------- кластер: агент узла ----------
def _conf_etcd_net():
    """(etcd_address, osd_network) из /etc/vitastor/vitastor.conf."""
    try:
        c = json.loads(open("/etc/vitastor/vitastor.conf").read() or "{}")
        ea = c.get("etcd_address") or ""
        if isinstance(ea, list):
            ea = ea[0] if ea else ""
        net = c.get("osd_network") or ""
        if isinstance(net, list):
            net = net[0] if net else ""
        return str(ea), str(net)
    except Exception:
        return "", ""


def _node_stats():
    """Лёгкая телеметрия узла: загрузка CPU, аптайм, память."""
    st = {"load": None, "uptime": None, "cores": 0,
          "mem_total": 0, "mem_used": 0}
    try:
        with open("/proc/loadavg") as f:
            st["load"] = [float(x) for x in f.read().split()[:3]]
    except Exception:
        pass
    try:
        with open("/proc/uptime") as f:
            st["uptime"] = int(float(f.read().split()[0]))
    except Exception:
        pass
    try:
        mt = ma = 0
        for ln in open("/proc/meminfo"):
            if ln.startswith("MemTotal:"):
                mt = int(ln.split()[1]) * 1024
            elif ln.startswith("MemAvailable:"):
                ma = int(ln.split()[1]) * 1024
        st["mem_total"] = mt
        st["mem_used"] = max(mt - ma, 0)
    except Exception:
        pass
    try:
        st["cores"] = os.cpu_count() or 0
    except Exception:
        pass
    return st


def node_info():
    """Состояние узла (агентский эндпоинт для Мастера кластера)."""
    etcd_addr, osd_net = _conf_etcd_net()
    conf = os.path.exists("/etc/vitastor/vitastor.conf")
    etcd_local = run_cmd(["systemctl", "is-active", "etcd"]).get("out") == "active"
    mon_local = run_cmd(["systemctl", "is-active",
                         "vitastor-mon"]).get("out") == "active"
    role = ("master" if (etcd_local and mon_local)
            else ("worker" if conf else "unconfigured"))
    try:
        host = os.uname().nodename
    except Exception:
        host = "node"
    osds = []
    osds_up = 0
    for u in _osd_units():
        try:
            n = u.split("@", 1)[1].split(".", 1)[0]
        except Exception:
            continue
        osds.append(n)
        if run_cmd(["systemctl", "is-active", u]).get("out") == "active":
            osds_up += 1
    return {"hostname": host, "ip": _primary_ip(),
            "installed": os.path.exists(VITASTOR_CLI),
            "conf_exists": conf, "etcd_address": etcd_addr,
            "osd_network": osd_net, "role": role, "etcd_local": etcd_local,
            "mon_local": mon_local, "free_disks": free_disks(),
            "osds": sorted(osds), "osds_up": osds_up,
            "stats": _node_stats(), "ts": time.time()}


def node_join(etcd_address, osd_network):
    """Подключить ЭТОТ узел к кластеру в worker-режиме: пакеты Vitastor +
    vitastor.conf на чужой etcd. etcd/монитор тут не разворачиваются."""
    etcd_address = (etcd_address or "").strip()
    osd_network = (osd_network or "").strip()
    if not re.match(r"^https?://[0-9.]+:\d+$", etcd_address):
        return {"ok": False, "results": [],
                "msg": "etcd_address: формат http://IP:2379"}
    if not _CIDR_RE.match(osd_network):
        return {"ok": False, "results": [], "msg": "сеть OSD: формат X.X.X.X/NN"}
    results = []

    def note(title, text, ok=True):
        results.append({"title": title, "ok": ok, "cmd": "",
                        "out": text if ok else "", "err": "" if ok else text})

    if not os.path.exists(VITASTOR_CLI):
        inst = vitastor_install()
        results.extend(inst.get("results", []))
        if not inst.get("ok"):
            return {"ok": False, "results": results,
                    "msg": "не удалось установить пакеты Vitastor на узле"}
    else:
        note("Пакеты Vitastor", "уже установлены")

    try:
        os.makedirs("/etc/vitastor", exist_ok=True)
        with open("/etc/vitastor/vitastor.conf", "w") as f:
            f.write(json.dumps({"etcd_address": etcd_address,
                                "osd_network": osd_network}, indent=2) + "\n")
        note("/etc/vitastor/vitastor.conf",
             "etcd_address=%s, osd_network=%s" % (etcd_address, osd_network))
    except Exception as e:
        note("/etc/vitastor/vitastor.conf", str(e), ok=False)
        return {"ok": False, "results": results,
                "msg": "не удалось записать vitastor.conf"}

    run_cmd(["systemctl", "enable", "vitastor.target"])
    note("Узел подключён",
         "vitastor.conf указывает на etcd кластера; узел готов принимать OSD")
    return {"ok": True, "results": results,
            "msg": "Узел подключён к кластеру (worker-режим)."}


def node_prepare_disk(disks, tag):
    """Подготовить диски ЭТОГО узла как OSD и назначить тег пула."""
    disks = [str(d) for d in (disks or [])]
    tag = (tag or "").strip()
    if not disks:
        return {"ok": False, "results": [], "msg": "диски не выбраны"}
    if not _NAME_RE.match(tag):
        return {"ok": False, "results": [],
                "msg": "тег OSD: латиница/цифры/_/-"}
    etcd_addr, _ = _conf_etcd_net()
    if not etcd_addr:
        return {"ok": False, "results": [],
                "msg": "узел не подключён к кластеру (нет vitastor.conf)"}
    dpaths = [d if d.startswith("/dev/") else "/dev/" + d for d in disks]
    results = []

    def emit(title, r):
        ok = (r.get("rc") == 0)
        results.append({"title": title, "ok": ok, "cmd": r.get("cmd"),
                        "out": r.get("out"), "err": r.get("err")})
        return ok

    before = _osd_set()
    if not emit("vitastor-disk prepare " + " ".join(dpaths),
                run_cmd([VITASTOR_DISK, "prepare"] + dpaths, timeout=300)):
        return {"ok": False, "results": results,
                "msg": "vitastor-disk prepare не удался"}
    time.sleep(10)
    new = sorted(_osd_set() - before, key=lambda x: int(x) if x.isdigit() else 0)
    results.append({"title": "Новые OSD", "ok": bool(new), "cmd": "",
                    "out": ", ".join(new), "err": "" if new
                    else "новые OSD не появились"})
    for n in new:
        emit("Тег osd.%s -> %s" % (n, tag),
             run_cmd([ETCDCTL, "--endpoints=" + etcd_addr, "put",
                      "/vitastor/config/osd/" + n,
                      json.dumps({"tags": [tag]})], env=_etcd_env()))
    ok = bool(new) and all(x["ok"] for x in results)
    return {"ok": ok, "results": results, "new_osds": new,
            "msg": ("Добавлено OSD: %s (тег %s)." % (", ".join(new), tag))
            if ok else "подготовка дисков завершилась с ошибками"}


# ---------- кластер: оркестрация с главного узла ----------
def _agent_call(ip, path, payload=None, timeout=600):
    """HTTP-вызов агента PROXOMATRON на узле <ip>. payload=None -> GET."""
    url = "http://%s:%d%s" % (ip, PORT, path)
    try:
        if payload is None:
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}"), None
    except Exception as e:
        return None, str(e)


def cluster_nodes():
    """Узлы кластера: главный (self) + зарегистрированные в /proxomatron/nodes/."""
    ci = cluster_info()
    nodes = [{"ip": ci.get("cur_ip") or ci.get("host_ip"),
              "hostname": ci.get("node"), "role": "master", "self": True}]
    seen = {nodes[0]["ip"]}
    r = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                 "/proxomatron/nodes/", "--prefix", "-w", "json"], env=_etcd_env())
    try:
        for kv in (json.loads(r.get("out") or "{}") or {}).get("kvs") or []:
            key = base64.b64decode(kv.get("key", "")).decode("utf-8", "ignore")
            ip = key.rsplit("/", 1)[-1]
            if ip in seen:
                continue
            seen.add(ip)
            try:
                meta = json.loads(base64.b64decode(
                    kv.get("value", "")).decode("utf-8", "ignore"))
            except Exception:
                meta = {}
            nodes.append({"ip": ip, "hostname": meta.get("hostname") or ip,
                          "role": "worker", "self": False})
    except Exception:
        pass
    return {"nodes": nodes}


def cluster_node_info(ip):
    """Прокси к агенту узла <ip> — для UI (свободные диски и т.п.)."""
    ip = (ip or "").strip()
    if not _IP_RE.match(ip):
        return {"error": "IP узла некорректен"}
    info, err = _agent_call(ip, "/api/node/info", timeout=20)
    if info is None:
        return {"error": err or "узел недоступен", "ip": ip}
    info["ip"] = ip
    return info


def cluster_overview():
    """Сводка по всем узлам кластера для вкладки «Кластер» (только master).

    Опрашивает агент каждого узла параллельно: self — локально, остальные —
    HTTP-вызовом /api/node/info. Узлы без ответа помечаются online=False."""
    nodes = cluster_nodes().get("nodes", [])
    ci = cluster_info()
    result = {}

    def fetch(n):
        ip = n.get("ip")
        entry = {"ip": ip, "hostname": n.get("hostname"),
                 "role": n.get("role"), "self": bool(n.get("self"))}
        if n.get("self"):
            try:
                entry.update(node_info())
                entry["online"] = True
            except Exception as e:
                entry["online"] = False
                entry["error"] = str(e)
        else:
            info, err = _agent_call(ip, "/api/node/info", timeout=10)
            if info is None:
                entry["online"] = False
                entry["error"] = err or "узел недоступен"
            else:
                entry.update(info)
                entry["online"] = True
        entry["ip"] = ip
        entry["self"] = bool(n.get("self"))
        result[ip] = entry

    threads = []
    for n in nodes:
        t = threading.Thread(target=fetch, args=(n,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=14)
    ordered = [result[n["ip"]] for n in nodes if n.get("ip") in result]
    online = sum(1 for e in ordered if e.get("online"))
    return {"ts": time.time(),
            "master": ci.get("cur_ip") or ci.get("host_ip"),
            "total": len(ordered), "online": online, "nodes": ordered}


def cluster_add_node(ip):
    """Подключить узел <ip> к кластеру через его агент PROXOMATRON."""
    ip = (ip or "").strip()
    if not _IP_RE.match(ip):
        return {"ok": False, "results": [], "msg": "IP узла некорректен"}
    ci = cluster_info()
    master_ip = ci.get("cur_ip") or ci.get("host_ip")
    if ip == master_ip:
        return {"ok": False, "results": [],
                "msg": "это адрес главного узла — добавлять не нужно"}
    etcd_addr = ci.get("etcd_address") or ("http://%s:2379" % master_ip)
    osd_net = ci.get("osd_network")
    if not osd_net:
        return {"ok": False, "results": [],
                "msg": "у кластера не задана сеть OSD — сначала Мастер control plane"}
    results = []
    info, err = _agent_call(ip, "/api/node/info", timeout=20)
    if info is None:
        return {"ok": False, "results": [
            {"title": "Связь с агентом PROXOMATRON на " + ip, "ok": False,
             "cmd": "GET http://%s:8080/api/node/info" % ip,
             "out": "", "err": err or "недоступен"}],
            "msg": "PROXOMATRON-агент на %s недоступен — установите там PROXOMATRON" % ip}
    results.append({"title": "Агент PROXOMATRON на " + ip, "ok": True,
                    "cmd": "GET /api/node/info",
                    "out": "%s, Vitastor: %s" % (info.get("hostname"),
                           "установлен" if info.get("installed")
                           else "будет установлен"), "err": ""})
    jr, jerr = _agent_call(ip, "/api/node/join",
                           {"confirm": "join", "etcd_address": etcd_addr,
                            "osd_network": osd_net}, timeout=600)
    if jr is None:
        results.append({"title": "Подключение узла", "ok": False,
                        "cmd": "POST /api/node/join", "out": "",
                        "err": jerr or "нет ответа"})
        return {"ok": False, "results": results, "msg": "join не выполнен"}
    results.extend(jr.get("results", []))
    if not jr.get("ok"):
        return {"ok": False, "results": results,
                "msg": "узел не подключён: " + (jr.get("msg") or "")}
    run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "put",
             "/proxomatron/nodes/" + ip,
             json.dumps({"hostname": info.get("hostname") or ip})],
            env=_etcd_env())
    results.append({"title": "Узел зарегистрирован в кластере", "ok": True,
                    "cmd": "etcdctl put /proxomatron/nodes/" + ip,
                    "out": "", "err": ""})
    return {"ok": True, "results": results,
            "msg": "Узел %s подключён. Дальше — «Добавить OSD» на этом узле." % ip}


def cluster_add_osd(ip, disks, tag):
    """Подготовить диски узла <ip> как OSD через его агент."""
    ip = (ip or "").strip()
    if not _IP_RE.match(ip):
        return {"ok": False, "results": [], "msg": "IP узла некорректен"}
    r, err = _agent_call(ip, "/api/node/prepare-disk",
                         {"confirm": "prepare", "disks": disks, "tag": tag},
                         timeout=600)
    if r is None:
        return {"ok": False, "results": [
            {"title": "Связь с узлом " + ip, "ok": False,
             "cmd": "POST /api/node/prepare-disk", "out": "",
             "err": err or "нет ответа"}],
            "msg": "узел %s недоступен" % ip}
    return r


def cluster_create_pool(name, pg_size, pg_minsize, pg_count, tag):
    """Создать пул кластера (failure_domain host) на главном узле."""
    name = (name or "").strip()
    tag = (tag or "").strip()
    if not _NAME_RE.match(name):
        return {"ok": False, "results": [], "msg": "имя пула некорректно"}
    if not _NAME_RE.match(tag):
        return {"ok": False, "results": [], "msg": "тег OSD некорректен"}
    try:
        ps, ms, pc = int(pg_size), int(pg_minsize), int(pg_count)
    except Exception:
        return {"ok": False, "results": [],
                "msg": "PG-параметры должны быть числами"}
    if not (1 <= ps <= 7 and 1 <= ms <= ps and 1 <= pc <= 256):
        return {"ok": False, "results": [],
                "msg": "PG-параметры вне допустимых диапазонов"}
    for pc_ in pools_config().values():
        if isinstance(pc_, dict) and pc_.get("name") == name:
            return {"ok": False, "results": [],
                    "msg": "пул '%s' уже существует" % name}
    r = run_cmd([VITASTOR_CLI, "create-pool", name, "-s", str(ps),
                 "--pg_minsize", str(ms), "-n", str(pc),
                 "--failure_domain", "host", "--osd_tags", tag], timeout=120)
    ok = (r.get("rc") == 0)
    return {"ok": ok,
            "results": [{"title": "Создание пула кластера " + name, "ok": ok,
                         "cmd": r.get("cmd"), "out": r.get("out"),
                         "err": r.get("err")}],
            "msg": ("Пул '%s' создан: replica %d/%d, %d PG, failure_domain=host, "
                    "тег %s." % (name, ps, ms, pc, tag)) if ok
            else "create-pool завершился ошибкой"}


# ---------- мастер пулов ----------
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
_MNT_RE = re.compile(r"^/mnt/[A-Za-z0-9._-]{1,48}$")
SYSTEMD_DIR = "/etc/systemd/system"


def _etcd_env():
    return dict(os.environ, ETCDCTL_API="3")


def run_cmd(argv, timeout=180, env=None):
    """Выполнить команду (argv-список, без shell), вернуть {cmd, rc, out, err}."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return {"cmd": " ".join(argv), "rc": p.returncode,
                "out": (p.stdout or "").strip(), "err": (p.stderr or "").strip()}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(argv), "rc": -1, "out": "", "err": "истекло время ожидания"}
    except Exception as e:
        return {"cmd": " ".join(argv), "rc": -1, "out": "", "err": str(e)}


def pools_config():
    """etcd /vitastor/config/pools -> {id: {...}}"""
    try:
        p = subprocess.run([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                            "/vitastor/config/pools", "--print-value-only"],
                           capture_output=True, text=True, timeout=8, env=_etcd_env())
        return json.loads(p.stdout or "{}") or {}
    except Exception:
        return {}


def free_disks():
    """Пустые диски-кандидаты под OSD: тип disk, без разделов, без ФС, не смонтирован."""
    out = []
    try:
        p = subprocess.run([LSBLK, "-J", "-b", "-o",
                            "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL"],
                           capture_output=True, text=True, timeout=8)
        for d in json.loads(p.stdout or "{}").get("blockdevices", []):
            nm = d.get("name") or ""
            if d.get("type") != "disk" or nm.startswith(SKIP):
                continue
            if d.get("children") or d.get("fstype") or d.get("mountpoint"):
                continue
            out.append({"name": nm, "path": "/dev/" + nm,
                        "size": d.get("size") or 0,
                        "model": (d.get("model") or "").strip()})
    except Exception:
        pass
    return out


def osd_disks():
    """{osd_num(str): {"part": "/dev/sda1", "disk": "sda"}} — разделы Vitastor-OSD."""
    res = {}
    try:
        p = subprocess.run([LSBLK, "-J", "-b", "-o", "NAME,TYPE,PARTTYPE"],
                           capture_output=True, text=True, timeout=8)
        parts = []

        def walk(nodes):
            for n in nodes:
                if (n.get("parttype") or "").lower() == VITA_PART_GUID:
                    parts.append(n.get("name"))
                walk(n.get("children") or [])

        walk(json.loads(p.stdout or "{}").get("blockdevices", []))
        for part in parts:
            r = subprocess.run([VITASTOR_DISK, "read-sb", "/dev/" + part],
                               capture_output=True, text=True, timeout=6)
            try:
                sb = json.loads(r.stdout or "{}")
            except Exception:
                continue
            on = sb.get("osd_num")
            if on is not None:
                res[str(on)] = {"part": "/dev/" + part,
                                "disk": _diskname("/dev/" + part)}
    except Exception:
        pass
    return res


def pool_osd_plan(pool_name):
    """Для удаляемого пула: какие OSD можно убрать (только его), какие общие.
    Возвращает (removable[{num,part,disk}], shared[nums])."""
    info = wizard_info()
    target = None
    others = []
    for p in info["pools"]:
        if p["name"] == pool_name:
            target = p
        else:
            others.append(p)
    if not target:
        return [], []
    tt = set(target.get("osd_tags") or [])
    dm = osd_disks()
    removable, shared = [], []
    for o in info["osds"]:
        otags = set(o.get("tags") or [])
        if not tt.issubset(otags):
            continue
        in_other = any(set(p.get("osd_tags") or []).issubset(otags)
                       for p in others)
        if in_other:
            shared.append(o["num"])
        else:
            d = dm.get(o["num"]) or {}
            removable.append({"num": o["num"], "part": d.get("part"),
                              "disk": d.get("disk")})
    return removable, shared


def wizard_info():
    """Состояние кластера для мастера: пулы, OSD, свободные диски, монтирования."""
    pools = []
    for pid, c in sorted(pools_config().items(),
                         key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 1 << 30):
        if not isinstance(c, dict):
            continue
        pools.append({
            "id": pid, "name": c.get("name") or ("pool" + str(pid)),
            "scheme": c.get("scheme") or "replicated",
            "pg_size": c.get("pg_size"), "pg_minsize": c.get("pg_minsize"),
            "pg_count": c.get("pg_count"),
            "failure_domain": c.get("failure_domain") or "host",
            "osd_tags": c.get("osd_tags"), "used_for_app": c.get("used_for_app"),
        })
    osds = []
    tree, _ = cli_json(["osd-tree"])
    dm = osd_disk_map()
    if isinstance(tree, list):
        for o in tree:
            if isinstance(o, dict) and o.get("type") == "osd":
                num = str(o.get("name"))
                tags = o.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                osds.append({"num": num, "tags": tags,
                             "size": o.get("size"), "free": o.get("free"),
                             "up": o.get("up") == "up", "disk": dm.get(num)})
        osds.sort(key=lambda x: int(x["num"]) if x["num"].isdigit() else 0)
    return {"pools": pools, "osds": osds,
            "free_disks": free_disks(), "mounts": vitastorfs_mounts()}


def _wiz_int(req, key, lo, hi):
    v = req.get(key)
    if v in (None, "", "—"):
        raise ValueError("%s не задан" % key)
    try:
        iv = int(v)
    except Exception:
        raise ValueError("%s должно быть числом" % key)
    if not (lo <= iv <= hi):
        raise ValueError("%s вне диапазона %d..%d" % (key, lo, hi))
    return iv


def wiz_validate(req):
    """Проверка запроса мастера. Возвращает (clean_dict, error_or_None)."""
    act = req.get("action")
    if act not in ("create", "edit", "delete", "replace"):
        return None, "неизвестное действие"
    info = wizard_info()
    pool_names = {p["name"] for p in info["pools"]}
    free_paths = {d["path"] for d in info["free_disks"]}
    osd_nums = {o["num"] for o in info["osds"]}
    c = {"action": act}
    if act == "create":
        name = (req.get("name") or "").strip()
        if not _NAME_RE.match(name):
            return None, "имя пула: латиница/цифры/_/-, до 32 символов"
        if name in pool_names:
            return None, "пул '%s' уже существует" % name
        try:
            pg_size = _wiz_int(req, "pg_size", 1, 7)
            pg_minsize = _wiz_int(req, "pg_minsize", 1, 7)
            pg_count = _wiz_int(req, "pg_count", 1, 256)
        except ValueError as e:
            return None, str(e)
        if pg_minsize > pg_size:
            return None, "pg_minsize не больше pg_size"
        fd = req.get("failure_domain") or "osd"
        if fd not in ("osd", "host"):
            return None, "failure_domain: osd либо host"
        tag = (req.get("tag") or "").strip()
        if not _NAME_RE.match(tag):
            return None, "тег OSD: латиница/цифры/_/-, до 32 символов"
        disks = [str(x) for x in (req.get("disks") or [])]
        for dp in disks:
            if dp not in free_paths:
                return None, "диск %s не в списке свободных" % dp
        ex = [str(x) for x in (req.get("existing_osds") or [])]
        for n in ex:
            if n not in osd_nums:
                return None, "OSD %s не существует" % n
        if len(disks) + len(ex) < pg_size:
            return None, "дисков/OSD меньше, чем реплик (%d)" % pg_size
        mount = req.get("mount") or {}
        mpath = ""
        if mount.get("enable"):
            mpath = (mount.get("path") or "").strip()
            if not _MNT_RE.match(mpath):
                return None, "путь монтирования: /mnt/<имя>"
        c.update(name=name, pg_size=pg_size, pg_minsize=pg_minsize,
                 pg_count=pg_count, failure_domain=fd, tag=tag,
                 disks=disks, existing_osds=ex,
                 mount_enable=bool(mount.get("enable")), mount_path=mpath)
        return c, None
    if act == "edit":
        pool = (req.get("pool") or "").strip()
        if pool not in pool_names:
            return None, "пул '%s' не найден" % pool
        cur = next(p for p in info["pools"] if p["name"] == pool)
        changes = {}
        try:
            for key, lo, hi in (("pg_size", 1, 7), ("pg_minsize", 1, 7),
                                ("pg_count", 1, 256)):
                if req.get(key) in (None, "", "—"):
                    continue
                iv = _wiz_int(req, key, lo, hi)
                if iv != cur.get(key):
                    changes[key] = iv
        except ValueError as e:
            return None, str(e)
        fd = req.get("failure_domain")
        if fd in ("osd", "host") and fd != cur.get("failure_domain"):
            changes["failure_domain"] = fd
        nn = (req.get("new_name") or "").strip()
        if nn and nn != pool:
            if not _NAME_RE.match(nn):
                return None, "новое имя: латиница/цифры/_/-, до 32 символов"
            if nn in pool_names:
                return None, "пул '%s' уже существует" % nn
            changes["name"] = nn
        ps = changes.get("pg_size", cur.get("pg_size") or 1)
        ms = changes.get("pg_minsize", cur.get("pg_minsize") or 1)
        if ms > ps:
            return None, "pg_minsize не больше pg_size"
        if not changes:
            return None, "нет изменений для применения"
        c.update(pool=pool, changes=changes)
        return c, None
    if act == "replace":
        mode = req.get("mode")
        if mode not in ("oneshot", "retire", "induct"):
            return None, "режим замены: oneshot, retire или induct"
        c["mode"] = mode
        if mode in ("retire", "oneshot"):
            osd = str(req.get("osd") or "").strip()
            if osd not in osd_nums:
                return None, "OSD %s не существует" % (osd or "—")
            c["osd"] = osd
        if mode in ("induct", "oneshot"):
            disk = str(req.get("disk") or "").strip()
            if disk not in free_paths:
                return None, "диск %s не в списке свободных" % (disk or "—")
            c["disk"] = disk
        if mode == "induct":
            pool = (req.get("pool") or "").strip()
            if pool not in pool_names:
                return None, "пул '%s' не найден" % (pool or "—")
            c["pool"] = pool
        return c, None
    # delete
    pool = (req.get("pool") or "").strip()
    if pool not in pool_names:
        return None, "пул '%s' не найден" % pool
    remove_osds = bool(req.get("remove_osds"))
    wipe_disks = bool(req.get("wipe_disks"))
    if wipe_disks and not remove_osds:
        return None, "очистка дисков невозможна без удаления OSD"
    c.update(pool=pool, remove_osds=remove_osds, wipe_disks=wipe_disks)
    return c, None


def wiz_confirm_word(c):
    if c["action"] == "create":
        return "СОЗДАТЬ"
    if c["action"] == "edit":
        return "ИЗМЕНИТЬ"
    if c["action"] == "replace":
        if c["mode"] == "induct":
            return c["disk"].rsplit("/", 1)[-1]
        return "osd" + str(c["osd"])
    return c["pool"]


def wizard_plan(c):
    """Список шагов-команд для предпросмотра (без выполнения)."""
    steps = []
    act = c["action"]
    if act == "create":
        if c["disks"]:
            steps.append({"danger": True, "title": "Подготовить диски как OSD",
                          "cmd": "vitastor-disk prepare " + " ".join(c["disks"]),
                          "note": "ПОЛНОЕ СТИРАНИЕ выбранных дисков"})
        ex = ("; существующим OSD " + ", ".join(c["existing_osds"])
              + " тег добавляется к меткам" if c["existing_osds"] else "")
        steps.append({"danger": False, "title": "Назначить тег '%s'" % c["tag"],
                      "cmd": "etcdctl put /vitastor/config/osd/<N> "
                             "'{\"tags\":[\"%s\"]}'" % c["tag"],
                      "note": "новым OSD — полная замена меток" + ex})
        steps.append({"danger": False, "title": "Создать пул",
                      "cmd": "vitastor-cli create-pool %s -s %d --pg_minsize %d "
                             "-n %d --failure_domain %s --osd_tags %s" % (
                                 c["name"], c["pg_size"], c["pg_minsize"],
                                 c["pg_count"], c["failure_domain"], c["tag"]),
                      "note": "replicated %d/%d" % (c["pg_size"], c["pg_minsize"])})
        if c["mount_enable"]:
            img = "fs-" + c["name"]
            steps.append({"danger": False, "title": "Образ метаданных VitastorFS",
                          "cmd": "vitastor-cli create -s 1G --pool %s %s --force"
                                 % (c["name"], img),
                          "note": "после ожидания active; создание проверяется"})
            steps.append({"danger": False, "title": "Пометить пул used_for_app",
                          "cmd": "vitastor-cli modify-pool --used_for_app fs:%s %s"
                                 % (img, c["name"]), "note": ""})
            steps.append({"danger": False, "title": "Юнит и запуск монтирования",
                          "cmd": "systemd vitastorfs-%s -> %s; enable --now"
                                 % (c["name"], c["mount_path"]),
                          "note": "служба проверяется на is-active"})
        return steps
    if act == "edit":
        ch = c["changes"]
        args = []
        for k in ("pg_size", "pg_minsize", "pg_count", "failure_domain"):
            if k in ch:
                args.append("--%s %s" % (k, ch[k]))
        if "name" in ch:
            args.append("--name %s" % ch["name"])
        heavy = "pg_count" in ch or "pg_size" in ch
        steps.append({"danger": heavy, "title": "Изменить параметры пула",
                      "cmd": "vitastor-cli modify-pool %s %s"
                             % (c["pool"], " ".join(args)),
                      "note": "вызовет ребаланс данных" if heavy else ""})
        return steps
    if act == "replace":
        mode = c["mode"]
        if mode in ("retire", "oneshot"):
            osd = c["osd"]
            steps.append({"danger": True, "title": "Остановить демон OSD",
                          "cmd": "systemctl stop vitastor-osd@%s" % osd,
                          "note": ""})
            steps.append({"danger": True,
                          "title": "Вывести osd.%s из кластера" % osd,
                          "cmd": "vitastor-cli rm-osd %s --force "
                                 "--allow-data-loss" % osd,
                          "note": "копия данных на osd.%s теряется; пул уходит "
                                  "в degraded до ввода нового диска" % osd})
        if mode in ("induct", "oneshot"):
            if mode == "oneshot":
                tags = _osd_tags(c["osd"])
                tnote = "теги сбойного osd.%s: %s" % (
                    c["osd"], ", ".join(tags) or "—")
            else:
                tags = _pool_tags(c["pool"])
                tnote = "теги пула %s: %s" % (
                    c["pool"], ", ".join(tags) or "—")
            steps.append({"danger": True,
                          "title": "Подготовить новый диск как OSD",
                          "cmd": "vitastor-disk prepare %s" % c["disk"],
                          "note": "ПОЛНОЕ СТИРАНИЕ диска %s" % c["disk"]})
            steps.append({"danger": False,
                          "title": "Назначить теги новому OSD",
                          "cmd": "etcdctl put /vitastor/config/osd/<N> "
                                 "'{\"tags\":[...]}'",
                          "note": tnote + " — кластер ресинкает данные на "
                                  "новый OSD, пул не пересоздаётся"})
        if mode == "retire":
            steps.append({"danger": False, "title": "Дальше — замена диска",
                          "cmd": "(вручную)",
                          "note": "физически замените диск, затем запустите "
                                  "«Заменить диск» → «Шаг 2: ввести диск»"})
        return steps
    # delete
    removable, shared = ([], [])
    if c.get("remove_osds"):
        removable, shared = pool_osd_plan(c["pool"])
    mounts = vitastorfs_mounts()
    if c["pool"] in mounts:
        u = mounts[c["pool"]]["unit"]
        steps.append({"danger": True, "title": "Отключить монтирование VitastorFS",
                      "cmd": "systemctl disable --now %s; rm %s/%s"
                             % (u, SYSTEMD_DIR, u), "note": ""})
    keep = "" if c.get("remove_osds") else "; диски и OSD сохраняются"
    steps.append({"danger": True, "title": "Удалить пул",
                  "cmd": "vitastor-cli rm-pool --force %s" % c["pool"],
                  "note": "данные пула уничтожаются" + keep})
    fs_img = _pool_fs_image(c["pool"])
    if fs_img:
        steps.append({"danger": True,
                      "title": "Удалить образ метаданных VitastorFS",
                      "cmd": "etcdctl del /vitastor/index/image/%s (+ inode-конфиг)"
                             % fs_img,
                      "note": "иначе образ %s останется сиротой" % fs_img})
    if c.get("remove_osds"):
        if removable:
            parts = " ".join((o["part"] or "osd." + o["num"]) for o in removable)
            nums = ", ".join("osd." + o["num"] for o in removable)
            steps.append({"danger": True,
                          "title": "Удалить OSD пула — " + nums,
                          "cmd": "vitastor-disk purge --force --allow-data-loss "
                                 + parts,
                          "note": "OSD останавливаются и стираются из etcd"})
        else:
            steps.append({"danger": False, "title": "Удаление OSD",
                          "cmd": "(нет OSD только этого пула)", "note": ""})
        if shared:
            steps.append({"danger": False,
                          "title": "Сохраняются OSD — "
                                   + ", ".join("osd." + n for n in shared),
                          "cmd": "(пропуск)",
                          "note": "используются другими пулами"})
    if c.get("wipe_disks"):
        disks = sorted({o["disk"] for o in removable if o["disk"]})
        if disks:
            steps.append({"danger": True, "title": "Очистить диски (wipe)",
                          "cmd": "wipefs -af + sgdisk --zap-all + partprobe: "
                                 + ", ".join("/dev/" + d for d in disks),
                          "note": "таблица разделов уничтожается — диски станут "
                                  "свободными"})
    return steps


def _write_fs_unit(pool, img, path):
    unit = "vitastorfs-%s.service" % pool
    content = (
        "[Unit]\n"
        "Description=VitastorFS mount (%s -> %s)\n"
        "After=network-online.target vitastor-mon.service vitastor.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        "ExecStartPre=/bin/mkdir -p %s\n"
        "ExecStart=/usr/bin/vitastor-nfs --fs %s --pool %s --foreground 1 mount %s\n"
        "ExecStopPost=-/bin/umount -l %s\n"
        "Restart=on-failure\nRestartSec=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    ) % (pool, path, path, img, pool, path, path)
    try:
        with open(SYSTEMD_DIR + "/" + unit, "w") as f:
            f.write(content)
        return {"cmd": "write " + unit, "rc": 0, "out": "юнит записан", "err": ""}
    except Exception as e:
        return {"cmd": "write " + unit, "rc": 1, "out": "", "err": str(e)}


def _wait_pool_active(pool, timeout=40):
    """Дождаться, пока пул появится в df и станет active (PG развёрнуты)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        df, _ = cli_json(["df"])
        if isinstance(df, list):
            for p in df:
                if isinstance(p, dict) and p.get("name") == pool \
                        and p.get("status") == "active":
                    return True
        time.sleep(2)
    return False


def _image_exists(name):
    """Образ есть и целостен — виден в vitastor-cli ls (есть inode-конфиг)."""
    ls, _ = cli_json(["ls"])
    if isinstance(ls, list):
        for im in ls:
            if isinstance(im, dict) and im.get("name") == name:
                return True
    return False


def _fs_image_ensure(pool, img):
    """Гарантировать корректный образ метаданных VitastorFS <img> в <pool>.
    Подчищает «полу-создание» (index в etcd без inode-конфига) и создаёт заново.
    Возвращает (ok, run_cmd-словарь)."""
    if _image_exists(img):
        return True, {"cmd": "vitastor-cli ls", "rc": 0,
                      "out": "образ " + img + " уже существует", "err": ""}
    # образа нет в ls — но мог остаться осиротевший index от прошлой попытки
    run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "del",
             "/vitastor/index/image/" + img], env=_etcd_env())
    r = run_cmd([VITASTOR_CLI, "create", "-s", "1G",
                 "--pool", pool, img, "--force"], timeout=60)
    if r["rc"] != 0:
        return False, r
    if not _image_exists(img):
        r["err"] = ((r["err"] + "; ") if r["err"] else "") \
            + "образ не виден в vitastor-cli ls — неполное создание"
        return False, r
    return True, r


def _fs_mount_verify(unit, mount_path):
    """VitastorFS реально работоспособна: служба active И запись/чтение проходят.
    Битый образ метаданных (K/V «Invalid block 0 magic») через is-active НЕ ловится —
    vitastor-nfs остаётся active, ошибка вылезает только на реальном I/O.
    Возвращает (ok, run_cmd-словарь)."""
    sr = run_cmd(["systemctl", "is-active", unit])
    if (sr.get("out") or "").strip() != "active":
        return False, {"cmd": "systemctl is-active " + unit, "rc": 1,
                        "out": sr.get("out") or sr.get("err") or "",
                        "err": "служба монтирования не активна"}
    probe = mount_path.rstrip("/") + "/.proxomatron-fscheck"
    r = run_cmd(["bash", "-c",
                 "echo proxomatron-fs-ok > '%s' && cat '%s' && rm -f '%s'"
                 % (probe, probe, probe)], timeout=30)
    if r.get("rc") == 0 and "proxomatron-fs-ok" in (r.get("out") or ""):
        return True, {"cmd": "запись/чтение " + probe, "rc": 0,
                      "out": "VitastorFS отвечает: запись и чтение в "
                             + mount_path + " работают", "err": ""}
    return False, {"cmd": "запись/чтение " + probe, "rc": 1,
                   "out": r.get("out") or "",
                   "err": (r.get("err") or "I/O не прошёл")
                          + " — образ метаданных повреждён "
                            "(K/V «Invalid block 0 magic»)"}


def _osd_tags(num):
    """Теги OSD из etcd /vitastor/config/osd/<num> -> list[str]."""
    r = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                 "/vitastor/config/osd/" + str(num), "--print-value-only"],
                env=_etcd_env())
    try:
        t = (json.loads(r.get("out") or "{}") or {}).get("tags") or []
        if isinstance(t, str):
            t = [t]
        return [str(x) for x in t]
    except Exception:
        return []


def _pool_tags(pool_name):
    """osd_tags пула -> list[str]."""
    for pc in pools_config().values():
        if isinstance(pc, dict) and pc.get("name") == pool_name:
            t = pc.get("osd_tags") or []
            if isinstance(t, str):
                t = [t]
            return [str(x) for x in t]
    return []


def _pool_fs_image(pool_name):
    """Имя образа метаданных VitastorFS пула (used_for_app fs:<img>), или None."""
    for pc in pools_config().values():
        if isinstance(pc, dict) and pc.get("name") == pool_name:
            ufa = pc.get("used_for_app") or ""
            if isinstance(ufa, str) and ufa.startswith("fs:"):
                return ufa[3:]
    return None


def _remove_fs_image(img):
    """Удалить образ VitastorFS из etcd (index + inode-конфиг). run_cmd-словарь."""
    idx = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                   "/vitastor/index/image/" + img, "--print-value-only"],
                  env=_etcd_env())
    pool_id = inode_id = None
    try:
        meta = json.loads(idx.get("out") or "{}")
        pool_id, inode_id = meta.get("pool_id"), meta.get("id")
    except Exception:
        pass
    keys = ["/vitastor/index/image/" + img]
    if pool_id is not None and inode_id is not None:
        keys.append("/vitastor/config/inode/%s/%s" % (pool_id, inode_id))
    rc, done = 0, []
    for k in keys:
        r = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "del", k],
                    env=_etcd_env())
        if r.get("rc") != 0:
            rc = 1
        done.append(k)
    return {"cmd": "etcdctl del " + " ".join(done), "rc": rc,
            "out": "удалены ключи etcd образа " + img, "err": ""}


def _osd_set():
    tree, _ = cli_json(["osd-tree"])
    if isinstance(tree, list):
        return {str(o.get("name")) for o in tree
                if isinstance(o, dict) and o.get("type") == "osd"}
    return set()


def wizard_apply(c):
    """Выполнить операцию мастера. Возвращает {ok, results, msg}."""
    act = c["action"]
    results = []

    def emit(title, r, danger=False):
        ok = (r.get("rc") == 0)
        results.append({"title": title, "danger": danger, "ok": ok,
                        "cmd": r.get("cmd"), "out": r.get("out"),
                        "err": r.get("err")})
        return ok

    def info(title, text):
        results.append({"title": title, "danger": False, "ok": True,
                        "cmd": "", "out": text, "err": ""})

    if act == "create":
        new_osds = []
        if c["disks"]:
            before = _osd_set()
            r = run_cmd([VITASTOR_DISK, "prepare"] + c["disks"], timeout=300)
            if not emit("Подготовка дисков: " + " ".join(c["disks"]), r, True):
                return {"ok": False, "results": results,
                        "msg": "подготовка дисков не удалась — пул не создан"}
            time.sleep(10)
            new_osds = sorted(_osd_set() - before,
                              key=lambda x: int(x) if x.isdigit() else 0)
            info("Новые OSD", "обнаружены: " + (", ".join(new_osds) or "нет"))
            if not new_osds:
                return {"ok": False, "results": results,
                        "msg": "новые OSD не появились после подготовки дисков"}
        for n in new_osds:
            r = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "put",
                         "/vitastor/config/osd/" + n,
                         json.dumps({"tags": [c["tag"]]})], env=_etcd_env())
            emit("Тег OSD %s -> %s" % (n, c["tag"]), r)
        if c["existing_osds"]:
            tagmap = {o["num"]: o["tags"] for o in wizard_info()["osds"]}
            for n in c["existing_osds"]:
                tags = list(tagmap.get(n, []))
                if c["tag"] not in tags:
                    tags.append(c["tag"])
                r = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "put",
                             "/vitastor/config/osd/" + n,
                             json.dumps({"tags": tags})], env=_etcd_env())
                emit("Тег OSD %s -> %s" % (n, ",".join(tags)), r)
        r = run_cmd([VITASTOR_CLI, "create-pool", c["name"],
                     "-s", str(c["pg_size"]), "--pg_minsize", str(c["pg_minsize"]),
                     "-n", str(c["pg_count"]), "--failure_domain", c["failure_domain"],
                     "--osd_tags", c["tag"]], timeout=120)
        if not emit("Создание пула " + c["name"], r):
            return {"ok": False, "results": results,
                    "msg": "create-pool завершился ошибкой"}
        if c["mount_enable"]:
            img = "fs-" + c["name"]
            unit = "vitastorfs-" + c["name"]
            if _wait_pool_active(c["name"], 40):
                info("Готовность пула", c["name"] + " active — PG развёрнуты")
            else:
                info("Готовность пула",
                     "пул не стал active за 40 c — продолжаю")
            ok_img, ir = _fs_image_ensure(c["name"], img)
            results.append({"title": "Образ метаданных " + img,
                            "danger": False, "ok": ok_img,
                            "cmd": ir.get("cmd"), "out": ir.get("out"),
                            "err": ir.get("err")})
            if not ok_img:
                return {"ok": False, "results": results,
                        "msg": "пул создан, но образ метаданных VitastorFS не "
                               "удался — монтирование пропущено (пул не помечен "
                               "used_for_app)"}
            emit("Пометка used_for_app",
                 run_cmd([VITASTOR_CLI, "modify-pool",
                          "--used_for_app", "fs:" + img, c["name"]], timeout=60))
            emit("systemd-юнит " + unit,
                 _write_fs_unit(c["name"], img, c["mount_path"]))
            emit("systemctl daemon-reload", run_cmd(["systemctl", "daemon-reload"]))
            run_cmd(["systemctl", "reset-failed", unit])
            emit("Запуск монтирования",
                 run_cmd(["systemctl", "enable", "--now", unit], timeout=60))
            # дождаться поднятия службы, затем дать NFS-серверу осесть
            for _ in range(6):
                if (run_cmd(["systemctl", "is-active", unit]).get("out")
                        or "") == "active":
                    break
                time.sleep(2)
            time.sleep(3)
            mnt_ok, mr = _fs_mount_verify(unit, c["mount_path"])
            # первый монтаж пустого образа может словить гонку с peering PG ->
            # битый K/V («Invalid block 0 magic»): is-active это НЕ показывает
            # (vitastor-nfs остаётся active), ловим реальной записью -> пере-
            # создаём образ метаданных и повторяем (до 2 раз)
            attempt = 0
            while not mnt_ok and attempt < 2:
                attempt += 1
                info("Монтирование: повтор %d" % attempt,
                     "VitastorFS не отвечает (%s) — пересоздаю образ метаданных"
                     % (mr.get("err") or "ошибка I/O"))
                old_pid = old_iid = None
                idxr = run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "get",
                                "/vitastor/index/image/" + img,
                                "--print-value-only"], env=_etcd_env())
                try:
                    m = json.loads(idxr.get("out") or "{}")
                    old_pid, old_iid = m.get("pool_id"), m.get("id")
                except Exception:
                    pass
                run_cmd(["systemctl", "stop", unit], timeout=30)
                run_cmd(["umount", "-l", c["mount_path"]])
                run_cmd([VITASTOR_CLI, "rm", img], timeout=180)
                run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "del",
                         "/vitastor/index/image/" + img], env=_etcd_env())
                if old_pid is not None and old_iid is not None:
                    run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "del",
                             "/vitastor/inode/stats/%s/%s"
                             % (old_pid, old_iid)], env=_etcd_env())
                _wait_pool_active(c["name"], 30)
                emit("Пересоздание образа " + img,
                     run_cmd([VITASTOR_CLI, "create", "-s", "1G",
                              "--pool", c["name"], img, "--force"], timeout=60))
                run_cmd(["systemctl", "reset-failed", unit])
                emit("Запуск монтирования (повтор %d)" % attempt,
                     run_cmd(["systemctl", "start", unit], timeout=60))
                time.sleep(8)
                mnt_ok, mr = _fs_mount_verify(unit, c["mount_path"])
            results.append({"title": "Проверка VitastorFS (запись/чтение)",
                            "danger": False, "ok": mnt_ok,
                            "cmd": mr.get("cmd"), "out": mr.get("out"),
                            "err": "" if mnt_ok else
                            (mr.get("err") or "")
                            + " — журнал: journalctl -u " + unit})
        ok = all(x["ok"] for x in results)
        return {"ok": ok, "results": results,
                "msg": "пул '%s' создан" % c["name"] if ok
                else "пул создан, но часть шагов с ошибками — проверьте лог"}
    if act == "edit":
        ch = c["changes"]
        args = [VITASTOR_CLI, "modify-pool", c["pool"]]
        for k in ("pg_size", "pg_minsize", "pg_count", "failure_domain"):
            if k in ch:
                args += ["--" + k, str(ch[k])]
        if "name" in ch:
            args += ["--name", str(ch["name"])]
        ok = emit("Изменение пула " + c["pool"], run_cmd(args, timeout=120))
        return {"ok": ok, "results": results,
                "msg": "параметры пула применены" if ok
                else "modify-pool завершился ошибкой"}
    if act == "replace":
        mode = c["mode"]
        retired_tags = []
        # --- фаза вывода сбойного OSD ---
        if mode in ("retire", "oneshot"):
            osd = str(c["osd"])
            retired_tags = _osd_tags(osd)
            info("osd.%s — теги пула" % osd,
                 ", ".join(retired_tags) or "без тегов")
            run_cmd(["systemctl", "stop", "vitastor-osd@" + osd], timeout=60)
            run_cmd(["systemctl", "reset-failed", "vitastor-osd@" + osd])
            info("Демон vitastor-osd@%s" % osd, "остановлен")
            rmok = emit("Вывод osd.%s из кластера" % osd,
                        run_cmd([VITASTOR_CLI, "rm-osd", osd, "--force",
                                 "--allow-data-loss"], timeout=180), True)
            if rmok:
                run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "del",
                         "/vitastor/config/osd/" + osd], env=_etcd_env())
                if mode == "oneshot":
                    # дождаться, пока osd-tree забудет выведенный OSD — иначе
                    # set-diff не увидит переиспользованный номер нового OSD
                    for _ in range(10):
                        if osd not in _osd_set():
                            break
                        time.sleep(2)
            elif mode == "oneshot":
                return {"ok": False, "results": results,
                        "msg": "не удалось вывести osd.%s — ввод нового диска "
                               "отменён" % osd}
        # --- фаза ввода нового диска ---
        if mode in ("induct", "oneshot"):
            if mode == "oneshot":
                tags, pool_label = retired_tags, "пул сбойного OSD"
            else:
                tags, pool_label = _pool_tags(c["pool"]), c["pool"]
            disk = c["disk"]
            before = _osd_set()
            if not emit("Подготовка диска %s как OSD" % disk,
                        run_cmd([VITASTOR_DISK, "prepare", disk],
                                timeout=300), True):
                return {"ok": False, "results": results,
                        "msg": "vitastor-disk prepare не удался — "
                               "диск не введён"}
            time.sleep(10)
            new_osds = sorted(_osd_set() - before,
                              key=lambda x: int(x) if x.isdigit() else 0)
            info("Новые OSD", "обнаружены: " + (", ".join(new_osds) or "нет"))
            if not new_osds:
                return {"ok": False, "results": results,
                        "msg": "новый OSD не появился после подготовки диска"}
            if tags:
                for n in new_osds:
                    emit("Тег osd.%s -> %s (%s)"
                         % (n, ",".join(tags), pool_label),
                         run_cmd([ETCDCTL, "--endpoints=" + ETCD_EP, "put",
                                  "/vitastor/config/osd/" + n,
                                  json.dumps({"tags": tags})],
                                 env=_etcd_env()))
            else:
                info("Теги OSD",
                     "целевых тегов нет — osd.%s оставлен без тега; назначьте "
                     "тег пула вручную" % ", ".join(new_osds))
        ok = all(x["ok"] for x in results)
        if not ok:
            msg = "замена выполнена частично — проверьте лог шагов"
        elif mode == "retire":
            msg = ("osd.%s выведен. Физически замените диск, затем запустите "
                   "«Заменить диск» → «Шаг 2: ввести диск»." % c["osd"])
        elif mode == "induct":
            msg = "Новый диск введён в пул — кластер ресинкает данные."
        else:
            msg = "Диск заменён — пул сохранён, кластер ресинкает данные."
        return {"ok": ok, "results": results, "msg": msg}
    # delete
    removable, shared = ([], [])
    if c.get("remove_osds"):
        removable, shared = pool_osd_plan(c["pool"])
    fs_img = _pool_fs_image(c["pool"])  # до rm-pool — потом конфиг исчезнет
    mounts = vitastorfs_mounts()
    if c["pool"] in mounts:
        u = mounts[c["pool"]]["unit"]
        emit("Остановка монтирования " + u,
             run_cmd(["systemctl", "disable", "--now", u], timeout=60), True)
        try:
            os.remove(SYSTEMD_DIR + "/" + u)
            info("Удаление юнита " + u, "файл удалён")
        except Exception as e:
            results.append({"title": "Удаление юнита " + u, "danger": True,
                            "ok": False, "cmd": "", "out": "", "err": str(e)})
        run_cmd(["systemctl", "daemon-reload"])
    pool_ok = emit("Удаление пула " + c["pool"],
                   run_cmd([VITASTOR_CLI, "rm-pool", "--force", c["pool"]],
                           timeout=120), True)
    if pool_ok and fs_img:
        emit("Удаление образа метаданных " + fs_img, _remove_fs_image(fs_img))
    if c.get("remove_osds") and pool_ok:
        for o in removable:
            dev = o["part"]
            if not dev:
                results.append({"title": "Удаление OSD " + o["num"],
                                "danger": True, "ok": False, "cmd": "",
                                "out": "", "err": "раздел OSD не найден"})
                continue
            emit("Удаление OSD %s (%s)" % (o["num"], dev),
                 run_cmd([VITASTOR_DISK, "purge", "--force",
                          "--allow-data-loss", dev], timeout=180), True)
        if shared:
            info("OSD сохранены",
                 "не тронуты (общие с другими пулами): "
                 + ", ".join("osd." + n for n in shared))
        if c.get("wipe_disks"):
            for d in sorted({o["disk"] for o in removable if o["disk"]}):
                dev = "/dev/" + d
                emit("wipefs " + dev,
                     run_cmd(["wipefs", "-af", dev], timeout=60), True)
                emit("sgdisk --zap-all " + dev,
                     run_cmd(["sgdisk", "--zap-all", dev], timeout=60), True)
                run_cmd(["partprobe", dev], timeout=30)
    ok = all(x["ok"] for x in results)
    return {"ok": ok, "results": results,
            "msg": "пул '%s' удалён" % c["pool"] if ok
            else "удаление завершилось с ошибками — проверьте лог"}


# ---------- управление службой (вкл/выкл/таймер автостопа) ----------
SVC_NAME = "proxomatron"
SVC_AUTOSTOP_UNIT = "proxomatron-autostop"
_DUR_RE = re.compile(r"^[A-Za-z0-9\s]+$")


def _autostop_next():
    """(epoch_at, left_text) — None/None если таймер не активен."""
    try:
        p = subprocess.run(
            ["systemctl", "is-active", SVC_AUTOSTOP_UNIT + ".timer"],
            capture_output=True, text=True, timeout=3)
        if (p.stdout or "").strip() != "active":
            return None, None
    except Exception:
        return None, None
    try:
        p = subprocess.run(
            ["systemctl", "list-timers", SVC_AUTOSTOP_UNIT + ".timer",
             "--no-pager"], capture_output=True, text=True, timeout=3)
        for line in (p.stdout or "").splitlines():
            f = line.split()
            if (len(f) >= 4 and len(f[0]) == 3 and f[0][0].isupper()
                    and f[1][:2].isdigit()):
                ts = " ".join(f[:4])
                p2 = subprocess.run(["date", "-d", ts, "+%s"],
                                    capture_output=True, text=True, timeout=3)
                v = (p2.stdout or "").strip()
                if v.lstrip("-").isdigit():
                    left = ""
                    for tok in f[4:]:
                        if tok == "-":
                            break
                        left = (left + " " + tok) if left else tok
                    return int(v), (left or None)
                break
    except Exception:
        pass
    return None, None


def service_info():
    info = {"active": False, "enabled": False, "now": int(time.time()),
            "autostop_at": None, "autostop_left": None}
    try:
        p = subprocess.run(["systemctl", "is-active", SVC_NAME],
                           capture_output=True, text=True, timeout=3)
        info["active"] = ((p.stdout or "").strip() == "active")
    except Exception:
        pass
    try:
        p = subprocess.run(["systemctl", "is-enabled", SVC_NAME],
                           capture_output=True, text=True, timeout=3)
        info["enabled"] = ((p.stdout or "").strip() == "enabled")
    except Exception:
        pass
    at, left = _autostop_next()
    info["autostop_at"] = at
    info["autostop_left"] = left
    return info


def _autostop_cancel():
    for unit in (SVC_AUTOSTOP_UNIT + ".timer", SVC_AUTOSTOP_UNIT + ".service"):
        subprocess.run(["systemctl", "stop", unit],
                       capture_output=True, timeout=10)
        subprocess.run(["systemctl", "reset-failed", unit],
                       capture_output=True, timeout=5)


def service_timer_set(duration):
    _autostop_cancel()
    if not duration:
        return {"ok": True, "msg": "автостоп отменён"}
    if not isinstance(duration, str) or not _DUR_RE.match(duration) \
            or not any(c.isdigit() for c in duration) or len(duration) > 24:
        return {"error": "недопустимый формат времени (например: 3h, 30min, 1h30m)"}
    p = subprocess.run(
        ["systemd-run", "--quiet", "--on-active=" + duration,
         "--unit=" + SVC_AUTOSTOP_UNIT,
         "--description=auto-stop PROXOMATRON",
         "/bin/systemctl", "stop", SVC_NAME],
        capture_output=True, text=True, timeout=10)
    if p.returncode != 0:
        return {"error": ((p.stderr or "").strip()
                          or "не удалось установить таймер")}
    return {"ok": True, "msg": "автостоп через " + duration}


def service_stop_now():
    # Запускаем остановку в отдельном transient-юните, чтобы текущий процесс
    # успел отправить HTTP-ответ до получения SIGTERM от systemctl stop.
    p = subprocess.run(
        ["systemd-run", "--quiet", "--on-active=1s",
         "--description=stop PROXOMATRON",
         "/bin/systemctl", "stop", SVC_NAME],
        capture_output=True, text=True, timeout=5)
    if p.returncode != 0:
        return {"error": ((p.stderr or "").strip()
                          or "не удалось остановить")}
    return {"ok": True}


# ============================================================================
# /api/host/* — данные для вкладки "Узел" (категория Host)
# ============================================================================

def _read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return ""


def host_sysinfo():
    """Hostname, OS, kernel, PVE version, uptime."""
    hn = run_cmd(["/bin/hostname"], timeout=3).get("out") or "?"
    kr = run_cmd(["/bin/uname", "-r"], timeout=3).get("out") or "?"
    pv = run_cmd(["/usr/bin/pveversion"], timeout=5)
    pve_ver = pv.get("out") or pv.get("err") or "не Proxmox-узел"
    ut_pretty = run_cmd(["/usr/bin/uptime", "-p"], timeout=3).get("out") or "?"
    uptime_secs = None
    try:
        uptime_secs = float(_read_file("/proc/uptime").split()[0])
    except Exception:
        pass
    os_pretty = ""
    for line in _read_file("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_pretty = line.split("=", 1)[1].strip().strip('"')
            break
    boot_time = None
    if uptime_secs is not None:
        try:
            boot_time = int(time.time() - uptime_secs)
        except Exception:
            pass
    return {
        "hostname": hn,
        "kernel": kr,
        "os": os_pretty or "?",
        "pve_version": pve_ver,
        "uptime_pretty": ut_pretty,
        "uptime_secs": uptime_secs,
        "boot_epoch": boot_time,
        "arch": run_cmd(["/bin/uname", "-m"], timeout=2).get("out") or "?",
    }


def host_resources():
    """CPU model/cores/load, память, swap, температура."""
    cpu_model = ""
    cpu_count = 0
    for line in _read_file("/proc/cpuinfo").splitlines():
        if line.startswith("model name") and not cpu_model:
            cpu_model = line.split(":", 1)[1].strip()
        if line.startswith("processor"):
            cpu_count += 1
    load = []
    try:
        load = _read_file("/proc/loadavg").split()[:3]
    except Exception:
        pass
    mem = {}
    for line in _read_file("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            mem[k.strip()] = v.strip()

    def _kib(key):
        v = mem.get(key, "")
        try:
            return int(v.split()[0])
        except Exception:
            return None

    mem_total = _kib("MemTotal")
    mem_avail = _kib("MemAvailable")
    mem_free = _kib("MemFree")
    mem_cached = _kib("Cached")
    swap_total = _kib("SwapTotal")
    swap_free = _kib("SwapFree")
    mem_used = (mem_total - mem_avail) if (mem_total and mem_avail) else None
    swap_used = (swap_total - swap_free) if (swap_total and swap_free is not None) else None
    sensors = run_cmd(["/usr/bin/sensors", "-A"], timeout=3)
    sensors_ok = (sensors.get("rc") == 0) and bool(sensors.get("out"))
    return {
        "cpu_model": cpu_model or "?",
        "cpu_cores": cpu_count,
        "loadavg": load,
        "mem_kib": {"total": mem_total, "used": mem_used,
                    "available": mem_avail, "free": mem_free, "cached": mem_cached},
        "swap_kib": {"total": swap_total, "used": swap_used, "free": swap_free},
        "sensors_text": sensors.get("out") if sensors_ok else "",
        "sensors_available": sensors_ok,
        "sensors_msg": "" if sensors_ok else (sensors.get("err")
                                              or "lm-sensors не установлен"),
    }


def host_vmct():
    """Список VM (qemu) и контейнеров (lxc) через pvesh."""
    try:
        node = os.uname().nodename
    except Exception:
        node = "node"
    qemu = run_cmd(["/usr/bin/pvesh", "get", "/nodes/" + node + "/qemu",
                    "--output-format", "json"], timeout=10)
    lxc = run_cmd(["/usr/bin/pvesh", "get", "/nodes/" + node + "/lxc",
                   "--output-format", "json"], timeout=10)
    try:
        vms = json.loads(qemu.get("out") or "[]") if qemu.get("rc") == 0 else []
    except Exception:
        vms = []
    try:
        cts = json.loads(lxc.get("out") or "[]") if lxc.get("rc") == 0 else []
    except Exception:
        cts = []
    return {
        "node": node, "vms": vms, "cts": cts,
        "vms_err": (qemu.get("err") or qemu.get("out") or "")
                   if qemu.get("rc") != 0 else None,
        "cts_err": (lxc.get("err") or lxc.get("out") or "")
                   if lxc.get("rc") != 0 else None,
    }


_cpu_last_total = None      # последний снимок /proc/stat (агрегат)
_cpu_last_cores = []        # последние снимки per-core
_net_last = {"counters": {}, "ts": 0}
_pwr_last = {"uj": None, "ts": 0}


def _read_cpu_stat_all():
    """/proc/stat -> {total: [user,nice,sys,idle,iowait,...], cores: [[..], ..]}"""
    total = None; cores = []
    for line in _read_file("/proc/stat").splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("cpu"):
            continue
        try:
            vals = [int(x) for x in parts[1:]]
        except Exception:
            continue
        if parts[0] == "cpu":
            total = vals
        else:
            cores.append(vals)
    return total, cores


def _cpu_pct_from_diff(prev, curr):
    if not prev or not curr or len(prev) < 4 or len(curr) < 4:
        return None
    diff = [c - p for c, p in zip(curr, prev)]
    tot = sum(diff)
    if tot <= 0:
        return None
    idle = diff[3] + (diff[4] if len(diff) > 4 else 0)
    return max(0.0, min(100.0, round((1.0 - idle / tot) * 100, 1)))


def _read_net_counters():
    """/proc/net/dev -> {ifname: {rx_bytes, tx_bytes, rx_packets, tx_packets}}"""
    res = {}
    for line in _read_file("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        if not name or name == "lo":
            continue
        parts = rest.split()
        if len(parts) < 16:
            continue
        try:
            res[name] = {
                "rx_bytes": int(parts[0]),
                "rx_packets": int(parts[1]),
                "tx_bytes": int(parts[8]),
                "tx_packets": int(parts[9]),
            }
        except Exception:
            pass
    return res


def _read_rapl_uj():
    """Intel RAPL package energy_uj (microjoules), либо None если недоступно."""
    paths = [
        "/sys/class/powercap/intel-rapl:0/energy_uj",
        "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj",
    ]
    for p in paths:
        v = _read_file(p).strip()
        if v.isdigit():
            try:
                return int(v)
            except Exception:
                pass
    return None


def _gpu_devices():
    """Список GPU (nvidia-smi); пусто если NVIDIA нет."""
    nv = run_cmd(["/usr/bin/nvidia-smi",
                  "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                  "--format=csv,noheader,nounits"], timeout=3)
    devs = []
    if nv.get("rc") == 0 and nv.get("out"):
        for line in nv["out"].splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 5:
                continue
            try:
                devs.append({
                    "name": parts[0],
                    "util_pct": int(parts[1]),
                    "mem_used_mib": int(parts[2]),
                    "mem_total_mib": int(parts[3]),
                    "temp_c": int(parts[4]),
                })
            except Exception:
                pass
    return devs


def _cpu_temperature():
    """CPU-package temp (°C) через /sys/class/hwmon (coretemp/k10temp/zenpower/cpu_thermal),
    с fallback на /sys/class/thermal (x86_pkg_temp). None — если ничего не нашлось."""
    best = None  # (score, °C)
    try:
        for base in os.listdir("/sys/class/hwmon"):
            d = "/sys/class/hwmon/" + base
            name = _read_file(d + "/name").strip()
            if name not in ("coretemp", "k10temp", "zenpower", "cpu_thermal"):
                continue
            try:
                files = os.listdir(d)
            except Exception:
                continue
            for f in sorted(files):
                if not f.endswith("_input"):
                    continue
                stem = f[:-len("_input")]
                label = _read_file(d + "/" + stem + "_label").strip()
                v = _read_file(d + "/" + f).strip()
                if not v or v.lstrip("-").isdigit() is False:
                    continue
                try:
                    mc = int(v)
                except Exception:
                    continue
                ll = label.lower()
                if "package" in ll:        sc = 100
                elif ll in ("tdie",):      sc = 90
                elif ll in ("tctl",):      sc = 80
                elif "core" in ll:         sc = 50
                elif not label:            sc = 40
                else:                      sc = 30
                if best is None or sc > best[0]:
                    best = (sc, mc)
    except Exception:
        pass
    if best is None:
        try:
            for base in os.listdir("/sys/class/thermal"):
                if not base.startswith("thermal_zone"):
                    continue
                d = "/sys/class/thermal/" + base
                t = _read_file(d + "/type").strip()
                if t not in ("x86_pkg_temp", "cpu-thermal", "soc_thermal"):
                    continue
                v = _read_file(d + "/temp").strip()
                try:
                    best = (10, int(v))
                except Exception:
                    pass
                if best is not None:
                    break
        except Exception:
            pass
    if best is None:
        return None
    return round(best[1] / 1000.0)


def _disk_temps():
    """{name: temp_c} через smartctl -A -n standby (HDD в простое не будятся).
    Кэш 60 секунд, чтобы не мучить диски на каждом тике системного монитора."""
    now = time.time()
    with _disk_temp_lock:
        if _disk_temp_cache["data"] and (now - _disk_temp_cache["ts"]) < 60:
            return _disk_temp_cache["data"]
    out = {}
    if not os.path.exists(SMARTCTL):
        with _disk_temp_lock:
            _disk_temp_cache["ts"] = now
            _disk_temp_cache["data"] = out
        return out
    for dd in (disks_info_cached() or []):
        name = dd.get("name")
        if not name or not re.match(r"^[A-Za-z0-9]+$", name):
            continue
        dev = "/dev/" + name
        if not os.path.exists(dev):
            continue
        tc = None
        for extra in ([], ["-d", "sat"]):
            try:
                p = subprocess.run(
                    [SMARTCTL, "--json=c", "-A", "-n", "standby"] + extra + [dev],
                    capture_output=True, text=True, timeout=6)
                j = json.loads(p.stdout or "{}")
            except Exception:
                continue
            t = (j.get("temperature") or {}).get("current")
            if t is None:
                nv = j.get("nvme_smart_health_information_log") or {}
                t = nv.get("temperature")
            if t is not None:
                try:
                    tc = int(t); break
                except Exception:
                    pass
        if tc is not None:
            out[name] = tc
    with _disk_temp_lock:
        _disk_temp_cache["ts"] = now
        _disk_temp_cache["data"] = out
    return out


_vm_vendor_cache = {"v": None, "ts": 0}


def _vm_vendor():
    """Кешированно: DMI sys_vendor (QEMU/VMware/Xen/...) либо 'bare-metal'."""
    if _vm_vendor_cache["v"] is not None and (time.time() - _vm_vendor_cache["ts"]) < 60:
        return _vm_vendor_cache["v"]
    v = _read_file("/sys/devices/virtual/dmi/id/sys_vendor").strip()
    if not v:
        v = ""
    # Если в /proc/cpuinfo есть флаг hypervisor — это VM
    if not v:
        hv = "hypervisor" in _read_file("/proc/cpuinfo")
        v = "VM (hypervisor)" if hv else "bare-metal"
    _vm_vendor_cache["v"] = v; _vm_vendor_cache["ts"] = time.time()
    return v


def _proc_thread_count():
    nproc, nthr = 0, 0
    try:
        for ent in os.listdir("/proc"):
            if not ent.isdigit():
                continue
            nproc += 1
            try:
                with open("/proc/%s/status" % ent) as f:
                    for line in f:
                        if line.startswith("Threads:"):
                            nthr += int(line.split()[1])
                            break
            except Exception:
                pass
    except Exception:
        pass
    return nproc, nthr


def host_monitor():
    """Снимок системного монитора: CPU/GPU/RAM/Storage/Net/Power.
    Использует diff между вызовами для скоростных метрик (CPU%, bps, ватты)."""
    global _cpu_last_total, _cpu_last_cores, _net_last, _pwr_last
    now = time.time()

    # ===== CPU =====
    total_now, cores_now = _read_cpu_stat_all()
    cpu_pct = _cpu_pct_from_diff(_cpu_last_total, total_now) if _cpu_last_total else None
    per_core = []
    for i, curr in enumerate(cores_now):
        prev = _cpu_last_cores[i] if i < len(_cpu_last_cores) else None
        per_core.append(_cpu_pct_from_diff(prev, curr) if prev else None)
    _cpu_last_total = total_now
    _cpu_last_cores = cores_now

    load = []
    try:
        load = [float(x) for x in _read_file("/proc/loadavg").split()[:3]]
    except Exception:
        pass

    cpu_model = ""; cpu_count = 0
    for line in _read_file("/proc/cpuinfo").splitlines():
        if line.startswith("model name") and not cpu_model:
            cpu_model = line.split(":", 1)[1].strip()
        if line.startswith("processor"):
            cpu_count += 1

    freqs = []
    for i in range(cpu_count):
        v = _read_file("/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq" % i).strip()
        if v.isdigit():
            try:
                freqs.append(int(v) // 1000)
            except Exception:
                pass

    # ===== RAM =====
    mem = {}
    for line in _read_file("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            try:
                mem[k.strip()] = int(v.strip().split()[0])
            except Exception:
                pass

    # ===== Network =====
    net_now = _read_net_counters()
    net_rates = []
    if _net_last.get("counters") and _net_last.get("ts"):
        dt = now - _net_last["ts"]
        if dt > 0:
            for name, curr in net_now.items():
                prev = _net_last["counters"].get(name)
                if not prev:
                    continue
                net_rates.append({
                    "name": name,
                    "rx_bps": max(0, int((curr["rx_bytes"] - prev["rx_bytes"]) / dt)),
                    "tx_bps": max(0, int((curr["tx_bytes"] - prev["tx_bytes"]) / dt)),
                    "rx_pps": max(0, int((curr["rx_packets"] - prev["rx_packets"]) / dt)),
                    "tx_pps": max(0, int((curr["tx_packets"] - prev["tx_packets"]) / dt)),
                })
    _net_last = {"counters": net_now, "ts": now}
    net_rates.sort(key=lambda x: -(x["rx_bps"] + x["tx_bps"]))

    # ===== GPU =====
    gpus = _gpu_devices()

    # ===== Power (RAPL package) =====
    uj_now = _read_rapl_uj()
    watts = None
    pwr_avail = False
    if uj_now is not None:
        pwr_avail = True
        if _pwr_last.get("uj") is not None and _pwr_last.get("ts"):
            dt = now - _pwr_last["ts"]
            if dt > 0:
                dj = (uj_now - _pwr_last["uj"]) / 1_000_000.0
                if dj >= 0:
                    watts = round(dj / dt, 1)
        _pwr_last = {"uj": uj_now, "ts": now}

    # Доп. инфо для правой панели спецификаций
    nproc, nthr = _proc_thread_count()
    uptime_s = None
    try:
        uptime_s = float(_read_file("/proc/uptime").split()[0])
    except Exception:
        pass
    base_freq = None
    v = _read_file("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency").strip()
    if v.isdigit():
        try:
            base_freq = int(v) // 1000
        except Exception:
            pass
    if base_freq is None:
        # fallback: cpuinfo "cpu MHz" line — это текущая, не базовая, но лучше чем ничего
        for line in _read_file("/proc/cpuinfo").splitlines():
            if line.startswith("cpu MHz"):
                try:
                    base_freq = int(float(line.split(":",1)[1].strip())); break
                except Exception:
                    pass

    # net cumulative — выдаём rx/tx_bytes снимок (для "Всего отправлено/получено")
    net_counters = {}
    for k, c in net_now.items():
        net_counters[k] = {"rx_bytes": c["rx_bytes"], "tx_bytes": c["tx_bytes"],
                            "rx_packets": c["rx_packets"], "tx_packets": c["tx_packets"]}

    return {
        "ts": now,
        "cpu": {
            "model": cpu_model, "cores": cpu_count, "pct": cpu_pct,
            "per_core_pct": per_core, "loadavg": load, "freq_mhz": freqs,
            "base_freq_mhz": base_freq,
            "sockets": 1,
            "vm_vendor": _vm_vendor(),
            "proc_count": nproc, "thread_count": nthr,
            "uptime_secs": uptime_s,
            "temp_c": _cpu_temperature(),
        },
        "ram": (lambda _arc=read_arcstats(): {
            "total_kib": mem.get("MemTotal"),
            "available_kib": mem.get("MemAvailable"),
            "free_kib": mem.get("MemFree"),
            "cached_kib": mem.get("Cached"),
            "buffers_kib": mem.get("Buffers"),
            "swap_total_kib": mem.get("SwapTotal"),
            "swap_free_kib": mem.get("SwapFree"),
            "committed_kib": mem.get("Committed_AS"),
            "zswap_kib": mem.get("Zswap"),
            "arc_size_bytes": (_arc.get("size") if _arc else None),
            "arc_max_bytes":  (_arc.get("c_max") if _arc else None),
            "arc_available":  bool(_arc and _arc.get("size") is not None),
        })(),
        "net": {"rates": net_rates, "counters": net_counters},
        "gpu": {"available": bool(gpus), "devices": gpus},
        "power": {"available": pwr_avail, "watts": watts},
    }


def _ethtool_info(name):
    """ethtool $name -> {autoneg, duplex, speed_mbps, link_detected}. Все могут быть None."""
    r = run_cmd(["/usr/sbin/ethtool", name], timeout=3)
    out = (r.get("out") or "") + "\n" + (r.get("err") or "")
    autoneg = None; duplex = None; speed = None; link = None
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Auto-negotiation:"):
            v = line.split(":", 1)[1].strip().lower()
            if v in ("on", "off"):
                autoneg = (v == "on")
        elif line.startswith("Duplex:"):
            v = line.split(":", 1)[1].strip().lower()
            if v in ("full", "half"):
                duplex = v
        elif line.startswith("Speed:"):
            v = line.split(":", 1)[1].strip()
            m = re.match(r"(\d+)", v)
            if m:
                try: speed = int(m.group(1))
                except Exception: pass
        elif line.startswith("Link detected:"):
            link = "yes" in line.lower()
    return {"autoneg": autoneg, "duplex": duplex,
            "speed_mbps": speed, "link_detected": link}


def network_interfaces():
    """Все сетевые интерфейсы узла: тип/state/MAC/MTU/IP/счётчики/speed/carrier
    + autoneg/duplex (через ethtool, только для физических)."""
    link = run_cmd(["/usr/sbin/ip", "-d", "-s", "-j", "link", "show"], timeout=5)
    addr = run_cmd(["/usr/sbin/ip", "-j", "addr", "show"], timeout=5)
    try:
        links = json.loads(link.get("out") or "[]")
    except Exception:
        links = []
    try:
        addrs = json.loads(addr.get("out") or "[]")
    except Exception:
        addrs = []

    addr_by_if = {}
    for a in addrs:
        name = a.get("ifname")
        if not name:
            continue
        ipv4, ipv6 = [], []
        for info in a.get("addr_info") or []:
            fam = info.get("family"); ip = info.get("local"); pre = info.get("prefixlen")
            if not ip:
                continue
            entry = "%s/%s" % (ip, pre)
            if fam == "inet":
                ipv4.append(entry)
            elif fam == "inet6":
                ipv6.append(entry)
        addr_by_if[name] = {"ipv4": ipv4, "ipv6": ipv6}

    interfaces = []
    for L in links:
        name = L.get("ifname", "")
        if not name:
            continue
        info_kind = (L.get("linkinfo") or {}).get("info_kind", "")
        link_type = L.get("link_type", "")
        if name == "lo":
            t = "loopback"
        elif info_kind == "bridge":
            t = "bridge"
        elif info_kind == "bond":
            t = "bond"
        elif info_kind == "vlan":
            t = "vlan"
        elif info_kind == "veth":
            t = "veth"
        elif info_kind == "vxlan":
            t = "vxlan"
        elif info_kind in ("tun", "tap"):
            t = info_kind
        elif name.startswith("tap"):
            t = "tap"
        elif name.startswith(("fwbr", "fwln", "fwpr")):
            t = "fw-bridge"
        elif name.startswith("veth"):
            t = "veth"
        elif link_type == "ether":
            t = "physical"
        else:
            t = link_type or "?"

        stats = L.get("stats64") or {}
        rx = stats.get("rx") or {}; tx = stats.get("tx") or {}

        speed = None
        try:
            v = _read_file("/sys/class/net/%s/speed" % name).strip()
            if v:
                s = int(v)
                if s > 0:
                    speed = s
        except Exception:
            pass
        carrier = None
        try:
            v = _read_file("/sys/class/net/%s/carrier" % name).strip()
            if v in ("0", "1"):
                carrier = (v == "1")
        except Exception:
            pass

        a = addr_by_if.get(name, {})
        et = {"autoneg": None, "duplex": None, "speed_mbps": None, "link_detected": None}
        if t == "physical":
            et = _ethtool_info(name)
            if et.get("speed_mbps") and not speed:
                speed = et["speed_mbps"]
        interfaces.append({
            "name": name, "type": t,
            "state": (L.get("operstate") or "?").lower(),
            "mac": L.get("address") or "",
            "mtu": L.get("mtu"),
            "master": L.get("master"),
            "ipv4": a.get("ipv4", []),
            "ipv6": a.get("ipv6", []),
            "rx_bytes": rx.get("bytes"), "tx_bytes": tx.get("bytes"),
            "rx_packets": rx.get("packets"), "tx_packets": tx.get("packets"),
            "rx_errors": rx.get("errors", 0), "tx_errors": tx.get("errors", 0),
            "speed_mbps": speed, "carrier": carrier,
            "autoneg": et.get("autoneg"), "duplex": et.get("duplex"),
            "link_detected": et.get("link_detected"),
            "info_kind": info_kind,
        })

    order = {"physical": 0, "bond": 1, "bridge": 2, "vlan": 3, "vxlan": 4,
             "veth": 5, "tap": 6, "tun": 6, "fw-bridge": 7, "loopback": 9}
    interfaces.sort(key=lambda x: (order.get(x["type"], 8), x["name"]))
    return {"interfaces": interfaces}


def host_cluster():
    """Состояние PVE-кластера: pvecm status + ha-manager status."""
    coro_active = run_cmd(["/bin/systemctl", "is-active", "corosync"],
                          timeout=3).get("out") == "active"
    pvecm = run_cmd(["/usr/bin/pvecm", "status"], timeout=5)
    ha = run_cmd(["/usr/sbin/ha-manager", "status"], timeout=5)
    standalone = (not coro_active) or (pvecm.get("rc") not in (0,))
    return {
        "corosync_active": coro_active,
        "standalone": standalone,
        "pvecm_text": pvecm.get("out") or pvecm.get("err") or "",
        "pvecm_rc": pvecm.get("rc"),
        "ha_text": ha.get("out") or ha.get("err") or "",
        "ha_rc": ha.get("rc"),
    }


INDEX_HTML = r'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PROXOMATRON</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --line:#30363d;
    --side:#10151c; --txt:#e6edf3; --dim:#8b949e; --accent:#2dd4bf;
    --ok:#3fb950; --no:#f78166; --warn:#f0b429; --info:#38bdf8;
    --rd:#38bdf8; --wr:#a371f7; --zfs:#38bdf8; --ceph:#f4c63a;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{background:var(--bg);color:var(--txt);
    font-family:"Segoe UI",Roboto,Arial,sans-serif;font-size:14px}
  .app{display:flex;min-height:100vh}

  .sidebar{width:222px;flex:none;background:var(--side);
    border-right:1px solid var(--line);display:flex;flex-direction:column;
    position:sticky;top:0;height:100vh}
  .brand{padding:17px 18px 13px;border-bottom:1px solid var(--line)}
  .brand .nm{font-size:19px;font-weight:700;letter-spacing:.4px}
  .brand .nm b{color:var(--accent)}
  .brand .bsub{font-size:11px;color:var(--dim);margin-top:3px}
  /* горизонтальный ряд категорий (vSphere-style) */
  .sidetabs{display:flex;align-items:center;border-bottom:1px solid var(--line);
    padding:0 4px;gap:0;position:relative;background:var(--side)}
  .sidetab{flex:1;display:flex;align-items:center;justify-content:center;
    height:42px;font-size:18px;color:var(--dim);cursor:pointer;
    border-bottom:2px solid transparent;transition:color .15s,border-color .15s}
  .sidetab:hover{color:var(--txt)}
  .sidetab.active{color:var(--accent);border-bottom-color:var(--accent)}
  .sidecol{width:22px;height:24px;display:flex;align-items:center;justify-content:center;
    color:#5b626d;font-size:11px;cursor:pointer;border-radius:4px;margin-right:2px}
  .sidecol:hover{color:var(--txt);background:#151b24}
  .nav{padding:8px 0;flex:1;overflow:auto;display:none}
  .nav.cat-active{display:block}
  .navgrp{font-size:10px;letter-spacing:1.2px;color:#5b626d;text-transform:uppercase;
    font-weight:700;padding:12px 18px 5px}
  .navitem{display:flex;align-items:center;gap:10px;padding:9px 18px 9px 20px;
    cursor:pointer;color:var(--dim);font-size:13.5px;border-left:3px solid transparent}
  .navitem:hover{background:#151b24;color:var(--txt)}
  .navitem.active{color:var(--txt);background:#15242b;border-left-color:var(--accent)}
  .navitem .ico{width:21px;height:21px;flex:none;border-radius:6px;
    background:#1c2330;display:flex;align-items:center;justify-content:center;
    font-size:12px;color:var(--dim)}
  .navitem.active .ico{background:var(--accent);color:#06231f}
  .sidefoot{padding:12px 18px;border-top:1px solid var(--line)}
  .live{display:flex;align-items:center;gap:8px;font-size:11.5px;color:var(--dim)}
  .pulse{width:9px;height:9px;border-radius:50%;background:var(--ok);
    box-shadow:0 0 7px var(--ok);animation:bl 2s infinite;flex:none}
  @keyframes bl{0%,100%{opacity:1}50%{opacity:.3}}
  .pulse.stale{background:var(--no);box-shadow:0 0 7px var(--no);animation:none}

  .main{flex:1;padding:13px 22px 22px;min-width:0}
  .banner{background:#3a1d18;border:1px solid #5a2a22;color:#f7b3a3;
    border-radius:8px;padding:7px 12px;font-size:12.5px;margin-bottom:9px;display:none}
  .view{display:none}
  .view.active{display:block}
  #view-zfs{--accent:var(--zfs)}
  #view-ceph{--accent:var(--ceph)}
  h1.vt{font-size:18px;margin-bottom:2px}
  .vsub{color:var(--dim);font-size:12px;margin-bottom:10px}
  .lbl{font-size:11px;letter-spacing:1px;color:var(--dim);text-transform:uppercase;
    margin:13px 0 6px;font-weight:600}
  .row{display:grid;gap:8px}
  .r6{grid-template-columns:repeat(6,1fr)}
  .r4{grid-template-columns:repeat(4,1fr)}
  .r3{grid-template-columns:repeat(3,1fr)}
  @media(max-width:980px){.r6,.r4,.r3{grid-template-columns:repeat(2,1fr)}}

  .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 11px}
  .stat .k{font-size:11px;color:var(--dim);display:flex;align-items:center;gap:6px}
  .stat .v{font-size:19px;font-weight:700;margin-top:2px;line-height:1.1}
  .stat .s{font-size:11px;color:var(--dim);margin-top:1px}
  .dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
  .dot.ok{background:var(--ok);box-shadow:0 0 6px var(--ok)}
  .dot.no{background:var(--no);box-shadow:0 0 6px var(--no)}
  .dot.warn{background:var(--warn);box-shadow:0 0 6px var(--warn)}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:11px 13px}

  /* мониторинг дисков */
  .monwrap{display:flex;gap:10px}
  .dlist{width:236px;flex:none;display:flex;flex-direction:column;gap:7px}
  .mongraphs{flex:1;min-width:0}
  @media(max-width:880px){.monwrap{flex-direction:column}.dlist{width:auto;flex-direction:row;flex-wrap:wrap}}
  .dwidget{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:8px 10px;cursor:pointer;min-width:160px;flex:1}
  .dwidget:hover{border-color:#46505e}
  .dwidget.sel{border-color:var(--accent);background:#13262a}
  .dw-top{display:flex;align-items:center;gap:7px}
  .dw-nm{font-family:Consolas,monospace;font-weight:700;font-size:14px}
  .dw-pct{margin-left:auto;font-size:12px;font-weight:700;color:var(--accent)}
  .dw-model{font-size:11px;color:var(--dim);margin:2px 0 4px;white-space:nowrap;
    overflow:hidden;text-overflow:ellipsis}
  .dw-spark{width:100%;height:26px;display:block}
  .monhead{display:flex;align-items:baseline;gap:12px;margin-bottom:8px}
  .monhead .mh-nm{font-size:18px;font-weight:700}
  .monhead .mh-sz{color:var(--dim);font-size:13px}
  .graphcard{background:var(--panel);border:1px solid var(--line);border-radius:11px;
    padding:9px 12px;margin-bottom:8px}
  .gh{display:flex;align-items:baseline;margin-bottom:6px}
  .gh .gt{font-size:12.5px;color:var(--dim)}
  .gh .gv{margin-left:auto;font-size:15px;font-weight:700}
  .gh .gmax{margin-left:8px;font-size:11px;color:#5b626d}
  canvas.graph{width:100%;height:104px;display:block}
  .mstat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 10px}
  .mstat .mk{font-size:11px;color:var(--dim)}
  .mstat .mv{font-size:15px;font-weight:700;margin-top:2px}

  /* кнопка и попап SMART */
  .smbtn{font-size:9px;font-weight:700;letter-spacing:.5px;background:#15242b;
    color:var(--accent);border:1px solid var(--accent);border-radius:5px;
    padding:2px 6px;cursor:pointer;font-family:inherit}
  .smbtn:hover{background:var(--accent);color:#06231f}
  .smverdict{display:flex;align-items:center;gap:11px;background:var(--panel);
    border:1px solid var(--line);border-radius:11px;padding:12px 14px;
    border-left:3px solid var(--line)}
  .smverdict.ok{border-left-color:var(--ok)}
  .smverdict.no{border-left-color:var(--no)}
  .smverdict.warn{border-left-color:var(--warn)}
  .smverdict .smv-dot{width:13px;height:13px}
  .smverdict .smv-t{font-size:14px;font-weight:700}
  .smverdict .smv-s{font-size:11.5px;color:var(--dim);margin-top:2px;
    font-family:Consolas,monospace}
  .smgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px}
  .smm{background:#0e1b22;border:1px solid var(--line);border-radius:9px;padding:8px 10px}
  .smm.warn{border-color:var(--warn)}
  .smm-v{font-size:17px;font-weight:700;line-height:1.15}
  .smm.warn .smm-v{color:var(--warn)}
  .smm-k{font-size:10.5px;color:var(--dim);margin-top:2px}
  .smtbl{width:100%;border-collapse:collapse;font-size:12px}
  .smtbl th,.smtbl td{padding:5px 9px;border-bottom:1px solid var(--line);text-align:left}
  .smtbl th{font-size:10px;text-transform:uppercase;color:var(--dim);letter-spacing:.4px}
  .smtbl tr:last-child td{border-bottom:none}
  .smtbl tr.smbad td{color:var(--no)}
  .smtbl tr.smbad td:first-child{font-weight:700}

  /* разметка */
  .pmrow{background:var(--panel);border:1px solid var(--line);border-radius:11px;
    padding:7px 12px;margin-bottom:6px}
  .pm-head{display:flex;align-items:center;gap:9px;margin-bottom:7px}
  .pm-nm{font-family:Consolas,monospace;font-weight:700;font-size:15px}
  .pm-model{color:var(--dim);font-size:12px}
  .pm-sz{margin-left:auto;font-weight:700}
  .badge{font-size:10px;padding:1px 8px;border-radius:5px;font-weight:600}
  .b-ssd{background:#15323a;color:var(--accent)}
  .b-hdd{background:#2a2410;color:var(--warn)}
  .pm-bar{display:flex;gap:3px;height:42px}
  .pseg{flex-basis:0;border:1px solid #8b8f96;border-radius:4px;overflow:hidden;
    display:flex;flex-direction:column;background:#0e1b22}
  .pseg .cap{height:6px;flex:none}
  .pseg .pb{flex:1;padding:4px 8px;overflow:hidden}
  .pseg .pnm{font-family:Consolas,monospace;font-weight:700;font-size:12px;white-space:nowrap}
  .pseg .pmeta{font-size:10.5px;color:var(--dim);margin-top:3px;line-height:1.4;white-space:nowrap}
  .c-efi{background:#2a8c8c}.c-lvm{background:#0b3f78}.c-ext{background:#16a34a}
  .c-swap{background:#c2680f}.c-raw{background:#6b7280}.c-vita{background:#0d7a6f}
  .c-vstor{background:#2dd4bf}
  .pseg.free{background:repeating-linear-gradient(135deg,#23262b 0 8px,#191c20 8px 16px);
    border-style:dashed;border-color:#3a3d42;align-items:center;justify-content:center}
  .pseg.free .fl{font-size:11px;color:var(--dim);text-align:center;padding:4px}

  /* ===== виджеты Vitastor ===== */
  .poolw{background:var(--panel);border:1px solid var(--line);border-radius:13px;
    padding:10px;margin-bottom:12px}
  .pw-3{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
  .pw-3-left{flex:1 1 320px;min-width:0;display:flex;flex-direction:column;gap:10px}
  .pw-block{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
    padding:11px 13px}
  .pw-3-left>.pw-block:last-child{flex:1}
  .pw-b3{width:262px;flex:none}
  .pw-io3{display:flex;flex-direction:column;gap:12px}
  .pw-io3-sec{padding-bottom:12px;border-bottom:1px solid var(--line)}
  .pw-io3-sec:last-child{padding-bottom:0;border-bottom:none}
  .pw-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:6px}
  .pw-name{font-size:17px;font-weight:700}
  .pw-name::before{content:"\25c8";color:var(--accent);margin-right:7px}
  .pw-meta{font-size:11.5px;color:var(--dim)}
  .pw-badge{font-size:10px;padding:2px 8px;border-radius:5px;font-weight:600}
  .pw-st-active{background:#16331f;color:var(--ok)}
  .pw-st-warn{background:#3a2a10;color:var(--warn)}
  .subw{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 10px}
  .subw-t{font-size:10.5px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim);
    font-weight:600;margin-bottom:7px;display:flex;justify-content:space-between}
  .subw-t b{color:var(--txt);font-size:11px}
  .subcol{display:flex;flex-direction:column;gap:9px}
  .poolio{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  @media(max-width:560px){.poolio{grid-template-columns:1fr}}
  .pio-cell{background:#0e1b22;border:1px solid var(--line);border-radius:8px;padding:8px 10px}
  .pio-k{font-size:11px;color:var(--dim);display:flex;align-items:center;gap:6px}
  .pio-v{font-size:17px;font-weight:700;margin-top:3px;line-height:1.1}
  .pio-x{font-size:11px;color:var(--dim);margin-top:2px}
  .gauge{height:26px;border-radius:8px;background:#0e1b22;border:1px solid var(--line);
    position:relative;overflow:hidden}
  .gauge-fill{height:100%;border-radius:7px 0 0 7px;transition:width .5s ease}
  .gauge-pct{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
    font-weight:700;font-size:13px;text-shadow:0 1px 4px #000}
  .gauge-meta{display:flex;justify-content:space-between;font-size:11.5px;color:var(--dim);margin-top:5px}
  .pggrid{display:flex;flex-wrap:wrap;gap:4px}
  .pgcell{width:15px;height:15px;border-radius:3px;background:#3a3d42}
  .pgcell.ok{background:var(--ok)}.pgcell.warn{background:var(--warn)}.pgcell.bad{background:var(--no)}
  .osdmini{display:flex;flex-direction:column;gap:9px}
  .om-row{display:flex;align-items:center;gap:8px;font-size:12px}
  .om-nm{font-weight:600;width:56px;flex:none}
  .om-bar{flex:1;height:8px;border-radius:4px;background:#0e1b22;border:1px solid var(--line);overflow:hidden}
  .om-bar i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--info))}
  .om-pct{width:60px;flex:none;text-align:right;color:var(--dim)}

  /* ===== дерево пула: кластер -> пул -> PG -> узел -> OSD -> диск ===== */
  .ptree{margin-top:6px}
  .trow{display:flex;align-items:flex-start;gap:8px;padding:2px 0;
    padding-left:calc(var(--d,0)*22px)}
  .tcon{color:#5b6573;font-family:Consolas,monospace;font-size:15px;flex:none;line-height:1.4}
  .tnode{display:flex;align-items:center;gap:9px;flex-wrap:wrap;min-width:0;padding-top:2px}
  .tk{font-size:9.5px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim);
    background:var(--panel2);border:1px solid var(--line);border-radius:5px;
    padding:2px 7px;flex:none;font-weight:700}
  .tnm{font-size:13px}
  .tnm b{color:var(--accent);font-weight:700}
  .tmeta{color:var(--dim);font-size:11.5px}
  .tfill{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);
    border-radius:8px;padding:7px 9px}
  .tcap{font-size:10px;letter-spacing:.5px;text-transform:uppercase;color:var(--dim);
    font-weight:700;margin-bottom:5px}
  .tio{display:flex;gap:22px;flex-wrap:wrap;font-size:12px;color:var(--dim)}
  .tio b{color:var(--txt);font-size:13px}
  .tosd{display:flex;align-items:center;gap:9px;flex:1;min-width:0;flex-wrap:wrap;
    font-size:12px;background:#0e1b22;border:1px solid var(--line);
    border-radius:7px;padding:5px 9px}
  .tosd-nm{font-weight:700;font-family:Consolas,monospace;font-size:12.5px}
  .tosd-arr{color:#5b6573}
  .tosd-dk{color:var(--dim)}
  .tosd-dk b{color:var(--accent);font-family:Consolas,monospace}
  .tosd-pct{color:var(--dim);font-size:11.5px;flex:none;margin-left:auto}

  /* ===== виджет пула: 2 колонки + мини-виджеты ===== */
  .pw-body{display:flex;flex-direction:column;gap:10px;margin-top:6px}
  .pw-rail{display:flex;flex-direction:row;flex-wrap:wrap;gap:8px}
  .pw-rail>.pdw{flex:1 1 150px;min-width:150px}
  .pw-pair{display:flex;gap:10px;flex:1;min-width:0;flex-wrap:wrap}
  .pw-pair>.tfill{flex:1;min-width:215px}
  .pw-tot{display:flex;flex-direction:column;gap:6px;font-size:12.5px;color:var(--dim)}
  .pw-tot b{color:var(--txt);font-size:14px;font-weight:700}
  .pdw{background:#0e1b22;border:1px solid var(--line);border-radius:9px;padding:8px 10px}
  .pdw-top{display:flex;justify-content:space-between;align-items:baseline}
  .pdw-nm{font-weight:700;font-family:Consolas,monospace;font-size:13px}
  .pdw-pct{font-size:13px;font-weight:700;color:var(--accent)}
  .pdw-model{font-size:9.5px;color:var(--dim);text-transform:uppercase;
    letter-spacing:.5px;margin:2px 0 5px}
  .pdw-spark{width:100%;height:40px;display:block}
  .pdw-osd{display:flex;align-items:center;gap:7px;margin-top:7px;
    padding-top:7px;border-top:1px solid var(--line)}
  .pdw-osd-nm{font-weight:700;font-family:Consolas,monospace;font-size:12px;flex:none}
  .pdw-osd-pct{font-size:11px;color:var(--dim);flex:none}
  .pdw-empty{color:var(--dim);font-size:12px;padding:8px 2px}

  /* ===== виджет: сеть Vitastor ===== */
  .vnet-row{display:flex;align-items:center;gap:14px;padding:6px 2px;
    border-bottom:1px solid var(--line)}
  .vnet-k{font-family:Consolas,monospace;font-size:13px;font-weight:700;
    color:var(--accent);width:148px;flex:none}
  .vnet-d{font-size:12px;color:var(--dim);flex:1;min-width:0}
  .vnet-v{font-family:Consolas,monospace;font-size:13px;color:var(--txt);font-weight:600}
  .vnet-na{color:var(--warn);font-weight:600}
  .vnet-src{font-size:11px;color:var(--dim);padding-top:7px}
  .engbadge{font-size:11px;font-weight:600;color:var(--dim);background:var(--panel2);
    border:1px solid var(--line);border-radius:7px;padding:4px 10px;
    vertical-align:middle;margin-left:11px;letter-spacing:.3px}
  .engbadge b{color:var(--accent);font-family:Consolas,monospace;font-weight:700}
  @media(max-width:1000px){
    .pw-body{flex-direction:column}
    .pw-rail{width:100%;flex-direction:row;flex-wrap:wrap}
    .pw-rail>.pdw{flex:1;min-width:190px}
    .pw-b3{width:100%}
  }

  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{border-bottom:1px solid var(--line);padding:6px 9px;text-align:left}
  th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.4px;font-weight:600}
  td b{color:var(--txt)}
  .io{display:flex;gap:26px;flex-wrap:wrap}
  .iob{flex:1;min-width:170px}
  .iob .iv{font-size:22px;font-weight:700}
  .iob .ik{font-size:11.5px;color:var(--dim);display:flex;align-items:center;gap:6px}
  .iob .ix{font-size:12px;color:var(--dim);margin-top:2px}
  .tri{width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent}
  .tri.r{border-top:8px solid var(--rd)}.tri.w{border-bottom:8px solid var(--wr)}
  .capbar{height:24px;border-radius:6px;background:#0e1b22;border:1px solid var(--line);
    overflow:hidden;display:flex;margin-top:4px}
  .capbar .used{background:var(--accent);height:100%}
  .capmeta{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);margin-top:6px}
  .tagchip{font-size:10px;padding:1px 7px;border-radius:5px;background:#15323a;color:var(--accent);margin-left:3px}
  .empty{color:var(--dim);font-size:12.5px;padding:10px 2px}
  .emptybox{background:var(--panel);border:1px dashed var(--line);border-radius:12px;
    padding:42px 24px;text-align:center}
  .emptybox .ei{font-size:34px;margin-bottom:10px;opacity:.6}
  .emptybox .et{font-size:15px;font-weight:600}
  .emptybox .ed{color:var(--dim);font-size:12.5px;margin-top:7px;line-height:1.6}

  /* кнопка установки Vitastor в 1 клик */
  .instbtn{margin-top:16px;background:var(--accent);color:#06231f;border:none;
    border-radius:8px;padding:10px 20px;font-size:13px;font-weight:700;
    cursor:pointer;font-family:inherit;letter-spacing:.3px}
  .instbtn:hover{filter:brightness(1.12)}
  .instbtn:disabled{opacity:.55;cursor:default;filter:none}
  .instlog{margin-top:16px;text-align:left;font-size:12px;line-height:1.7}
  .instlog .istep{padding:3px 0;border-bottom:1px solid var(--line)}
  .instlog .istep:last-child{border-bottom:none}
  .istep.ok{color:var(--ok)}
  .istep.bad{color:var(--no)}
  .istep .imsg{color:var(--dim);font-size:11.5px}
  .instlog .iwait{color:var(--warn)}
  .instlog .idone{margin-top:10px;font-weight:700;color:var(--ok)}
  .instlog .ifail{margin-top:10px;font-weight:700;color:var(--no)}
  .cpform{margin:16px auto 0;display:flex;flex-direction:column;gap:9px;max-width:480px}
  .cpf{display:flex;align-items:center;gap:12px}
  .cpf label{font-size:12.5px;color:var(--dim);width:160px;flex:none;text-align:right}
  .cpf input{flex:1;background:#0e1b22;color:var(--txt);border:1px solid var(--line);
    border-radius:7px;padding:7px 10px;font-size:13px;font-family:Consolas,monospace}
  .cpf input:focus{outline:none;border-color:var(--accent)}
  .cpsteps{margin-top:14px;font-size:12px;color:var(--dim);line-height:1.9}
  .cpsteps code{font-family:Consolas,monospace;color:var(--accent);font-size:11.5px}

  /* ===== настройки + ceph ===== */
  .navbot{padding:6px 0;border-top:1px solid var(--line)}
  .setrow{display:flex;align-items:center;gap:14px;padding:8px 2px;border-bottom:1px solid var(--line)}
  .setrow:last-child{border-bottom:none}
  .setrow .sk{font-size:13px;font-weight:600}
  .setrow .sd{font-size:11.5px;color:var(--dim);margin-top:2px}
  .setrow .sc{margin-left:auto;flex:none}
  select.vbsel{background:#0e1b22;color:var(--txt);border:1px solid var(--line);
    border-radius:7px;padding:6px 10px;font-size:13px;font-family:inherit;cursor:pointer}
  .srcok{color:var(--ok);font-weight:700}
  .srcno{color:var(--no);font-weight:700}
  .vbtog{position:relative;display:inline-block;width:42px;height:23px;cursor:pointer;flex:none}
  .vbtog input{opacity:0;width:0;height:0;position:absolute}
  .vbtog .sl{position:absolute;inset:0;background:#0e1b22;border:1px solid var(--line);
    border-radius:23px;transition:.15s}
  .vbtog .sl::before{content:"";position:absolute;width:17px;height:17px;left:2px;top:2px;
    background:#5b6573;border-radius:50%;transition:.15s}
  .vbtog input:checked+.sl{background:#16331f;border-color:var(--ok)}
  .vbtog input:checked+.sl::before{transform:translateX(19px);background:var(--ok)}
  .vbbtn{background:#0e1b22;color:var(--txt);border:1px solid var(--line);
    border-radius:7px;padding:6px 14px;font-size:13px;font-family:inherit;
    cursor:pointer}
  .vbbtn:hover{border-color:var(--accent);color:var(--accent)}
  .vbbtn:disabled{opacity:.55;cursor:default}
  .vbbtn.vbbtnp{background:var(--accent);color:#06231f;border-color:var(--accent);
    font-weight:600}
  .vbbtn.vbbtnp:hover{filter:brightness(1.08);color:#06231f}
  .acctgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px 14px;margin-top:4px}
  .acctgrid label{display:flex;flex-direction:column;gap:4px;font-size:11.5px;
    color:var(--dim);letter-spacing:.3px}
  .acctgrid input{background:#0b1117;color:var(--txt);border:1px solid var(--line);
    border-radius:7px;padding:7px 10px;font-size:13px;font-family:inherit;outline:none}
  .acctgrid input:focus{border-color:var(--accent)}
  .chips{display:flex;flex-wrap:wrap;gap:7px}
  .vbbtndg{border-color:var(--no);color:var(--no)}
  .vbbtndg:hover{background:#3a1014;border-color:var(--no);color:var(--no)}
  .vbbtndg.armed{background:var(--no);color:#fff;border-color:var(--no)}
  .vbbtndg.armed:hover{filter:brightness(1.1);color:#fff}
  .svckv{display:flex;align-items:baseline;gap:10px;padding:6px 0}
  .svckv .k{font-size:11.5px;color:var(--dim);letter-spacing:.3px;
    min-width:120px;text-transform:uppercase}
  .svckv .v{font-size:13px}
  .svchint code{font-family:Consolas,monospace;color:var(--accent);
    font-size:12px;background:#0b1117;padding:1px 6px;border-radius:4px}

  /* ZFS-пул: таблица наборов + дерево дисков */
  .zdstbl{margin:2px 0 9px}
  .ztype{font-size:10px;padding:2px 8px;border-radius:5px;font-weight:700;letter-spacing:.3px}
  .ztype.red{background:#16331f;color:var(--ok)}
  .ztype.nored{background:#0f2f2b;color:#2dd4bf}
  .ztree{margin-top:9px}
  .ztree-h{display:flex;align-items:center;gap:9px;margin-bottom:9px}
  .ztree-x{font-size:11px;color:#2dd4bf}

  footer{margin-top:14px;color:var(--dim);font-size:11px}

  /* мастер пулов */
  .lblrow{display:flex;align-items:center;gap:10px}
  .wizbtn{margin-left:auto;background:#15242b;color:var(--accent);
    border:1px solid var(--accent);border-radius:7px;padding:4px 11px;
    font-size:11px;font-weight:700;cursor:pointer;letter-spacing:.3px;
    text-transform:none}
  .wizbtn:hover{background:var(--accent);color:#06231f}
  .wizmask{display:none;position:fixed;inset:0;background:rgba(4,7,11,.78);
    z-index:50;align-items:center;justify-content:center;padding:18px}
  .wizbox{background:var(--bg);border:1px solid var(--line);border-radius:14px;
    width:760px;max-width:100%;max-height:92vh;display:flex;flex-direction:column;
    box-shadow:0 18px 60px rgba(0,0,0,.6)}
  .wizhd{display:flex;align-items:center;padding:13px 16px;
    border-bottom:1px solid var(--line);font-size:15px;font-weight:700}
  .wizx{margin-left:auto;cursor:pointer;font-size:22px;line-height:1;
    color:var(--dim);padding:0 4px}
  .wizx:hover{color:var(--no)}
  .wizsteps{display:flex;gap:6px;padding:10px 16px 4px}
  .wizpip{flex:1;font-size:10.5px;letter-spacing:.3px;color:var(--dim);
    text-transform:uppercase;font-weight:700;padding-bottom:6px;
    border-bottom:2px solid var(--line);text-align:center}
  .wizpip.on{color:var(--accent);border-color:var(--accent)}
  .wizpip.done{color:var(--ok);border-color:var(--ok)}
  .wizbody{padding:14px 16px;overflow:auto;flex:1;min-height:120px}
  .wizft{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--line)}
  .wizft .sp{flex:1}
  .wzb{background:#15242b;color:var(--txt);border:1px solid var(--line);
    border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;cursor:pointer}
  .wzb:hover{border-color:#46505e}
  .wzb.pri{background:var(--accent);color:#06231f;border-color:var(--accent)}
  .wzb.pri:hover{filter:brightness(1.1)}
  .wzb.dng{background:#3a1518;color:var(--no);border-color:var(--no)}
  .wzb.dng:hover{background:var(--no);color:#2a0d0d}
  .wzb:disabled{opacity:.4;cursor:not-allowed}
  .wizgrp{margin-bottom:14px}
  .wizgrp>.gl{font-size:11px;letter-spacing:1px;color:var(--dim);
    text-transform:uppercase;font-weight:600;margin-bottom:7px}
  .acts{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:8px}
  .actcard{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:11px;cursor:pointer;text-align:center}
  .actcard:hover{border-color:#46505e}
  .actcard.on{border-color:var(--accent);background:#13262a}
  .actcard.on.dng{border-color:var(--no);background:#2a1518}
  .actcard .ai{font-size:21px}
  .actcard .an{font-size:13px;font-weight:700;margin-top:3px}
  .actcard .ad{font-size:10.5px;color:var(--dim);margin-top:2px}
  .wizfld{display:flex;align-items:center;gap:10px;padding:6px 0}
  .wizfld label{font-size:12.5px;width:170px;flex:none;color:var(--dim)}
  .wizinp,.wizsel{background:#0e1b22;color:var(--txt);border:1px solid var(--line);
    border-radius:7px;padding:6px 9px;font-size:13px;font-family:inherit;flex:1;
    min-width:0}
  .wizinp:focus,.wizsel:focus{outline:none;border-color:var(--accent)}
  .wizhint{font-size:11px;color:var(--dim);margin-top:3px}
  .pick{display:flex;align-items:center;gap:9px;padding:7px 9px;
    background:var(--panel);border:1px solid var(--line);border-radius:8px;
    margin-bottom:6px;cursor:pointer}
  .pick:hover{border-color:#46505e}
  .pick.on{border-color:var(--accent);background:#13262a}
  .pick.dis{opacity:.45;cursor:not-allowed}
  .pick .pk-nm{font-family:Consolas,monospace;font-weight:700;font-size:13px}
  .pick .pk-meta{font-size:11px;color:var(--dim);margin-left:auto;text-align:right}
  .pick input{width:16px;height:16px;flex:none;accent-color:var(--accent)}
  .planrow{display:flex;gap:9px;padding:8px 10px;border:1px solid var(--line);
    border-radius:8px;margin-bottom:6px;background:var(--panel)}
  .planrow.dng{border-color:var(--no);background:#241317}
  .planrow .pn{font-size:11px;font-weight:700;color:var(--dim);flex:none;width:18px}
  .planrow .pt{font-size:12.5px;font-weight:600}
  .planrow .pc{font-family:Consolas,monospace;font-size:11px;color:var(--accent);
    margin-top:3px;word-break:break-all}
  .planrow.dng .pc{color:var(--no)}
  .planrow .pnote{font-size:11px;color:var(--warn);margin-top:2px}
  .reslog{font-family:Consolas,monospace;font-size:11.5px;white-space:pre-wrap;
    word-break:break-all}
  .resrow{padding:7px 10px;border-left:3px solid var(--line);margin-bottom:5px;
    background:var(--panel);border-radius:0 7px 7px 0}
  .resrow.ok{border-color:var(--ok)}
  .resrow.bad{border-color:var(--no)}
  .resrow .rt{font-size:12.5px;font-weight:600}
  .resrow .ro{font-family:Consolas,monospace;font-size:11px;color:var(--dim);
    margin-top:3px;white-space:pre-wrap;word-break:break-all}
  .resrow .re{color:var(--no)}
  .wizerr{background:#241317;border:1px solid var(--no);color:var(--no);
    border-radius:8px;padding:9px 12px;font-size:12.5px;margin-bottom:10px}
  .wizok{background:#13261b;border:1px solid var(--ok);color:var(--ok);
    border-radius:8px;padding:9px 12px;font-size:13px;font-weight:600;margin-bottom:10px}
  .cfmbox{background:#241317;border:1px solid var(--no);border-radius:9px;
    padding:11px 13px;margin-top:8px}
  .cfmbox .ct{font-size:12.5px;color:var(--no);margin-bottom:7px}
  .cfmbox b.cw{font-family:Consolas,monospace;background:#3a1518;padding:1px 6px;
    border-radius:4px}

  /* ===== вкладка «Кластер» ===== */
  .clsum{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:13px}
  .clsum .stat{flex:1;min-width:155px}
  .clgrid{display:grid;gap:11px;grid-template-columns:repeat(auto-fill,minmax(335px,1fr))}
  .clcard{background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:13px 15px;border-left:3px solid var(--line)}
  .clcard.on{border-left-color:var(--ok)}
  .clcard.off{border-left-color:var(--no)}
  .clcard.self{border-left-color:var(--accent)}
  .clhd{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .clhd .nm{font-size:15px;font-weight:700}
  .clcard .ip{font-size:11.5px;color:var(--dim);font-family:Consolas,monospace;margin-top:2px}
  .clrole{font-size:9.5px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;
    padding:2px 7px;border-radius:5px;background:#1c2330;color:var(--dim)}
  .clrole.master{background:#15323a;color:var(--accent)}
  .clrole.worker{background:#1d2b16;color:var(--ok)}
  .clrole.unconf{background:#3a2f14;color:var(--warn)}
  .clstate{margin-left:auto;font-size:11px;font-weight:700;display:flex;
    align-items:center;gap:6px}
  .clstate.on{color:var(--ok)}
  .clstate.off{color:var(--no)}
  .clsvc{display:flex;gap:6px;flex-wrap:wrap;margin:11px 0 9px}
  .svchip{font-size:10.5px;padding:3px 9px;border-radius:6px;background:#0e1b22;
    border:1px solid var(--line);color:var(--dim);display:flex;align-items:center;gap:5px}
  .svchip.on{color:var(--ok);border-color:#1d3a22}
  .svchip.no{color:var(--no);border-color:#3a2420}
  .clmet{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
  .clmet .m{background:#0e1b22;border:1px solid var(--line);border-radius:8px;padding:6px 9px}
  .clmet .mv{font-size:16px;font-weight:700;line-height:1.15}
  .clmet .mk{font-size:10px;color:var(--dim);margin-top:2px}
  .clbar{height:7px;border-radius:4px;background:#0e1b22;border:1px solid var(--line);
    overflow:hidden;margin-top:9px}
  .clbar i{display:block;height:100%;background:var(--accent)}
  .clbar i.warn{background:var(--warn)}
  .clbar i.no{background:var(--no)}
  .clbarm{display:flex;justify-content:space-between;font-size:10.5px;
    color:var(--dim);margin-top:3px}
  .cloff{font-size:12px;color:var(--dim);margin-top:10px;line-height:1.65}
  .cloff b{color:var(--no)}

  /* ===== Системный монитор (Win10 Task Manager-style 3-column) ===== */
  .sysmonwrap{display:grid;grid-template-columns:215px 1fr 215px;gap:14px;margin-top:8px;
    align-items:start}
  .sysmonlist{display:flex;flex-direction:column;gap:6px;max-height:calc(100vh - 200px);
    overflow-y:auto;overflow-x:hidden;
    scrollbar-width:none;-ms-overflow-style:none}
  .sysmonlist::-webkit-scrollbar{width:0;height:0;display:none}
  .sysmonlist .ldhd{display:flex;justify-content:space-between;align-items:center;
    color:var(--dim);font-size:12px;text-transform:none;padding:4px 4px 6px;
    border-bottom:1px solid var(--line);margin-bottom:4px}
  /* kind-color через CSS custom property — общий цвет рамки плитки и спарклайна */
  .sysmonitem.k-cpu  { --kc:#28e0c4 }
  .sysmonitem.k-gpu  { --kc:#ff8a3d }
  .sysmonitem.k-mem  { --kc:#a47bd0 }
  .sysmonitem.k-disk { --kc:#5fd07b }
  .sysmonitem.k-net  { --kc:#b266ff }
  .sysmonitem.k-pwr  { --kc:#c79bd6 }
  .sysmonitem{background:var(--panel);
    border:1.5px solid var(--kc, var(--line));border-radius:8px;
    padding:6px 8px;cursor:pointer;transition:background .12s,box-shadow .12s;
    display:flex;gap:8px;align-items:center}
  .sysmonitem:hover{background:#151b24}
  .sysmonitem.active{background:#15242b;box-shadow:0 0 0 1px var(--accent),
    inset 0 0 0 1px rgba(40,224,196,.15)}
  .sysmonitem.unav{opacity:.55}
  .sysmonitem .spr{flex:none;width:88px;height:46px;background:#0a0f15;border-radius:4px;
    border:1px solid var(--kc, var(--line));position:relative;overflow:hidden}
  .sysmonitem .spr canvas{display:block;width:100%;height:100%}
  .sysmonitem .info{flex:1;min-width:0;line-height:1.2}
  .sysmonitem .info .nm{display:flex;align-items:center;gap:5px;font-size:12.5px;
    font-weight:600;color:var(--txt);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .sysmonitem .info .dot{display:inline-block;width:7px;height:7px;border-radius:50%;
    background:var(--accent);flex:none}
  .sysmonitem .info .vl{font-size:11.5px;color:var(--dim);font-variant-numeric:tabular-nums;
    margin-top:1px}
  .sysmonitem .info .sb{font-size:10.5px;color:var(--dim);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:1px}

  .sysmonchart{background:var(--panel);border:1px solid var(--line);border-radius:6px;
    padding:14px 18px 16px;min-height:520px}
  /* kind-color на .sysmonchart прокидывается через --kc — рамки .bigpane перекрашиваются */
  .sysmonchart.k-cpu  { --kc:#28e0c4 }
  .sysmonchart.k-gpu  { --kc:#ff8a3d }
  .sysmonchart.k-mem  { --kc:#a47bd0 }
  .sysmonchart.k-disk { --kc:#5fd07b }
  .sysmonchart.k-net  { --kc:#b266ff }
  .sysmonchart.k-pwr  { --kc:#c79bd6 }
  .sysmonchart .chdr{display:flex;align-items:baseline;justify-content:space-between;
    gap:14px;margin-bottom:14px}
  .sysmonchart .ctitle{font-size:24px;font-weight:600;color:var(--txt);margin:0}
  .sysmonchart .ctitle .sm{font-size:14px;color:var(--dim);font-weight:400;margin-left:8px}
  .sysmonchart .cmodel{font-size:12px;color:var(--dim);margin-left:auto;padding-right:10px}
  .sysmonchart .crange{font-size:11.5px;color:var(--dim);background:#0f161f;
    border:1px solid var(--line);border-radius:4px;padding:3px 8px}

  .bigpane{background:#0a0f15;border:1.5px solid var(--kc, var(--line));border-radius:8px;
    margin-bottom:12px;padding:10px 12px 8px}
  .bigpane .bhdr{display:flex;justify-content:space-between;align-items:baseline;
    font-size:12px;color:var(--dim);margin-bottom:6px}
  .bigpane .bhdr .bmax{color:var(--dim);font-size:11px;font-variant-numeric:tabular-nums}
  .bigpane .bcvbox{position:relative;width:100%;height:140px;
    background-color:#0a0f15;
    background-image:
      repeating-linear-gradient(0deg,  transparent 0 calc(10% - 1px), #1a2330 calc(10% - 1px) 10%),
      repeating-linear-gradient(90deg, transparent 0 calc(10% - 1px), #1a2330 calc(10% - 1px) 10%)}
  .bigpane .bcv{display:block;width:100%;height:100%;position:absolute;inset:0}
  .bigpane .bfoot{display:flex;justify-content:space-between;font-size:10.5px;color:#5b626d;
    margin-top:5px;letter-spacing:.3px}

  /* CPU per-core: vertical bar slева + сетка маленьких графов справа */
  .cpubox{display:grid;grid-template-columns:50px 1fr;gap:10px;margin-bottom:10px}
  .cpubar{background:#0a0f15;border:1px solid var(--line);border-radius:4px;
    position:relative;display:flex;flex-direction:column;align-items:center;
    padding:8px 0;font-size:10.5px;color:var(--dim)}
  .cpubar .lbl{margin-bottom:6px;letter-spacing:.5px}
  .cpubar .bar{flex:1;width:18px;background:#0f1923;border-radius:2px;
    position:relative;overflow:hidden;border:1px solid #1a2330}
  .cpubar .bar span{position:absolute;left:0;right:0;bottom:0;background:var(--accent)}
  .cpubar .v{margin-top:6px;font-variant-numeric:tabular-nums;color:var(--accent);font-weight:600}
  .coregrid{display:grid;gap:8px;background:transparent;padding:0}
  .corecell{background-color:#0a0f15;border:1.5px solid #28e0c4;border-radius:6px;
    position:relative;height:60px;overflow:hidden;
    background-image:
      repeating-linear-gradient(0deg,  transparent 0 calc(25% - 1px), #1a2330 calc(25% - 1px) 25%),
      repeating-linear-gradient(90deg, transparent 0 calc(20% - 1px), #1a2330 calc(20% - 1px) 20%)}
  .corecell canvas{display:block;width:100%;height:100%;position:absolute;inset:0}
  .coreghdr{display:flex;justify-content:space-between;font-size:11px;color:var(--dim);
    margin-bottom:4px;padding:0 2px}

  .sysmonspecs{padding:8px 4px 8px 14px;font-size:12.5px}
  .sysmonspecs .srow{margin-bottom:10px}
  .sysmonspecs .sl{color:var(--dim);font-size:11.5px;line-height:1.15}
  .sysmonspecs .sv{color:var(--txt);font-weight:600;font-size:14px;
    font-variant-numeric:tabular-nums;line-height:1.25;margin-top:1px}
  .sysmonspecs .sv .u{color:var(--dim);font-size:11px;font-weight:400;margin-left:2px}
  .sysmonspecs .sgrp{margin:14px 0 8px;color:var(--dim);font-size:11.5px;
    font-weight:700;letter-spacing:.6px;text-transform:none;
    padding-top:10px;border-top:1px solid var(--line)}
  .sysmonspecs .legend{display:flex;gap:10px;font-size:11px;color:var(--dim);margin-top:4px}
  .sysmonspecs .legend .lk{display:flex;align-items:center;gap:4px}
  .sysmonspecs .legend .swat{width:10px;height:3px;border-radius:1px;background:var(--accent)}
  .memstruct{display:flex;height:8px;border-radius:2px;overflow:hidden;
    border:1px solid var(--line);margin-top:6px}
  .memstruct .seg{height:100%}

  .sysunav{padding:36px 18px;text-align:center;color:var(--dim);font-size:13px}
  .sysunav b{color:var(--txt);display:block;margin-bottom:8px;font-size:15px}
  /* ===== страницы Узла ===== */
  .hostpane{margin-top:14px;color:var(--txt);font-size:13.5px}
  .hostpane .err{color:var(--bad)}
  .kvtbl{border-collapse:collapse;width:100%;max-width:920px;
    background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .kvtbl th,.kvtbl td{padding:9px 14px;text-align:left;vertical-align:top;
    border-bottom:1px solid var(--line);font-size:13px}
  .kvtbl tr:last-child th,.kvtbl tr:last-child td{border-bottom:none}
  .kvtbl th{width:200px;color:var(--dim);font-weight:500;background:#0f161f}
  .kvtbl td{color:var(--txt)}
  .kvtbl pre{margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;
    font-size:12px;white-space:pre-wrap;color:var(--dim)}
  .svctbl{border-collapse:collapse;width:100%;
    background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .svctbl th,.svctbl td{padding:8px 12px;text-align:left;
    border-bottom:1px solid var(--line);font-size:13px}
  .svctbl tr:last-child td{border-bottom:none}
  .svctbl th{background:#0f161f;color:var(--dim);font-weight:600}
  .svctbl tbody tr:hover{background:#151b24}
  .svctbl .dim{color:var(--dim);font-size:12px}
  .hstchip{display:inline-block;font-size:11px;padding:2px 8px;border-radius:6px;
    background:#15242b;color:var(--dim);border:1px solid var(--line);
    font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:.3px}
  .hstchip.ok{color:var(--ok);border-color:#1a3a35;background:#102220}
  .hstchip.warn{color:#f0b441;border-color:#3a2e1a;background:#221c10}
  .hstchip.err{color:var(--bad);border-color:#3a1a1a;background:#221010}
  .progress{display:inline-block;height:8px;width:160px;background:#15242b;
    border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:8px;
    border:1px solid var(--line)}
  .progress span{display:block;height:100%;background:var(--accent);
    transition:width .25s}
  .progress span.warn{background:#f0b441}
  .progress span.err{background:var(--bad)}
  .journalbar{display:flex;align-items:center;gap:10px;margin:8px 0 10px;flex-wrap:wrap}
  .journalbar select{background:var(--panel);color:var(--txt);
    border:1px solid var(--line);border-radius:6px;padding:6px 10px;font-size:13px}
  .jrntext{background:#0a0f15;border:1px solid var(--line);border-radius:8px;
    padding:12px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;
    color:#9aa4b2;line-height:1.5;max-height:560px;overflow:auto;white-space:pre-wrap}
  .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:12px;margin-top:6px}
  .panel-soft{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
  .panel-soft .lbl{font-size:11px;letter-spacing:.4px;text-transform:uppercase;color:var(--dim);margin-bottom:8px}
  .vmctile{display:flex;justify-content:space-between;align-items:center;
    padding:6px 0;border-bottom:1px dashed var(--line);font-size:13px}
  .vmctile:last-child{border-bottom:none}
  /* ===== Network план ===== */
  .netplan{margin-top:14px}
  .planlist{margin:6px 0 0 0;padding-left:20px;color:var(--dim);font-size:13.5px;line-height:1.7}
  .planlist li{margin-bottom:3px}
  .planlist b{color:var(--txt);font-weight:600}
  .netnow{background:var(--panel);border:1px solid var(--line);border-radius:8px;
    padding:12px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
    color:var(--dim);white-space:pre-wrap;max-height:220px;overflow:auto}
  /* вкладки внутри страницы Vitastor (как в браузере) */
  .vtabs{display:flex;gap:3px;border-bottom:1px solid var(--line);margin:6px 0 14px}
  .vtab{padding:8px 17px;font-size:13px;font-weight:600;color:var(--dim);
    cursor:pointer;border:1px solid transparent;border-bottom:none;
    border-radius:8px 8px 0 0;margin-bottom:-1px;user-select:none}
  .vtab:hover{color:var(--txt)}
  .vtab.active{color:var(--txt);background:var(--panel);border-color:var(--line);
    border-bottom-color:var(--panel)}
  .vtabpane{display:none}
  .vtabpane.active{display:block}
</style>
</head>
<body>
<div class="app">

  <aside class="sidebar">
    <div class="brand">
      <div class="nm">&#9638; PROXO<b>MATRON</b></div>
      <div class="bsub">v__VBVERSION__ &middot; кластер <span id="cluname">&mdash;</span></div>
    </div>
    <div class="sidetabs">
      <div class="sidetab" data-cat="host" title="Узел &mdash; обзор хоста">&#128450;</div>
      <div class="sidetab active" data-cat="storage" title="Storage &mdash; хранилище">&#128451;</div>
      <div class="sidetab" data-cat="network" title="Network &mdash; сеть">&#127760;</div>
      <div class="sidecol" id="sidecol" title="свернуть (заглушка)">&#10094;</div>
    </div>
    <nav class="nav" data-cat="host">
      <div class="navgrp">Узел</div>
      <div class="navitem" data-view="host" data-subview="monitor"><span class="ico">&#9889;</span>Системный монитор</div>
      <div class="navitem" data-view="host" data-subview="sysinfo"><span class="ico">&#9432;</span>Системная информация</div>
      <div class="navitem" data-view="host" data-subview="vmct"><span class="ico">&#10070;</span>VM / CT</div>
      <div class="navitem" data-view="host" data-subview="cluster"><span class="ico">&#11041;</span>Кластер PVE</div>
    </nav>
    <nav class="nav cat-active" data-cat="storage">
      <div class="navgrp">Узел</div>
      <div class="navitem" data-view="mon"><span class="ico">&#9201;</span>Мониторинг</div>
      <div class="navitem" data-view="parts"><span class="ico">&#9707;</span>Разметка</div>
      <div class="navgrp">Подсистемы</div>
      <div class="navitem" data-view="vitastor"><span class="ico">&#9670;</span>Vitastor</div>
      <div class="navitem" data-view="ceph"><span class="ico">&#9673;</span>Ceph</div>
      <div class="navitem" data-view="zfs"><span class="ico">&#9633;</span>ZFS</div>
    </nav>
    <nav class="nav" data-cat="network">
      <div class="navgrp">Сеть</div>
      <div class="navitem" data-view="network" data-subview="overview"><span class="ico">&#9678;</span>Обзор</div>
      <div class="navitem" data-view="network" data-subview="bridges"><span class="ico">&#9776;</span>Bridges</div>
      <div class="navitem" data-view="network" data-subview="vlan"><span class="ico">&#9783;</span>VLAN</div>
    </nav>
    <div class="navbot">
      <div class="navitem" data-view="settings"><span class="ico">&#9881;</span>Настройки</div>
    </div>
    <div class="sidefoot">
      <div class="live"><span class="pulse" id="pulse"></span><span id="upd">подключение&hellip;</span></div>
    </div>
  </aside>

  <main class="main">
    <div class="banner" id="banner"></div>

    <section class="view" id="view-mon">
      <h1 class="vt">Физические диски &mdash; мониторинг</h1>
      <div class="vsub">нагрузка дисков в реальном времени &middot; окно 60&nbsp;секунд</div>
      <div class="monwrap">
        <div class="dlist" id="dlist"></div>
        <div class="mongraphs" id="mongraphs"></div>
      </div>
    </section>

    <section class="view" id="view-parts">
      <h1 class="vt">Физические диски &mdash; разметка</h1>
      <div class="vsub">структура разделов на каждом накопителе</div>
      <div id="parts"></div>
    </section>

    <section class="view" id="view-vitastor">
      <h1 class="vt">Vitastor <span class="engbadge">vitastor engine <b id="vengine">&mdash;</b></span></h1>
      <div class="vsub">распределённое блочное хранилище</div>
      <div class="vtabs">
        <div class="vtab active" data-vtab="storage">&#9670; Хранилище</div>
        <div class="vtab" data-vtab="cluster">&#9776; Кластер</div>
      </div>
      <div class="vtabpane active" id="vtab-storage">
        <div id="vita-install"></div>
        <div id="vita-body">
          <div class="lbl lblrow">Здоровье кластера
            <button class="wizbtn" id="cl-open">&#9881; Мастер кластера</button></div>
          <div class="row r6" id="health"></div>
          <div class="lbl lblrow">Пулы &mdash; виджеты
            <button class="wizbtn" id="wiz-open">&#9874; Мастер пулов Standalone</button></div>
          <div id="poolwidgets"></div>
          <div class="lbl">Тома (образы)</div>
          <div class="panel"><table id="vols"></table></div>
        </div>
      </div>
      <div class="vtabpane" id="vtab-cluster">
        <div class="lbl lblrow">Узлы кластера &mdash; работа других нод
          <button class="wizbtn" id="cl-open2">&#9881; Мастер кластера</button></div>
        <div id="cluster"></div>
      </div>
    </section>

    <section class="view" id="view-ceph">
      <h1 class="vt">Ceph</h1>
      <div class="vsub">состояние кластера Ceph на этом узле</div>
      <div id="ceph"></div>
    </section>

    <section class="view" id="view-zfs">
      <h1 class="vt">ZFS</h1>
      <div class="vsub">локальные пулы и наборы данных ZFS</div>
      <div class="vtabs">
        <div class="vtab active" data-vtab="pools">&#9633; Пулы</div>
        <div class="vtab" data-vtab="settings">&#9881; Настройки</div>
      </div>
      <div class="vtabpane active" id="zftab-pools">
        <div class="lblrow" style="margin:8px 0 2px">
          <button class="wizbtn" id="zw-open">&#9874; Мастер пулов ZFS</button>
          <button class="wizbtn" id="cc-open" style="margin-left:8px">&#9881; Управление кэшем</button></div>
        <div id="zfs"></div>
      </div>
      <div class="vtabpane" id="zftab-settings">
        <div class="netplan">
          <div class="lbl">Настройки модуля ZFS</div>
          <ul class="planlist">
            <li><b>ARC-кэш</b> &mdash; пока через кнопку «Управление кэшем» на вкладке «Пулы»</li>
            <li><b>L2ARC / SLOG</b> &mdash; добавление кеш/лог устройств (в плане)</li>
            <li><b>Сжатие/дедупликация</b> &mdash; глобальные параметры (в плане)</li>
            <li><b>zfs.conf / module params</b> &mdash; редактирование <code>/etc/modprobe.d/zfs.conf</code> (в плане)</li>
            <li><b>Автоснимки</b> &mdash; интеграция с <code>zfs-auto-snapshot</code> / <code>zrepl</code> (в плане)</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="view" id="view-host">
      <h1 class="vt"><span id="hostTitle">Узел &mdash; Системная информация</span></h1>
      <div class="vsub" id="hostSub">сводка по Proxmox-узлу</div>

      <div class="host-sect" data-sub="sysinfo">
        <div id="host-sysinfo" class="hostpane">загрузка&hellip;</div>
      </div>
      <div class="host-sect" data-sub="monitor" style="display:none">
        <div id="host-monitor" class="hostpane">загрузка&hellip;</div>
      </div>
      <div class="host-sect" data-sub="vmct" style="display:none">
        <div id="host-vmct" class="hostpane">загрузка&hellip;</div>
      </div>
      <div class="host-sect" data-sub="cluster" style="display:none">
        <div id="host-cluster" class="hostpane">загрузка&hellip;</div>
      </div>
    </section>

    <section class="view" id="view-network">
      <h1 class="vt"><span id="netTitle">Сеть &mdash; обзор</span> <span class="engbadge">в разработке &middot; v0.2.x</span></h1>
      <div class="vsub" id="netSub">сетевые настройки Proxmox-узла</div>

      <div class="net-sect" data-sub="overview">
        <div class="lblrow" style="margin:6px 0 10px">
          <span style="color:var(--dim);font-size:12px">состояние интерфейсов — <code>ip -d -s -j link/addr</code></span>
          <button class="wizbtn" id="netRefresh" style="margin-left:auto">&#10227; Обновить</button>
        </div>
        <div id="netifaces">загрузка&hellip;</div>
      </div>

      <div class="net-sect" data-sub="bridges" style="display:none">
        <div class="netplan">
          <div class="lbl">Bridges &mdash; в разработке</div>
          <ul class="planlist">
            <li>Список <code>vmbr*</code> с MTU, портами, STP</li>
            <li>Кнопки «создать», «удалить», «изменить порты»</li>
            <li>Применение через <code>ifreload -a</code> (ifupdown2)</li>
          </ul>
        </div>
      </div>

      <div class="net-sect" data-sub="vlan" style="display:none">
        <div class="netplan">
          <div class="lbl">VLAN &mdash; в разработке</div>
          <ul class="planlist">
            <li>VLAN-интерфейсы поверх bridge'ей и физических портов</li>
            <li>VLAN-aware bridge (auto vlans / vid)</li>
            <li>Связка с PVE storage и VM, использующими VLAN</li>
          </ul>
        </div>
      </div>

    </section>

    <section class="view" id="view-settings">
      <h1 class="vt">Настройки</h1>
      <div class="vsub">параметры дашборда PROXOMATRON</div>
      <div id="settings"></div>
    </section>
  </main>
</div>

<div class="wizmask" id="wizmask">
  <div class="wizbox">
    <div class="wizhd"><span id="wiztitle">Мастер пулов Standalone</span>
      <span class="wizx" id="wizclose">&times;</span></div>
    <div class="wizsteps" id="wizsteps"></div>
    <div class="wizbody" id="wizbody"></div>
    <div class="wizft" id="wizft"></div>
  </div>
</div>

<div class="wizmask" id="clmask">
  <div class="wizbox" style="width:620px">
    <div class="wizhd"><span>Мастер кластера Vitastor</span>
      <span class="wizx" id="clclose">&times;</span></div>
    <div class="wizsteps" id="clsteps"></div>
    <div class="wizbody" id="clbody"></div>
    <div class="wizft" id="clft"></div>
  </div>
</div>

<div class="wizmask" id="zwmask">
  <div class="wizbox" style="width:620px">
    <div class="wizhd"><span>Мастер пулов ZFS</span>
      <span class="wizx" id="zwclose">&times;</span></div>
    <div class="wizsteps" id="zwsteps"></div>
    <div class="wizbody" id="zwbody"></div>
    <div class="wizft" id="zwft"></div>
  </div>
</div>

<div class="wizmask" id="ccmask">
  <div class="wizbox" style="width:560px">
    <div class="wizhd"><span>Управление кэшем ZFS ARC</span>
      <span class="wizx" id="ccclose">&times;</span></div>
    <div class="wizbody" id="ccbody"></div>
    <div class="wizft" id="ccft"></div>
  </div>
</div>

<div class="wizmask" id="smmask">
  <div class="wizbox" style="width:660px">
    <div class="wizhd"><span id="smtitle">SMART</span>
      <span class="wizx" id="smclose">&times;</span></div>
    <div class="wizbody" id="smbody"></div>
    <div class="wizft" id="smft"></div>
  </div>
</div>

<script>
function hb(n){
  if(n==null||isNaN(n)) return "&mdash;";
  n=+n; var u=["B","KiB","MiB","GiB","TiB","PiB"],i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return n.toFixed(n<10&&i>0?1:0)+" "+u[i];
}
function num(n){ n=+n||0; return n.toLocaleString("ru-RU"); }
function el(id){ return document.getElementById(id); }
function plural(n,one,few,many){
  var a=Math.abs(n)%100, b=a%10;
  if(a>10&&a<20) return many;
  if(b>1&&b<5) return few;
  if(b===1) return one;
  return many;
}

var viewCategory={
  host:"host",
  mon:"storage", parts:"storage",
  vitastor:"storage", ceph:"storage", zfs:"storage",
  network:"network"
};
function setCategory(cat){
  document.querySelectorAll(".sidetab").forEach(function(t){
    t.classList.toggle("active", t.getAttribute("data-cat")===cat);
  });
  document.querySelectorAll(".nav").forEach(function(n){
    n.classList.toggle("cat-active", n.getAttribute("data-cat")===cat);
  });
  try{ localStorage.setItem("vb_cat", cat); }catch(e){}
}
function setView(name, subview){
  document.querySelectorAll(".view").forEach(function(v){v.classList.remove("active");});
  var v=el("view-"+name); if(v) v.classList.add("active");
  document.querySelectorAll(".navitem").forEach(function(it){
    var match = it.getAttribute("data-view")===name;
    if(match && subview){
      match = it.getAttribute("data-subview")===subview;
    } else if(match && it.getAttribute("data-subview")){
      match = it.getAttribute("data-subview")==="overview";
    }
    it.classList.toggle("active", match);
  });
  var cat=viewCategory[name]; if(cat) setCategory(cat);
  if(name==="settings") renderSettings();
  if(name==="host") renderHost(subview||"monitor");
  if(name==="network") renderNetwork(subview||"overview");
  if(name==="vitastor" && el("vtab-cluster") && el("vtab-cluster").classList.contains("active")){
    if(clTabTimer) clearTimeout(clTabTimer);
    tickCluster();
  }
  try{ localStorage.setItem("vb_view", name);
       if(name==="network") localStorage.setItem("vb_netsub", subview||"overview");
       if(name==="host") localStorage.setItem("vb_hostsub", subview||"monitor"); }catch(e){}
}
document.querySelectorAll(".navitem").forEach(function(it){
  it.addEventListener("click", function(){
    setView(it.getAttribute("data-view"), it.getAttribute("data-subview")||null);
  });
});
document.querySelectorAll(".sidetab").forEach(function(t){
  t.addEventListener("click", function(){
    var cat=t.getAttribute("data-cat");
    var defaults={host:"host", storage:"mon", network:"network"};
    var defaultSub={host:"monitor", network:"overview"};
    setView(defaults[cat]||"storage", defaultSub[cat]||null);
  });
});
/* вкладки внутри страницы Vitastor */
function setVTab(name){
  document.querySelectorAll("#view-vitastor .vtab").forEach(function(t){
    t.classList.toggle("active", t.getAttribute("data-vtab")===name);
  });
  document.querySelectorAll("#view-vitastor .vtabpane").forEach(function(p){
    p.classList.toggle("active", p.id==="vtab-"+name);
  });
  try{ localStorage.setItem("vb_vtab", name); }catch(e){}
  if(name==="cluster"){
    el("cluster").innerHTML="<div class=\"empty\">Опрос узлов кластера&hellip;</div>";
    if(clTabTimer) clearTimeout(clTabTimer);
    tickCluster();
  }
}
document.querySelectorAll("#view-vitastor .vtab").forEach(function(t){
  t.addEventListener("click", function(){ setVTab(t.getAttribute("data-vtab")); });
});
/* вкладки внутри страницы ZFS */
function setZfsTab(name){
  document.querySelectorAll("#view-zfs .vtab").forEach(function(t){
    t.classList.toggle("active", t.getAttribute("data-vtab")===name);
  });
  document.querySelectorAll("#view-zfs .vtabpane").forEach(function(p){
    p.classList.toggle("active", p.id==="zftab-"+name);
  });
  try{ localStorage.setItem("vb_zftab", name); }catch(e){}
}
document.querySelectorAll("#view-zfs .vtab").forEach(function(t){
  t.addEventListener("click", function(){ setZfsTab(t.getAttribute("data-vtab")); });
});
function applyVisibility(){
  var vis={vitastor:cfg.showVita,ceph:cfg.showCeph,zfs:cfg.showZfs};
  document.querySelectorAll(".navitem").forEach(function(it){
    var v=it.getAttribute("data-view");
    if(vis.hasOwnProperty(v)) it.style.display=vis[v]?"":"none";
  });
  var act=document.querySelector(".view.active");
  if(act){
    var cur=act.id.replace("view-","");
    if(vis.hasOwnProperty(cur)&&!vis[cur]) setView(cfg.showZfs?"zfs":(cfg.showVita?"vitastor":(cfg.showCeph?"ceph":"mon")));
  }
}

/* графики */
function drawArea(cv, data, color, ymax, noGrid){
  var w=cv.clientWidth||600, h=cv.clientHeight||140;
  cv.width=w; cv.height=h;
  var ctx=cv.getContext("2d");
  ctx.clearRect(0,0,w,h);
  if(!noGrid){
    ctx.strokeStyle="#222a35"; ctx.lineWidth=1;
    for(var g=1;g<4;g++){ var gy=h*g/4; ctx.beginPath(); ctx.moveTo(0,gy+.5); ctx.lineTo(w,gy+.5); ctx.stroke(); }
  }
  if(!data||!data.length||ymax<=0) return;
  var N=60;
  function X(i){ return (i/(N-1))*w; }
  function Y(v){ return h-Math.min(v,ymax)/ymax*(h-3)-1; }
  var off=N-data.length;
  ctx.beginPath(); ctx.moveTo(X(off), h);
  for(var i=0;i<data.length;i++) ctx.lineTo(X(off+i), Y(data[i]));
  ctx.lineTo(X(off+data.length-1), h); ctx.closePath();
  var grad=ctx.createLinearGradient(0,0,0,h);
  grad.addColorStop(0,color+"77"); grad.addColorStop(1,color+"0c");
  ctx.fillStyle=grad; ctx.fill();
  ctx.beginPath();
  for(var j=0;j<data.length;j++){ var fx=X(off+j),fy=Y(data[j]); if(j) ctx.lineTo(fx,fy); else ctx.moveTo(fx,fy); }
  ctx.strokeStyle=color; ctx.lineWidth=2; ctx.lineJoin="round"; ctx.stroke();
}
function niceMax(v){
  if(v<=0) return 1048576;
  var p=Math.pow(2,Math.ceil(Math.log2(v)));
  if(v>p*0.8) p*=2;
  return Math.max(p,1048576);
}

/* ---- мониторинг дисков ---- */
var lastDM=null, selDisk=null;
try{ selDisk=localStorage.getItem("vb_disk")||null; }catch(e){}
function renderDiskList(dm){
  var disks=dm.disks||[], series=dm.series||{};
  if(!disks.length){ el("dlist").innerHTML="<div class=\"empty\">дисков нет</div>"; return; }
  if(!selDisk || !disks.some(function(d){return d.name===selDisk;})) selDisk=disks[0].name;
  el("dlist").innerHTML=disks.map(function(d){
    var s=series[d.name]||[], cur=s.length?s[s.length-1]:{};
    var sel=(d.name===selDisk)?" sel":"";
    return "<div class=\"dwidget"+sel+"\" data-disk=\""+d.name+"\">"+
      "<div class=\"dw-top\"><span class=\"dw-nm\">"+d.name+"</span>"+
      "<span class=\"dw-pct\">"+(cur.util||0).toFixed(0)+"%</span>"+
      "<button class=\"smbtn\" data-smart=\""+d.name+"\">SMART</button></div>"+
      "<div class=\"dw-model\">"+(d.model||"диск")+"</div>"+
      "<canvas class=\"dw-spark\" data-spark=\""+d.name+"\"></canvas></div>";
  }).join("");
  el("dlist").querySelectorAll(".dwidget").forEach(function(w){
    w.addEventListener("click", function(){
      selDisk=w.getAttribute("data-disk");
      try{ localStorage.setItem("vb_disk", selDisk); }catch(e){}
      renderDiskList(lastDM); renderMon(lastDM);
    });
  });
  el("dlist").querySelectorAll(".smbtn").forEach(function(b){
    b.addEventListener("click", function(e){
      e.stopPropagation();
      smOpen(b.getAttribute("data-smart"));
    });
  });
  el("dlist").querySelectorAll(".dw-spark").forEach(function(cv){
    var s=series[cv.getAttribute("data-spark")]||[];
    drawArea(cv, s.map(function(x){return x.util;}), "#2dd4bf", 100);
  });
}
function mstat(k,v){
  return "<div class=\"mstat\"><div class=\"mk\">"+k+"</div><div class=\"mv\">"+v+"</div></div>";
}
function renderMon(dm){
  var disks=dm.disks||[], series=dm.series||{};
  var disk=disks.filter(function(d){return d.name===selDisk;})[0];
  if(!disk){ el("mongraphs").innerHTML="<div class=\"empty\">выберите диск</div>"; return; }
  var s=series[disk.name]||[], cur=s.length?s[s.length-1]:{rbps:0,wbps:0,riops:0,wiops:0,util:0};
  var rd=s.map(function(x){return x.rbps||0;});
  var wr=s.map(function(x){return x.wbps||0;});
  var utl=s.map(function(x){return x.util||0;});
  var iomax=niceMax(Math.max.apply(null,[1].concat(rd).concat(wr)));
  var ssd=(disk.rota===false);
  el("mongraphs").innerHTML=
    "<div class=\"monhead\"><span class=\"mh-nm\">Накопитель "+disk.name+"</span>"+
      "<span class=\"mh-sz\">"+hb(disk.size)+" &middot; "+(ssd?"SSD":"HDD")+"</span></div>"+
    "<div class=\"graphcard\"><div class=\"gh\"><span class=\"gt\">Активное время &mdash; 60 с</span>"+
      "<span class=\"gv\" style=\"color:var(--accent)\">"+(cur.util||0).toFixed(0)+"%</span>"+
      "<span class=\"gmax\">/ 100%</span></div><canvas class=\"graph\" id=\"g-util\"></canvas></div>"+
    "<div class=\"graphcard\"><div class=\"gh\"><span class=\"gt\">График чтения &mdash; 60 с</span>"+
      "<span class=\"gv\" style=\"color:var(--rd)\">"+hb(cur.rbps)+"/с</span>"+
      "<span class=\"gmax\">/ "+hb(iomax)+"/с</span></div><canvas class=\"graph\" id=\"g-read\"></canvas></div>"+
    "<div class=\"graphcard\"><div class=\"gh\"><span class=\"gt\">График записи &mdash; 60 с</span>"+
      "<span class=\"gv\" style=\"color:var(--wr)\">"+hb(cur.wbps)+"/с</span>"+
      "<span class=\"gmax\">/ "+hb(iomax)+"/с</span></div><canvas class=\"graph\" id=\"g-write\"></canvas></div>"+
    "<div class=\"row r4\">"+
      mstat("Скорость чтения", hb(cur.rbps)+"/с")+mstat("Скорость записи", hb(cur.wbps)+"/с")+
      mstat("Чтение IOPS", num(cur.riops))+mstat("Запись IOPS", num(cur.wiops))+
    "</div><div class=\"row r4\" style=\"margin-top:11px\">"+
      mstat("Активное время",(cur.util||0).toFixed(0)+"%")+mstat("Ёмкость",hb(disk.size))+
      mstat("Тип",ssd?"SSD":"HDD")+mstat("Разделов",(disk.children||[]).length)+
    "</div>";
  drawArea(el("g-util"), utl, "#2dd4bf", 100);
  drawArea(el("g-read"), rd, "#38bdf8", iomax);
  drawArea(el("g-write"), wr, "#a371f7", iomax);
}

/* ---- разметка ---- */
var VITA_PT="e7009fac-a5a1-4d72-af72-53de13059903";
function isVitaPart(c){
  return (c.parttype||"").toLowerCase()===VITA_PT
    || (c.fstype||"").toLowerCase().indexOf("vitastor")>=0;
}
function partColor(c){
  if(isVitaPart(c)) return "c-vstor";
  var f=(c.fstype||"").toLowerCase();
  if(f.indexOf("fat")>=0) return "c-efi";
  if(f.indexOf("lvm")>=0) return "c-lvm";
  if(f.indexOf("ext")>=0||f.indexOf("xfs")>=0||f.indexOf("btrfs")>=0) return "c-ext";
  if(f.indexOf("swap")>=0) return "c-swap";
  if(f.indexOf("zfs")>=0) return "c-vita";
  return "c-raw";
}
function partRole(c){
  if(isVitaPart(c)) return "vitastor_member";
  return c.fstype||c.partlabel||"raw";
}
function renderParts(disks){
  if(disks==null){ el("parts").innerHTML="<div class=\"empty\">нет данных lsblk</div>"; return; }
  if(!disks.length){ el("parts").innerHTML="<div class=\"empty\">дисков нет</div>"; return; }
  el("parts").innerHTML=disks.map(function(d){
    var ssd=(d.rota===false), kids=(d.children||[]), used=0;
    kids.forEach(function(c){ used+=(+c.size||0); });
    var free=(+d.size||0)-used;
    var segs=kids.map(function(c){
      var role=partRole(c);
      var mnt=c.mountpoint?(" &#8599; "+c.mountpoint):"";
      return "<div class=\"pseg\" style=\"flex-grow:"+Math.max(c.size||1,1)+";min-width:120px\">"+
        "<div class=\"cap "+partColor(c)+"\"></div><div class=\"pb\"><div class=\"pnm\">"+c.name+"</div>"+
        "<div class=\"pmeta\">"+hb(c.size)+" &middot; "+role+mnt+"</div></div></div>";
    }).join("");
    if(free>(+d.size||0)*0.01 && free>10485760)
      segs+="<div class=\"pseg free\" style=\"flex-grow:"+free+";min-width:90px\"><div class=\"fl\">свободно<br>"+hb(free)+"</div></div>";
    if(!kids.length) segs="<div class=\"pseg free\" style=\"flex-grow:1\"><div class=\"fl\">без разделов &middot; "+hb(d.size)+"</div></div>";
    return "<div class=\"pmrow\"><div class=\"pm-head\"><span class=\"pm-nm\">"+d.name+"</span>"+
      "<span class=\"badge "+(ssd?"b-ssd":"b-hdd")+"\">"+(ssd?"SSD":"HDD")+"</span>"+
      "<span class=\"pm-model\">"+(d.model||"")+"</span><span class=\"pm-sz\">"+hb(d.size)+"</span></div>"+
      "<div class=\"pm-bar\">"+segs+"</div></div>";
  }).join("");
}

/* ---- vitastor ---- */
function card(k,dotcls,v,s){
  var d=dotcls?"<span class=\"dot "+dotcls+"\"></span>":"";
  return "<div class=\"stat\"><div class=\"k\">"+d+k+"</div><div class=\"v\">"+v+"</div>"+
         "<div class=\"s\">"+(s||"")+"</div></div>";
}
function pgClass(state){
  state=state||[];
  for(var i=0;i<state.length;i++){
    var s=state[i];
    if(s==="incomplete"||s==="down"||s==="offline") return "bad";
  }
  for(var j=0;j<state.length;j++){
    var t=state[j];
    if(t.indexOf("degraded")>=0||t.indexOf("backfill")>=0||t.indexOf("misplaced")>=0||t.indexOf("repeer")>=0) return "warn";
  }
  return state.indexOf("active")>=0 ? "ok" : "";
}
function osdsOfPool(pool, osds){
  var tags=pool.osd_tags||[];
  if(!tags.length) return osds;
  return osds.filter(function(o){
    var ot=o.tags||[];
    return tags.some(function(t){return ot.indexOf(t)>=0;});
  });
}
function gaugeColor(p,ok){ return p>=85?"#f78166":(p>=70?"#f0b429":(ok||"#2dd4bf")); }

function trow(d,con,kind,name,meta){
  return "<div class=\"trow\" style=\"--d:"+d+"\">"+
    "<span class=\"tcon\">"+con+"</span>"+
    "<span class=\"tnode\"><span class=\"tk\">"+kind+"</span>"+
    "<span class=\"tnm\">"+name+"</span>"+
    (meta?"<span class=\"tmeta\">"+meta+"</span>":"")+"</span></div>";
}

function renderPoolWidgets(pools, osds, pg, vols, st){
  st=st||{};
  if(!pools.length){ el("poolwidgets").innerHTML="<div class=\"empty\">пулов нет</div>"; return; }
  var cluName=st.mon_master||"vita";
  var etcd=(st.etcd_alive!=null?st.etcd_alive:"?")+"/"+(st.etcd_count!=null?st.etcd_count:"?");
  var osdUpAll=osds.filter(function(o){return o.up==="up";}).length;
  var dm=lastDM||{}, dmSeries=dm.series||{}, dmDisks=dm.disks||[];
  var sparks=[];
  el("poolwidgets").innerHTML=pools.map(function(p){
    var r2u=p.raw_to_usable||1;
    var uUsed=(p.used_raw||0)/r2u, uFree=(p.max_available||0), uTot=uUsed+uFree;
    var pct=uTot>0?(uUsed/uTot*100):0, col=gaugeColor(pct);

    var pd=pg&&pg[String(p.id)];
    var pgTotal=(pd&&pd.total)||p.pg_count||0;
    var pgAct=(pd&&pd.by_state&&pd.by_state.active)||0;
    var pgcells="";
    if(pd&&pd.pgs&&pd.pgs.length){
      pgcells=pd.pgs.map(function(x){
        var s=(x.state||[]).join("+")||"?";
        return "<i class=\"pgcell "+pgClass(x.state)+"\" title=\"PG "+x.pg+" · "+s+" · primary osd."+x.primary+"\"></i>";
      }).join("");
    } else {
      var cls=(p.status==="active")?"ok":"";
      for(var i=0;i<pgTotal;i++) pgcells+="<i class=\"pgcell "+cls+"\"></i>";
    }

    var po=osdsOfPool(p, osds);
    function sumOp(opname){
      var iops=0,bps=0,bytes=0;
      po.forEach(function(o){ var op=((o.op_stats||{})[opname])||{};
        iops+=+op.iops||0; bps+=+op.bps||0; bytes+=+op.bytes||0; });
      return {iops:iops,bps:bps,bytes:bytes};
    }
    var prd=sumOp("primary_read"), pwr=sumOp("primary_write");
    var nvol=(vols||[]).filter(function(v){return v.pool_name===p.name||v.pool_id===p.id;}).length;
    var tags=(p.osd_tags||[]).map(function(t){return "<span class=\"tagchip\">"+t+"</span>";}).join("");
    var stcls=(p.status==="active")?"pw-st-active":"pw-st-warn";

    /* ===== блок 1 — общая информация: кластер, пул, пространство, PG ===== */
    var T1="";
    T1+=trow(0,"&#9492;","Кластер","<b>"+cluName+"</b>",
      "monitor "+cluName+" &middot; etcd "+etcd+" &middot; OSD "+osdUpAll+"/"+osds.length+" в кластере");
    T1+=trow(1,"&#9492;","Пул",
      "<b>"+p.name+"</b> <span class=\"pw-badge "+stcls+"\">"+(p.status||"")+"</span>",
      (p.scheme||"")+" "+(p.scheme_name||"")+" &middot; failure domain: "+(p.failure_domain||"?")+
      " &middot; "+nvol+" образов"+(tags?" &nbsp;"+tags:""));
    if(p.mount){
      if(p.mount.img){
        var fv=(vols||[]).filter(function(v){return v.name===p.mount.img;})[0];
        var imeta="метаданные VitastorFS";
        if(fv) imeta+=" &middot; "+hb(fv.size)+" &middot; занято "+hb(fv.used_size);
        T1+=trow(2,"&#9492;","образ","<b>"+p.mount.img+"</b>",imeta);
      }
      var mst=p.mount.mounted?"<span style=\"color:var(--ok)\">смонтирован</span>"
        :(p.mount.active?"<span style=\"color:var(--warn)\">не смонтирован</span>"
        :"<span style=\"color:var(--no)\">служба остановлена</span>");
      T1+=trow(p.mount.img?3:2,"&#9492;","ФС","<b>"+p.mount.path+"</b>",
        "VitastorFS &middot; "+String(p.mount.unit).replace(".service","")+" &middot; "+mst);
    }
    T1+="<div class=\"trow\" style=\"--d:2\">"+
      "<div class=\"pw-pair\">"+
        "<div class=\"tfill\"><div class=\"tcap\">Использование пространства</div>"+
          "<div class=\"gauge\"><div class=\"gauge-fill\" style=\"width:"+pct.toFixed(1)+"%;background:"+col+"\"></div>"+
          "<div class=\"gauge-pct\">"+pct.toFixed(1)+"%</div></div>"+
          "<div class=\"gauge-meta\"><span>занято "+hb(uUsed)+"</span>"+
          "<span>свободно "+hb(uFree)+" из "+hb(uTot)+"</span></div></div>"+
        "<div class=\"tfill\"><div class=\"tcap\">Placement Groups &mdash; "+pgAct+" / "+pgTotal+" active</div>"+
          "<div class=\"pggrid\">"+pgcells+"</div></div>"+
      "</div></div>";

    /* ===== блок 2 — карточки дисков (график + заполнение OSD) ===== */
    var rail="";
    po.forEach(function(o){
      var dk=o.disk;
      if(!dk) return;
      var ser=dmSeries[dk]||[];
      var cur=ser.length?ser[ser.length-1]:{};
      var dinfo=null;
      for(var k=0;k<dmDisks.length;k++){ if(dmDisks[k].name===dk){ dinfo=dmDisks[k]; break; } }
      var cid="pspk-"+p.id+"-"+dk;
      sparks.push({id:cid,ser:ser});
      var sz=+o.size||0, fr=+o.free||0, ou=sz?((sz-fr)/sz*100):0;
      rail+="<div class=\"pdw\">"+
        "<div class=\"pdw-top\"><span class=\"pdw-nm\">"+dk+"</span>"+
        "<span class=\"pdw-pct\">"+(+(cur.util||0)).toFixed(0)+"%</span></div>"+
        "<div class=\"pdw-model\">"+((dinfo&&dinfo.model)||"диск")+"</div>"+
        "<canvas class=\"pdw-spark\" id=\""+cid+"\"></canvas>"+
        "<div class=\"pdw-osd\"><span class=\"dot "+(o.up==="up"?"ok":"no")+"\"></span>"+
        "<span class=\"pdw-osd-nm\">osd."+o.name+"</span>"+
        "<span class=\"om-bar\"><i style=\"width:"+ou.toFixed(1)+"%\"></i></span>"+
        "<span class=\"pdw-osd-pct\">"+ou.toFixed(0)+"% &middot; "+hb(sz)+"</span></div>"+
        "</div>";
    });
    if(!rail) rail="<div class=\"pdw-empty\">нет данных по дискам</div>";

    /* ===== блок 3 — инфо: ввод-вывод + всего записано/прочитано ===== */
    var blk3="<div class=\"pw-io3\">"+
        "<div class=\"pw-io3-sec\"><div class=\"tcap\">Ввод-вывод по пулу</div>"+
          "<div class=\"tio\" style=\"flex-direction:column;gap:6px\">"+
            "<span><span class=\"tri r\"></span> Чтение <b>"+num(prd.iops)+"</b> IOPS &middot; "+hb(prd.bps)+"/с</span>"+
            "<span><span class=\"tri w\"></span> Запись <b>"+num(pwr.iops)+"</b> IOPS &middot; "+hb(pwr.bps)+"/с</span>"+
          "</div></div>"+
        "<div class=\"pw-io3-sec\"><div class=\"tcap\">Всего по пулу</div>"+
          "<div class=\"pw-tot\">"+
            "<span>записано <b>"+hb(pwr.bytes)+"</b></span>"+
            "<span>прочитано <b>"+hb(prd.bytes)+"</b></span>"+
          "</div></div>"+
      "</div>";

    /* три блока: слева сверху — общая инфо, слева снизу — диски, справа — инфо */
    return "<div class=\"poolw\"><div class=\"pw-3\">"+
        "<div class=\"pw-3-left\">"+
          "<div class=\"pw-block\">"+
            "<div class=\"pw-head\">"+
              "<span class=\"pw-name\">"+p.name+"</span>"+
              "<span class=\"pw-badge "+stcls+"\">"+(p.status||"")+"</span>"+
              "<span class=\"pw-meta\">иерархия кластера</span></div>"+
            "<div class=\"ptree\">"+T1+"</div>"+
          "</div>"+
          "<div class=\"pw-block\">"+
            "<div class=\"pw-body\">"+
              "<div class=\"pw-rail\">"+rail+"</div>"+
            "</div>"+
          "</div>"+
        "</div>"+
        "<div class=\"pw-block pw-b3\">"+blk3+"</div>"+
      "</div></div>";
  }).join("");

  sparks.forEach(function(s){
    var cv=el(s.id);
    if(cv) drawArea(cv, s.ser.map(function(x){return x.util||0;}), "#2dd4bf", 100);
  });
}

function instSteps(res){
  if(res.error) return "<div class=\"ifail\">Ошибка: "+res.error+"</div>";
  var h="";
  (res.results||[]).forEach(function(s){
    h+="<div class=\"istep "+(s.ok?"ok":"bad")+"\">"+(s.ok?"✔":"✖")+
       " "+s.title+(s.err?" <span class=\"imsg\">"+s.err+"</span>":"")+"</div>";
  });
  h+="<div class=\""+(res.ok?"idone":"ifail")+"\">"+(res.msg||"")+"</div>";
  if(res.ok) h+="<div class=\"imsg\">Страница обновится через 3 с…</div>";
  return h;
}
function instRun(url,body,btn,btnHtml,log){
  var box=el("vita-install");
  box.setAttribute("data-busy","1");
  btn.disabled=true;
  fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(body)}).then(function(r){return r.json();})
    .then(function(res){
      log.innerHTML=instSteps(res);
      btn.disabled=false; btn.innerHTML=btnHtml;
      if(res&&res.ok){ setTimeout(function(){location.reload();},3000); }
      else box.setAttribute("data-busy","0");
    })
    .catch(function(e){
      log.innerHTML="<div class=\"ifail\">Сбой запроса: "+e+
        " (операция могла продолжиться на сервере)</div>";
      btn.disabled=false; btn.innerHTML=btnHtml;
      box.setAttribute("data-busy","0");
    });
}
function renderVitaInstall(){
  var box=el("vita-install");
  if(box.getAttribute("data-mode")==="install") return;
  box.setAttribute("data-mode","install"); box.setAttribute("data-busy","0");
  box.innerHTML=
    "<div class=\"emptybox\"><div class=\"ei\">&#9633;</div>"+
    "<div class=\"et\">Vitastor не установлен</div>"+
    "<div class=\"ed\">CLI-утилита <b>vitastor-cli</b> на этом узле отсутствует. "+
    "Кнопка ниже добавит apt-репозиторий vitastor.io и установит пакеты "+
    "(vitastor, etcd). Control plane (etcd + монитор) затем настраивается "+
    "отдельным мастером.</div>"+
    "<button class=\"instbtn\" id=\"vita-install-btn\">&#11015; Установить Vitastor в 1 клик</button>"+
    "<div class=\"instlog\" id=\"vita-install-log\"></div></div>";
  el("vita-install-btn").onclick=doVitaInstall;
}
function doVitaInstall(){
  if(!confirm("Установить Vitastor?\n\nБудет добавлен apt-репозиторий vitastor.io "+
    "и установлены пакеты vitastor + etcd. Это может занять 1–2 минуты."))
    return;
  var btn=el("vita-install-btn"), log=el("vita-install-log");
  btn.innerHTML="Установка… (1–2 мин)";
  log.innerHTML="<div class=\"iwait\">Идёт установка пакетов, подождите…</div>";
  instRun("/api/install/vitastor",{confirm:"vitastor"},btn,
    "&#11015; Установить Vitastor в 1 клик",log);
}
function cpFld(label,id,val){
  return "<div class=\"cpf\"><label>"+label+"</label>"+
    "<input id=\""+id+"\" value=\""+String(val||"").replace(/"/g,"&quot;")+
    "\" autocomplete=\"off\"></div>";
}
function renderVitaControlPlane(cp){
  cp=cp||{};
  var box=el("vita-install");
  if(box.getAttribute("data-mode")==="cp") return;
  box.setAttribute("data-mode","cp"); box.setAttribute("data-busy","0");
  box.innerHTML=
    "<div class=\"emptybox\" style=\"text-align:left\">"+
    "<div style=\"text-align:center\"><div class=\"ei\">&#9881;</div>"+
    "<div class=\"et\">Vitastor установлен — control plane не настроен</div>"+
    "<div class=\"ed\">Пакеты на месте, но кластер (etcd + монитор) ещё не "+
    "развёрнут. Мастер ниже настроит одноузловой control plane.</div></div>"+
    "<div class=\"cpform\">"+
      cpFld("Имя узла (etcd)","vita-cp-node",cp.node)+
      cpFld("IP этого узла","vita-cp-ip",cp.ip)+
      cpFld("Сеть OSD (CIDR)","vita-cp-net",cp.network)+
    "</div>"+
    "<div class=\"cpsteps\">Будет выполнено:"+
      "<div>&bull; остановлен стоковый etcd, очищены его данные</div>"+
      "<div>&bull; <code>/etc/default/etcd</code> &mdash; конфиг под Vitastor</div>"+
      "<div>&bull; <code>/etc/vitastor/vitastor.conf</code></div>"+
      "<div>&bull; запуск <code>etcd</code> и <code>vitastor-mon</code></div>"+
    "</div>"+
    "<div style=\"text-align:center\"><button class=\"instbtn\" id=\"vita-cp-btn\">"+
    "&#9881; Развернуть control plane</button></div>"+
    "<div class=\"instlog\" id=\"vita-cp-log\"></div></div>";
  el("vita-cp-btn").onclick=doVitaControlPlane;
}
function doVitaControlPlane(){
  var node=el("vita-cp-node").value.trim(),
      ip=el("vita-cp-ip").value.trim(),
      net=el("vita-cp-net").value.trim();
  if(!node||!ip||!net){ alert("Заполните все три поля."); return; }
  if(!confirm("Развернуть control plane Vitastor?\n\nУзел: "+node+"\nIP: "+ip+
    "\nСеть OSD: "+net+"\n\nСтоковый etcd будет остановлен и его данные очищены, "+
    "затем поднимутся etcd под Vitastor и монитор."))
    return;
  var btn=el("vita-cp-btn"), log=el("vita-cp-log");
  btn.innerHTML="Развёртывание…";
  log.innerHTML="<div class=\"iwait\">Настройка control plane, подождите…</div>";
  instRun("/api/install/controlplane",
    {confirm:"controlplane",node:node,ip:ip,network:net},btn,
    "&#9881; Развернуть control plane",log);
}
function renderVitastor(d){
  d=d||{};
  if(el("vita-install").getAttribute("data-busy")==="1") return;
  if(d.installed===false){
    el("vita-body").style.display="none";
    renderVitaInstall();
    return;
  }
  if(d.cp&&d.cp.conf===false){
    el("vita-body").style.display="none";
    renderVitaControlPlane(d.cp);
    return;
  }
  el("vita-install").innerHTML="";
  el("vita-install").setAttribute("data-mode","");
  el("vita-install").setAttribute("data-busy","0");
  el("vita-body").style.display="";
  var st=d.status||{}, pools=d.pools||[], osds=(d.osds||[]).filter(function(o){return o.type==="osd";});
  var vols=d.volumes||[];
  el("cluname").textContent=st.mon_master||"vita";
  if(d.engine) el("vengine").textContent=d.engine;
  var osdUp=osds.filter(function(o){return o.up==="up";}).length, osdN=osds.length;
  var poolAct=pools.filter(function(p){return p.status==="active";}).length;
  var etcdOk=(st.etcd_alive===st.etcd_count)&&st.etcd_count>0;
  var objs=(st.object_counts&&st.object_counts.object)||0;
  var net=(d.config||{}).osd_network;
  if(Array.isArray(net)) net=net.join(", ");
  el("health").innerHTML=
    card("Монитор",st.mon_count>0?"ok":"no",(st.mon_count||0)+" up","master: "+(st.mon_master||"&mdash;"))+
    card("etcd",etcdOk?"ok":"no",(st.etcd_alive!=null?st.etcd_alive:"?")+" / "+(st.etcd_count!=null?st.etcd_count:"?"),"метаданные")+
    card("Пулы",poolAct===pools.length&&pools.length?"ok":"warn",poolAct+" / "+pools.length,"активных")+
    card("OSD",osdUp===osdN&&osdN>0?"ok":(osdN?"warn":"no"),osdUp+" / "+osdN,"демоны хранения")+
    card("Объекты","",num(objs),"блоков данных")+
    card("Сеть",net?"ok":"warn","<span style=\"font-size:13px\">"+(net||"&mdash;")+"</span>","Vitastor osd_network");
  renderPoolWidgets(pools, osds, d.pg, vols, st);
  var vt="<tr><th>Образ</th><th>Пул</th><th>Размер</th><th>Занято (thin)</th></tr>";
  if(!vols.length) vt+="<tr><td colspan=4 class=\"empty\">образов нет</td></tr>";
  vols.forEach(function(v){
    vt+="<tr><td><b>"+v.name+"</b></td><td>"+(v.pool_name||v.pool_id)+"</td>"+
        "<td>"+hb(v.size)+"</td><td>"+hb(v.used_size)+"</td></tr>";
  });
  el("vols").innerHTML=vt;
}

/* ---- zfs ---- */
function renderZfs(z){
  z=z||{}; var box=el("zfs");
  if(z.installed===false){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9633;</div>"+
      "<div class=\"et\">ZFS не установлен</div>"+
      "<div class=\"ed\">CLI-утилиты zpool / zfs на узле отсутствуют.</div></div>"; return;
  }
  var pools=z.pools||[], ds=z.datasets||[];
  if(!pools.length){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9633;</div>"+
      "<div class=\"et\">ZFS-пулов на этом узле нет</div>"+
      "<div class=\"ed\">Утилиты ZFS установлены, пул можно создать на свободных дисках.</div></div>"; return;
  }
  var tmap={mirror:"зеркало",raidz1:"RAIDZ1",raidz2:"RAIDZ2",raidz3:"RAIDZ3",
            stripe:"страйп",single:"одиночный диск",draid:"dRAID"};
  var h="<div class=\"lbl\">Пулы ZFS</div>";
  pools.forEach(function(p){
    var pct=(p.size&&p.alloc!=null)?(p.alloc/p.size*100):0;
    var capn=parseInt(p.capacity,10); if(isNaN(capn)) capn=Math.round(pct);
    var t=p.topology||{}, tt=t.type||"", di=t.diskinfo||[];
    var tlabel=tmap[tt]||tt||"&mdash;";
    var redund=(tt==="mirror"||tt.indexOf("raidz")===0||tt==="draid");
    var online=(p.health==="ONLINE");

    var mine=ds.filter(function(x){
      return x.name===p.name||x.name.indexOf(p.name+"/")===0;});
    var tbl="<table class=\"zdstbl\"><tr><th>Имя</th><th>Тип</th><th>Занято</th>"+
      "<th>Доступно</th><th>recordsize</th><th>volblocksize</th>"+
      "<th>Точка монтирования</th></tr>";
    if(!mine.length) tbl+="<tr><td colspan=7 class=\"empty\">наборов нет</td></tr>";
    mine.forEach(function(x){
      tbl+="<tr><td><b>"+x.name+"</b></td><td>"+x.type+"</td><td>"+hb(x.used)+"</td>"+
        "<td>"+hb(x.avail)+"</td>"+
        "<td>"+(x.recordsize?hb(x.recordsize):"&mdash;")+"</td>"+
        "<td>"+(x.volblocksize?hb(x.volblocksize):"&mdash;")+"</td>"+
        "<td>"+(x.mountpoint||"&mdash;")+"</td></tr>";
    });
    tbl+="</table>";

    var tree="";
    if(di.length){
      tree="<div class=\"ztree\"><div class=\"ztree-h\">"+
        "<span class=\"ztype "+(redund?"red":"nored")+"\">"+tlabel+"</span>"+
        (redund?"":"<span class=\"ztree-x\">без избыточности</span>")+"</div>";
      di.forEach(function(dk,idx){
        var last=(idx===di.length-1);
        var dst=dk.state||"", dok=dst?(dst==="ONLINE"):online;
        tree+="<div class=\"trow\" style=\"--d:0\"><span class=\"tcon\">"+
          (last?"&#9492;":"&#9500;")+"</span>"+
          "<div class=\"tosd\"><span class=\"dot "+(dok?"ok":"no")+"\" title=\""+
            (dst||(online?"ONLINE":p.health))+"\"></span>"+
          "<span class=\"tosd-dk\">диск <b>"+dk.name+"</b></span>"+
          "<span class=\"om-bar\"><i style=\"width:"+capn+"%\"></i></span>"+
          "<span class=\"tosd-pct\">"+capn+"% &middot; "+
            (dk.size?hb(dk.size):"&mdash;")+"</span></div></div>";
      });
      tree+="</div>";
    }

    h+="<div class=\"poolw\"><div class=\"pw-head\">"+
      "<span class=\"pw-name\">"+p.name+"</span>"+
      "<span class=\"pw-badge "+(online?"pw-st-active":"pw-st-warn")+"\">"+p.health+"</span>"+
      (tt?"<span class=\"pw-meta\">"+tlabel+"</span>":"")+"</div>"+
      tbl+
      "<div class=\"gauge\"><div class=\"gauge-fill\" style=\"width:"+pct.toFixed(1)+
        "%;background:"+gaugeColor(pct,"#38bdf8")+"\"></div>"+
        "<div class=\"gauge-pct\">"+pct.toFixed(1)+"%</div></div>"+
      "<div class=\"gauge-meta\"><span>занято "+hb(p.alloc)+"</span>"+
        "<span>"+hb(p.size)+"</span></div>"+
      tree+"</div>";
  });
  var arc=z.arc||{}, sizes=[], amax=1;
  if(arc.present){
    sizes=(arc.series||[]).map(function(x){return x.size||0;});
    amax=niceMax(Math.max.apply(null,[1].concat(sizes)));
    h+="<div class=\"lbl\">Кэш ARC</div>"+
      "<div class=\"graphcard\"><div class=\"gh\">"+
        "<span class=\"gt\">Размер ARC &mdash; окно 60 с</span>"+
        "<span class=\"gv\" style=\"color:var(--accent)\">"+hb(arc.size)+"</span>"+
        "<span class=\"gmax\">/ "+hb(amax)+"</span></div>"+
        "<canvas class=\"graph\" id=\"arc-graph\"></canvas></div>"+
      "<div class=\"row r4\">"+
        mstat("Размер ARC",hb(arc.size))+
        mstat("Целевой (c)",hb(arc.c))+
        mstat("Максимум",hb(arc.c_max))+
        mstat("Хит-рейт",(arc.hit_ratio!=null?arc.hit_ratio+"%":"&mdash;"))+
      "</div>";
  }
  box.innerHTML=h;
  if(arc.present){ var cv=el("arc-graph"); if(cv) drawArea(cv,sizes,"#38bdf8",amax); }
}

/* ---- ceph ---- */
function renderCeph(c){
  c=c||{}; var box=el("ceph");
  if(c.installed===false){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9673;</div>"+
      "<div class=\"et\">Ceph не установлен</div>"+
      "<div class=\"ed\">CLI-утилита ceph на этом узле отсутствует.<br>"+
      "В Proxmox устанавливается командой <b>pveceph install</b>.</div></div>"; return;
  }
  if(!c.configured){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9673;</div>"+
      "<div class=\"et\">Кластер Ceph не настроен</div>"+
      "<div class=\"ed\">Пакеты Ceph установлены, но кластер не инициализирован."+
      (c.error?"<br><span style=\"color:#5b626d\">"+c.error+"</span>":"")+
      "<br>Инициализация: <b>pveceph init</b> &rarr; <b>pveceph mon create</b>.</div></div>"; return;
  }
  var hs=(c.health||"").toUpperCase();
  var hcls=hs.indexOf("OK")>=0?"ok":(hs.indexOf("WARN")>=0?"warn":"no");
  var used=c.bytes_used||0, tot=c.bytes_total||0, pct=tot?(used/tot*100):0;
  var h="<div class=\"lbl\">Здоровье кластера</div><div class=\"row r4\">"+
    card("Здоровье",hcls,c.health||"&mdash;","состояние Ceph")+
    card("Мониторы",c.mon_num>0?"ok":"no",(c.mon_num||0),"кворум "+(c.quorum||0))+
    card("OSD",(c.osd_up===c.osd_num&&c.osd_num>0)?"ok":(c.osd_num?"warn":"no"),
      (c.osd_up||0)+" / "+(c.osd_num||0),(c.osd_in||0)+" in")+
    card("PG",c.pg_num?"ok":"warn",num(c.pg_num||0),(c.pools||0)+" пулов")+
    "</div>";
  h+="<div class=\"lbl\">Ёмкость кластера</div><div class=\"panel\">"+
    "<div class=\"capbar\"><div class=\"used\" style=\"width:"+pct.toFixed(1)+"%\"></div></div>"+
    "<div class=\"capmeta\"><span>занято "+hb(used)+" ("+pct.toFixed(1)+"%)</span>"+
    "<span>свободно "+hb(c.bytes_avail)+" из "+hb(tot)+"</span></div></div>";
  var pbs=c.pgs_by_state||[];
  h+="<div class=\"lbl\">Состояние PG</div><div class=\"panel\"><table>"+
    "<tr><th>Состояние</th><th>Групп размещения</th></tr>";
  if(!pbs.length) h+="<tr><td colspan=2 class=\"empty\">нет данных</td></tr>";
  pbs.forEach(function(s){
    h+="<tr><td><b>"+(s.state_name||"?")+"</b></td><td>"+num(s.count)+"</td></tr>";
  });
  box.innerHTML=h+"</table></div>";
}

/* ---- настройки: блок «Сеанс / служба» ---- */
var _svcAt=null, _svcTick=null, _stopArmed=false, _stopArmedT=null;
function fmtSvcLeft(sec){
  if(sec<=0) return "0 с";
  var h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=sec%60;
  if(h>0) return h+" ч "+m+" мин";
  if(m>0) return m+" мин "+s+" с";
  return s+" с";
}
function fmtSvcTime(ts){
  var d=new Date(ts*1000);
  return ("0"+d.getHours()).slice(-2)+":"+("0"+d.getMinutes()).slice(-2);
}
function tickSvcLeft(){
  var box=el("svc-stop-info");
  if(!box){ if(_svcTick){clearInterval(_svcTick);_svcTick=null;} return; }
  if(!_svcAt){ return; }
  var left=_svcAt-Math.floor(Date.now()/1000);
  if(left<=0){
    box.innerHTML="<span style=\"color:var(--no)\">остановка в процессе&hellip;</span>";
    if(_svcTick){clearInterval(_svcTick);_svcTick=null;}
    setTimeout(function(){ location.href="/login"; }, 5000);
    return;
  }
  box.innerHTML="остановится в <b>"+fmtSvcTime(_svcAt)+
    "</b> &middot; через <b>"+fmtSvcLeft(left)+"</b>";
}
function refreshSvc(){
  if(!el("svc-state")) return;
  fetch("/api/service/info",{cache:"no-store"})
    .then(function(r){return r.json();}).then(function(j){
      if(!el("svc-state")) return;
      var st=(j.active?"<span style=\"color:var(--ok)\">активна</span>"
                       :"<span style=\"color:var(--no)\">остановлена</span>");
      st+=" &middot; автозапуск "+(j.enabled
        ?"<b>включён</b>":"<span style=\"color:var(--dim)\">отключён</span>");
      el("svc-state").innerHTML=st;
      _svcAt=j.autostop_at||null;
      if(_svcTick){ clearInterval(_svcTick); _svcTick=null; }
      if(_svcAt){
        el("svc-cancel").style.display="";
        tickSvcLeft();
        _svcTick=setInterval(tickSvcLeft, 1000);
      }else{
        el("svc-cancel").style.display="none";
        el("svc-stop-info").innerHTML="<span style=\"color:var(--dim)\">не задан</span>";
      }
    }).catch(function(){});
}
function svcSetTimer(dur){
  fetch("/api/service/timer",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({duration:dur||""})
  }).then(function(r){return r.json();}).then(function(j){
    if(j&&j.error){ alert(j.error); }
    refreshSvc();
  }).catch(function(){ alert("нет связи с сервером"); });
}
function svcStopReset(btn,msg){
  _stopArmed=false;
  btn.textContent="Остановить службу";
  btn.classList.remove("armed");
  if(msg) msg.textContent="";
}
function renderSvcSection(){
  refreshSvc();
  var qs=document.querySelectorAll("#svc-quick button");
  for(var i=0;i<qs.length;i++){
    qs[i].addEventListener("click", function(){
      svcSetTimer(this.getAttribute("data-d"));
    });
  }
  el("svc-cancel").addEventListener("click", function(){ svcSetTimer(""); });
  var btn=el("svc-stop-btn"), msg=el("svc-stop-msg");
  btn.addEventListener("click", function(){
    if(!_stopArmed){
      _stopArmed=true;
      btn.textContent="Подтвердить";
      btn.classList.add("armed");
      msg.style.color="var(--no)";
      msg.textContent="нажмите ещё раз в течение 5 с";
      clearTimeout(_stopArmedT);
      _stopArmedT=setTimeout(function(){ svcStopReset(btn,msg); }, 5000);
      return;
    }
    clearTimeout(_stopArmedT); _stopArmed=false;
    btn.disabled=true; btn.textContent="останавливаем&hellip;";
    fetch("/api/service/stop",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({confirm:"stop"})
    }).then(function(r){return r.json();}).then(function(j){
      if(j&&j.error){
        btn.disabled=false; svcStopReset(btn,msg);
        msg.style.color="var(--no)"; msg.textContent=j.error;
        return;
      }
      msg.style.color="var(--no)";
      msg.textContent="служба останавливается, переход на /login…";
      setTimeout(function(){ location.href="/login"; }, 4000);
    }).catch(function(){
      btn.disabled=false; svcStopReset(btn,msg);
      msg.style.color="var(--no)"; msg.textContent="нет связи с сервером";
    });
  });
}

/* ---- настройки ---- */
function ovOpt(ms){ return "<option value=\""+ms+"\""+(cfg.ovMs===ms?" selected":"")+">"+(ms/1000)+" с</option>"; }
function dmOpt(ms){ return "<option value=\""+ms+"\""+(cfg.dmMs===ms?" selected":"")+">"+(ms/1000)+" с</option>"; }
function renderSettings(){
  var d=lastOverview||{}, v=d.vitastor||{}, st=v.status||{};
  var errs=v.errors||[];
  var zfsOk=!!(d.zfs&&d.zfs.installed!==false);
  var cephOk=!!(d.ceph&&d.ceph.installed!==false);
  function srcRow(name,ok,note){
    return "<tr><td><b>"+name+"</b></td>"+
      "<td class=\""+(ok?"srcok":"srcno")+"\">"+(ok?"&#10003;":"&#10007;")+"</td>"+
      "<td style=\"color:var(--dim)\">"+(note||"")+"</td></tr>";
  }
  var h="<div class=\"lbl\">Приложение</div><div class=\"row r4\">"+
    card("Версия","",d.version||"&mdash;","PROXOMATRON")+
    card("Порт","",location.port?(":"+location.port):"&mdash;","HTTP-сервер")+
    card("Кластер","",st.mon_master||"&mdash;","Vitastor monitor")+
    card("Узел","",location.hostname,"адрес дашборда")+
    "</div>";
  h+="<div class=\"lbl\">Обновление данных</div><div class=\"panel\">"+
    "<div class=\"setrow\"><div><div class=\"sk\">Интервал опроса хранилищ</div>"+
      "<div class=\"sd\">Vitastor / ZFS / Ceph &middot; /api/overview</div></div>"+
      "<div class=\"sc\"><select class=\"vbsel\" id=\"set-ov\">"+
        ovOpt(2000)+ovOpt(5000)+ovOpt(10000)+ovOpt(30000)+"</select></div></div>"+
    "<div class=\"setrow\"><div><div class=\"sk\">Интервал опроса дисков</div>"+
      "<div class=\"sd\">нагрузка накопителей &middot; /api/diskmon</div></div>"+
      "<div class=\"sc\"><select class=\"vbsel\" id=\"set-dm\">"+
        dmOpt(1000)+dmOpt(2000)+dmOpt(5000)+"</select></div></div>"+
    "</div>";
  h+="<div class=\"lbl\">Разделы интерфейса</div>"+
    "<div class=\"sd\" style=\"margin:0 2px 6px\">Разделы хранилищ по умолчанию "+
    "скрыты — включите нужные. Vitastor показан по умолчанию.</div>"+
    "<div class=\"panel\">"+
    "<div class=\"setrow\"><div><div class=\"sk\">Показывать Vitastor</div>"+
      "<div class=\"sd\">раздел распределённого хранилища Vitastor</div></div>"+
      "<div class=\"sc\"><label class=\"vbtog\"><input type=\"checkbox\" id=\"set-show-vita\""+
        (cfg.showVita?" checked":"")+"><span class=\"sl\"></span></label></div></div>"+
    "<div class=\"setrow\"><div><div class=\"sk\">Показывать Ceph</div>"+
      "<div class=\"sd\">раздел кластера Ceph</div></div>"+
      "<div class=\"sc\"><label class=\"vbtog\"><input type=\"checkbox\" id=\"set-show-ceph\""+
        (cfg.showCeph?" checked":"")+"><span class=\"sl\"></span></label></div></div>"+
    "<div class=\"setrow\"><div><div class=\"sk\">Показывать ZFS</div>"+
      "<div class=\"sd\">раздел локальных пулов ZFS</div></div>"+
      "<div class=\"sc\"><label class=\"vbtog\"><input type=\"checkbox\" id=\"set-show-zfs\""+
        (cfg.showZfs?" checked":"")+"><span class=\"sl\"></span></label></div></div>"+
    "</div>";
  h+="<div class=\"lbl\">Источники данных</div><div class=\"panel\"><table>"+
    "<tr><th>Источник</th><th>Статус</th><th>Примечание</th></tr>"+
    srcRow("vitastor-cli", errs.length===0,
      errs.length?errs.join("; "):"status / df / osd-tree / ls")+
    srcRow("etcd", (st.etcd_alive||0)>0,
      "состояния PG &middot; "+(st.etcd_alive||0)+" / "+(st.etcd_count||0)+" узлов")+
    srcRow("lsblk / diskstats", true, "разметка и нагрузка дисков")+
    srcRow("ZFS", zfsOk, zfsOk?"zpool / zfs":"утилиты не установлены")+
    srcRow("Ceph", cephOk,
      cephOk?(d.ceph.configured?"кластер активен":"не настроен"):"не установлен")+
    "</table></div>";
  h+="<div class=\"lbl\">Сеанс &middot; служба</div><div class=\"panel\">"+
    "<div style=\"padding:10px 12px\">"+
      "<div class=\"svckv\"><div class=\"k\">Состояние</div>"+
        "<div class=\"v\" id=\"svc-state\">&hellip;</div></div>"+
      "<div class=\"svckv\"><div class=\"k\">Автостоп</div>"+
        "<div class=\"v\" id=\"svc-stop-info\">&hellip;</div>"+
        "<button class=\"vbbtn\" id=\"svc-cancel\" style=\"display:none;margin-left:auto\">Отменить таймер</button>"+
      "</div>"+
    "</div>"+
    "<div style=\"padding:10px 12px;border-top:1px solid var(--line)\">"+
      "<div class=\"sk\" style=\"margin-bottom:4px\">Запустить таймер автостопа</div>"+
      "<div class=\"sd svchint\" style=\"margin-bottom:8px\">"+
        "Через выбранный интервал служба автоматически остановится. "+
        "Снова запустить можно по SSH: <code>proxomatronctl start</code></div>"+
      "<div class=\"chips\" id=\"svc-quick\">"+
        "<button class=\"vbbtn\" data-d=\"30min\">30 минут</button>"+
        "<button class=\"vbbtn\" data-d=\"1h\">1 час</button>"+
        "<button class=\"vbbtn\" data-d=\"3h\">3 часа</button>"+
        "<button class=\"vbbtn\" data-d=\"8h\">8 часов</button>"+
      "</div>"+
    "</div>"+
    "<div style=\"padding:10px 12px;border-top:1px solid var(--line)\">"+
      "<div class=\"sk\" style=\"color:var(--no);margin-bottom:4px\">Остановить сейчас</div>"+
      "<div class=\"sd svchint\" style=\"margin-bottom:8px\">"+
        "Сеанс закроется, служба остановится. Запустить снова: "+
        "<code>proxomatronctl start</code></div>"+
      "<button class=\"vbbtn vbbtndg\" id=\"svc-stop-btn\">Остановить службу</button>"+
      "<span id=\"svc-stop-msg\" style=\"margin-left:12px;font-size:12.5px;color:var(--dim)\"></span>"+
    "</div>"+
    "</div>";
  h+="<div class=\"lbl\">Учётная запись</div><div class=\"panel\">"+
    "<div class=\"setrow\"><div><div class=\"sk\">Текущий пользователь</div>"+
      "<div class=\"sd\" id=\"acct-who\">&hellip;</div></div>"+
      "<div class=\"sc\"><button class=\"vbbtn\" id=\"acct-logout\">Выйти</button></div></div>"+
    "<div style=\"padding:10px 12px 12px;border-top:1px solid var(--line)\">"+
      "<div class=\"sk\" style=\"margin-bottom:8px\">Сменить логин и пароль</div>"+
      "<div class=\"acctgrid\">"+
        "<label>Текущий пароль<input type=\"password\" id=\"acct-old\" autocomplete=\"current-password\"></label>"+
        "<label>Новый логин<input type=\"text\" id=\"acct-login\" autocomplete=\"username\"></label>"+
        "<label>Новый пароль<input type=\"password\" id=\"acct-new\" autocomplete=\"new-password\"></label>"+
        "<label>Повтор пароля<input type=\"password\" id=\"acct-new2\" autocomplete=\"new-password\"></label>"+
      "</div>"+
      "<div style=\"margin-top:10px;display:flex;align-items:center;gap:12px\">"+
        "<button class=\"vbbtn vbbtnp\" id=\"acct-save\">Сохранить</button>"+
        "<span id=\"acct-msg\" style=\"font-size:12.5px\"></span>"+
      "</div>"+
    "</div></div>";
  el("settings").innerHTML=h;
  el("set-ov").addEventListener("change",function(){
    cfg.ovMs=+this.value; saveCfg(); applyIntervals();
  });
  el("set-dm").addEventListener("change",function(){
    cfg.dmMs=+this.value; saveCfg(); applyIntervals();
  });
  el("set-show-vita").addEventListener("change",function(){
    cfg.showVita=this.checked; saveCfg(); applyVisibility();
  });
  el("set-show-ceph").addEventListener("change",function(){
    cfg.showCeph=this.checked; saveCfg(); applyVisibility();
  });
  el("set-show-zfs").addEventListener("change",function(){
    cfg.showZfs=this.checked; saveCfg(); applyVisibility();
  });
  renderSvcSection();
  fetch("/api/auth/me",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(j){
      el("acct-who").textContent=j&&j.login?j.login:"—";
      el("acct-login").value=j&&j.login?j.login:"";
    }).catch(function(){});
  el("acct-logout").addEventListener("click",function(){
    fetch("/api/auth/logout",{method:"POST"}).then(function(){
      location.href="/login";
    });
  });
  el("acct-save").addEventListener("click",function(){
    var msg=el("acct-msg"); msg.style.color="var(--dim)"; msg.textContent="";
    var old=el("acct-old").value, lg=el("acct-login").value.trim(),
        n1=el("acct-new").value, n2=el("acct-new2").value;
    if(!old){ msg.style.color="var(--no)"; msg.textContent="введите текущий пароль"; return; }
    if(!lg){ msg.style.color="var(--no)"; msg.textContent="логин не может быть пустым"; return; }
    if(n1.length<4){ msg.style.color="var(--no)"; msg.textContent="новый пароль не короче 4 символов"; return; }
    if(n1!==n2){ msg.style.color="var(--no)"; msg.textContent="пароли не совпадают"; return; }
    el("acct-save").disabled=true;
    fetch("/api/auth/change",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({old_password:old,login:lg,password:n1})
    }).then(function(r){return r.json();}).then(function(j){
      el("acct-save").disabled=false;
      if(j&&j.ok){
        msg.style.color="var(--accent)"; msg.textContent="сохранено";
        el("acct-old").value=""; el("acct-new").value=""; el("acct-new2").value="";
        el("acct-who").textContent=j.login||lg;
      }else{
        msg.style.color="var(--no)"; msg.textContent=(j&&j.error)||"ошибка";
      }
    }).catch(function(){
      el("acct-save").disabled=false;
      msg.style.color="var(--no)"; msg.textContent="нет связи";
    });
  });
}

/* ---- мастер пулов ---- */
var wizInfo=null, wiz=null;

function wizEsc(s){
  return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function wizSel(id,opts,cur){
  var h="<select class=\"wizsel\" id=\""+id+"\">";
  opts.forEach(function(o){
    h+="<option"+(String(o)===String(cur)?" selected":"")+">"+o+"</option>";
  });
  return h+"</select>";
}
function wizFld(label,inner,hint){
  return "<div class=\"wizfld\"><label>"+label+"</label>"+inner+"</div>"+
    (hint?"<div class=\"wizhint\" style=\"margin-left:180px\">"+hint+"</div>":"");
}
function wizPool(name){
  var ps=(wizInfo&&wizInfo.pools)||[];
  for(var i=0;i<ps.length;i++) if(ps[i].name===name) return ps[i];
  return null;
}
var WNAME=/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;

function wizOpen(){
  wiz={step:1,action:"create",
       name:"",pg_size:2,pg_minsize:1,pg_count:16,failure_domain:"osd",tag:"",
       disks:[],existing_osds:[],mount_enable:false,mount_path:"",
       editPool:"",new_name:"",delPool:"",remove_osds:false,wipe_disks:false,
       rmode:"oneshot",rosd:"",rdisk:"",rpool:"",
       plan:null,confirm:"",result:null,busy:false,err:""};
  el("wizmask").style.display="flex";
  el("wizsteps").innerHTML=""; el("wizft").innerHTML="";
  el("wizbody").innerHTML="<div class=\"wizhint\">Загрузка состояния кластера…</div>";
  fetch("/api/wizard/info",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){ wizInfo=d; wizRender(); })
    .catch(function(e){
      el("wizbody").innerHTML="<div class=\"wizerr\">Не удалось загрузить данные кластера: "+e+"</div>";
    });
}
function wizClose(){ el("wizmask").style.display="none"; wiz=null; }

function wizKinds(){
  return wiz.action==="create"
    ? ["action","disks","mount","review","result"]
    : ["action","review","result"];
}
function wizLabels(){
  return wiz.action==="create"
    ? ["Действие","Диски","Монтирование","Проверка","Готово"]
    : ["Действие","Проверка","Готово"];
}
function wizActLabel(){
  return {create:"Применить",edit:"Применить",
          replace:"Выполнить замену",delete:"Удалить пул"}[wiz.action]||"Применить";
}

function wizRender(){
  if(!wiz) return;
  var kinds=wizKinds(), labels=wizLabels();
  if(wiz.step>kinds.length) wiz.step=kinds.length;
  if(wiz.step<1) wiz.step=1;
  var kind=kinds[wiz.step-1], sp="";
  for(var i=0;i<labels.length;i++){
    var cl="wizpip"+(i+1<wiz.step?" done":"")+(i+1===wiz.step?" on":"");
    sp+="<div class=\""+cl+"\">"+labels[i]+"</div>";
  }
  el("wizsteps").innerHTML=sp;
  var body={action:wizBodyAction,disks:wizBodyDisks,mount:wizBodyMount,
            review:wizBodyReview,result:wizBodyResult}[kind];
  el("wizbody").innerHTML=
    (wiz.err?"<div class=\"wizerr\">"+wizEsc(wiz.err)+"</div>":"")+body();
  wizBind(kind);
  wizFooter(kind);
}

function wizBodyAction(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Что сделать</div><div class=\"acts\">";
  [["create","&#10010;","Создать","новый пул на дисках"],
   ["edit","&#9998;","Изменить","параметры пула"],
   ["replace","&#8635;","Заменить диск","вывод/ввод OSD"],
   ["delete","&#10006;","Удалить","снести пул"]].forEach(function(c){
    var on=(wiz.action===c[0]);
    h+="<div class=\"actcard"+(on?" on":"")+(c[0]==="delete"?" dng":"")+
       "\" data-act=\""+c[0]+"\"><div class=\"ai\">"+c[1]+"</div><div class=\"an\">"+
       c[2]+"</div><div class=\"ad\">"+c[3]+"</div></div>";
  });
  h+="</div></div>";
  if(wiz.action==="create") return h+wizParamsCreate();
  if(wiz.action==="edit") return h+wizParamsEdit();
  if(wiz.action==="replace") return h+wizParamsReplace();
  return h+wizParamsDelete();
}
function wizParamsReplace(){
  var osds=(wizInfo.osds)||[], fd=(wizInfo.free_disks)||[],
      pools=(wizInfo.pools)||[];
  var h="<div class=\"wizgrp\"><div class=\"gl\">Режим замены диска</div>"+
        "<div class=\"acts\">";
  [["oneshot","&#8644;","Одношаговый","вывести OSD и сразу ввести новый диск"],
   ["retire","&#8854;","Шаг 1: вывести OSD","убрать сбойный OSD из кластера"],
   ["induct","&#8853;","Шаг 2: ввести диск","добавить новый диск в пул"]
  ].forEach(function(m){
    var on=(wiz.rmode===m[0]);
    h+="<div class=\"actcard"+(on?" on":"")+"\" data-rmode=\""+m[0]+"\">"+
       "<div class=\"ai\">"+m[1]+"</div><div class=\"an\">"+m[2]+"</div>"+
       "<div class=\"ad\">"+m[3]+"</div></div>";
  });
  h+="</div></div>";
  if(wiz.rmode==="retire"||wiz.rmode==="oneshot"){
    h+="<div class=\"wizgrp\"><div class=\"gl\">Сбойный OSD — будет выведен из "+
       "кластера (rm-osd --allow-data-loss)</div>";
    if(!osds.length) h+="<div class=\"wizhint\">OSD не найдены.</div>";
    osds.forEach(function(o){
      var on=(wiz.rosd===o.num), tg=(o.tags||[]).join(", ")||"без тега";
      h+="<div class=\"pick"+(on?" on":"")+"\" data-rosd=\""+wizEsc(o.num)+"\">"+
         "<input type=\"radio\" name=\"rosd\""+(on?" checked":"")+">"+
         "<span class=\"pk-nm\">osd."+wizEsc(o.num)+"</span>"+
         "<span class=\"pk-meta\">"+hb(o.size)+" &middot; "+wizEsc(tg)+" &middot; "+
         (o.up?"<span style=\"color:var(--ok)\">up</span>"
              :"<span style=\"color:var(--no)\">down</span>")+"</span></div>";
    });
    h+="</div>";
  }
  if(wiz.rmode==="induct"||wiz.rmode==="oneshot"){
    h+="<div class=\"wizgrp\"><div class=\"gl\">Новый диск — будет стёрт и "+
       "подготовлен как OSD</div>";
    if(!fd.length) h+="<div class=\"wizhint\">Свободных дисков не найдено — "+
       "вставьте новый диск и обновите Мастер.</div>";
    fd.forEach(function(d){
      var on=(wiz.rdisk===d.path);
      h+="<div class=\"pick"+(on?" on":"")+"\" data-rdisk=\""+wizEsc(d.path)+"\">"+
         "<input type=\"radio\" name=\"rdisk\""+(on?" checked":"")+">"+
         "<span class=\"pk-nm\">"+wizEsc(d.name)+"</span>"+
         "<span class=\"pk-meta\">"+hb(d.size)+
         (d.model?" &middot; "+wizEsc(d.model):"")+"</span></div>";
    });
    h+="</div>";
  }
  if(wiz.rmode==="induct"){
    if(!pools.length) h+="<div class=\"wizerr\">В кластере нет пулов.</div>";
    else{
      if(!wizPool(wiz.rpool)) wiz.rpool=pools[0].name;
      var o="";
      pools.forEach(function(p){
        o+="<option"+(p.name===wiz.rpool?" selected":"")+">"+p.name+"</option>";
      });
      h+="<div class=\"wizgrp\"><div class=\"gl\">Целевой пул</div>"+
         wizFld("Пул","<select class=\"wizsel\" id=\"w-rpool\">"+o+"</select>",
           "новый OSD получит теги этого пула и войдёт в него")+"</div>";
    }
  }
  if(wiz.rmode==="oneshot")
    h+="<div class=\"wizhint\">Новый OSD унаследует теги выбранного сбойного "+
       "OSD и войдёт в тот же пул. Пул не пересоздаётся.</div>";
  if(wiz.rmode==="retire")
    h+="<div class=\"wizhint\">После вывода OSD физически замените диск, затем "+
       "запустите Мастер ещё раз: «Заменить диск» → «Шаг 2: ввести диск».</div>";
  return h;
}
function wizParamsCreate(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Параметры нового пула</div>";
  h+=wizFld("Имя пула","<input class=\"wizinp\" id=\"w-name\" value=\""+
     wizEsc(wiz.name)+"\" placeholder=\"pool3\">","латиница, цифры, _ и -");
  h+=wizFld("Реплик (pg_size)",wizSel("w-pgsize",[1,2,3,4],wiz.pg_size),
     "число копий каждого блока данных");
  h+=wizFld("Минимум реплик",wizSel("w-pgmin",[1,2,3,4],wiz.pg_minsize),
     "при скольких живых копиях принимать запись");
  h+=wizFld("PG (pg_count)","<input class=\"wizinp\" id=\"w-pgcount\" type=\"number\""+
     " min=\"1\" max=\"256\" value=\""+wiz.pg_count+"\">","групп размещения, обычно степень 2");
  h+=wizFld("Домен отказа",wizSel("w-fd",["osd","host"],wiz.failure_domain),
     "osd — реплики на разных OSD одного узла");
  h+=wizFld("Тег OSD","<input class=\"wizinp\" id=\"w-tag\" value=\""+
     wizEsc(wiz.tag)+"\" placeholder=\"p3\">","метка, по ней пул выбирает OSD");
  return h+"</div>";
}
function wizParamsEdit(){
  var pools=(wizInfo.pools)||[];
  if(!pools.length) return "<div class=\"wizerr\">В кластере нет пулов для изменения.</div>";
  if(!wizPool(wiz.editPool)) wiz.editPool=pools[0].name;
  var cur=wizPool(wiz.editPool),o="";
  pools.forEach(function(p){
    o+="<option"+(p.name===wiz.editPool?" selected":"")+">"+p.name+"</option>";
  });
  var h="<div class=\"wizgrp\"><div class=\"gl\">Изменение пула</div>";
  h+=wizFld("Пул","<select class=\"wizsel\" id=\"w-epool\">"+o+"</select>","");
  h+=wizFld("PG (pg_count)","<input class=\"wizinp\" id=\"w-epgcount\" type=\"number\""+
     " min=\"1\" max=\"256\" value=\""+(cur.pg_count||"")+"\">","сейчас: "+(cur.pg_count||"—"));
  h+=wizFld("Реплик (pg_size)",wizSel("w-epgsize",[1,2,3,4],cur.pg_size),
     "сейчас: "+(cur.pg_size||"—"));
  h+=wizFld("Минимум реплик",wizSel("w-epgmin",[1,2,3,4],cur.pg_minsize),
     "сейчас: "+(cur.pg_minsize||"—"));
  h+=wizFld("Домен отказа",wizSel("w-efd",["osd","host"],cur.failure_domain),
     "сейчас: "+(cur.failure_domain||"—"));
  h+=wizFld("Новое имя","<input class=\"wizinp\" id=\"w-ename\" value=\"\""+
     " placeholder=\"пусто = не менять\">","переименование пула");
  return h+"</div>";
}
function wizPoolOsds(poolName){
  var pools=(wizInfo.pools)||[], osds=(wizInfo.osds)||[];
  var target=null, others=[];
  pools.forEach(function(p){
    if(p.name===poolName) target=p; else others.push(p);
  });
  if(!target) return {removable:[],shared:[]};
  var tt=target.osd_tags||[], removable=[], shared=[];
  osds.forEach(function(o){
    var ot=o.tags||[];
    if(!tt.every(function(t){return ot.indexOf(t)>=0;})) return;
    var inOther=others.some(function(p){
      return (p.osd_tags||[]).every(function(t){return ot.indexOf(t)>=0;});
    });
    (inOther?shared:removable).push(o);
  });
  return {removable:removable,shared:shared};
}
function wizParamsDelete(){
  var pools=(wizInfo.pools)||[];
  if(!pools.length) return "<div class=\"wizerr\">В кластере нет пулов.</div>";
  if(!wizPool(wiz.delPool)) wiz.delPool=pools[0].name;
  var o="";
  pools.forEach(function(p){
    o+="<option"+(p.name===wiz.delPool?" selected":"")+">"+p.name+"</option>";
  });
  var m=(wizInfo.mounts||{})[wiz.delPool];
  var po=wizPoolOsds(wiz.delPool);
  var rmList=po.removable.map(function(x){return "osd."+x.num;}).join(", ")||"нет";
  var disks=[];
  po.removable.forEach(function(x){
    if(x.disk&&disks.indexOf(x.disk)<0) disks.push(x.disk);
  });
  var dkList=disks.map(function(d){return "/dev/"+d;}).join(", ")||"нет";
  var wdis=!wiz.remove_osds;
  var h="<div class=\"wizgrp\"><div class=\"gl\">Удаление пула</div>";
  h+=wizFld("Пул","<select class=\"wizsel\" id=\"w-dpool\">"+o+"</select>","");
  h+="<div class=\"wizerr\">Данные пула «"+wizEsc(wiz.delPool)+
     "» будут безвозвратно уничтожены."+
     (m?" Монтирование "+wizEsc(m.path)+" будет отключено, юнит удалён.":"")+
     "</div>";
  h+="<div class=\"pick"+(wiz.remove_osds?" on":"")+"\" id=\"w-rmosd\">"+
     "<input type=\"checkbox\""+(wiz.remove_osds?" checked":"")+">"+
     "<span class=\"pk-nm\">Удалить OSD пула</span>"+
     "<span class=\"pk-meta\">"+wizEsc(rmList)+"</span></div>";
  h+="<div class=\"pick"+(wiz.wipe_disks&&!wdis?" on":"")+(wdis?" dis":"")+
     "\" id=\"w-wipe\"><input type=\"checkbox\""+
     (wiz.wipe_disks&&!wdis?" checked":"")+(wdis?" disabled":"")+">"+
     "<span class=\"pk-nm\">Очистить диски (wipe)</span>"+
     "<span class=\"pk-meta\">"+wizEsc(dkList)+"</span></div>";
  if(po.shared.length)
    h+="<div class=\"wizhint\">OSD "+
       po.shared.map(function(x){return "osd."+x.num;}).join(", ")+
       " используются другими пулами — будут сохранены.</div>";
  h+="<div class=\"wizhint\">Без «Удалить OSD» диски и OSD остаются в кластере. "+
     "«Очистить диски» уничтожает таблицу разделов — диск становится свободным.</div>";
  return h+"</div>";
}

function wizBodyDisks(){
  var fd=(wizInfo.free_disks)||[], osds=(wizInfo.osds)||[];
  var h="<div class=\"wizgrp\"><div class=\"gl\">Свободные диски — будут стёрты и "+
     "подготовлены как новые OSD</div>";
  if(!fd.length) h+="<div class=\"wizhint\">Свободных дисков не найдено.</div>";
  fd.forEach(function(d){
    var on=wiz.disks.indexOf(d.path)>=0;
    h+="<div class=\"pick"+(on?" on":"")+"\" data-disk=\""+wizEsc(d.path)+"\">"+
       "<input type=\"checkbox\""+(on?" checked":"")+">"+
       "<span class=\"pk-nm\">"+wizEsc(d.name)+"</span>"+
       "<span class=\"pk-meta\">"+hb(d.size)+(d.model?" &middot; "+wizEsc(d.model):"")+
       "</span></div>";
  });
  h+="</div><div class=\"wizgrp\"><div class=\"gl\">Существующие OSD — добавить в пул "+
     "(тег дописывается, OSD остаётся в своём пуле)</div>";
  if(!osds.length) h+="<div class=\"wizhint\">OSD не найдены.</div>";
  osds.forEach(function(o){
    var on=wiz.existing_osds.indexOf(o.num)>=0;
    var tg=(o.tags||[]).join(", ")||"без тега";
    h+="<div class=\"pick"+(on?" on":"")+"\" data-osd=\""+wizEsc(o.num)+"\">"+
       "<input type=\"checkbox\""+(on?" checked":"")+">"+
       "<span class=\"pk-nm\">osd."+wizEsc(o.num)+"</span>"+
       "<span class=\"pk-meta\">"+hb(o.size)+" &middot; "+wizEsc(tg)+" &middot; "+
       (o.up?"up":"down")+"</span></div>";
  });
  h+="</div>";
  var have=wiz.disks.length+wiz.existing_osds.length;
  h+="<div class=\"wizhint\">Выбрано накопителей: <b>"+have+"</b>, требуется минимум "+
     "<b>"+wiz.pg_size+"</b> (= число реплик).</div>";
  return h;
}
function wizBodyMount(){
  if(!wiz.mount_path) wiz.mount_path="/mnt/"+(wiz.name||"pool");
  var h="<div class=\"wizgrp\"><div class=\"gl\">Монтирование как VitastorFS</div>";
  h+="<div class=\"pick"+(wiz.mount_enable?" on":"")+"\" id=\"w-mnt-tog\">"+
     "<input type=\"checkbox\""+(wiz.mount_enable?" checked":"")+">"+
     "<span class=\"pk-nm\">Смонтировать пул в каталог</span>"+
     "<span class=\"pk-meta\">создаст ФС-образ + systemd-юнит</span></div>";
  h+=wizFld("Точка монтирования","<input class=\"wizinp\" id=\"w-mpath\" value=\""+
     wizEsc(wiz.mount_path)+"\""+(wiz.mount_enable?"":" disabled")+">",
     "каталог вида /mnt/&lt;имя&gt;");
  h+="<div class=\"wizhint\">Без монтирования пул остаётся блочным — образы можно "+
     "создавать через vitastor-cli или Proxmox.</div></div>";
  return h;
}
function wizBodyReview(){
  if(wiz.busy) return "<div class=\"wizhint\">Получение плана…</div>";
  if(!wiz.plan) return "<div class=\"wizhint\">План не загружен.</div>";
  var h="<div class=\"wizgrp\"><div class=\"gl\">Будут выполнены команды</div>";
  wiz.plan.steps.forEach(function(s,i){
    h+="<div class=\"planrow"+(s.danger?" dng":"")+"\"><div class=\"pn\">"+(i+1)+
       "</div><div><div class=\"pt\">"+wizEsc(s.title)+"</div>"+
       "<div class=\"pc\">"+wizEsc(s.cmd)+"</div>"+
       (s.note?"<div class=\"pnote\">"+wizEsc(s.note)+"</div>":"")+"</div></div>";
  });
  h+="</div>";
  var cw=wiz.plan.confirm_word;
  h+="<div class=\"cfmbox\"><div class=\"ct\">Для запуска введите слово "+
     "<b class=\"cw\">"+wizEsc(cw)+"</b> в поле ниже:</div>"+
     "<input class=\"wizinp\" id=\"w-confirm\" value=\""+wizEsc(wiz.confirm)+
     "\" placeholder=\"подтверждение\" style=\"flex:none;width:230px\" autocomplete=\"off\">"+
     "</div>";
  return h;
}
function wizBodyResult(){
  if(wiz.busy) return "<div class=\"wizhint\">Выполнение операции, не закрывайте окно…</div>";
  var r=wiz.result;
  if(!r) return "<div class=\"wizhint\">Нет результата.</div>";
  if(r.error) return "<div class=\"wizerr\">"+wizEsc(r.error)+"</div>";
  var h=(r.ok?"<div class=\"wizok\">&#10003; "+wizEsc(r.msg)+"</div>"
             :"<div class=\"wizerr\">&#9888; "+wizEsc(r.msg)+"</div>");
  (r.results||[]).forEach(function(s){
    h+="<div class=\"resrow "+(s.ok?"ok":"bad")+"\"><div class=\"rt\">"+
       (s.ok?"&#10003; ":"&#10007; ")+wizEsc(s.title)+"</div>";
    if(s.cmd) h+="<div class=\"ro\">$ "+wizEsc(s.cmd)+"</div>";
    if(s.out) h+="<div class=\"ro\">"+wizEsc(s.out)+"</div>";
    if(s.err) h+="<div class=\"ro re\">"+wizEsc(s.err)+"</div>";
    h+="</div>";
  });
  return h;
}

function wizReadInputs(kind){
  if(!wiz) return;
  function v(id){ var e=el(id); return e?String(e.value).trim():null; }
  if(kind==="action"){
    if(wiz.action==="create"){
      if(el("w-name")) wiz.name=v("w-name");
      if(el("w-pgsize")) wiz.pg_size=+v("w-pgsize");
      if(el("w-pgmin")) wiz.pg_minsize=+v("w-pgmin");
      if(el("w-pgcount")) wiz.pg_count=+v("w-pgcount");
      if(el("w-fd")) wiz.failure_domain=v("w-fd");
      if(el("w-tag")) wiz.tag=v("w-tag");
    } else if(wiz.action==="edit"){
      if(el("w-epool")) wiz.editPool=v("w-epool");
      if(el("w-epgcount")) wiz.pg_count=+v("w-epgcount");
      if(el("w-epgsize")) wiz.pg_size=+v("w-epgsize");
      if(el("w-epgmin")) wiz.pg_minsize=+v("w-epgmin");
      if(el("w-efd")) wiz.failure_domain=v("w-efd");
      if(el("w-ename")) wiz.new_name=v("w-ename");
    } else if(wiz.action==="replace"){
      if(el("w-rpool")) wiz.rpool=v("w-rpool");
    } else if(el("w-dpool")) wiz.delPool=v("w-dpool");
  } else if(kind==="mount"){
    if(el("w-mpath")) wiz.mount_path=v("w-mpath");
  } else if(kind==="review"){
    if(el("w-confirm")) wiz.confirm=el("w-confirm").value;
  }
}
function wizValidateStep(kind){
  if(kind==="action"){
    if(wiz.action==="create"){
      if(!WNAME.test(wiz.name||"")) return "Имя пула: латиница/цифры/_/-, до 32 символов.";
      if(!WNAME.test(wiz.tag||"")) return "Тег OSD: латиница/цифры/_/-, до 32 символов.";
      if(!(wiz.pg_count>=1&&wiz.pg_count<=256)) return "PG: число от 1 до 256.";
      if(wiz.pg_minsize>wiz.pg_size) return "Минимум реплик не больше pg_size.";
    } else if(wiz.action==="edit"){
      if(!wiz.editPool) return "Выберите пул.";
      if(wiz.new_name&&!WNAME.test(wiz.new_name)) return "Новое имя некорректно.";
    } else if(wiz.action==="replace"){
      if((wiz.rmode==="retire"||wiz.rmode==="oneshot")&&!wiz.rosd)
        return "Выберите сбойный OSD.";
      if((wiz.rmode==="induct"||wiz.rmode==="oneshot")&&!wiz.rdisk)
        return "Выберите новый диск.";
      if(wiz.rmode==="induct"&&!wiz.rpool) return "Выберите целевой пул.";
    } else if(!wiz.delPool) return "Выберите пул.";
  } else if(kind==="disks"){
    if(wiz.disks.length+wiz.existing_osds.length<wiz.pg_size)
      return "Выберите минимум "+wiz.pg_size+" накопителей (= число реплик).";
  } else if(kind==="mount"){
    if(wiz.mount_enable&&!/^\/mnt\/[A-Za-z0-9._-]{1,48}$/.test(wiz.mount_path||""))
      return "Точка монтирования: /mnt/<имя>.";
  }
  return "";
}
function wizReq(){
  if(wiz.action==="create") return {action:"create",name:wiz.name,
    pg_size:wiz.pg_size,pg_minsize:wiz.pg_minsize,pg_count:wiz.pg_count,
    failure_domain:wiz.failure_domain,tag:wiz.tag,
    disks:wiz.disks,existing_osds:wiz.existing_osds,
    mount:{enable:wiz.mount_enable,path:wiz.mount_path},confirm:wiz.confirm};
  if(wiz.action==="edit") return {action:"edit",pool:wiz.editPool,
    pg_size:wiz.pg_size,pg_minsize:wiz.pg_minsize,pg_count:wiz.pg_count,
    failure_domain:wiz.failure_domain,new_name:wiz.new_name,confirm:wiz.confirm};
  if(wiz.action==="replace") return {action:"replace",mode:wiz.rmode,
    osd:wiz.rosd,disk:wiz.rdisk,pool:wiz.rpool,confirm:wiz.confirm};
  return {action:"delete",pool:wiz.delPool,remove_osds:wiz.remove_osds,
    wipe_disks:wiz.wipe_disks,confirm:wiz.confirm};
}
function wizBind(kind){
  var b;
  if(kind==="action"){
    document.querySelectorAll(".actcard[data-act]").forEach(function(c){
      c.onclick=function(){
        wizReadInputs("action");
        wiz.action=c.getAttribute("data-act"); wiz.step=1; wiz.err="";
        wizRender();
      };
    });
    document.querySelectorAll(".actcard[data-rmode]").forEach(function(c){
      c.onclick=function(){
        wizReadInputs("action");
        wiz.rmode=c.getAttribute("data-rmode"); wiz.err=""; wizRender();
      };
    });
    document.querySelectorAll(".pick[data-rosd]").forEach(function(p){
      p.onclick=function(){ wiz.rosd=p.getAttribute("data-rosd"); wizRender(); };
    });
    document.querySelectorAll(".pick[data-rdisk]").forEach(function(p){
      p.onclick=function(){ wiz.rdisk=p.getAttribute("data-rdisk"); wizRender(); };
    });
    if(b=el("w-rpool")) b.onchange=function(){ wiz.rpool=this.value; wizRender(); };
    if(b=el("w-epool")) b.onchange=function(){ wiz.editPool=this.value; wizRender(); };
    if(b=el("w-dpool")) b.onchange=function(){ wiz.delPool=this.value; wizRender(); };
    if(b=el("w-rmosd")) b.onclick=function(){
      wiz.remove_osds=!wiz.remove_osds;
      if(!wiz.remove_osds) wiz.wipe_disks=false;
      wizRender();
    };
    if(b=el("w-wipe")) b.onclick=function(){
      if(!wiz.remove_osds) return;
      wiz.wipe_disks=!wiz.wipe_disks; wizRender();
    };
  } else if(kind==="disks"){
    document.querySelectorAll(".pick[data-disk]").forEach(function(p){
      p.onclick=function(){
        var x=p.getAttribute("data-disk"), i=wiz.disks.indexOf(x);
        if(i>=0) wiz.disks.splice(i,1); else wiz.disks.push(x);
        wizRender();
      };
    });
    document.querySelectorAll(".pick[data-osd]").forEach(function(p){
      p.onclick=function(){
        var x=p.getAttribute("data-osd"), i=wiz.existing_osds.indexOf(x);
        if(i>=0) wiz.existing_osds.splice(i,1); else wiz.existing_osds.push(x);
        wizRender();
      };
    });
  } else if(kind==="mount"){
    if(b=el("w-mnt-tog")) b.onclick=function(){
      wizReadInputs("mount"); wiz.mount_enable=!wiz.mount_enable; wizRender();
    };
  } else if(kind==="review"){
    if(b=el("w-confirm")) b.oninput=function(){
      wiz.confirm=this.value; wizFooter("review");
    };
  }
}
function wizFooter(kind){
  var kinds=wizKinds(), h="";
  if(kind==="result"){
    h="<div class=\"sp\"></div><button class=\"wzb pri\" id=\"wz-done\">Закрыть</button>";
  } else {
    if(wiz.step>1&&!wiz.busy) h+="<button class=\"wzb\" id=\"wz-back\">Назад</button>";
    h+="<div class=\"sp\"></div><button class=\"wzb\" id=\"wz-cancel\">Отмена</button>";
    if(kind==="review"){
      var ready=wiz.plan&&wiz.confirm===wiz.plan.confirm_word&&!wiz.busy;
      var dng=(wiz.action==="delete"||wiz.action==="replace");
      h+="<button class=\"wzb "+(dng?"dng":"pri")+"\" id=\"wz-apply\""+
         (ready?"":" disabled")+">"+wizActLabel()+"</button>";
    } else {
      h+="<button class=\"wzb pri\" id=\"wz-next\""+(wiz.busy?" disabled":"")+
         ">Далее</button>";
    }
  }
  el("wizft").innerHTML=h;
  var b;
  if(b=el("wz-back")) b.onclick=function(){
    wizReadInputs(kind); wiz.step--; wiz.err=""; wizRender();
  };
  if(b=el("wz-cancel")) b.onclick=wizClose;
  if(b=el("wz-done")) b.onclick=function(){ wizClose(); tickOverview(); };
  if(b=el("wz-next")) b.onclick=function(){ wizNext(kind); };
  if(b=el("wz-apply")) b.onclick=wizApply;
}
function wizNext(kind){
  wizReadInputs(kind);
  var err=wizValidateStep(kind);
  if(err){ wiz.err=err; wizRender(); return; }
  wiz.err=""; wiz.step++;
  if(wizKinds()[wiz.step-1]==="review") wizLoadPlan();
  else wizRender();
}
function wizLoadPlan(){
  wiz.busy=true; wiz.plan=null; wizRender();
  fetch("/api/wizard/plan",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(wizReq())}).then(function(r){return r.json();})
    .then(function(d){
      wiz.busy=false;
      if(d.error){ wiz.err=d.error; wiz.step--; wizRender(); return; }
      wiz.plan=d; wiz.confirm=""; wizRender();
    }).catch(function(e){
      wiz.busy=false; wiz.err="Ошибка связи с сервером: "+e; wiz.step--; wizRender();
    });
}
function wizApply(){
  if(!wiz.plan||wiz.confirm!==wiz.plan.confirm_word) return;
  wiz.busy=true; wiz.result=null; wiz.step=wizKinds().length;
  wizRender();
  fetch("/api/wizard/apply",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(wizReq())}).then(function(r){return r.json();})
    .then(function(d){ wiz.busy=false; wiz.result=d; wizRender(); })
    .catch(function(e){
      wiz.busy=false; wiz.result={error:"Ошибка связи с сервером: "+e}; wizRender();
    });
}
el("wiz-open").addEventListener("click",wizOpen);
el("wizclose").addEventListener("click",wizClose);
el("wizmask").addEventListener("click",function(e){
  if(e.target===this&&wiz&&!wiz.busy) wizClose();
});

/* ---- мастер кластера ---- */
var cl=null, clInfo=null, clNodes=[];
var CL_LABELS=["Действие","Проверка","Готово"];
function clOpen(){
  cl={step:1,action:"reconfigure",node:"",ip:"",network:"",mode:"preserve",
      addIp:"",osdNode:"",osdDisks:[],osdTag:"",osdInfo:null,osdLoading:false,
      pName:"",pSize:2,pMin:1,pPg:16,pTag:"",
      confirm:"",result:null,busy:false,err:""};
  clNodes=[];
  el("clmask").style.display="flex";
  el("clsteps").innerHTML=""; el("clft").innerHTML="";
  el("clbody").innerHTML="<div class=\"wizhint\">Загрузка конфигурации кластера…</div>";
  fetch("/api/cluster/info",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){
      clInfo=d;
      cl.node=d.node||""; cl.ip=d.cur_ip||d.host_ip||""; cl.network=d.osd_network||"";
      return fetch("/api/cluster/nodes",{cache:"no-store"});
    })
    .then(function(r){return r.json();})
    .then(function(d){ clNodes=(d&&d.nodes)||[]; clRender(); })
    .catch(function(e){
      el("clbody").innerHTML="<div class=\"wizerr\">Не удалось загрузить "+
        "конфигурацию кластера: "+e+"</div>";
    });
}
function clConfirmWord(){
  if(cl.action==="add-node") return cl.addIp;
  if(cl.action==="add-osd") return cl.osdNode;
  if(cl.action==="create-pool") return cl.pName;
  return cl.ip;
}
function clReqBody(){
  if(cl.action==="add-node")
    return {action:"add-node",ip:cl.addIp,confirm:cl.confirm};
  if(cl.action==="add-osd")
    return {action:"add-osd",ip:cl.osdNode,disks:cl.osdDisks,tag:cl.osdTag,
            confirm:cl.confirm};
  if(cl.action==="create-pool")
    return {action:"create-pool",name:cl.pName,pg_size:cl.pSize,
            pg_minsize:cl.pMin,pg_count:cl.pPg,tag:cl.pTag,confirm:cl.confirm};
  return {action:"reconfigure",node:cl.node,ip:cl.ip,network:cl.network,
          mode:cl.mode,confirm:cl.confirm};
}
function clPickNode(ip){
  cl.osdNode=ip; cl.osdDisks=[]; cl.osdInfo=null; cl.osdLoading=true; clRender();
  fetch("/api/cluster/node-info?ip="+encodeURIComponent(ip),{cache:"no-store"})
    .then(function(r){return r.json();})
    .then(function(d){ cl.osdLoading=false; cl.osdInfo=d; clRender(); })
    .catch(function(e){
      cl.osdLoading=false; cl.osdInfo={error:"связь с узлом: "+e}; clRender();
    });
}
function clClose(){ el("clmask").style.display="none"; cl=null; }
function clRender(){
  if(!cl) return;
  if(cl.step<1) cl.step=1; if(cl.step>3) cl.step=3;
  var sp="";
  for(var i=0;i<CL_LABELS.length;i++)
    sp+="<div class=\"wizpip"+(i+1<cl.step?" done":"")+(i+1===cl.step?" on":"")+
       "\">"+CL_LABELS[i]+"</div>";
  el("clsteps").innerHTML=sp;
  var body=cl.step===1?clBodyParams():cl.step===2?clBodyReview():clBodyResult();
  el("clbody").innerHTML=
    (cl.err?"<div class=\"wizerr\">"+wizEsc(cl.err)+"</div>":"")+body;
  clBind(); clFooter();
}
function clBodyParams(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Действие с кластером</div>"+
        "<div class=\"acts\">";
  [["reconfigure","&#9881;","Сменить IP","IP узла / сеть OSD"],
   ["add-node","&#10133;","Добавить узел","подключить сервер к кластеру"],
   ["add-osd","&#128190;","Добавить OSD","диски узла как OSD"],
   ["create-pool","&#9776;","Создать пул","пул кластера по узлам"]
  ].forEach(function(a){
    var on=(cl.action===a[0]);
    h+="<div class=\"actcard"+(on?" on":"")+"\" data-claction=\""+a[0]+"\">"+
       "<div class=\"ai\">"+a[1]+"</div><div class=\"an\">"+a[2]+"</div>"+
       "<div class=\"ad\">"+a[3]+"</div></div>";
  });
  h+="</div></div>";
  if(cl.action==="add-node") return h+clParamsAddNode();
  if(cl.action==="add-osd") return h+clParamsAddOsd();
  if(cl.action==="create-pool") return h+clParamsPool();
  return h+clParamsReconf();
}
function clParamsReconf(){
  var i=clInfo||{};
  var h="<div class=\"wizgrp\"><div class=\"gl\">Текущая конфигурация</div>"+
    "<div class=\"wizhint\">etcd_address: <b>"+wizEsc(i.etcd_address||"&mdash;")+
    "</b><br>osd_network: <b>"+wizEsc(i.osd_network||"&mdash;")+"</b><br>"+
    "пулов: <b>"+(i.pools||0)+"</b> &middot; OSD: <b>"+(i.osds||0)+"</b></div></div>";
  h+="<div class=\"wizgrp\"><div class=\"gl\">Новые параметры</div>";
  h+=wizFld("Имя узла (etcd)","<input class=\"wizinp\" id=\"cl-node\" value=\""+
     wizEsc(cl.node)+"\">","");
  h+=wizFld("IP узла","<input class=\"wizinp\" id=\"cl-ip\" value=\""+
     wizEsc(cl.ip)+"\">","IP уже должен быть назначен сетевому интерфейсу");
  h+=wizFld("Сеть OSD (CIDR)","<input class=\"wizinp\" id=\"cl-net\" value=\""+
     wizEsc(cl.network)+"\">","напр. 192.168.33.0/24");
  h+="</div>";
  h+="<div class=\"wizgrp\"><div class=\"gl\">Данные etcd (пулы / OSD / PG)</div>"+
     "<div class=\"acts\">";
  [["preserve","&#128190;","Сохранить данные","etcd через force-new-cluster &mdash; конфиг кластера цел"],
   ["reinit","&#9888;","Переинициализировать","etcd начисто &mdash; конфиг кластера теряется"]
  ].forEach(function(m){
    var on=(cl.mode===m[0]);
    h+="<div class=\"actcard"+(on?" on":"")+(m[0]==="reinit"?" dng":"")+
       "\" data-clmode=\""+m[0]+"\"><div class=\"ai\">"+m[1]+"</div>"+
       "<div class=\"an\">"+m[2]+"</div><div class=\"ad\">"+m[3]+"</div></div>";
  });
  h+="</div></div>";
  if(cl.mode==="reinit"&&((i.pools||0)+(i.osds||0))>0)
    h+="<div class=\"wizerr\">В кластере есть пулы/OSD &mdash; режим «начисто» "+
       "сотрёт весь конфиг кластера из etcd.</div>";
  return h;
}
function clParamsAddNode(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Новый узел кластера</div>";
  h+=wizFld("IP узла","<input class=\"wizinp\" id=\"cl-addip\" value=\""+
     wizEsc(cl.addIp)+"\" placeholder=\"192.168.33.134\">",
     "на узле уже должен работать PROXOMATRON (агент)");
  h+="</div><div class=\"wizhint\">Мастер обратится к агенту PROXOMATRON на узле, "+
     "установит Vitastor (если нужно) и пропишет vitastor.conf на etcd этого "+
     "кластера. etcd и монитор на узле не разворачиваются — он worker.</div>";
  return h;
}
function clParamsAddOsd(){
  var nodes=(clNodes||[]).filter(function(n){return !n.self;});
  var h="<div class=\"wizgrp\"><div class=\"gl\">Узел кластера</div>";
  if(!nodes.length)
    h+="<div class=\"wizhint\">Нет добавленных узлов — сначала действие "+
       "«Добавить узел».</div>";
  else{
    h+="<div class=\"acts\">";
    nodes.forEach(function(n){
      var on=(cl.osdNode===n.ip);
      h+="<div class=\"actcard"+(on?" on":"")+"\" data-clnode=\""+wizEsc(n.ip)+
         "\"><div class=\"ai\">&#128421;</div><div class=\"an\">"+
         wizEsc(n.hostname)+"</div><div class=\"ad\">"+wizEsc(n.ip)+"</div></div>";
    });
    h+="</div>";
  }
  h+="</div>";
  if(cl.osdNode){
    h+="<div class=\"wizgrp\"><div class=\"gl\">Свободные диски узла "+
       wizEsc(cl.osdNode)+" — будут стёрты и подготовлены как OSD</div>";
    if(cl.osdLoading) h+="<div class=\"wizhint\">Загрузка дисков узла…</div>";
    else if(cl.osdInfo&&cl.osdInfo.error)
      h+="<div class=\"wizerr\">"+wizEsc(cl.osdInfo.error)+"</div>";
    else{
      var fd=(cl.osdInfo&&cl.osdInfo.free_disks)||[];
      if(!fd.length) h+="<div class=\"wizhint\">Свободных дисков на узле нет.</div>";
      fd.forEach(function(dk){
        var on=cl.osdDisks.indexOf(dk.path)>=0;
        h+="<div class=\"pick"+(on?" on":"")+"\" data-cldisk=\""+wizEsc(dk.path)+
           "\"><input type=\"checkbox\""+(on?" checked":"")+">"+
           "<span class=\"pk-nm\">"+wizEsc(dk.name)+"</span>"+
           "<span class=\"pk-meta\">"+hb(dk.size)+
           (dk.model?" &middot; "+wizEsc(dk.model):"")+"</span></div>";
      });
    }
    h+="</div>";
    h+="<div class=\"wizgrp\"><div class=\"gl\">Тег пула</div>"+
       wizFld("Тег OSD","<input class=\"wizinp\" id=\"cl-osdtag\" value=\""+
       wizEsc(cl.osdTag)+"\" placeholder=\"p1\">",
       "новые OSD получат этот тег — по нему пул кластера их выбирает")+"</div>";
  }
  return h;
}
function clParamsPool(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Параметры пула кластера</div>";
  h+=wizFld("Имя пула","<input class=\"wizinp\" id=\"cl-pname\" value=\""+
     wizEsc(cl.pName)+"\" placeholder=\"clpool\">","латиница/цифры/_/-");
  h+=wizFld("Реплик (pg_size)",wizSel("cl-psize",[1,2,3,4],cl.pSize),
     "число копий блока; для устойчивости по узлам &ge; 2");
  h+=wizFld("Минимум реплик",wizSel("cl-pmin",[1,2,3,4],cl.pMin),
     "при скольких живых копиях принимать запись");
  h+=wizFld("PG (pg_count)","<input class=\"wizinp\" id=\"cl-ppg\" type=\"number\""+
     " min=\"1\" max=\"256\" value=\""+cl.pPg+"\">","обычно степень двойки");
  h+=wizFld("Тег OSD","<input class=\"wizinp\" id=\"cl-ptag\" value=\""+
     wizEsc(cl.pTag)+"\" placeholder=\"p1\">","пул возьмёт OSD с этим тегом");
  h+="</div><div class=\"wizhint\">Пул создаётся с failure_domain=<b>host</b> — "+
     "реплики раскладываются по разным узлам кластера. Узлы и OSD добавьте "+
     "заранее действиями «Добавить узел» и «Добавить OSD».</div>";
  return h;
}
function clPlan(){
  if(cl.action==="add-node") return [
    {d:false,t:"Проверить агент PROXOMATRON на узле "+cl.addIp,
     c:"GET http://"+cl.addIp+":8080/api/node/info"},
    {d:true,t:"Установить пакеты Vitastor на узле (если отсутствуют)",
     c:"apt install vitastor … (репозиторий vitastor.io)"},
    {d:false,t:"Записать vitastor.conf узла на etcd кластера",
     c:"etcd_address="+((clInfo&&clInfo.etcd_address)||"http://?:2379")},
    {d:false,t:"Зарегистрировать узел в кластере",
     c:"etcdctl put /proxomatron/nodes/"+cl.addIp}];
  if(cl.action==="add-osd") return [
    {d:true,t:"Подготовить диски узла "+cl.osdNode+" как OSD",
     c:"vitastor-disk prepare "+(cl.osdDisks.join(" ")||"—")+
       " — ПОЛНОЕ СТИРАНИЕ дисков"},
    {d:false,t:"Назначить тег '"+cl.osdTag+"' новым OSD",
     c:"etcdctl put /vitastor/config/osd/<N> {tags:["+cl.osdTag+"]}"}];
  if(cl.action==="create-pool") return [
    {d:false,t:"Создать пул кластера '"+cl.pName+"'",
     c:"vitastor-cli create-pool "+cl.pName+" -s "+cl.pSize+" --pg_minsize "+
       cl.pMin+" -n "+cl.pPg+" --failure_domain host --osd_tags "+cl.pTag}];
  var st=[
    {d:true,t:"Остановить службы",
     c:"systemctl stop vitastor-osd@* vitastor-mon etcd"},
    {d:false,t:"Записать /etc/vitastor/vitastor.conf",
     c:"etcd_address=http://"+cl.ip+":2379, osd_network="+cl.network},
    {d:false,t:"Записать /etc/default/etcd",c:"URL etcd на IP "+cl.ip}];
  if(cl.mode==="reinit")
    st.push({d:true,t:"Очистить данные etcd",
      c:"rm -rf /var/lib/etcd/* — конфиг кластера теряется"});
  else
    st.push({d:true,t:"Запуск etcd с --force-new-cluster",
      c:"K/V-данные сохраняются, обновляется только peer-URL"});
  st.push({d:false,t:"Запуск vitastor-mon и всех OSD",
    c:"systemctl restart vitastor-mon + vitastor-osd@*"});
  st.push({d:false,t:"Проверка",c:"etcd health + vitastor-cli status"});
  return st;
}
function clBodyReview(){
  var titles={reconfigure:"Смена IP / сети кластера",
    "add-node":"Добавление узла "+cl.addIp,
    "add-osd":"Добавление OSD на узле "+cl.osdNode,
    "create-pool":"Создание пула кластера "+cl.pName};
  var h="<div class=\"wizgrp\"><div class=\"gl\">"+
        wizEsc(titles[cl.action]||"")+" — будет выполнено</div>";
  clPlan().forEach(function(s,i){
    h+="<div class=\"planrow"+(s.d?" dng":"")+"\"><div class=\"pn\">"+(i+1)+
       "</div><div><div class=\"pt\">"+wizEsc(s.t)+"</div>"+
       "<div class=\"pc\">"+wizEsc(s.c)+"</div></div></div>";
  });
  h+="</div>";
  var cw=clConfirmWord();
  h+="<div class=\"cfmbox\"><div class=\"ct\">Для запуска введите "+
     "<b class=\"cw\">"+wizEsc(cw)+"</b> в поле ниже:</div>"+
     "<input class=\"wizinp\" id=\"cl-confirm\" value=\""+wizEsc(cl.confirm)+
     "\" placeholder=\"подтверждение\" style=\"flex:none;width:230px\" "+
     "autocomplete=\"off\"></div>";
  return h;
}
function clBodyResult(){
  if(cl.busy) return "<div class=\"wizhint\">Применение… не закрывайте окно. "+
    "Операция с кластером может занять до 1–2 минут.</div>";
  var r=cl.result;
  if(!r) return "<div class=\"wizhint\">Нет результата.</div>";
  if(r.error) return "<div class=\"wizerr\">"+wizEsc(r.error)+"</div>";
  var h=(r.ok?"<div class=\"wizok\">&#10003; "+wizEsc(r.msg)+"</div>"
             :"<div class=\"wizerr\">&#9888; "+wizEsc(r.msg)+"</div>");
  (r.results||[]).forEach(function(s){
    h+="<div class=\"resrow "+(s.ok?"ok":"bad")+"\"><div class=\"rt\">"+
       (s.ok?"&#10003; ":"&#10007; ")+wizEsc(s.title)+"</div>";
    if(s.cmd) h+="<div class=\"ro\">$ "+wizEsc(s.cmd)+"</div>";
    if(s.out) h+="<div class=\"ro\">"+wizEsc(s.out)+"</div>";
    if(s.err) h+="<div class=\"ro re\">"+wizEsc(s.err)+"</div>";
    h+="</div>";
  });
  return h;
}
function clReadInputs(){
  if(!cl) return;
  if(cl.step===1){
    if(cl.action==="reconfigure"){
      if(el("cl-node")) cl.node=el("cl-node").value.trim();
      if(el("cl-ip")) cl.ip=el("cl-ip").value.trim();
      if(el("cl-net")) cl.network=el("cl-net").value.trim();
    } else if(cl.action==="add-node"){
      if(el("cl-addip")) cl.addIp=el("cl-addip").value.trim();
    } else if(cl.action==="add-osd"){
      if(el("cl-osdtag")) cl.osdTag=el("cl-osdtag").value.trim();
    } else if(cl.action==="create-pool"){
      if(el("cl-pname")) cl.pName=el("cl-pname").value.trim();
      if(el("cl-psize")) cl.pSize=+el("cl-psize").value;
      if(el("cl-pmin")) cl.pMin=+el("cl-pmin").value;
      if(el("cl-ppg")) cl.pPg=+el("cl-ppg").value;
      if(el("cl-ptag")) cl.pTag=el("cl-ptag").value.trim();
    }
  } else if(cl.step===2){
    if(el("cl-confirm")) cl.confirm=el("cl-confirm").value;
  }
}
function clBind(){
  var b;
  document.querySelectorAll(".actcard[data-claction]").forEach(function(c){
    c.onclick=function(){
      clReadInputs(); cl.action=c.getAttribute("data-claction");
      cl.err=""; clRender();
    };
  });
  document.querySelectorAll(".actcard[data-clmode]").forEach(function(c){
    c.onclick=function(){
      clReadInputs(); cl.mode=c.getAttribute("data-clmode"); cl.err=""; clRender();
    };
  });
  document.querySelectorAll(".actcard[data-clnode]").forEach(function(c){
    c.onclick=function(){
      clReadInputs(); clPickNode(c.getAttribute("data-clnode"));
    };
  });
  document.querySelectorAll(".pick[data-cldisk]").forEach(function(p){
    p.onclick=function(){
      var x=p.getAttribute("data-cldisk"), i=cl.osdDisks.indexOf(x);
      if(i>=0) cl.osdDisks.splice(i,1); else cl.osdDisks.push(x);
      clRender();
    };
  });
  if(b=el("cl-confirm")) b.oninput=function(){ cl.confirm=this.value; clFooter(); };
}
function clFooter(){
  var h="";
  if(cl.step===3){
    h="<div class=\"sp\"></div>"+(cl.busy?"":
       "<button class=\"wzb pri\" id=\"cl-done\">Закрыть</button>");
  } else {
    if(cl.step>1) h+="<button class=\"wzb\" id=\"cl-back\">Назад</button>";
    h+="<div class=\"sp\"></div><button class=\"wzb\" id=\"cl-cancel\">Отмена</button>";
    if(cl.step===2){
      var cw=clConfirmWord();
      var ready=(cw&&cl.confirm===cw&&!cl.busy);
      var dng=(cl.action==="reconfigure"||cl.action==="add-osd");
      h+="<button class=\"wzb "+(dng?"dng":"pri")+"\" id=\"cl-apply\""+
         (ready?"":" disabled")+">Применить</button>";
    } else {
      h+="<button class=\"wzb pri\" id=\"cl-next\">Далее</button>";
    }
  }
  el("clft").innerHTML=h;
  var b;
  if(b=el("cl-back")) b.onclick=function(){
    clReadInputs(); cl.step--; cl.err=""; clRender();
  };
  if(b=el("cl-cancel")) b.onclick=clClose;
  if(b=el("cl-done")) b.onclick=function(){ clClose(); tickOverview(); };
  if(b=el("cl-next")) b.onclick=clNext;
  if(b=el("cl-apply")) b.onclick=clApply;
}
function clValidateParams(){
  var IP=/^\d{1,3}(\.\d{1,3}){3}$/;
  if(cl.action==="reconfigure"){
    if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(cl.node)) return "Имя узла некорректно.";
    if(!IP.test(cl.ip)) return "IP-адрес некорректен.";
    if(!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(cl.network))
      return "Сеть OSD: формат X.X.X.X/NN.";
  } else if(cl.action==="add-node"){
    if(!IP.test(cl.addIp)) return "IP узла некорректен.";
  } else if(cl.action==="add-osd"){
    if(!cl.osdNode) return "Выберите узел кластера.";
    if(!cl.osdDisks.length) return "Выберите хотя бы один диск.";
    if(!WNAME.test(cl.osdTag||"")) return "Тег OSD: латиница/цифры/_/-.";
  } else {
    if(!WNAME.test(cl.pName||"")) return "Имя пула: латиница/цифры/_/-.";
    if(!WNAME.test(cl.pTag||"")) return "Тег OSD: латиница/цифры/_/-.";
    if(!(cl.pPg>=1&&cl.pPg<=256)) return "PG: число от 1 до 256.";
    if(cl.pMin>cl.pSize) return "Минимум реплик не больше pg_size.";
  }
  return "";
}
function clNext(){
  clReadInputs();
  if(cl.step===1){
    var err=clValidateParams();
    if(err){ cl.err=err; clRender(); return; }
  }
  cl.err=""; cl.confirm=""; cl.step++; clRender();
}
function clApply(){
  if(!cl||cl.confirm!==clConfirmWord()) return;
  cl.busy=true; cl.result=null; cl.step=3; clRender();
  fetch("/api/cluster/apply",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(clReqBody())}).then(function(r){return r.json();})
    .then(function(d){ cl.busy=false; cl.result=d; clRender(); })
    .catch(function(e){
      cl.busy=false; cl.result={error:"Ошибка связи с сервером: "+e}; clRender();
    });
}
el("cl-open").addEventListener("click",clOpen);
el("cl-open2").addEventListener("click",clOpen);
el("clclose").addEventListener("click",clClose);
el("clmask").addEventListener("click",function(e){
  if(e.target===this&&cl&&!cl.busy) clClose();
});

/* ===== Мастер пулов ZFS ===== */
var zw=null;
var ZW_LABELS=["Параметры","Проверка","Готово"];
var ZW_MODES=[
  {id:"single",   ic:"&#9707;",nm:"Одиночный",  ad:"страйп, без избыточности",  min:1,exact:0},
  {id:"mirror",   ic:"&#9636;",nm:"Зеркало",    ad:"одно зеркало (mirror)",     min:2,exact:0},
  {id:"zr1",      ic:"&#9638;",nm:"RAIDZ1",     ad:"1 диск чётности, мин. 3",   min:3,exact:0},
  {id:"zr2",      ic:"&#9638;",nm:"RAIDZ2",     ad:"2 диска чётности, мин. 4",  min:4,exact:0},
  {id:"mirror2+2",ic:"&#9707;",nm:"Зеркало 2+2",ad:"страйп из 2 зеркал по 2",   min:4,exact:4}
];
function zwMode(id){
  for(var i=0;i<ZW_MODES.length;i++) if(ZW_MODES[i].id===id) return ZW_MODES[i];
  return null;
}
function zwOpen(){
  zw={step:1,name:"",mode:"mirror",disks:[],confirm:"",info:null,
      busy:false,result:null,err:""};
  el("zwmask").style.display="flex";
  el("zwsteps").innerHTML=""; el("zwft").innerHTML="";
  el("zwbody").innerHTML="<div class=\"wizhint\">Загрузка свободных дисков…</div>";
  fetch("/api/zfs/wizard-info",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){
      zw.info=d;
      if(d.installed===false){
        el("zwbody").innerHTML="<div class=\"wizerr\">ZFS на этом узле не "+
          "установлен — нет утилит zpool / zfs.</div>";
        el("zwft").innerHTML="<div class=\"sp\"></div>"+
          "<button class=\"wzb\" id=\"zw-cancel\">Закрыть</button>";
        var b=el("zw-cancel"); if(b) b.onclick=zwClose;
        return;
      }
      zwRender();
    })
    .catch(function(e){
      el("zwbody").innerHTML="<div class=\"wizerr\">Не удалось загрузить данные: "+e+"</div>";
    });
}
function zwClose(){ if(zw&&zw.busy) return; el("zwmask").style.display="none"; zw=null; }
function zwVdev(){
  var d=zw.disks;
  if(zw.mode==="mirror") return "mirror "+d.join(" ");
  if(zw.mode==="zr1") return "raidz1 "+d.join(" ");
  if(zw.mode==="zr2") return "raidz2 "+d.join(" ");
  if(zw.mode==="mirror2+2")
    return "mirror "+d.slice(0,2).join(" ")+" mirror "+d.slice(2,4).join(" ");
  return d.join(" ");
}
function zwCmd(){
  return "zpool create -f -o ashift=12 "+(zw.name||"<имя>")+" "+
         (zw.disks.length?zwVdev():"<диски>");
}
function zwValidate(){
  if(!WNAME.test(zw.name||"")) return "Имя пула: латиница/цифры/_/-, до 32 символов.";
  if(/^[0-9]/.test(zw.name||"")) return "Имя пула ZFS не может начинаться с цифры.";
  if(zw.info&&(zw.info.pools||[]).indexOf(zw.name)>=0)
    return "Пул ZFS «"+zw.name+"» уже существует.";
  var m=zwMode(zw.mode);
  if(!m) return "Выберите режим пула.";
  if(zw.disks.length<m.min)
    return "Режим «"+m.nm+"» требует не менее "+m.min+" "+
           plural(m.min,"диска","дисков","дисков")+".";
  if(m.exact&&zw.disks.length!==m.exact)
    return "Режим «"+m.nm+"» требует ровно "+m.exact+" диска.";
  return "";
}
function zwReadInputs(){
  if(!zw) return;
  if(el("zw-name")) zw.name=el("zw-name").value.trim();
  if(el("zw-confirm")) zw.confirm=el("zw-confirm").value;
}
function zwRender(){
  if(!zw) return;
  if(zw.step<1) zw.step=1; if(zw.step>3) zw.step=3;
  var sp="";
  for(var i=0;i<ZW_LABELS.length;i++)
    sp+="<div class=\"wizpip"+(i+1<zw.step?" done":"")+(i+1===zw.step?" on":"")+
       "\">"+ZW_LABELS[i]+"</div>";
  el("zwsteps").innerHTML=sp;
  var body=zw.step===1?zwBodyParams():zw.step===2?zwBodyReview():zwBodyResult();
  el("zwbody").innerHTML=
    (zw.err?"<div class=\"wizerr\">"+wizEsc(zw.err)+"</div>":"")+body;
  zwBind(); zwFooter();
}
function zwBodyParams(){
  var h="<div class=\"wizgrp\"><div class=\"gl\">Имя пула</div>";
  h+=wizFld("Имя пула ZFS","<input class=\"wizinp\" id=\"zw-name\" value=\""+
     wizEsc(zw.name)+"\" placeholder=\"tank\" autocomplete=\"off\">",
     "латиница/цифры/_/-, не начинать с цифры");
  h+="</div><div class=\"wizgrp\"><div class=\"gl\">Режим избыточности</div>"+
     "<div class=\"acts\">";
  ZW_MODES.forEach(function(m){
    var on=(zw.mode===m.id);
    h+="<div class=\"actcard"+(on?" on":"")+"\" data-zwmode=\""+m.id+"\">"+
       "<div class=\"ai\">"+m.ic+"</div><div class=\"an\">"+m.nm+"</div>"+
       "<div class=\"ad\">"+m.ad+"</div></div>";
  });
  h+="</div></div>";
  var fd=(zw.info&&zw.info.free_disks)||[], m=zwMode(zw.mode)||{};
  h+="<div class=\"wizgrp\"><div class=\"gl\">Диски пула — будут стёрты "+
     "(выбрано "+zw.disks.length+(m.exact?" из "+m.exact:
     ", минимум "+m.min)+")</div>";
  if(!fd.length)
    h+="<div class=\"wizhint\">Свободных дисков нет. Пулу ZFS нужны диски без "+
       "разделов, файловой системы и точек монтирования.</div>";
  fd.forEach(function(d){
    var idx=zw.disks.indexOf(d.path), on=idx>=0;
    h+="<div class=\"pick"+(on?" on":"")+"\" data-zwdisk=\""+wizEsc(d.path)+
       "\"><input type=\"checkbox\""+(on?" checked":"")+">"+
       "<span class=\"pk-nm\">"+wizEsc(d.name)+"</span>"+
       (on?"<span class=\"tagchip\">#"+(idx+1)+"</span>":"")+
       "<span class=\"pk-meta\">"+hb(d.size)+
       (d.model?" &middot; "+wizEsc(d.model):"")+"</span></div>";
  });
  h+="</div><div class=\"wizgrp\"><div class=\"gl\">Команда</div>"+
     "<div class=\"planrow\"><div class=\"pn\">$</div><div>"+
     "<div class=\"pc\">"+wizEsc(zwCmd())+"</div></div></div></div>";
  return h;
}
function zwBodyReview(){
  var m=zwMode(zw.mode)||{};
  var h="<div class=\"wizgrp\"><div class=\"gl\">Создание пула ZFS «"+
        wizEsc(zw.name)+"» — будет выполнено</div>";
  [{t:"Создать пул в режиме «"+m.nm+"» на "+zw.disks.length+" "+
       plural(zw.disks.length,"диске","дисках","дисках"),c:zwCmd()},
   {t:"Проверить состояние пула",c:"zpool status "+zw.name}
  ].forEach(function(s,i){
    h+="<div class=\"planrow\"><div class=\"pn\">"+(i+1)+"</div><div>"+
       "<div class=\"pt\">"+wizEsc(s.t)+"</div>"+
       "<div class=\"pc\">"+wizEsc(s.c)+"</div></div></div>";
  });
  h+="</div><div class=\"wizerr\">Диски "+wizEsc(zw.disks.join(", "))+
     " будут безвозвратно стёрты.</div>";
  h+="<div class=\"cfmbox\"><div class=\"ct\">Для запуска введите имя пула "+
     "<b class=\"cw\">"+wizEsc(zw.name)+"</b> в поле ниже:</div>"+
     "<input class=\"wizinp\" id=\"zw-confirm\" value=\""+wizEsc(zw.confirm)+
     "\" placeholder=\"подтверждение\" style=\"flex:none;width:230px\" "+
     "autocomplete=\"off\"></div>";
  return h;
}
function zwBodyResult(){
  if(zw.busy) return "<div class=\"wizhint\">Создание пула ZFS… не закрывайте окно.</div>";
  var r=zw.result;
  if(!r) return "<div class=\"wizhint\">Нет результата.</div>";
  if(r.error) return "<div class=\"wizerr\">"+wizEsc(r.error)+"</div>";
  var h=(r.ok?"<div class=\"wizok\">&#10003; "+wizEsc(r.msg)+"</div>"
             :"<div class=\"wizerr\">&#9888; "+wizEsc(r.msg)+"</div>");
  (r.results||[]).forEach(function(s){
    h+="<div class=\"resrow "+(s.ok?"ok":"bad")+"\"><div class=\"rt\">"+
       (s.ok?"&#10003; ":"&#10007; ")+wizEsc(s.title)+"</div>";
    if(s.cmd) h+="<div class=\"ro\">$ "+wizEsc(s.cmd)+"</div>";
    if(s.out) h+="<div class=\"ro\">"+wizEsc(s.out)+"</div>";
    if(s.err) h+="<div class=\"ro re\">"+wizEsc(s.err)+"</div>";
    h+="</div>";
  });
  return h;
}
function zwBind(){
  document.querySelectorAll(".actcard[data-zwmode]").forEach(function(c){
    c.onclick=function(){
      zwReadInputs(); zw.mode=c.getAttribute("data-zwmode"); zw.err=""; zwRender();
    };
  });
  document.querySelectorAll(".pick[data-zwdisk]").forEach(function(p){
    p.onclick=function(){
      zwReadInputs();
      var x=p.getAttribute("data-zwdisk"), i=zw.disks.indexOf(x);
      if(i>=0) zw.disks.splice(i,1); else zw.disks.push(x);
      zw.err=""; zwRender();
    };
  });
  var b;
  if(b=el("zw-name")) b.oninput=function(){ zw.name=this.value.trim(); };
  if(b=el("zw-confirm")) b.oninput=function(){ zw.confirm=this.value; zwFooter(); };
}
function zwFooter(){
  var h="";
  if(zw.step===3){
    h="<div class=\"sp\"></div>"+(zw.busy?"":
       "<button class=\"wzb pri\" id=\"zw-done\">Закрыть</button>");
  } else if(zw.step===2){
    h="<button class=\"wzb\" id=\"zw-back\">Назад</button>"+
      "<div class=\"sp\"></div><button class=\"wzb\" id=\"zw-cancel\">Отмена</button>";
    var ready=(zw.name&&zw.confirm===zw.name&&!zw.busy);
    h+="<button class=\"wzb dng\" id=\"zw-apply\""+(ready?"":" disabled")+
       ">Создать пул</button>";
  } else {
    h="<div class=\"sp\"></div><button class=\"wzb\" id=\"zw-cancel\">Отмена</button>"+
      "<button class=\"wzb pri\" id=\"zw-next\">Далее</button>";
  }
  el("zwft").innerHTML=h;
  var b;
  if(b=el("zw-back")) b.onclick=function(){
    zwReadInputs(); zw.step=1; zw.err=""; zwRender();
  };
  if(b=el("zw-cancel")) b.onclick=zwClose;
  if(b=el("zw-done")) b.onclick=function(){ zwClose(); tickOverview(); };
  if(b=el("zw-next")) b.onclick=zwNext;
  if(b=el("zw-apply")) b.onclick=zwApply;
}
function zwNext(){
  zwReadInputs();
  var err=zwValidate();
  if(err){ zw.err=err; zwRender(); return; }
  zw.err=""; zw.confirm=""; zw.step=2; zwRender();
}
function zwApply(){
  zwReadInputs();
  if(!zw||zw.confirm!==zw.name) return;
  var err=zwValidate();
  if(err){ zw.err=err; zw.step=1; zwRender(); return; }
  zw.busy=true; zw.result=null; zw.step=3; zwRender();
  fetch("/api/zfs/create",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({name:zw.name,mode:zw.mode,disks:zw.disks,
                         confirm:zw.confirm})})
    .then(function(r){return r.json();})
    .then(function(d){ zw.busy=false; zw.result=d; zwRender(); })
    .catch(function(e){
      zw.busy=false; zw.result={error:"Ошибка связи с сервером: "+e}; zwRender();
    });
}
el("zw-open").addEventListener("click",zwOpen);
el("zwclose").addEventListener("click",zwClose);
el("zwmask").addEventListener("click",function(e){
  if(e.target===this&&zw&&!zw.busy) zwClose();
});

/* ===== Управление кэшем ZFS ARC ===== */
var cc=null;
function ccOpen(){
  cc={info:null,busy:false,result:null,err:"",val:"",unit:"GiB"};
  el("ccmask").style.display="flex";
  el("ccbody").innerHTML="<div class=\"wizhint\">Загрузка состояния кэша…</div>";
  el("ccft").innerHTML="";
  fetch("/api/zfs/cache",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){ cc.info=d; ccInit(); ccRender(); })
    .catch(function(e){
      el("ccbody").innerHTML="<div class=\"wizerr\">Не удалось загрузить "+
        "состояние кэша: "+e+"</div>";
    });
}
function ccClose(){ if(cc&&cc.busy) return; el("ccmask").style.display="none"; cc=null; }
function ccInit(){
  var i=cc.info||{}, cur=i.arc_max_runtime||i.c_max||0;
  if(cur>=1073741824){
    var g=cur/1073741824;
    cc.val=String(g%1?g.toFixed(1):g.toFixed(0)); cc.unit="GiB";
  } else {
    cc.val=String(Math.max(128,Math.round(cur/1048576))); cc.unit="MiB";
  }
}
function ccBytes(){
  var v=parseFloat(String(cc.val).replace(",","."));
  if(isNaN(v)||v<=0) return 0;
  return Math.round(v*(cc.unit==="GiB"?1073741824:1048576));
}
function ccValid(){
  var b=ccBytes(), i=cc.info||{};
  return i.present!==false&&b>=(i.min_allowed||0)&&b<=(i.max_allowed||0);
}
function ccBodyForm(){
  var i=cc.info||{};
  if(i.present===false)
    return "<div class=\"wizerr\">Кэш ZFS ARC недоступен — модуль ZFS не "+
           "загружен или статистика arcstats отсутствует.</div>";
  var eff=i.arc_max_runtime||i.c_max||0;
  var h="<div class=\"wizgrp\"><div class=\"gl\">Текущее состояние</div>"+
    "<div class=\"wizhint\" style=\"line-height:2\">"+
    "Занято кэшем сейчас: <b>"+hb(i.size)+"</b><br>"+
    "Действующий максимум ARC: <b>"+hb(eff)+"</b>"+
      (i.arc_max_runtime?"":" (авто)")+"<br>"+
    "В конфиге zfs.conf: <b>"+
      (i.arc_max_persist?hb(i.arc_max_persist):"не задан")+"</b><br>"+
    "Всего ОЗУ на узле: <b>"+hb(i.total_ram)+"</b></div></div>";
  h+="<div class=\"wizgrp\"><div class=\"gl\">Новый максимум кэша ARC</div>"+
     "<div class=\"wizfld\"><label>Размер кэша</label>"+
     "<input class=\"wizinp\" id=\"cc-val\" value=\""+wizEsc(cc.val)+
       "\" style=\"flex:none;width:110px\" autocomplete=\"off\">"+
     "<select class=\"wizsel\" id=\"cc-unit\" style=\"flex:none;width:84px\">"+
       "<option"+(cc.unit==="MiB"?" selected":"")+">MiB</option>"+
       "<option"+(cc.unit==="GiB"?" selected":"")+">GiB</option>"+
     "</select><span id=\"cc-eff\" style=\"margin-left:8px;font-size:12px\"></span>"+
     "</div>"+
     "<div class=\"wizhint\" style=\"margin-left:180px\">допустимый диапазон "+
       "128 MiB – 256 GiB</div>"+
     "<div style=\"margin:9px 0 0 180px;display:flex;gap:6px;flex-wrap:wrap\">";
  [["256","MiB"],["512","MiB"],["1","GiB"],["4","GiB"],["16","GiB"],
   ["64","GiB"]].forEach(function(p){
    h+="<span class=\"tagchip\" style=\"cursor:pointer;padding:3px 9px\" "+
       "data-ccpreset=\""+p[0]+"|"+p[1]+"\">"+p[0]+"&nbsp;"+p[1]+"</span>";
  });
  h+="</div></div>";
  h+="<div class=\"wizhint\">Новый максимум действует сразу; запись в "+
     "/etc/modprobe.d/zfs.conf вступит в силу после следующей загрузки "+
     "модуля ZFS (перезагрузка узла).</div>";
  return h;
}
function ccBodyResult(){
  var r=cc.result;
  if(!r) return "";
  if(r.error) return "<div class=\"wizerr\">"+wizEsc(r.error)+"</div>";
  var h=(r.ok?"<div class=\"wizok\">&#10003; "+wizEsc(r.msg)+"</div>"
             :"<div class=\"wizerr\">&#9888; "+wizEsc(r.msg)+"</div>");
  (r.results||[]).forEach(function(s){
    h+="<div class=\"resrow "+(s.ok?"ok":"bad")+"\"><div class=\"rt\">"+
       (s.ok?"&#10003; ":"&#10007; ")+wizEsc(s.title)+"</div>";
    if(s.cmd) h+="<div class=\"ro\">$ "+wizEsc(s.cmd)+"</div>";
    if(s.out) h+="<div class=\"ro\">"+wizEsc(s.out)+"</div>";
    if(s.err) h+="<div class=\"ro re\">"+wizEsc(s.err)+"</div>";
    h+="</div>";
  });
  return h;
}
function ccUpdateEff(){
  var s=el("cc-eff"); if(!s) return;
  var b=ccBytes();
  if(!b){ s.textContent=""; }
  else if(!ccValid()){ s.style.color="var(--no)"; s.textContent="вне диапазона"; }
  else { s.style.color="var(--dim)"; s.textContent="= "+hb(b); }
  ccFooter();
}
function ccBind(){
  var b;
  if(b=el("cc-val")) b.oninput=function(){ cc.val=this.value; ccUpdateEff(); };
  if(b=el("cc-unit")) b.onchange=function(){ cc.unit=this.value; ccUpdateEff(); };
  document.querySelectorAll("[data-ccpreset]").forEach(function(c){
    c.onclick=function(){
      var p=c.getAttribute("data-ccpreset").split("|");
      cc.val=p[0]; cc.unit=p[1]; ccRender();
    };
  });
}
function ccFooter(){
  if(cc.busy){ el("ccft").innerHTML=""; return; }
  if(cc.result){
    el("ccft").innerHTML="<div class=\"sp\"></div>"+
      "<button class=\"wzb pri\" id=\"cc-done\">Закрыть</button>";
    var d=el("cc-done"); if(d) d.onclick=function(){ ccClose(); tickOverview(); };
    return;
  }
  var ok=ccValid();
  el("ccft").innerHTML="<div class=\"sp\"></div>"+
    "<button class=\"wzb\" id=\"cc-cancel\">Отмена</button>"+
    "<button class=\"wzb pri\" id=\"cc-apply\""+(ok?"":" disabled")+
    ">Применить</button>";
  var x;
  if(x=el("cc-cancel")) x.onclick=ccClose;
  if(x=el("cc-apply")) x.onclick=ccApply;
}
function ccRender(){
  if(!cc) return;
  var body;
  if(cc.busy) body="<div class=\"wizhint\">Применение настроек кэша… "+
    "не закрывайте окно.</div>";
  else if(cc.result) body=ccBodyResult();
  else body=ccBodyForm();
  el("ccbody").innerHTML=(cc.err?"<div class=\"wizerr\">"+wizEsc(cc.err)+
    "</div>":"")+body;
  if(!cc.busy&&!cc.result&&(cc.info||{}).present!==false){ ccBind(); ccUpdateEff(); }
  ccFooter();
}
function ccApply(){
  if(!cc||!ccValid()) return;
  var b=ccBytes();
  cc.busy=true; cc.err=""; cc.result=null; ccRender();
  fetch("/api/zfs/cache",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({confirm:"cache",bytes:b})})
    .then(function(r){return r.json();})
    .then(function(d){ cc.busy=false; cc.result=d; ccRender(); })
    .catch(function(e){
      cc.busy=false; cc.result={error:"Ошибка связи с сервером: "+e}; ccRender();
    });
}
el("cc-open").addEventListener("click",ccOpen);
el("ccclose").addEventListener("click",ccClose);
el("ccmask").addEventListener("click",function(e){
  if(e.target===this&&cc&&!cc.busy) ccClose();
});

/* ===== попап SMART диска ===== */
var sm=null;
function smOpen(disk){
  sm={disk:disk,info:null};
  el("smmask").style.display="flex";
  el("smtitle").textContent="SMART — диск "+disk;
  el("smbody").innerHTML="<div class=\"wizhint\">Чтение SMART-данных диска "+
    disk+"…</div>";
  el("smft").innerHTML="";
  fetch("/api/smart?disk="+encodeURIComponent(disk),{cache:"no-store"})
    .then(function(r){return r.json();})
    .then(function(d){ if(sm) sm.info=d; smRender(); })
    .catch(function(e){
      el("smbody").innerHTML="<div class=\"wizerr\">Не удалось получить "+
        "SMART-данные: "+e+"</div>";
      smFooter();
    });
}
function smClose(){ el("smmask").style.display="none"; sm=null; }
function smMetric(k,v,warn){
  return "<div class=\"smm"+(warn?" warn":"")+"\"><div class=\"smm-v\">"+v+
         "</div><div class=\"smm-k\">"+k+"</div></div>";
}
function smRender(){
  if(!sm) return;
  var d=sm.info||{};
  if(d.error){
    el("smbody").innerHTML="<div class=\"wizerr\">"+wizEsc(d.error)+"</div>";
    smFooter(); return;
  }
  var p=d.health_passed;
  var hc=p===true?"ok":(p===false?"no":"warn");
  var ht=p===true?"PASSED — диск исправен":
         (p===false?"FAILED — диск под угрозой":"состояние не определено");
  var h="<div class=\"smverdict "+hc+"\">"+
    "<span class=\"smv-dot dot "+hc+"\"></span><div>"+
    "<div class=\"smv-t\">SMART: "+ht+"</div>"+
    "<div class=\"smv-s\">"+wizEsc(d.model||"диск")+
      (d.serial?"  ·  S/N "+wizEsc(d.serial):"")+
      (d.firmware?"  ·  FW "+wizEsc(d.firmware):"")+"</div></div></div>";
  h+="<div class=\"smgrid\">"+
    smMetric("Температура",d.temperature!=null?d.temperature+" °C":"&mdash;",
             d.temperature!=null&&d.temperature>=55)+
    smMetric("Наработка",d.power_on_hours!=null?num(d.power_on_hours)+" ч":"&mdash;",
             false)+
    smMetric("Включений",d.power_cycles!=null?num(d.power_cycles):"&mdash;",false)+
    smMetric("Тип",d.is_ssd?"SSD":(d.rotation?num(d.rotation)+" rpm":"&mdash;"),
             false)+"</div>";
  var at=d.attributes||[];
  if(at.length){
    h+="<div class=\"lbl\" style=\"margin-top:14px\">SMART-атрибуты"+
       (d.nvme?" (NVMe health log)":"")+"</div>";
    h+="<div class=\"panel\" style=\"padding:0;overflow:hidden\">"+
       "<table class=\"smtbl\"><tr><th>ID</th><th>Атрибут</th><th>Знач.</th>"+
       "<th>Худш.</th><th>Порог</th><th>Raw</th></tr>";
    at.forEach(function(a){
      var rawn=parseInt(a.raw,10);
      var bad=(a.when_failed&&a.when_failed!=="-"&&a.when_failed!=="")||
              (a.crit&&!isNaN(rawn)&&rawn>0);
      h+="<tr"+(bad?" class=\"smbad\"":"")+">"+
         "<td>"+(a.id!=null?a.id:"&mdash;")+"</td>"+
         "<td>"+wizEsc(a.name||"")+"</td>"+
         "<td>"+(a.value!=null?a.value:"&mdash;")+"</td>"+
         "<td>"+(a.worst!=null?a.worst:"&mdash;")+"</td>"+
         "<td>"+(a.thresh!=null?a.thresh:"&mdash;")+"</td>"+
         "<td>"+(a.raw!=null?wizEsc(String(a.raw)):"&mdash;")+"</td></tr>";
    });
    h+="</table></div>";
  } else {
    h+="<div class=\"wizhint\" style=\"margin-top:12px\">"+
       "Таблица SMART-атрибутов недоступна для этого устройства."+
       (d.messages&&d.messages.length?"<br>smartctl: "+
         wizEsc(d.messages.join("; ")):"")+"</div>";
  }
  el("smbody").innerHTML=h;
  smFooter();
}
function smFooter(){
  el("smft").innerHTML="<div class=\"sp\"></div>"+
    "<button class=\"wzb\" id=\"sm-refresh\">Обновить</button>"+
    "<button class=\"wzb pri\" id=\"sm-done\">Закрыть</button>";
  var b;
  if(b=el("sm-refresh")) b.onclick=function(){ if(sm) smOpen(sm.disk); };
  if(b=el("sm-done")) b.onclick=smClose;
}
el("smclose").addEventListener("click",smClose);
el("smmask").addEventListener("click",function(e){
  if(e.target===this) smClose();
});

/* ===== вкладка «Кластер» — обзор узлов ===== */
function esc(s){
  return String(s==null?"":s).replace(/&/g,"&amp;")
    .replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function fmtUptime(s){
  if(s==null) return "&mdash;";
  s=+s;
  var d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  if(d>0) return d+" д "+h+" ч";
  if(h>0) return h+" ч "+m+" мин";
  return m+" мин";
}
function clSvChip(label, ok){
  return "<span class=\"svchip "+(ok?"on":"no")+"\">"+
         (ok?"●":"○")+" "+label+"</span>";
}
function clCard(n){
  var on=!!n.online, self=!!n.self;
  var cls="clcard "+(self?"self":(on?"on":"off"));
  var role=n.role||"";
  var roleCls=role==="master"?"master":(role==="worker"?"worker":
              (role==="unconfigured"?"unconf":""));
  var roleTxt=role==="master"?"master":(role==="worker"?"worker":
              (role==="unconfigured"?"не настроен":(role||"&mdash;")));
  var h="<div class=\""+cls+"\"><div class=\"clhd\">";
  h+="<span class=\"nm\">"+esc(n.hostname||n.ip)+"</span>";
  if(self) h+="<span class=\"clrole master\">этот узел</span>";
  h+="<span class=\"clrole "+roleCls+"\">"+roleTxt+"</span>";
  h+="<span class=\"clstate "+(on?"on":"off")+"\"><span class=\"dot "+
     (on?"ok":"no")+"\"></span>"+(on?"online":"offline")+"</span></div>";
  h+="<div class=\"ip\">"+esc(n.ip)+"</div>";
  if(!on){
    h+="<div class=\"cloff\"><b>Агент PROXOMATRON не отвечает.</b><br>"+
       (n.error?("Причина: "+esc(n.error)):"Узел недоступен по сети.")+
       "<br>Запустите PROXOMATRON на узле или проверьте связь.</div></div>";
    return h;
  }
  h+="<div class=\"clsvc\">"+clSvChip("etcd",n.etcd_local)+
     clSvChip("monitor",n.mon_local)+clSvChip("vitastor-cli",n.installed)+
     clSvChip("vitastor.conf",n.conf_exists)+"</div>";
  var st=n.stats||{};
  var osds=(n.osds||[]).length, up=+n.osds_up||0;
  var fd=(n.free_disks||[]).length;
  h+="<div class=\"clmet\">";
  h+="<div class=\"m\"><div class=\"mv\">"+up+" / "+osds+"</div>"+
     "<div class=\"mk\">OSD активно</div></div>";
  h+="<div class=\"m\"><div class=\"mv\">"+fd+"</div>"+
     "<div class=\"mk\">свободных дисков</div></div>";
  h+="<div class=\"m\"><div class=\"mv\" style=\"font-size:13px\">"+
     fmtUptime(st.uptime)+"</div><div class=\"mk\">аптайм</div></div></div>";
  if(st.load&&st.cores){
    var la=+st.load[0], pct=Math.min(la/st.cores*100,100);
    var lc=pct>90?"no":(pct>65?"warn":"");
    h+="<div class=\"clbar\"><i class=\""+lc+"\" style=\"width:"+
       pct.toFixed(0)+"%\"></i></div>";
    h+="<div class=\"clbarm\"><span>CPU load "+la.toFixed(2)+"</span><span>"+
       st.cores+" "+plural(st.cores,"ядро","ядра","ядер")+"</span></div>";
  }
  if(st.mem_total){
    var mp=st.mem_used/st.mem_total*100;
    var mc=mp>90?"no":(mp>78?"warn":"");
    h+="<div class=\"clbar\"><i class=\""+mc+"\" style=\"width:"+
       mp.toFixed(0)+"%\"></i></div>";
    h+="<div class=\"clbarm\"><span>RAM "+hb(st.mem_used)+" / "+
       hb(st.mem_total)+"</span><span>"+mp.toFixed(0)+"%</span></div>";
  }
  h+="</div>";
  return h;
}
function renderCluster(d){
  var box=el("cluster"); if(!box) return;
  if(!d||d.error){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9888;</div>"+
      "<div class=\"et\">Сводка кластера недоступна</div>"+
      "<div class=\"ed\">"+esc((d&&d.error)||"нет данных")+"</div></div>";
    return;
  }
  var nodes=d.nodes||[];
  if(!nodes.length){
    box.innerHTML="<div class=\"emptybox\"><div class=\"ei\">&#9776;</div>"+
      "<div class=\"et\">Узлы кластера не обнаружены</div>"+
      "<div class=\"ed\">Добавьте узлы через Мастер кластера.</div></div>";
    return;
  }
  var totOsd=0, upOsd=0;
  nodes.forEach(function(n){
    totOsd+=(n.osds||[]).length; upOsd+=(+n.osds_up||0);
  });
  var h="<div class=\"clsum\">";
  h+="<div class=\"stat\"><div class=\"k\">Узлов в кластере</div>"+
     "<div class=\"v\">"+(d.total||nodes.length)+"</div>"+
     "<div class=\"s\">"+(d.online||0)+" online</div></div>";
  h+="<div class=\"stat\"><div class=\"k\">OSD активно</div>"+
     "<div class=\"v\">"+upOsd+" / "+totOsd+"</div></div>";
  h+="<div class=\"stat\"><div class=\"k\">Главный узел</div>"+
     "<div class=\"v\" style=\"font-size:14px\">"+esc(d.master||"—")+"</div></div>";
  h+="</div><div class=\"clgrid\">";
  nodes.forEach(function(n){ h+=clCard(n); });
  h+="</div>";
  box.innerHTML=h;
}
var clTabTimer=null;
function clTabVisible(){
  return el("view-vitastor").classList.contains("active") &&
         el("vtab-cluster").classList.contains("active");
}
function tickCluster(){
  if(!clTabVisible()) return;
  fetch("/api/cluster/overview",{cache:"no-store"})
    .then(function(r){return r.json();})
    .then(function(d){ lastOk=Date.now(); renderCluster(d); })
    .catch(function(e){ renderCluster({error:"нет связи с API: "+e}); })
    .then(function(){
      if(clTabTimer) clearTimeout(clTabTimer);
      if(clTabVisible()) clTabTimer=setTimeout(tickCluster,7000);
    });
}

/* ---- циклы ---- */
var lastOk=0, lastOverview=null;
function tickOverview(){
  fetch("/api/overview",{cache:"no-store"}).then(function(r){return r.json();}).then(function(d){
    lastOk=Date.now(); lastOverview=d;
    var b=el("banner"), errs=(d.vitastor&&d.vitastor.errors)||[];
    var vt=d.vitastor||{};
    var vinst=(vt.installed!==false)&&!(vt.cp&&vt.cp.conf===false);
    if(errs.length&&vinst){ b.style.display="block"; b.textContent="vitastor-cli: "+errs.join("; "); }
    else b.style.display="none";
    renderVitastor(d.vitastor); renderZfs(d.zfs); renderCeph(d.ceph);
    if(el("view-settings").classList.contains("active")) renderSettings();
  }).catch(function(e){
    var b=el("banner"); b.style.display="block"; b.textContent="Нет связи с API: "+e;
  });
}
/* ===== страницы Узла ===== */
function renderHost(subview){
  var sub = subview || "monitor";
  if(sub==="resources") sub="monitor"; // миграция: старое имя
  var titles = {
    sysinfo:"Системная информация", monitor:"Системный монитор",
    vmct:"VM / CT", cluster:"Кластер PVE"
  };
  var t = el("hostTitle"); if(t) t.innerHTML = "Узел &mdash; " + (titles[sub]||"обзор");
  document.querySelectorAll("#view-host .host-sect").forEach(function(s){
    s.style.display = (s.getAttribute("data-sub")===sub) ? "" : "none";
  });
  // Останавливаем sysmon-poller, если ушли с monitor
  if(sub!=="monitor" && _sysmon && _sysmon.timer){
    clearInterval(_sysmon.timer); _sysmon.timer=null;
  }
  var renderers = {
    sysinfo:renderHostSysinfo, monitor:renderHostMonitor,
    vmct:renderHostVmct, cluster:renderHostCluster
  };
  var fn = renderers[sub]; if(fn) fn();
}
function _hostFetch(url, into, render){
  fetch(url, {cache:"no-store"}).then(function(r){return r.json();})
    .then(render)
    .catch(function(e){
      var t=el(into); if(t) t.innerHTML='<div class="err">ошибка: '+esc(String(e))+'</div>';
    });
}
function fmtBytesKiB(kib){
  if(kib==null) return "&mdash;";
  var n=+kib;
  if(n>=1024*1024) return (n/(1024*1024)).toFixed(2)+" GiB";
  if(n>=1024) return (n/1024).toFixed(1)+" MiB";
  return n+" KiB";
}
function renderHostSysinfo(){
  _hostFetch("/api/host/sysinfo", "host-sysinfo", function(d){
    var ut = (d.uptime_secs!=null) ? (fmtUptime(d.uptime_secs)+
      ' <span class="dim">('+esc(d.uptime_pretty||"")+')</span>') : esc(d.uptime_pretty||"?");
    var bt = "";
    if(d.boot_epoch){ try{ bt = new Date(d.boot_epoch*1000).toISOString().replace("T"," ").substring(0,19)+" UTC"; }catch(e){} }
    var h='<table class="kvtbl">'+
      '<tr><th>Hostname</th><td><b>'+esc(d.hostname)+'</b></td></tr>'+
      '<tr><th>OS</th><td>'+esc(d.os)+'</td></tr>'+
      '<tr><th>Kernel</th><td>'+esc(d.kernel)+' &middot; '+esc(d.arch)+'</td></tr>'+
      '<tr><th>Proxmox VE</th><td><pre>'+esc(d.pve_version)+'</pre></td></tr>'+
      '<tr><th>Uptime</th><td>'+ut+'</td></tr>'+
      (bt?('<tr><th>Boot time</th><td><span class="dim">'+esc(bt)+'</span></td></tr>'):'')+
      '</table>';
    el("host-sysinfo").innerHTML = h;
  });
}
function _pct(used, total){
  if(!total) return 0; return Math.max(0, Math.min(100, Math.round(used/total*100)));
}
function _bar(pct){
  var cls = pct>=90?" err":(pct>=75?" warn":"");
  return '<div class="progress"><span class="'+cls.trim()+'" style="width:'+pct+'%"></span></div>'+pct+'%';
}
/* ===== Системный монитор (Win10 Task Manager-style 3-column) ===== */
var _sysmon = {
  selected: "cpu",
  timer: null,
  data: null,           // последний /api/host/monitor
  dm: null,             // последний /api/diskmon
  hist: {               // история значений (макс 60 точек)
    cpu: [], cores: [], gpu: [],
    mem_used: [], mem_swap: [], mem_arc: [],
    pwr: [],
    disks: {},          // {sda: {util:[], rw:[]}}
    nets:  {},          // {ens18: {tot:[], rx:[], tx:[]}}
  }
};
function _h60(arr, v){ arr.push(v==null?0:+v); while(arr.length>60) arr.shift(); return arr; }
function fmtBpsShort(b){
  if(b==null||!isFinite(b)) return "0 B/s";
  var n=+b;
  if(n>=1e9) return (n/1e9).toFixed(2)+" GB/s";
  if(n>=1e6) return (n/1e6).toFixed(1)+" MB/s";
  if(n>=1e3) return (n/1e3).toFixed(1)+" KB/s";
  return Math.round(n)+" B/s";
}
function fmtBitsShort(b){
  if(b==null||!isFinite(b)) return "0 bps";
  var n=+b*8;
  if(n>=1e9) return (n/1e9).toFixed(2)+" Gbps";
  if(n>=1e6) return (n/1e6).toFixed(1)+" Mbps";
  if(n>=1e3) return (n/1e3).toFixed(1)+" Kbps";
  return Math.round(n)+" bps";
}
function fmtBytesB(b){
  if(b==null||!isFinite(b)) return "0 B";
  var n=+b;
  if(n>=1099511627776) return (n/1099511627776).toFixed(2)+" TiB";
  if(n>=1073741824)    return (n/1073741824).toFixed(2)+" GiB";
  if(n>=1048576)       return (n/1048576).toFixed(1)+" MiB";
  if(n>=1024)          return (n/1024).toFixed(1)+" KiB";
  return Math.round(n)+" B";
}
function fmtSecsHMS(s){
  if(s==null) return "—";
  s=Math.floor(+s);
  var d=Math.floor(s/86400), h=Math.floor(s%86400/3600),
      m=Math.floor(s%3600/60), ss=s%60;
  function p(n){return n<10?'0'+n:n;}
  return p(d)+':'+p(h)+':'+p(m)+':'+p(ss);
}
function fmtFreqGHz(mhz){
  if(mhz==null) return "—";
  if(mhz>=1000) return (mhz/1000).toFixed(2)+" ГГц";
  return mhz+" МГц";
}
function _pushSysmonHist(h, dm){
  var hh=_sysmon.hist;
  // CPU
  _h60(hh.cpu, h.cpu && h.cpu.pct);
  // per-core
  if(h.cpu && h.cpu.per_core_pct){
    while(hh.cores.length < h.cpu.per_core_pct.length) hh.cores.push([]);
    h.cpu.per_core_pct.forEach(function(p,i){ _h60(hh.cores[i], p); });
  }
  // RAM used (KiB) — для отрисовки графика
  if(h.ram && h.ram.total_kib){
    var used = h.ram.total_kib - (h.ram.available_kib||0);
    _h60(hh.mem_used, used);
    var swUsed = (h.ram.swap_total_kib && h.ram.swap_free_kib!=null)
                  ? (h.ram.swap_total_kib - h.ram.swap_free_kib) : 0;
    _h60(hh.mem_swap, swUsed);
    _h60(hh.mem_arc, h.ram.arc_size_bytes || 0);
  }
  // GPU avg util
  var gU=0, gN=0;
  if(h.gpu && h.gpu.devices) h.gpu.devices.forEach(function(g){ gU+=g.util_pct; gN++; });
  _h60(hh.gpu, gN?Math.round(gU/gN):0);
  _h60(hh.pwr, h.power && h.power.watts);
  // Per-net
  if(h.net && h.net.rates){
    h.net.rates.forEach(function(r){
      var k = r.name;
      if(!hh.nets[k]) hh.nets[k] = {tot:[], rx:[], tx:[]};
      _h60(hh.nets[k].rx, r.rx_bps);
      _h60(hh.nets[k].tx, r.tx_bps);
      _h60(hh.nets[k].tot, r.rx_bps + r.tx_bps);
    });
  }
  // Per-disk (из /api/diskmon series)
  if(dm && dm.series){
    Object.keys(dm.series).forEach(function(name){
      var s = dm.series[name] || [];
      var last = s.length ? s[s.length-1] : null;
      if(!hh.disks[name]) hh.disks[name] = {util:[], rw:[]};
      _h60(hh.disks[name].util, last ? last.util : 0);
      _h60(hh.disks[name].rw,   last ? ((last.rbps||0)+(last.wbps||0)) : 0);
    });
  }
}
function renderHostMonitor(){
  var pane = el("host-monitor"); if(!pane) return;
  pane.innerHTML =
    '<div class="sysmonwrap">'+
      '<div class="sysmonlist" id="sysmonList">'+
        '<div class="ldhd"><span>Устройства</span></div>'+
      '</div>'+
      '<div class="sysmonchart" id="sysmonChart">'+
        '<div class="chdr"><h2 class="ctitle">Загрузка&hellip;</h2></div></div>'+
      '<div class="sysmonspecs" id="sysmonSpecs"></div>'+
    '</div>';
  if(_sysmon.timer) clearInterval(_sysmon.timer);
  _tickSysmon(); _sysmon.timer = setInterval(_tickSysmon, 2000);
}
function _tickSysmon(){
  var sect = document.querySelector("#view-host .host-sect[data-sub=\"monitor\"]");
  if(!el("host-monitor") || !sect || sect.style.display==="none"){
    if(_sysmon.timer){ clearInterval(_sysmon.timer); _sysmon.timer=null; }
    return;
  }
  Promise.all([
    fetch("/api/host/monitor",{cache:"no-store"}).then(function(r){return r.json();}),
    fetch("/api/diskmon",{cache:"no-store"}).then(function(r){return r.json();}).catch(function(){return null;})
  ]).then(function(arr){
    _sysmon.data = arr[0]; _sysmon.dm = arr[1];
    _pushSysmonHist(_sysmon.data, _sysmon.dm);
    _renderSysmonList();
    _renderSysmonDetail();
  }).catch(function(e){
    var ch=el("sysmonChart"); if(ch) ch.innerHTML='<div class="err">ошибка: '+esc(String(e))+'</div>';
  });
}
function _buildDevices(){
  // Динамический список устройств: CPU, GPU, MEM, per-disk, per-net, PWR
  var h = _sysmon.data || {}, dm = _sysmon.dm || {};
  var list = [];

  // CPU
  var cpu = h.cpu || {};
  var cpuFreq = (cpu.freq_mhz && cpu.freq_mhz.length
          ? fmtFreqGHz(Math.round(cpu.freq_mhz.reduce(function(a,b){return a+b;},0)/cpu.freq_mhz.length))
          : (cpu.base_freq_mhz ? fmtFreqGHz(cpu.base_freq_mhz) : ""));
  var cpuTemp = (cpu.temp_c!=null) ? (cpu.temp_c + " °C") : "";
  list.push({key:"cpu", kind:"cpu", color:"#28e0c4",
    nm:"ЦП",
    val: (cpu.pct!=null ? Math.round(cpu.pct)+"%" : "—"),
    sb: [cpuFreq, cpuTemp].filter(function(x){return !!x;}).join(" · "),
    series: _sysmon.hist.cpu, ymax:100});

  // GPU
  var gAvail = !!(h.gpu && h.gpu.available);
  var gU = null;
  if(gAvail && h.gpu.devices && h.gpu.devices.length){
    var u=0; h.gpu.devices.forEach(function(g){u+=g.util_pct;});
    gU = Math.round(u / h.gpu.devices.length);
  }
  list.push({key:"gpu", kind:"gpu", color:"#ff8a3d",
    nm:"ГП", val: (gU!=null ? gU+"%" : "0%"),
    sb: gAvail ? (h.gpu.devices[0].name||"") : "",
    series: _sysmon.hist.gpu, ymax:100, unav:!gAvail});

  // Memory
  var ram = h.ram || {};
  var memPct = null, memUsed = null;
  if(ram.total_kib){
    memUsed = ram.total_kib - (ram.available_kib||0);
    memPct = Math.round(memUsed / ram.total_kib * 100);
  }
  list.push({key:"mem", kind:"mem", color:"#a47bd0",
    nm:"Память",
    val: (memPct!=null ? memPct+"%" : "—"),
    sb: (ram.total_kib ? (fmtBytesB((memUsed||0)*1024)+" / "+fmtBytesB(ram.total_kib*1024)) : ""),
    series: _sysmon.hist.mem_used,
    ymax: ram.total_kib || null});

  // Per-disk tiles
  var disks = (dm && dm.disks) || [];
  disks.forEach(function(d, idx){
    var name = d.name;
    var hist = _sysmon.hist.disks[name] || {util:[], rw:[]};
    var util = hist.util.length ? hist.util[hist.util.length-1] : 0;
    var typ = (d.rota==="1") ? "HDD" : "SSD";
    var bus = (d.tran || "").toUpperCase() || "—";
    var dctr = ((dm.counters||{})[name]) || {};
    var dtemp = (dctr.temp_c!=null) ? (dctr.temp_c + " °C") : "";
    list.push({key:"disk:"+name, kind:"disk", color:"#5fd07b",
      nm:"Диск ("+idx+")",
      val: Math.round(util)+"%",
      sb: [typ + " · " + bus, dtemp].filter(function(x){return !!x;}).join(" · "),
      series: hist.util, ymax:100,
      disk_name: name, disk_info: d, disk_temp_c: dctr.temp_c});
  });

  // Per-net tiles — только физические/bond/bridge (без tap/veth/fwbr/lo)
  var rates = (h.net && h.net.rates) || [];
  rates.forEach(function(r){
    var n = r.name;
    if(/^(lo|tap|veth|fwbr|fwln|fwpr)/.test(n)) return;
    var hist = _sysmon.hist.nets[n] || {tot:[], rx:[], tx:[]};
    list.push({key:"net:"+n, kind:"net", color:"#b266ff",
      nm: n,
      val: fmtBpsShort(r.rx_bps + r.tx_bps),
      sb: "S: "+fmtBitsShort(r.tx_bps)+"   R: "+fmtBitsShort(r.rx_bps),
      series: hist.tot, ymax:null,
      net_name: n, net_rate: r});
  });

  // Power (если доступен)
  if(h.power && h.power.available){
    list.push({key:"pwr", kind:"pwr", color:"#c79bd6",
      nm:"Питание",
      val: (h.power.watts!=null ? h.power.watts+" W" : "—"),
      sb: "Intel RAPL",
      series: _sysmon.hist.pwr, ymax:null});
  }
  return list;
}
function _renderSysmonList(){
  var devs = _buildDevices();
  // Если выбранный девайс пропал — переключаемся на CPU
  if(!devs.some(function(d){return d.key === _sysmon.selected;})){
    _sysmon.selected = "cpu";
  }
  var listEl = el("sysmonList");
  var h = '<div class="ldhd"><span>Устройства</span></div>';
  devs.forEach(function(d){
    var cls = "sysmonitem k-" + d.kind +
              (d.key === _sysmon.selected ? " active" : "") +
              (d.unav ? " unav" : "");
    h += '<div class="'+cls+'" data-key="'+esc(d.key)+'">'+
      '<div class="spr"><canvas id="spk-'+esc(d.key).replace(/:/g,"-")+'"></canvas></div>'+
      '<div class="info">'+
        '<div class="nm"><span class="dot" style="background:'+d.color+'"></span>'+esc(d.nm)+'</div>'+
        '<div class="vl">'+d.val+'</div>'+
        '<div class="sb">'+esc(d.sb||"")+'</div>'+
      '</div></div>';
  });
  listEl.innerHTML = h;
  devs.forEach(function(d){
    var cv = el("spk-"+d.key.replace(/:/g,"-"));
    if(cv) drawArea(cv, d.series, d.color, d.ymax, true);
  });
  document.querySelectorAll(".sysmonitem").forEach(function(node){
    node.onclick = function(){
      _sysmon.selected = node.getAttribute("data-key");
      _renderSysmonList(); _renderSysmonDetail();
    };
  });
}
function _bigPaneHTML(id, title, max, color){
  return '<div class="bigpane">'+
    '<div class="bhdr"><span>'+title+'</span><span class="bmax">'+max+'</span></div>'+
    '<div class="bcvbox"><canvas class="bcv" id="'+id+'"></canvas></div>'+
    '<div class="bfoot"><span>60 секунд назад</span><span>0</span></div>'+
  '</div>';
}
function _drawBcv(id, series, color, ymax){
  var c = el(id); if(!c) return;
  drawArea(c, series, color, ymax, true);
}
function _specRow(label, value){
  return '<div class="srow"><div class="sl">'+label+'</div><div class="sv">'+value+'</div></div>';
}
function _renderSysmonDetail(){
  var devs = _buildDevices();
  var dev = null;
  for(var i=0;i<devs.length;i++) if(devs[i].key === _sysmon.selected){ dev=devs[i]; break; }
  if(!dev){ return; }
  el("sysmonChart").className = "sysmonchart k-" + dev.kind;
  if(dev.kind==="cpu")  return _renderSmCPU(dev);
  if(dev.kind==="gpu")  return _renderSmGPU(dev);
  if(dev.kind==="mem")  return _renderSmMem(dev);
  if(dev.kind==="disk") return _renderSmDisk(dev);
  if(dev.kind==="net")  return _renderSmNet(dev);
  if(dev.kind==="pwr")  return _renderSmPwr(dev);
}
function _renderSmCPU(dev){
  var d = _sysmon.data || {}; var c = d.cpu || {};
  var pct = c.pct==null ? 0 : c.pct;
  var nCores = (c.per_core_pct||[]).length || c.cores || 1;
  // grid columns: 1 если ≤4 ядер, 2 если ≤16, 4 иначе
  var cols = nCores <= 4 ? 1 : (nCores <= 16 ? 2 : 4);
  var rows = Math.ceil(nCores / cols);
  var coreCells = "";
  for(var i=0;i<nCores;i++){
    coreCells += '<div class="corecell"><canvas id="cc-'+i+'"></canvas></div>';
  }
  var chart =
    '<div class="cpubox"><div class="cpubar"><div class="lbl">ЦП</div>'+
      '<div class="bar"><span style="height:'+Math.round(pct)+'%"></span></div>'+
      '<div class="v">'+Math.round(pct)+'%</div></div>'+
      '<div class="bcvbox" style="position:relative">'+
        '<div class="coreghdr"><span>Загрузка по ядрам за 60 секунд</span>'+
        '<span>100% / ядро</span></div>'+
        '<div class="coregrid" style="grid-template-columns:repeat('+cols+',1fr);'+
          'grid-template-rows:repeat('+rows+',1fr);height:280px">'+coreCells+'</div>'+
      '</div></div>';

  el("sysmonChart").innerHTML =
    '<div class="chdr">'+
      '<h2 class="ctitle">ЦП</h2>'+
      '<div class="cmodel">'+esc(c.model||"")+'</div>'+
      '<div class="crange">1 минута</div>'+
    '</div>'+
    chart;
  // отрисуем per-core
  (c.per_core_pct||[]).forEach(function(_, i){
    var cv=el("cc-"+i); if(!cv) return;
    drawArea(cv, _sysmon.hist.cores[i]||[], "#28e0c4", 100, true);
  });
  // правая колонка
  var freqAvg = (c.freq_mhz && c.freq_mhz.length)
    ? Math.round(c.freq_mhz.reduce(function(a,b){return a+b;},0)/c.freq_mhz.length) : null;
  var hs =
    _specRow("Использование", '<span style="color:'+dev.color+'">'+(Math.round(pct))+' %</span>')+
    _specRow("Скорость", fmtFreqGHz(freqAvg))+
    _specRow("Температура", (c.temp_c!=null?(c.temp_c+" °C"):"—"))+
    _specRow("Процессы", (c.proc_count!=null?c.proc_count:"—"))+
    _specRow("Потоки", (c.thread_count!=null?c.thread_count:"—"))+
    _specRow("Время работы", (c.uptime_secs!=null?fmtSecsHMS(c.uptime_secs):"—"))+
    '<div class="sgrp">Спецификации</div>'+
    _specRow("Базовая скорость", fmtFreqGHz(c.base_freq_mhz))+
    _specRow("Сокеты", (c.sockets||1))+
    _specRow("Ядра", (c.cores||"—"))+
    _specRow("Виртуальные процессоры", (c.cores||"—"))+
    _specRow("Виртуализация", esc(c.vm_vendor||"—"));
  el("sysmonSpecs").innerHTML = hs;
}
function _renderSmMem(dev){
  var d = _sysmon.data || {}; var m = d.ram || {};
  var totB = (m.total_kib||0)*1024;
  var avB  = (m.available_kib!=null) ? m.available_kib*1024 : 0;
  var usedB = totB - avB;
  var cachedB = (m.cached_kib||0)*1024;
  var freeB = (m.free_kib||0)*1024;
  var pct = totB ? Math.round(usedB/totB*100) : 0;
  var swTotB = (m.swap_total_kib||0)*1024;
  var swUsedB = swTotB - ((m.swap_free_kib||0)*1024);
  var arcB = m.arc_size_bytes || 0;
  var arcMaxB = m.arc_max_bytes || null;
  var arcOk = !!m.arc_available;
  var commB = (m.committed_kib||0)*1024;

  var arcMaxLabel = arcMaxB ? fmtBytesB(arcMaxB)
                            : (arcOk ? fmtBytesB(arcB) : "—");
  el("sysmonChart").innerHTML =
    '<div class="chdr">'+
      '<h2 class="ctitle">Память</h2>'+
      '<div class="cmodel"></div>'+
      '<div class="crange">'+fmtBytesB(totB)+'</div>'+
    '</div>'+
    _bigPaneHTML("bcv-mem","Использование памяти за 60 секунд", fmtBytesB(totB), dev.color)+
    _bigPaneHTML("bcv-swap","Использование подкачки за 60 секунд",
                 (swTotB?fmtBytesB(swTotB):"—"), "#5fd07b")+
    _bigPaneHTML("bcv-arc",
                 (arcOk ? "ZFS ARC cache за 60 секунд" : "ZFS ARC cache (модуль не загружен)"),
                 arcMaxLabel, "#38bdf8");
  _drawBcv("bcv-mem", _sysmon.hist.mem_used, dev.color, m.total_kib);
  _drawBcv("bcv-swap", _sysmon.hist.mem_swap, "#5fd07b", m.swap_total_kib || null);
  _drawBcv("bcv-arc", _sysmon.hist.mem_arc, "#38bdf8", arcMaxB || null);

  // memstruct: used (colored), cached, free
  var pu = totB ? Math.round((usedB-cachedB)/totB*100) : 0;  // только anon
  var pc = totB ? Math.round(cachedB/totB*100) : 0;
  var pf = Math.max(0, 100 - pu - pc);

  el("sysmonSpecs").innerHTML =
    _specRow("Используется", fmtBytesB(usedB))+
    _specRow("Доступно", fmtBytesB(avB))+
    _specRow("Кэшировано", fmtBytesB(cachedB))+
    _specRow("ZFS ARC", (arcOk
              ? (fmtBytesB(arcB) + (arcMaxB?(' <span class="u">/ '+fmtBytesB(arcMaxB)+'</span>'):''))
              : '<span class="u">недоступен</span>'))+
    _specRow("Выделено", (commB?fmtBytesB(commB):"—"))+
    _specRow("Загрузка", pct+' %')+
    '<div class="sgrp">Структура памяти</div>'+
    '<div class="memstruct">'+
      '<div class="seg" style="width:'+pu+'%;background:#5b9bd5"></div>'+
      '<div class="seg" style="width:'+pc+'%;background:#a47bd0"></div>'+
      '<div class="seg" style="width:'+pf+'%;background:#3a4250"></div>'+
    '</div>'+
    '<div class="legend">'+
      '<span class="lk"><span class="swat" style="background:#5b9bd5"></span>Используется</span>'+
      '<span class="lk"><span class="swat" style="background:#a47bd0"></span>Кэш</span>'+
      '<span class="lk"><span class="swat" style="background:#3a4250"></span>Свободно</span>'+
    '</div>'+
    '<div class="sgrp">Спецификации</div>'+
    _specRow("Скорость", "Неизвестно")+
    _specRow("Модулей", "—")+
    _specRow("Форм-фактор", "DIMM")+
    _specRow("Тип памяти", "RAM");
}
function _renderSmDisk(dev){
  var name = dev.disk_name;
  var info = dev.disk_info || {};
  var dm = _sysmon.dm || {};
  var ser = (dm.series||{})[name] || [];
  var last = ser.length ? ser[ser.length-1] : {};
  var rbps = last.rbps||0, wbps = last.wbps||0;
  var util = last.util||0;
  var hist = _sysmon.hist.disks[name] || {util:[], rw:[]};
  // Cumulative counters
  var ctr = ((dm.counters||{})[name]) || {};
  var totR = ctr.read_bytes||0, totW = ctr.write_bytes||0;
  var idx = ((_sysmon.dm && _sysmon.dm.disks)||[]).findIndex(function(x){return x.name===name;});
  var typ = (info.rota==="1") ? "HDD" : "SSD";
  var bus = (info.tran || "").toUpperCase() || "—";

  // Подсчёт avg response time: ioms / total_ios * 1000 = ms per io. Берём для последних 1 сек.
  var avgMs = 0;
  if(last && last.riops!=null){
    var ios = (last.riops||0)+(last.wiops||0);
    // util — это процент busy за период; не даёт ms. Простая оценка:
    avgMs = ios>0 ? (last.util/100/ios*1000).toFixed(2) : "0.00";
  }

  // Max bandwidth: фиксированная шкала 250→500→1000→2500→5000→10000→50000 MiB/s
  var bwMax = 0;
  hist.rw.forEach(function(v){ if(v>bwMax) bwMax=v; });
  function roundBw(b){
    var MiB = 1048576;
    var levels = [250*MiB, 500*MiB, 1000*MiB, 2500*MiB,
                  5000*MiB, 10000*MiB, 50000*MiB];
    for(var i=0;i<levels.length;i++) if(b <= levels[i]) return levels[i];
    return levels[levels.length-1];
  }
  bwMax = roundBw(bwMax);  // дефолт = 250 MiB/s когда трафика 0

  el("sysmonChart").innerHTML =
    '<div class="chdr">'+
      '<h2 class="ctitle">Диск ('+(idx<0?'?':idx)+')</h2>'+
      '<div class="cmodel">'+esc(info.model||"—")+'</div>'+
      '<div class="crange">1 минута</div>'+
    '</div>'+
    _bigPaneHTML("bcv-disku","Активное время за 60 секунд","100%",dev.color)+
    _bigPaneHTML("bcv-diskbw","Пропускная способность за 60 секунд",fmtBytesB(bwMax)+"/s","#5fd07b");
  _drawBcv("bcv-disku", hist.util, dev.color, 100);
  _drawBcv("bcv-diskbw", hist.rw, "#5fd07b", bwMax);

  el("sysmonSpecs").innerHTML =
    _specRow("Чтение", '<span style="color:'+dev.color+'">'+fmtBpsShort(rbps)+'</span>')+
    _specRow("Запись", '<span style="color:#5fd07b">'+fmtBpsShort(wbps)+'</span>')+
    _specRow("Всего прочитано", fmtBytesB(totR))+
    _specRow("Всего записано", fmtBytesB(totW))+
    _specRow("Активное время", util.toFixed(1)+' %')+
    _specRow("Среднее время отклика", avgMs+' ms')+
    _specRow("Температура", (ctr.temp_c!=null?(ctr.temp_c+" °C"):"—"))+
    '<div class="sgrp">Спецификации</div>'+
    _specRow("Ёмкость", (info.size?fmtBytesB(+info.size):"—"))+
    _specRow("Тип носителя", typ)+
    _specRow("Шина", bus)+
    _specRow("Системный диск", "—");
}
function _renderSmNet(dev){
  var d = _sysmon.data || {};
  var name = dev.net_name;
  var rate = dev.net_rate || {};
  var hist = _sysmon.hist.nets[name] || {tot:[], rx:[], tx:[]};
  var ctr = (d.net && d.net.counters && d.net.counters[name]) || {};
  // Фиксированная шкала Y: 1 → 2.5 → 5 → 10 → 25 Gbps (в B/s = bits/8)
  var bwMax = 0;
  hist.tot.forEach(function(v){ if(v>bwMax) bwMax=v; });
  function roundBw2(b){
    var levels = [125e6,      // 1 Gbps
                  312.5e6,    // 2.5 Gbps
                  625e6,      // 5 Gbps
                  1250e6,     // 10 Gbps
                  3125e6];    // 25 Gbps
    for(var i=0;i<levels.length;i++) if(b <= levels[i]) return levels[i];
    return levels[levels.length-1];
  }
  bwMax = roundBw2(bwMax);  // дефолт = 1 Gbps когда трафика 0

  var rx = rate.rx_bps||0, tx = rate.tx_bps||0;
  var totRx = ctr.rx_bytes||0, totTx = ctr.tx_bytes||0;

  el("sysmonChart").innerHTML =
    '<div class="chdr">'+
      '<h2 class="ctitle">'+esc(name)+'</h2>'+
      '<div class="cmodel">сетевой интерфейс</div>'+
      '<div class="crange">1 минута</div>'+
    '</div>'+
    _bigPaneHTML("bcv-net","Пропускная способность за 60 секунд", fmtBitsShort(bwMax), dev.color);
  _drawBcv("bcv-net", hist.tot, dev.color, bwMax);

  el("sysmonSpecs").innerHTML =
    _specRow("Отправка", '<span style="color:'+dev.color+'">'+fmtBitsShort(tx)+'</span>')+
    _specRow("Получение", '<span style="color:#5fa3d6">'+fmtBitsShort(rx)+'</span>')+
    _specRow("Всего отправлено", fmtBytesB(totTx))+
    _specRow("Всего получено", fmtBytesB(totRx))+
    '<div class="sgrp">Спецификации</div>'+
    _specRow("Имя интерфейса", esc(name))+
    _specRow("Тип соединения", "—")+
    _specRow("Скорость линка", "—")+
    _specRow("Аппаратный адрес", "—")+
    _specRow("IPv4-адрес", "—")+
    '<div class="legend" style="margin-top:10px">'+
      '<span class="lk"><span class="swat" style="background:'+dev.color+'"></span>Отправка</span>'+
      '<span class="lk"><span class="swat" style="background:#5fa3d6"></span>Получение</span>'+
    '</div>';
  // Дополним спецификации через /api/network/interfaces (отдельный fetch, кешируется в lastNet)
  _maybeFetchNetIfaces(name, dev);
}
var _lastNetIf = {ts:0, data:null};
function _maybeFetchNetIfaces(name, dev){
  var now = Date.now();
  function applySpecs(d){
    if(!d || !d.interfaces) return;
    var ent = null;
    for(var i=0;i<d.interfaces.length;i++) if(d.interfaces[i].name===name){ ent=d.interfaces[i]; break; }
    if(!ent) return;
    var sp = el("sysmonSpecs"); if(!sp) return;
    // patch только спецификации — пере-генерим часть после Спецификации
    var rate = dev.net_rate || {};
    var data = _sysmon.data || {};
    var ctr = (data.net && data.net.counters && data.net.counters[name]) || {};
    var rx = rate.rx_bps||0, tx = rate.tx_bps||0;
    var totRx = ctr.rx_bytes||0, totTx = ctr.tx_bytes||0;
    sp.innerHTML =
      _specRow("Отправка", '<span style="color:'+dev.color+'">'+fmtBitsShort(tx)+'</span>')+
      _specRow("Получение", '<span style="color:#5fa3d6">'+fmtBitsShort(rx)+'</span>')+
      _specRow("Всего отправлено", fmtBytesB(totTx))+
      _specRow("Всего получено", fmtBytesB(totRx))+
      '<div class="sgrp">Спецификации</div>'+
      _specRow("Имя интерфейса", esc(ent.name))+
      _specRow("Тип соединения", esc(ent.type||"—"))+
      _specRow("Скорость линка", (ent.speed_mbps?(ent.speed_mbps+" Mbps"):"—"))+
      _specRow("Аппаратный адрес", '<code style="font-size:11px">'+esc(ent.mac||"—")+'</code>')+
      _specRow("IPv4-адрес", (ent.ipv4&&ent.ipv4.length?'<code style="font-size:11px">'+esc(ent.ipv4[0])+'</code>':"—"))+
      _specRow("IPv6-адрес", (ent.ipv6&&ent.ipv6.length?'<code style="font-size:11px">'+esc(ent.ipv6[0])+'</code>':"—"))+
      '<div class="legend" style="margin-top:10px">'+
        '<span class="lk"><span class="swat" style="background:'+dev.color+'"></span>Отправка</span>'+
        '<span class="lk"><span class="swat" style="background:#5fa3d6"></span>Получение</span>'+
      '</div>';
  }
  if(_lastNetIf.data && (now - _lastNetIf.ts) < 10000){
    applySpecs(_lastNetIf.data); return;
  }
  fetch("/api/network/interfaces",{cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){ _lastNetIf={ts:Date.now(), data:d}; applySpecs(d); })
    .catch(function(){});
}
function _renderSmGPU(dev){
  var d = _sysmon.data || {};
  if(!(d.gpu && d.gpu.available)){
    el("sysmonChart").innerHTML =
      '<div class="chdr"><h2 class="ctitle">ГП</h2><div class="cmodel"></div></div>'+
      '<div class="sysunav"><b>GPU не обнаружен</b>'+
      'Поддерживается NVIDIA через <code>nvidia-smi</code>. Для AMD/Intel — в плане.</div>';
    el("sysmonSpecs").innerHTML = '';
    return;
  }
  var g0 = d.gpu.devices[0];
  el("sysmonChart").innerHTML =
    '<div class="chdr">'+
      '<h2 class="ctitle">ГП</h2>'+
      '<div class="cmodel">'+esc(g0.name)+'</div>'+
      '<div class="crange">1 минута</div>'+
    '</div>'+
    _bigPaneHTML("bcv-gpu","Утилизация за 60 секунд","100%",dev.color);
  _drawBcv("bcv-gpu", _sysmon.hist.gpu, dev.color, 100);
  var memPct = g0.mem_total_mib ? Math.round(g0.mem_used_mib/g0.mem_total_mib*100) : 0;
  el("sysmonSpecs").innerHTML =
    _specRow("Утилизация", g0.util_pct+' %')+
    _specRow("VRAM", g0.mem_used_mib+" / "+g0.mem_total_mib+" MiB ("+memPct+" %)")+
    _specRow("Температура", g0.temp_c+" °C")+
    '<div class="sgrp">Спецификации</div>'+
    _specRow("Модель", esc(g0.name));
}
function _renderSmPwr(dev){
  var d = _sysmon.data || {};
  if(!(d.power && d.power.available)){
    el("sysmonChart").innerHTML =
      '<div class="chdr"><h2 class="ctitle">Питание</h2></div>'+
      '<div class="sysunav"><b>RAPL недоступен</b>'+
      'Чтение Intel-RAPL не работает (VM или ядро не предоставляет /sys/class/powercap).</div>';
    el("sysmonSpecs").innerHTML = '';
    return;
  }
  el("sysmonChart").innerHTML =
    '<div class="chdr"><h2 class="ctitle">Питание</h2>'+
      '<div class="cmodel">Intel RAPL (energy_uj)</div></div>'+
    _bigPaneHTML("bcv-pwr","Мощность за 60 секунд","",dev.color);
  _drawBcv("bcv-pwr", _sysmon.hist.pwr, dev.color, null);
  el("sysmonSpecs").innerHTML =
    _specRow("Текущая", (d.power.watts!=null?d.power.watts+" W":"—"));
}
function renderHostResources(){
  _hostFetch("/api/host/resources", "host-resources", function(d){
    var m=d.mem_kib||{}, s=d.swap_kib||{};
    var mPct=_pct(m.used, m.total), sPct=_pct(s.used, s.total);
    var load = (d.loadavg && d.loadavg.length) ? d.loadavg.join(", ") : "?";
    var h='<table class="kvtbl">'+
      '<tr><th>CPU</th><td>'+esc(d.cpu_model)+' &middot; <b>'+esc(d.cpu_cores)+'</b> ядер(а)</td></tr>'+
      '<tr><th>Load average</th><td><code>'+esc(load)+'</code></td></tr>'+
      '<tr><th>Память</th><td>'+_bar(mPct)+
        ' <span class="dim">'+fmtBytesKiB(m.used)+' / '+fmtBytesKiB(m.total)+
        ' (доступно '+fmtBytesKiB(m.available)+', кэш '+fmtBytesKiB(m.cached)+')</span></td></tr>'+
      '<tr><th>Swap</th><td>'+
        (s.total?(_bar(sPct)+' <span class="dim">'+fmtBytesKiB(s.used)+' / '+fmtBytesKiB(s.total)+'</span>')
                :'<span class="dim">не настроен</span>')+'</td></tr>'+
      '<tr><th>Температура</th><td>'+
        (d.sensors_available
          ? '<pre>'+esc(d.sensors_text)+'</pre>'
          : '<span class="dim">'+esc(d.sensors_msg||"sensors недоступен")+'</span>')+
        '</td></tr>'+
      '</table>';
    el("host-resources").innerHTML = h;
  });
}
function renderHostVmct(){
  _hostFetch("/api/host/vmct", "host-vmct", function(d){
    function svgList(items, kind){
      if(!items || !items.length){
        return '<div class="dim">пусто</div>';
      }
      var s = "";
      items.forEach(function(it){
        var name = it.name || ("ID "+it.vmid);
        var stCls = (it.status==="running")?"ok":(it.status==="stopped"?"":"warn");
        s += '<div class="vmctile">'+
          '<span><b>'+esc(it.vmid)+'</b> &middot; '+esc(name)+
          ' <span class="dim">'+esc(kind)+'</span></span>'+
          '<span class="hstchip '+stCls+'">'+esc(it.status||"?")+'</span></div>';
      });
      return s;
    }
    var h = '<div class="grid2">'+
      '<div class="panel-soft"><div class="lbl">Виртуальные машины ('+(d.vms||[]).length+')</div>'+
        (d.vms_err?'<div class="err">'+esc(d.vms_err)+'</div>':svgList(d.vms,"VM"))+'</div>'+
      '<div class="panel-soft"><div class="lbl">Контейнеры LXC ('+(d.cts||[]).length+')</div>'+
        (d.cts_err?'<div class="err">'+esc(d.cts_err)+'</div>':svgList(d.cts,"CT"))+'</div>'+
      '</div>';
    el("host-vmct").innerHTML = h;
  });
}
function renderHostCluster(){
  _hostFetch("/api/host/cluster", "host-cluster", function(d){
    var h='<table class="kvtbl">'+
      '<tr><th>Corosync</th><td><span class="hstchip '+(d.corosync_active?"ok":"warn")+'">'+
        (d.corosync_active?"active":"inactive")+'</span></td></tr>'+
      '<tr><th>Режим</th><td>'+
        (d.standalone
          ? '<span class="hstchip warn">standalone</span> <span class="dim">узел не в кластере PVE</span>'
          : '<span class="hstchip ok">в кластере</span>')+
        '</td></tr>'+
      '</table>'+
      '<div class="grid2" style="margin-top:14px">'+
        '<div class="panel-soft"><div class="lbl">pvecm status</div>'+
          '<pre style="margin:0;font-size:12px;white-space:pre-wrap;color:var(--dim)">'+
          esc(d.pvecm_text||"")+'</pre></div>'+
        '<div class="panel-soft"><div class="lbl">ha-manager status</div>'+
          '<pre style="margin:0;font-size:12px;white-space:pre-wrap;color:var(--dim)">'+
          esc(d.ha_text||"")+'</pre></div>'+
      '</div>';
    el("host-cluster").innerHTML = h;
  });
}
function renderNetwork(subview){
  var sub = subview || "overview";
  var titles = {
    overview: "Сеть &mdash; интерфейсы",
    bridges:  "Сеть &mdash; Bridges",
    vlan:     "Сеть &mdash; VLAN"
  };
  var nt = el("netTitle"); if(nt) nt.innerHTML = titles[sub] || "Сеть";
  document.querySelectorAll("#view-network .net-sect").forEach(function(s){
    s.style.display = (s.getAttribute("data-sub")===sub) ? "" : "none";
  });
  if(sub === "overview") renderNetworkInterfaces();
}
function fmtBytes(b){
  if(b==null) return "&mdash;";
  var n=+b;
  if(n>=1e12) return (n/1e12).toFixed(2)+" TB";
  if(n>=1e9)  return (n/1e9).toFixed(2)+" GB";
  if(n>=1e6)  return (n/1e6).toFixed(1)+" MB";
  if(n>=1e3)  return (n/1e3).toFixed(1)+" KB";
  return n+" B";
}
function renderNetworkInterfaces(){
  fetch("/api/network/interfaces", {cache:"no-store"}).then(function(r){return r.json();})
    .then(function(d){
      var ifs = d.interfaces || [];
      if(!ifs.length){
        el("netifaces").innerHTML = '<div class="err">не удалось получить список интерфейсов</div>';
        return;
      }
      var phys = ifs.filter(function(i){ return i.type==="physical" || i.type==="bond"; });
      var virt = ifs.filter(function(i){
        return i.type!=="physical" && i.type!=="bond" && i.type!=="loopback" &&
               !(i.name||"").match(/^(tap|veth|fw(br|ln|pr))/);
      });

      // ===== Physical NICs / Bond — главная таблица в стиле vSphere =====
      var h = '<div class="lbl" style="margin:4px 0 8px">Физические адаптеры';
      h += ' <span class="dim" style="font-weight:400;text-transform:none;letter-spacing:0">('+phys.length+')</span></div>';
      h += '<table class="svctbl"><thead><tr>'+
        '<th>Name</th><th>MAC address</th><th>Auto-negotiate</th><th>Link speed</th>'+
        '</tr></thead><tbody>';
      phys.forEach(function(i){
        // Name + IP под ним (если есть)
        var addrLines = "";
        (i.ipv4||[]).forEach(function(a){
          addrLines += '<div class="dim" style="font-size:11px"><code>'+esc(a)+'</code></div>';
        });
        var nameHtml = '<span style="color:var(--accent);font-weight:600">'+esc(i.name)+'</span>';
        if(i.master) nameHtml += ' <span class="dim" style="font-size:11px">→ '+esc(i.master)+'</span>';
        if(i.type==="bond") nameHtml += ' <span class="hstchip" style="font-size:10px;padding:1px 6px;margin-left:6px">bond</span>';
        // Auto-negotiate
        var auto;
        if(i.autoneg === true)       auto = 'Enabled';
        else if(i.autoneg === false) auto = '<span class="dim">Disabled</span>';
        else                         auto = '<span class="dim">&mdash;</span>';
        // Link speed: "10000 Mbps, full duplex" или "Link down"
        var speed;
        var noLink = (i.state==="down") || (i.carrier===false) || (i.link_detected===false) ||
                     !i.speed_mbps;
        if(noLink){
          speed = '<span class="dim">Link down</span>';
        } else {
          speed = '<b>'+i.speed_mbps+'</b> Mbps' +
                  (i.duplex ? ', '+esc(i.duplex)+' duplex' : '');
        }
        h += '<tr>'+
          '<td>'+nameHtml+addrLines+'</td>'+
          '<td><code class="dim" style="font-size:12px">'+esc(i.mac||"")+'</code></td>'+
          '<td>'+auto+'</td>'+
          '<td>'+speed+'</td>'+
          '</tr>';
      });
      if(!phys.length){
        h += '<tr><td colspan="4" class="dim" style="text-align:center;padding:18px">'+
             'физические адаптеры не найдены</td></tr>';
      }
      h += '</tbody></table>';

      // ===== Виртуальные интерфейсы — компактная таблица ниже =====
      if(virt.length){
        h += '<div class="lbl" style="margin:22px 0 8px">Виртуальные интерфейсы';
        h += ' <span class="dim" style="font-weight:400;text-transform:none;letter-spacing:0">('+virt.length+')</span></div>';
        h += '<table class="svctbl"><thead><tr>'+
          '<th>Name</th><th>Type</th><th>State</th><th>MAC</th><th>MTU</th><th>Адреса</th>'+
          '</tr></thead><tbody>';
        virt.forEach(function(i){
          var stCls = (i.state==="up")?"ok":(i.state==="down"?"err":"warn");
          var addrs = [];
          (i.ipv4||[]).forEach(function(a){ addrs.push('<code style="font-size:11px">'+esc(a)+'</code>'); });
          (i.ipv6||[]).forEach(function(a){ addrs.push('<code class="dim" style="font-size:11px">'+esc(a)+'</code>'); });
          var addrsHtml = addrs.length ? addrs.join('<br>') : '<span class="dim">&mdash;</span>';
          var nameHtml = '<b>'+esc(i.name)+'</b>';
          if(i.master) nameHtml += ' <span class="dim" style="font-size:11px">→ '+esc(i.master)+'</span>';
          h += '<tr>'+
            '<td>'+nameHtml+'</td>'+
            '<td><span class="hstchip">'+esc(i.type)+'</span></td>'+
            '<td><span class="hstchip '+stCls+'">'+esc(i.state)+'</span></td>'+
            '<td><code class="dim" style="font-size:11px">'+esc(i.mac||"")+'</code></td>'+
            '<td class="dim">'+(i.mtu||"&mdash;")+'</td>'+
            '<td>'+addrsHtml+'</td>'+
            '</tr>';
        });
        h += '</tbody></table>';
      }

      el("netifaces").innerHTML = h;
      var btn = el("netRefresh"); if(btn) btn.onclick = renderNetworkInterfaces;
    })
    .catch(function(e){
      el("netifaces").innerHTML = '<div class="err">ошибка: '+esc(String(e))+'</div>';
    });
}
function tickDiskmon(){
  fetch("/api/diskmon",{cache:"no-store"}).then(function(r){return r.json();}).then(function(d){
    lastOk=Date.now(); lastDM=d;
    renderDiskList(d); renderMon(d); renderParts(d.disks);
  }).catch(function(e){});
}
function clock(){
  if(!lastOk) return;
  var s=Math.round((Date.now()-lastOk)/1000);
  el("upd").textContent="обновлено "+s+" с назад";
  el("pulse").classList.toggle("stale", s>14);
}
var cfg={ovMs:5000,dmMs:2000,showVita:false,showCeph:false,showZfs:true};
try{ var sc=JSON.parse(localStorage.getItem("vb_cfg")||"{}");
  if(+sc.ovMs) cfg.ovMs=+sc.ovMs; if(+sc.dmMs) cfg.dmMs=+sc.dmMs;
  if(sc.hasOwnProperty("showVita")) cfg.showVita=!!sc.showVita;
  if(sc.hasOwnProperty("showCeph")) cfg.showCeph=!!sc.showCeph;
  if(sc.hasOwnProperty("showZfs")) cfg.showZfs=!!sc.showZfs; }catch(e){}
function saveCfg(){ try{ localStorage.setItem("vb_cfg",JSON.stringify(cfg)); }catch(e){} }
var ovTimer=null, dmTimer=null;
function applyIntervals(){
  if(ovTimer) clearInterval(ovTimer);
  if(dmTimer) clearInterval(dmTimer);
  ovTimer=setInterval(tickOverview,cfg.ovMs);
  dmTimer=setInterval(tickDiskmon,cfg.dmMs);
}

var start="host";
var startSub="monitor";
var startCat="host";
try{
  var sv=localStorage.getItem("vb_view"); if(sv) start=sv;
  if(start==="storage") start="host"; // миграция: страница 'storage' удалена → дефолт = Узел/Монитор
  var sc=localStorage.getItem("vb_cat"); if(sc) startCat=sc;
  if(start==="network"){ var ssub=localStorage.getItem("vb_netsub"); if(ssub) startSub=ssub; }
  if(start==="host"){ var hsub=localStorage.getItem("vb_hostsub"); if(hsub) startSub=hsub; }
}catch(e){}
applyVisibility();
var visMap={vitastor:cfg.showVita,ceph:cfg.showCeph,zfs:cfg.showZfs};
if(visMap.hasOwnProperty(start)&&!visMap[start]) start="host";
if(startCat) setCategory(startCat);
setView(start, startSub);
var startVTab="storage";
try{ var svt=localStorage.getItem("vb_vtab"); if(svt) startVTab=svt; }catch(e){}
setVTab(startVTab);
var startZfsTab="pools";
try{ var szt=localStorage.getItem("vb_zftab"); if(szt) startZfsTab=szt; }catch(e){}
setZfsTab(startZfsTab);
tickOverview(); tickDiskmon();
applyIntervals();
setInterval(clock,1000);
window.addEventListener("resize",function(){ if(lastDM) renderMon(lastDM); });
</script>
</body>
</html>
'''


# ---------- авторизация ----------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "proxomatron.json")
COOKIE_NAME = "vbsess"
SESSION_TTL = 30 * 86400
PBKDF2_ITERS = 200000
_cfg_lock = threading.Lock()


def _hash_password(pw):
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, salt.hex(), h.hex())


def _verify_password(pw, stored):
    if not isinstance(stored, str) or not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters_s, salt_hex, hash_hex = stored.split("$", 3)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            got = hashlib.pbkdf2_hmac(
                "sha256", pw.encode("utf-8"), salt, int(iters_s))
        except Exception:
            return False
        return hmac.compare_digest(got, expected)
    # plain (для дефолта admin/admin и ручного редактирования файла)
    return hmac.compare_digest(pw, stored)


def cfg_load():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
            if not isinstance(data, dict):
                data = {}
    except Exception:
        data = {}
    changed = False
    if not isinstance(data.get("login"), str) or not data["login"].strip():
        data["login"] = "admin"
        changed = True
    if not isinstance(data.get("password"), str) or not data["password"]:
        data["password"] = "admin"
        changed = True
    if not isinstance(data.get("secret"), str) or len(data["secret"]) < 32:
        data["secret"] = secrets.token_hex(32)
        changed = True
    if changed:
        try:
            cfg_save(data)
        except Exception:
            pass
    return data


def cfg_save(data):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        pass


def _make_token(login, secret):
    exp = int(time.time()) + SESSION_TTL
    payload = "%s|%d" % (login, exp)
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    raw = ("%s|%s" % (payload, sig)).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _verify_token(tok, secret):
    try:
        pad = "=" * (-len(tok) % 4)
        raw = base64.urlsafe_b64decode((tok + pad).encode("ascii"))
        text = raw.decode("utf-8")
        login, exp_s, sig = text.rsplit("|", 2)
        exp = int(exp_s)
        if exp < int(time.time()):
            return None
        payload = "%s|%s" % (login, exp_s)
        expected = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        return login
    except Exception:
        return None


def _parse_cookies(header):
    out = {}
    if not header:
        return out
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k.strip()] = v.strip()
    return out


LOGIN_HTML = r'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PROXOMATRON — вход</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;
    --dim:#8b949e;--accent:#2dd4bf;--err:#f85149}
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--txt);
    font:14px/1.45 -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;
    display:flex;align-items:center;justify-content:center}
  .box{width:340px;background:var(--panel);border:1px solid var(--line);
    border-radius:12px;padding:26px 28px 22px}
  .brand{font-size:18px;font-weight:600;letter-spacing:0.3px;
    margin-bottom:2px}
  .brand b{color:var(--accent)}
  .sub{font-size:11.5px;color:var(--dim);margin-bottom:18px}
  label{display:block;font-size:11.5px;color:var(--dim);
    margin:10px 0 4px;letter-spacing:0.3px}
  input{width:100%;background:#0b0f15;color:var(--txt);
    border:1px solid var(--line);border-radius:8px;
    padding:9px 11px;font-size:14px;outline:none}
  input:focus{border-color:var(--accent)}
  button{width:100%;margin-top:18px;background:var(--accent);
    color:#06231f;border:0;border-radius:8px;padding:10px;
    font-size:14px;font-weight:600;cursor:pointer}
  button:disabled{opacity:0.6;cursor:default}
  .err{margin-top:12px;color:var(--err);font-size:12.5px;min-height:16px}
  .ver{margin-top:14px;text-align:center;font-size:11px;color:var(--dim)}
</style>
</head>
<body>
<form class="box" id="f" autocomplete="on">
  <div class="brand">&#9638; PROXO<b>MATRON</b></div>
  <div class="sub">вход в панель управления</div>
  <label for="lg">Логин</label>
  <input id="lg" name="login" autocomplete="username" autofocus required>
  <label for="pw">Пароль</label>
  <input id="pw" name="password" type="password"
    autocomplete="current-password" required>
  <button id="go" type="submit">Войти</button>
  <div class="err" id="err"></div>
  <div class="ver">v__VBVERSION__</div>
</form>
<script>
var f=document.getElementById("f"), go=document.getElementById("go"),
    err=document.getElementById("err");
f.addEventListener("submit", function(e){
  e.preventDefault(); err.textContent=""; go.disabled=true;
  fetch("/api/auth/login",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({login:document.getElementById("lg").value,
      password:document.getElementById("pw").value})
  }).then(function(r){return r.json().then(function(j){return [r.ok,j];});})
    .then(function(p){
      if(p[0]&&p[1].ok){ location.href="/"; return; }
      err.textContent=(p[1]&&p[1].error)||"ошибка входа";
      go.disabled=false;
    }).catch(function(e){
      err.textContent="нет связи с сервером"; go.disabled=false;
    });
});
</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _redirect(self, loc, extra=None):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()

    def _auth_user(self):
        cfg = cfg_load()
        cookies = _parse_cookies(self.headers.get("Cookie") or "")
        tok = cookies.get(COOKIE_NAME)
        if not tok:
            return None, cfg
        login = _verify_token(tok, cfg["secret"])
        if login and login == cfg["login"]:
            return login, cfg
        return None, cfg

    def _require_auth(self, is_api):
        user, cfg = self._auth_user()
        if user:
            return user, cfg
        if is_api:
            self._send(401, "application/json",
                       json.dumps({"error": "требуется вход"}).encode("utf-8"))
        else:
            self._redirect("/login")
        return None, cfg

    def _read_json(self):
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b"{}"
            return json.loads(raw.decode("utf-8") or "{}"), None
        except Exception:
            return None, "некорректный JSON"

    def _set_session_cookie(self, tok):
        return ("Set-Cookie",
                "%s=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d"
                % (COOKIE_NAME, tok, SESSION_TTL))

    def _clear_session_cookie(self):
        return ("Set-Cookie",
                "%s=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
                % COOKIE_NAME)

    def _handle_login(self):
        req, err = self._read_json()
        if err:
            self._send(400, "application/json",
                       json.dumps({"error": err}).encode("utf-8"))
            return
        login = (req.get("login") or "").strip()
        pw = req.get("password") or ""
        cfg = cfg_load()
        if login != cfg["login"] or not _verify_password(pw, cfg["password"]):
            time.sleep(0.4)
            self._send(401, "application/json", json.dumps(
                {"error": "неверный логин или пароль"}).encode("utf-8"))
            return
        tok = _make_token(login, cfg["secret"])
        self._send(200, "application/json",
                   json.dumps({"ok": True}).encode("utf-8"),
                   extra=[self._set_session_cookie(tok)])

    def _handle_logout(self):
        self._send(200, "application/json",
                   json.dumps({"ok": True}).encode("utf-8"),
                   extra=[self._clear_session_cookie()])

    def _handle_change(self):
        user, _ = self._require_auth(is_api=True)
        if not user:
            return
        req, err = self._read_json()
        if err:
            self._send(400, "application/json",
                       json.dumps({"error": err}).encode("utf-8"))
            return
        old = req.get("old_password") or ""
        new_login = (req.get("login") or "").strip()
        new_pw = req.get("password") or ""
        if not new_login:
            self._send(200, "application/json", json.dumps(
                {"error": "логин не может быть пустым"}).encode("utf-8"))
            return
        if len(new_pw) < 4:
            self._send(200, "application/json", json.dumps(
                {"error": "пароль не короче 4 символов"}).encode("utf-8"))
            return
        with _cfg_lock:
            cfg = cfg_load()
            if not _verify_password(old, cfg["password"]):
                self._send(200, "application/json", json.dumps(
                    {"error": "текущий пароль неверен"}).encode("utf-8"))
                return
            cfg["login"] = new_login
            cfg["password"] = _hash_password(new_pw)
            cfg["secret"] = secrets.token_hex(32)
            try:
                cfg_save(cfg)
            except Exception as e:
                self._send(500, "application/json", json.dumps(
                    {"error": "не удалось сохранить: " + str(e)}
                ).encode("utf-8"))
                return
            tok = _make_token(new_login, cfg["secret"])
        self._send(200, "application/json",
                   json.dumps({"ok": True, "login": new_login}).encode("utf-8"),
                   extra=[self._set_session_cookie(tok)])

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send(200, "text/plain", b"ok")
            return
        if path == "/login":
            user, _ = self._auth_user()
            if user:
                self._redirect("/")
                return
            self._send(200, "text/html; charset=utf-8",
                       LOGIN_HTML.replace("__VBVERSION__", VERSION).encode("utf-8"))
            return
        if path == "/api/auth/me":
            user, cfg = self._auth_user()
            if not user:
                self._send(401, "application/json", json.dumps(
                    {"error": "требуется вход"}).encode("utf-8"))
                return
            self._send(200, "application/json",
                       json.dumps({"login": cfg["login"]}).encode("utf-8"))
            return
        is_api = path.startswith("/api/")
        user, _ = self._require_auth(is_api=is_api)
        if not user:
            return
        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8",
                       INDEX_HTML.replace("__VBVERSION__", VERSION).encode("utf-8"))
        elif path == "/api/overview":
            self._send(200, "application/json",
                       json.dumps(overview_cached()).encode("utf-8"))
        elif path == "/api/diskmon":
            self._send(200, "application/json",
                       json.dumps(diskmon()).encode("utf-8"))
        elif path == "/api/smart":
            disk = ""
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if kv.startswith("disk="):
                        disk = kv[5:]
            self._send(200, "application/json",
                       json.dumps(smart_info(disk)).encode("utf-8"))
        elif path == "/api/wizard/info":
            self._send(200, "application/json",
                       json.dumps(wizard_info()).encode("utf-8"))
        elif path == "/api/cluster/info":
            self._send(200, "application/json",
                       json.dumps(cluster_info()).encode("utf-8"))
        elif path == "/api/cluster/nodes":
            self._send(200, "application/json",
                       json.dumps(cluster_nodes()).encode("utf-8"))
        elif path == "/api/cluster/overview":
            self._send(200, "application/json",
                       json.dumps(cluster_overview()).encode("utf-8"))
        elif path == "/api/cluster/node-info":
            ip = ""
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if kv.startswith("ip="):
                        ip = kv[3:]
            self._send(200, "application/json",
                       json.dumps(cluster_node_info(ip)).encode("utf-8"))
        elif path == "/api/node/info":
            self._send(200, "application/json",
                       json.dumps(node_info()).encode("utf-8"))
        elif path == "/api/zfs/wizard-info":
            self._send(200, "application/json",
                       json.dumps(zfs_wizard_info()).encode("utf-8"))
        elif path == "/api/zfs/cache":
            self._send(200, "application/json",
                       json.dumps(zfs_cache_info()).encode("utf-8"))
        elif path == "/api/service/info":
            self._send(200, "application/json",
                       json.dumps(service_info()).encode("utf-8"))
        elif path == "/api/host/sysinfo":
            self._send(200, "application/json",
                       json.dumps(host_sysinfo()).encode("utf-8"))
        elif path == "/api/host/resources":
            self._send(200, "application/json",
                       json.dumps(host_resources()).encode("utf-8"))
        elif path == "/api/host/vmct":
            self._send(200, "application/json",
                       json.dumps(host_vmct()).encode("utf-8"))
        elif path == "/api/host/cluster":
            self._send(200, "application/json",
                       json.dumps(host_cluster()).encode("utf-8"))
        elif path == "/api/host/monitor":
            self._send(200, "application/json",
                       json.dumps(host_monitor()).encode("utf-8"))
        elif path == "/api/network/interfaces":
            self._send(200, "application/json",
                       json.dumps(network_interfaces()).encode("utf-8"))
        elif path == "/healthz":
            self._send(200, "text/plain", b"ok")
        else:
            self._send(404, "text/plain; charset=utf-8", "не найдено".encode("utf-8"))

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/auth/login":
            self._handle_login()
            return
        if path == "/api/auth/logout":
            self._handle_logout()
            return
        if path == "/api/auth/change":
            self._handle_change()
            return
        if path not in ("/api/wizard/plan", "/api/wizard/apply",
                        "/api/install/vitastor", "/api/install/controlplane",
                        "/api/cluster/apply", "/api/node/join",
                        "/api/node/prepare-disk", "/api/zfs/create",
                        "/api/zfs/cache", "/api/service/timer",
                        "/api/service/stop"):
            self._send(404, "text/plain; charset=utf-8",
                       "не найдено".encode("utf-8"))
            return
        user, _ = self._require_auth(is_api=True)
        if not user:
            return
        if path == "/api/service/timer":
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(ln) if ln else b"{}"
                req = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                self._send(400, "application/json", json.dumps(
                    {"error": "некорректный JSON"}).encode("utf-8"))
                return
            dur = (req.get("duration") or "").strip() if req.get("duration") else ""
            resp = service_timer_set(dur)
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/service/stop":
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(ln) if ln else b"{}"
                req = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                self._send(400, "application/json", json.dumps(
                    {"error": "некорректный JSON"}).encode("utf-8"))
                return
            if (req.get("confirm") or "") != "stop":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено (нужно: stop)"}
                ).encode("utf-8"))
                return
            resp = service_stop_now()
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b"{}"
            req = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._send(400, "application/json",
                       json.dumps({"error": "некорректный JSON"}).encode("utf-8"))
            return
        if path == "/api/install/vitastor":
            if (req.get("confirm") or "") != "vitastor":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено"}).encode("utf-8"))
                return
            with _wiz_lock:
                resp = vitastor_install()
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/install/controlplane":
            if (req.get("confirm") or "") != "controlplane":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено"}).encode("utf-8"))
                return
            with _wiz_lock:
                resp = control_plane_setup(req.get("node"), req.get("ip"),
                                           req.get("network"))
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/node/join":
            if (req.get("confirm") or "") != "join":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено"}).encode("utf-8"))
                return
            with _wiz_lock:
                resp = node_join(req.get("etcd_address"), req.get("osd_network"))
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/node/prepare-disk":
            if (req.get("confirm") or "") != "prepare":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено"}).encode("utf-8"))
                return
            with _wiz_lock:
                resp = node_prepare_disk(req.get("disks"), req.get("tag"))
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/zfs/cache":
            if (req.get("confirm") or "") != "cache":
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение не получено"}).encode("utf-8"))
                return
            with _wiz_lock:
                resp = zfs_set_cache(req.get("bytes"))
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/zfs/create":
            name = (req.get("name") or "").strip()
            if not name or (req.get("confirm") or "").strip() != name:
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение неверно — введите имя пула"}
                ).encode("utf-8"))
                return
            with _wiz_lock:
                resp = zfs_create_pool(name, req.get("mode"), req.get("disks"))
            with _lock:
                _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        if path == "/api/cluster/apply":
            action = req.get("action") or "reconfigure"
            cf = (req.get("confirm") or "").strip()
            resp = None
            if action == "reconfigure":
                ip = (req.get("ip") or "").strip()
                if not ip or cf != ip:
                    resp = {"error": "подтверждение неверно — введите новый IP"}
            elif action in ("add-node", "add-osd"):
                ip = (req.get("ip") or "").strip()
                if not ip or cf != ip:
                    resp = {"error": "подтверждение неверно — введите IP узла"}
            elif action == "create-pool":
                nm = (req.get("name") or "").strip()
                if not nm or cf != nm:
                    resp = {"error": "подтверждение неверно — введите имя пула"}
            else:
                resp = {"error": "неизвестное действие кластера"}
            if resp is None:
                with _wiz_lock:
                    if action == "reconfigure":
                        resp = cluster_reconfigure(
                            req.get("node"), (req.get("ip") or "").strip(),
                            req.get("network"), req.get("mode"))
                    elif action == "add-node":
                        resp = cluster_add_node((req.get("ip") or "").strip())
                    elif action == "add-osd":
                        resp = cluster_add_osd((req.get("ip") or "").strip(),
                                               req.get("disks"), req.get("tag"))
                    else:
                        resp = cluster_create_pool(
                            req.get("name"), req.get("pg_size"),
                            req.get("pg_minsize"), req.get("pg_count"),
                            req.get("tag"))
                with _lock:
                    _cache["ts"] = 0.0
            self._send(200, "application/json",
                       json.dumps(resp).encode("utf-8"))
            return
        c, err = wiz_validate(req)
        if err:
            self._send(200, "application/json",
                       json.dumps({"error": err}).encode("utf-8"))
            return
        if path == "/api/wizard/plan":
            resp = {"ok": True, "steps": wizard_plan(c),
                    "confirm_word": wiz_confirm_word(c)}
        else:
            cw = wiz_confirm_word(c)
            if (req.get("confirm") or "").strip() != cw:
                self._send(200, "application/json", json.dumps(
                    {"error": "подтверждение неверно (нужно: %s)" % cw}
                ).encode("utf-8"))
                return
            with _wiz_lock:
                resp = wizard_apply(c)
            with _lock:
                _cache["ts"] = 0.0
        self._send(200, "application/json", json.dumps(resp).encode("utf-8"))

    def log_message(self, *args):
        pass


def main():
    threading.Thread(target=sampler_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("PROXOMATRON %s -- http://0.0.0.0:%d" % (VERSION, PORT), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
