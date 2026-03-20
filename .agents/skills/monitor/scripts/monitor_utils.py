"""
Monitor Utils - Módulo completo de coleta de métricas do sistema.

Utiliza `psutil` e `platform` para coletar dados abrangentes:
  - CPU: uso, núcleos, frequência, tipo de processador, temperatura
  - Memória: RAM total/usada/disponível, swap
  - Disco: partições, espaço total/usado/livre por unidade
  - Rede: throughput, totais acumulados
  - Sistema: SO, hostname, uptime, processos top consumidores
"""

import json
import logging
import os
import platform
import subprocess
import time
from typing import Any, Optional

import psutil

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
KELVIN_OFFSET = 273.15
KELVIN_DIVISOR = 10.0
DEFAULT_INTERVAL_SECONDS = 1
DASHBOARD_JS_FILENAME = "metrics-data.js"
TOP_PROCESSES_COUNT = 10


def get_cpu_temp() -> Optional[float]:
    """Tenta obter a temperatura da CPU via WMI (Windows).

    Returns:
        Temperatura em graus Celsius ou ``None`` se indisponível.
    """
    try:
        cmd = (
            'powershell -Command "'
            "Get-CimInstance -Namespace root/wmi "
            "-ClassName MsAcpi_ThermalZoneTemperature "
            '| Select-Object -Property CurrentTemperature"'
        )
        output = subprocess.check_output(
            cmd, shell=True, timeout=5
        ).decode().strip()

        for line in output.split("\n"):
            stripped = line.strip()
            if stripped.isdigit():
                temp_kelvin = float(stripped)
                return (temp_kelvin / KELVIN_DIVISOR) - KELVIN_OFFSET
    except subprocess.TimeoutExpired:
        logger.warning("Timeout ao tentar obter temperatura da CPU.")
    except Exception as exc:
        logger.debug("Não foi possível obter a temperatura: %s", exc)

    return None


def _format_bytes(num_bytes: float) -> str:
    """Converte bytes para representação legível (KB, MB, GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _get_disk_info() -> list[dict[str, Any]]:
    """Coleta informações de todas as partições de disco."""
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disks.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "filesystem": partition.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percentage": usage.percent,
                "total_formatted": _format_bytes(usage.total),
                "used_formatted": _format_bytes(usage.used),
                "free_formatted": _format_bytes(usage.free),
            })
        except (PermissionError, OSError) as exc:
            logger.debug("Não foi possível acessar %s: %s", partition.mountpoint, exc)
    return disks


def _get_cpu_info() -> dict[str, Any]:
    """Coleta informações detalhadas sobre o processador."""
    freq = psutil.cpu_freq()
    return {
        "processor": platform.processor() or "N/A",
        "architecture": platform.machine(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "frequency_mhz": round(freq.current, 0) if freq else None,
        "max_frequency_mhz": round(freq.max, 0) if freq and freq.max else None,
    }


def _get_system_info() -> dict[str, str]:
    """Coleta informações gerais do sistema operacional."""
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    hours, remainder = divmod(int(uptime_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "python_version": platform.python_version(),
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "uptime_seconds": uptime_seconds,
    }


def _get_top_processes(n: int = TOP_PROCESSES_COUNT) -> list[dict[str, Any]]:
    """Retorna os N processos que mais consomem CPU/memória."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "cpu_percent": info["cpu_percent"] or 0.0,
                "memory_percent": round(info["memory_percent"] or 0.0, 1),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
    return procs[:n]


def _get_swap_info() -> dict[str, Any]:
    """Coleta informações da memória swap."""
    swap = psutil.swap_memory()
    return {
        "total": swap.total,
        "used": swap.used,
        "free": swap.free,
        "percentage": swap.percent,
        "total_formatted": _format_bytes(swap.total),
        "used_formatted": _format_bytes(swap.used),
    }


def collect_metrics(interval: int = DEFAULT_INTERVAL_SECONDS) -> dict[str, Any]:
    """Coleta métricas completas de desempenho do sistema.

    Args:
        interval: Duração (em segundos) da janela de medição da CPU e rede.

    Returns:
        Dicionário com métricas de CPU, memória, disco, rede, sistema e processos.
    """
    net_start = psutil.net_io_counters()
    cpu_percent = psutil.cpu_percent(interval=interval)
    net_end = psutil.net_io_counters()

    mem = psutil.virtual_memory()

    bytes_sent_per_sec = (net_end.bytes_sent - net_start.bytes_sent) / interval
    bytes_recv_per_sec = (net_end.bytes_recv - net_start.bytes_recv) / interval

    return {
        "timestamp": time.time(),
        "system": _get_system_info(),
        "cpu": {
            "percentage": cpu_percent,
            "temp": get_cpu_temp(),
            **_get_cpu_info(),
        },
        "memory": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percentage": mem.percent,
            "total_formatted": _format_bytes(mem.total),
            "used_formatted": _format_bytes(mem.used),
            "available_formatted": _format_bytes(mem.available),
        },
        "swap": _get_swap_info(),
        "disks": _get_disk_info(),
        "network": {
            "sent_bps": bytes_sent_per_sec,
            "recv_bps": bytes_recv_per_sec,
            "total_sent": net_end.bytes_sent,
            "total_recv": net_end.bytes_recv,
            "sent_formatted": _format_bytes(bytes_sent_per_sec) + "/s",
            "recv_formatted": _format_bytes(bytes_recv_per_sec) + "/s",
        },
        "top_processes": _get_top_processes(),
    }


def save_dashboard_data(metrics: dict[str, Any]) -> str:
    """Salva as métricas como arquivo JS para o dashboard.

    Returns:
        Caminho absoluto do arquivo salvo.
    """
    target_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard")
    os.makedirs(target_dir, exist_ok=True)
    filepath = os.path.join(target_dir, DASHBOARD_JS_FILENAME)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"window.PC_METRICS = {json.dumps(metrics, indent=2)};")

    return os.path.abspath(filepath)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    collected = collect_metrics()
    print(json.dumps(collected, indent=2))
    saved_path = save_dashboard_data(collected)
    print(f"\nDados salvos em: {saved_path}")
