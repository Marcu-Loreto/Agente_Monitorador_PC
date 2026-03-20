"""
repair_tools.py — Ferramentas de reparo e manutenção do Windows.

Define funções seguras que executam APENAS comandos pré-aprovados
de manutenção do sistema operacional. Nenhum comando arbitrário é aceito.

Ferramentas:
  - chkdsk (verificação de disco)
  - sfc /scannow (verificação de arquivos do sistema)
  - DISM (reparo da imagem do Windows)
  - cleanmgr (limpeza de disco)
  - defrag (desfragmentação)
  - ipconfig (renovar IP / flush DNS)
"""

import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# Timeout para comandos (5 minutos max)
COMMAND_TIMEOUT = 300


def _run_safe_command(
    cmd: list[str],
    description: str,
    timeout: int = COMMAND_TIMEOUT,
    shell: bool = False,
) -> dict:
    """Executa um comando pré-definido de forma segura.

    Returns:
        Dicionário com status, stdout e stderr.
    """
    logger.info("Executando %s: %s", description, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "command": description,
            "exit_code": result.returncode,
            "output": result.stdout[:2000] if result.stdout else "",
            "error": result.stderr[:1000] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        msg = f"Timeout ({timeout}s) ao executar {description}."
        logger.warning(msg)
        return {"status": "timeout", "command": description, "output": msg}
    except PermissionError:
        msg = (
            f"Sem permissão para executar {description}. "
            "Execute o Streamlit como Administrador."
        )
        logger.warning(msg)
        return {"status": "permission_denied", "command": description, "output": msg}
    except Exception as exc:
        msg = f"Erro ao executar {description}: {exc}"
        logger.error(msg)
        return {"status": "error", "command": description, "output": msg}


# ---------------------------------------------------------------------------
# Ferramentas de Reparo
# ---------------------------------------------------------------------------

def run_sfc_scan() -> dict:
    """Executa o System File Checker (sfc /scannow).

    Verifica a integridade dos arquivos do sistema Windows e repara
    arquivos corrompidos. Requer privilégios de administrador.
    """
    return _run_safe_command(
        ["sfc", "/scannow"],
        "System File Checker (sfc /scannow)",
    )


def run_dism_health() -> dict:
    """Executa DISM para verificar e reparar a imagem do Windows.

    Sequência: CheckHealth → ScanHealth → RestoreHealth.
    Requer privilégios de administrador e conexão com a internet.
    """
    results = []

    # 1. CheckHealth (rápido)
    r1 = _run_safe_command(
        ["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"],
        "DISM CheckHealth",
        timeout=60,
    )
    results.append(r1)

    # 2. ScanHealth
    r2 = _run_safe_command(
        ["DISM", "/Online", "/Cleanup-Image", "/ScanHealth"],
        "DISM ScanHealth",
        timeout=120,
    )
    results.append(r2)

    # 3. RestoreHealth (pode demorar)
    r3 = _run_safe_command(
        ["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"],
        "DISM RestoreHealth",
    )
    results.append(r3)

    return {
        "command": "DISM Health Check (3 etapas)",
        "steps": results,
        "status": "success" if all(r["status"] == "success" for r in results) else "partial",
    }


def run_chkdsk(drive: str = "C:") -> dict:
    """Agenda uma verificação de disco (chkdsk) para a próxima reinicialização.

    Args:
        drive: Letra da unidade (ex: 'C:', 'D:').

    Note:
        O chkdsk em unidades em uso só pode rodar na próxima inicialização.
    """
    # Sanitizar drive: aceitar apenas letras + ':'
    clean_drive = drive.strip().upper()
    if len(clean_drive) != 2 or not clean_drive[0].isalpha() or clean_drive[1] != ":":
        return {
            "status": "error",
            "command": "chkdsk",
            "output": f"Unidade inválida: '{drive}'. Use o formato 'C:' ou 'D:'.",
        }

    return _run_safe_command(
        ["chkdsk", clean_drive, "/F", "/R", "/X"],
        f"Check Disk ({clean_drive})",
    )


def run_disk_cleanup() -> dict:
    """Inicia a Limpeza de Disco do Windows (cleanmgr).

    Note:
        Abre a interface gráfica do cleanmgr. O usuário deve
        selecionar as opções e confirmar a limpeza.
    """
    return _run_safe_command(
        ["cleanmgr", "/d", "C"],
        "Limpeza de Disco (cleanmgr)",
        timeout=10,  # Retorna rápido pois abre GUI
    )


def run_defrag_analysis(drive: str = "C:") -> dict:
    """Executa análise de fragmentação de um disco.

    Args:
        drive: Letra da unidade.

    Note:
        Apenas ANÁLISE, não desfragmenta. Para SSDs, o Windows
        faz TRIM automaticamente.
    """
    clean_drive = drive.strip().upper()
    if len(clean_drive) != 2 or not clean_drive[0].isalpha() or clean_drive[1] != ":":
        return {
            "status": "error",
            "command": "defrag",
            "output": f"Unidade inválida: '{drive}'.",
        }

    return _run_safe_command(
        ["defrag", clean_drive, "/A"],
        f"Análise de fragmentação ({clean_drive})",
        timeout=120,
    )


def run_flush_dns() -> dict:
    """Limpa o cache DNS do Windows (ipconfig /flushdns)."""
    return _run_safe_command(
        ["ipconfig", "/flushdns"],
        "Flush DNS Cache",
        timeout=10,
    )


def run_renew_ip() -> dict:
    """Renova o endereço IP via DHCP (ipconfig /renew)."""
    release = _run_safe_command(
        ["ipconfig", "/release"],
        "IP Release",
        timeout=15,
    )
    renew = _run_safe_command(
        ["ipconfig", "/renew"],
        "IP Renew",
        timeout=30,
    )
    return {
        "command": "Renovação de IP (release + renew)",
        "steps": [release, renew],
        "status": renew["status"],
    }
