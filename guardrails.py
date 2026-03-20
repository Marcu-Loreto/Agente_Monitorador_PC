"""
Guardrails — Módulo de segurança para o agente Minitor.

Implementa múltiplas camadas de proteção:
  1. Input Validation   — detecta prompt injection e payloads maliciosos
  2. Scope Enforcement  — restringe ao domínio de monitoramento de PC
  3. Output Validation  — previne vazamento de dados sensíveis
  4. Rate Limiting      — limita a frequência de requisições por sessão
  5. Input Sanitization — limpa e normaliza o input do usuário
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH = 1000
MAX_MESSAGES_PER_MINUTE = 10
MAX_HISTORY_LENGTH = 50

# ---------------------------------------------------------------------------
# 1. Padrões de Prompt Injection
# ---------------------------------------------------------------------------
# Padrões que tentam manipular o comportamento do LLM
_INJECTION_PATTERNS: list[re.Pattern] = [
    # Tentativas de redefinir identidade / papel
    re.compile(r"(ignore|esqueça|esqueca|desconsidere)\s+(todas?\s+)?(as\s+)?(instru[çc][õo]es|regras|restri[çc][õo]es)", re.IGNORECASE),
    re.compile(r"(you\s+are\s+now|agora\s+você\s+é|finja\s+(ser|que))", re.IGNORECASE),
    re.compile(r"(novo\s+papel|new\s+role|act\s+as|atue\s+como)\b", re.IGNORECASE),

    # Tentativas de manipulação do system prompt
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"(mostre|revele|exiba|print|diga)\s+(seu|sua|suas|o|seu\s+pr[oó]prio|me)?\s*(system|sistema|prompt|instru[çc][õo]es|configura[çc][ãa]o)", re.IGNORECASE),
    re.compile(r"(qual|what|quais?)\s+([eé]|is|s[aã]o)\s+(seu|sua|your|seus|suas)\s*(prompt|instru[çc][ãa]o|instru[çc][õo]es)", re.IGNORECASE),
    re.compile(r"(revele|mostre|exiba|expon?ha)\s+(suas?|as)\s+(regras|instru[çc][õo]es|diretrizes)", re.IGNORECASE),
    # Catch-all: qualquer menção a "seu prompt" ou "suas instruções" em contexto de extração
    re.compile(r"seu\s+prompt", re.IGNORECASE),
    re.compile(r"qual.{0,15}prompt", re.IGNORECASE),
    re.compile(r"(diga|fale|conte).{0,20}(instru[çc][õo]es|configura[çc])", re.IGNORECASE),

    # Tentativas de bypass / jailbreak conhecidos
    re.compile(r"\bDAN\b.*\bmode\b", re.IGNORECASE),
    re.compile(r"(developer|desenvolvedor)\s+mode", re.IGNORECASE),
    re.compile(r"modo\s+(desenvolvedor|developer|dev)", re.IGNORECASE),
    re.compile(r"ativ[ea]\s+(o\s+)?modo\s+(desenvolvedor|developer|dev)", re.IGNORECASE),
    re.compile(r"(jailbreak|bypass|override)", re.IGNORECASE),

    # Tentativas de execução de código / comandos
    re.compile(r"(execute|run|rode|exec)\s+(este|this|o)?\s*(comando|command|script|código|code)", re.IGNORECASE),
    re.compile(r"(import\s+os|subprocess|eval\(|exec\(|__import__)", re.IGNORECASE),
    re.compile(r"(rm\s+-rf|del\s+/|format\s+c:)", re.IGNORECASE),

    # Tentativas de acessar arquivos do sistema
    re.compile(r"(leia|read|cat|type|abra)\s+(o\s+)?(arquivo|file)\s+(/etc/|C:\\|\.env)", re.IGNORECASE),
    re.compile(r"\.\./", re.IGNORECASE),  # path traversal

    # Delimitadores de manipulação contextual
    re.compile(r"<\|?(system|im_start|im_end|endoftext)\|?>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]|\[SYSTEM\]", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# 2. Padrões de Escopo Permitido (PC Health)
# ---------------------------------------------------------------------------
_SCOPE_KEYWORDS: list[re.Pattern] = [
    re.compile(r"(cpu|processador|processor|núcleo|core)", re.IGNORECASE),
    re.compile(r"(mem[oó]ria|ram|memory|swap)", re.IGNORECASE),
    re.compile(r"(rede|network|internet|wifi|wi-fi|download|upload|throughput|banda)", re.IGNORECASE),
    re.compile(r"(temperatura|temperature|temp|esquentando|quente|calor)", re.IGNORECASE),
    re.compile(r"(desempenho|performance|lento|lentidão|travando|lag|consumo)", re.IGNORECASE),
    re.compile(r"(monitor|monitorar|dashboard|saúde|health|diagnóstico|diagnostico)", re.IGNORECASE),
    re.compile(r"(pc|computador|máquina|maquina|computer|sistema|system|hardware)", re.IGNORECASE),
    re.compile(r"(disco|disk|ssd|hd|armazenamento|storage|parti[çc][ãa]o|espa[çc]o)", re.IGNORECASE),
    re.compile(r"(processo|process|tarefa|task|programa|aplicativo|app)", re.IGNORECASE),
    re.compile(r"(otimizar|melhorar|improve|optimize|resolver|limpar|cleanup)", re.IGNORECASE),
    re.compile(r"(uptime|ligado|boot|inicializa[çc]|hostname|nome do)", re.IGNORECASE),
    re.compile(r"(frequ[êe]ncia|frequency|ghz|mhz|hertz)", re.IGNORECASE),
    re.compile(r"(windows|linux|vers[ãa]o|atualiza[çc]|update)", re.IGNORECASE),
    re.compile(r"(drive|unidade|volume|C:|D:|E:|GB|MB|TB)", re.IGNORECASE),
    re.compile(r"(reparo|reparar|repair|consertar|corrigir|fix|verificar|scan)", re.IGNORECASE),
    re.compile(r"(sfc|dism|chkdsk|scandisk|checkdisk|cleanmgr|defrag)", re.IGNORECASE),
    re.compile(r"(limpeza|limpar|cleanup|desfragment|fragmenta)", re.IGNORECASE),
    re.compile(r"(dns|ip|dhcp|ipconfig|flush|renovar|renew)", re.IGNORECASE),
    re.compile(r"(corrompido|corrupto|danificado|erro|error|falha|crash)", re.IGNORECASE),
    # Saudações e perguntas genéricas são permitidas
    re.compile(r"^(oi|olá|hello|hi|bom dia|boa tarde|boa noite|obrigado|valeu|tchau|bye)", re.IGNORECASE),
    re.compile(r"(o que você faz|como funciona|ajuda|help|quem é você)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# 3. Padrões de Dados Sensíveis na Saída
# ---------------------------------------------------------------------------
_SENSITIVE_OUTPUT_PATTERNS: list[re.Pattern] = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),           # OpenAI API keys
    re.compile(r"(api[_-]?key|secret|password|senha)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"OPENAI_API_KEY\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", re.IGNORECASE),  # tokens
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # emails
    re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),  # CPF
]


# ---------------------------------------------------------------------------
# Resultado da Validação
# ---------------------------------------------------------------------------
@dataclass
class GuardrailResult:
    """Resultado da verificação de guardrails."""
    is_safe: bool
    reason: Optional[str] = None
    threat_type: Optional[str] = None


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
@dataclass
class RateLimiter:
    """Controle de taxa de requisições por sessão."""
    max_per_minute: int = MAX_MESSAGES_PER_MINUTE
    timestamps: list[float] = field(default_factory=list)

    def check(self) -> GuardrailResult:
        """Verifica se o limite de requisições foi excedido."""
        now = time.time()
        cutoff = now - 60.0
        self.timestamps = [t for t in self.timestamps if t > cutoff]

        if len(self.timestamps) >= self.max_per_minute:
            logger.warning("Rate limit excedido: %d msgs/min", len(self.timestamps))
            return GuardrailResult(
                is_safe=False,
                reason=(
                    f"⏱️ Você atingiu o limite de {self.max_per_minute} "
                    f"mensagens por minuto. Aguarde um momento."
                ),
                threat_type="rate_limit",
            )

        self.timestamps.append(now)
        return GuardrailResult(is_safe=True)


# ---------------------------------------------------------------------------
# Funções de Validação
# ---------------------------------------------------------------------------

def validate_input(user_input: str) -> GuardrailResult:
    """Valida o input do usuário contra múltiplas ameaças.

    Checks:
      - Tamanho máximo
      - Prompt injection patterns
      - Escopo permitido (domínio PC health)
    """
    # 1. Tamanho
    if len(user_input.strip()) == 0:
        return GuardrailResult(
            is_safe=False,
            reason="Por favor, digite uma pergunta.",
            threat_type="empty_input",
        )

    if len(user_input) > MAX_INPUT_LENGTH:
        logger.warning("Input excede tamanho máximo: %d chars", len(user_input))
        return GuardrailResult(
            is_safe=False,
            reason=f"⚠️ Sua mensagem é muito longa (máx. {MAX_INPUT_LENGTH} caracteres).",
            threat_type="input_too_long",
        )

    # 2. Prompt Injection
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(user_input):
            logger.warning(
                "Prompt injection detectado. Padrão: '%s' | Input: '%.100s'",
                pattern.pattern, user_input,
            )
            return GuardrailResult(
                is_safe=False,
                reason=(
                    "🛡️ Sua mensagem contém padrões que não são permitidos. "
                    "Por favor, reformule sua pergunta sobre o desempenho do PC."
                ),
                threat_type="prompt_injection",
            )

    # 3. Escopo (off-topic check)
    if not _is_in_scope(user_input):
        logger.info("Input fora de escopo: '%.100s'", user_input)
        return GuardrailResult(
            is_safe=False,
            reason=(
                "🎯 Sou especializado em monitoramento de PC. "
                "Posso ajudar com CPU, memória, rede, temperatura e desempenho. "
                "Por favor, faça uma pergunta relacionada à saúde do seu computador."
            ),
            threat_type="out_of_scope",
        )

    return GuardrailResult(is_safe=True)


def validate_output(agent_output: str) -> str:
    """Sanitiza a saída do agente removendo dados sensíveis.

    Returns:
        A saída limpa com dados sensíveis mascarados.
    """
    sanitized = agent_output
    for pattern in _SENSITIVE_OUTPUT_PATTERNS:
        match = pattern.search(sanitized)
        if match:
            logger.warning("Dados sensíveis detectados na saída do agente: padrão '%s'", pattern.pattern)
            sanitized = pattern.sub("[DADO PROTEGIDO]", sanitized)

    return sanitized


def sanitize_input(user_input: str) -> str:
    """Limpa e normaliza o input do usuário.

    - Remove caracteres de controle
    - Normaliza espaços em branco
    - Remove tags HTML/XML
    """
    # Remover caracteres de controle (exceto newline)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", user_input)
    # Remover tags HTML/XML
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    # Normalizar espaços
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def truncate_history(chat_history: list, max_length: int = MAX_HISTORY_LENGTH) -> list:
    """Trunca o histórico de chat para evitar context overflow.

    Mantém as mensagens mais recentes.
    """
    if len(chat_history) > max_length:
        logger.info(
            "Truncando histórico: %d → %d mensagens",
            len(chat_history), max_length,
        )
        return chat_history[-max_length:]
    return chat_history


# ---------------------------------------------------------------------------
# Funções Internas
# ---------------------------------------------------------------------------

def _is_in_scope(user_input: str) -> bool:
    """Verifica se o input está no escopo de monitoramento de PC.

    Mensagens curtas (< 15 chars) são consideradas em escopo
    para permitir saudações e perguntas simples.
    """
    if len(user_input.strip()) < 15:
        return True

    return any(pattern.search(user_input) for pattern in _SCOPE_KEYWORDS)
