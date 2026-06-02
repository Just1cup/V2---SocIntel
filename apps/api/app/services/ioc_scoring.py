from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IoCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    MAC = "mac"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    USER_AGENT = "user_agent"
    ASN = "asn"
    CERTIFICATE = "certificate"
    OTHER = "other"


class SourceTier(str, Enum):
    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3 = "tier3"
    TIER4 = "tier4"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class SourceSignal:
    source_name: str
    tier: SourceTier
    verdict: Verdict
    confidence: float
    last_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    in_malware_delivery: bool = False
    in_sandbox: bool = False
    in_malware_family: bool = False
    in_campaign: bool = False
    in_actor: bool = False
    in_ttp: bool = False
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class InfraSignal:
    is_bulletproof_asn: bool = False
    is_newly_registered: bool = False
    uses_shared_cert: bool = False
    is_tor_exit: bool = False
    is_vpn_proxy: bool = False
    has_suspicious_tld: bool = False
    has_malicious_url_pattern: bool = False
    asn_abuse_score: float = 0.0


@dataclass
class InternalObservation:
    seen_in_siem: bool = False
    seen_in_edr: bool = False
    seen_in_firewall: bool = False
    seen_in_proxy: bool = False
    seen_in_dns: bool = False
    in_previous_case: bool = False
    case_severity: str | None = None
    internal_hit_count: int = 0


@dataclass
class FalsePositiveContext:
    is_known_fp: bool = False
    is_cdn: bool = False
    is_public_resolver: bool = False
    is_shared_hosting: bool = False
    is_greynoise_benign: bool = False
    is_known_scanner: bool = False
    is_allowlisted: bool = False


@dataclass
class IoCInput:
    value: str
    ioc_type: IoCType
    sources: list[SourceSignal] = field(default_factory=list)
    infra: InfraSignal = field(default_factory=InfraSignal)
    internal: InternalObservation = field(default_factory=InternalObservation)
    fp_context: FalsePositiveContext = field(default_factory=FalsePositiveContext)
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScoringResult:
    risk_score: float
    confidence_score: float
    risk_level: RiskLevel
    verdict: Verdict
    evidence_breakdown: dict[str, float]
    penalties: dict[str, float]
    mitre_techniques: list[str]
    tags: list[str]
    justification: str
    recommended_actions: list[str]
    sources_used: list[str]
    last_seen: datetime | None
    analysis_timestamp: datetime
    anti_fp_flags: list[str]


SOURCE_TIER_MULTIPLIER = {
    SourceTier.TIER1: 1.25,
    SourceTier.TIER2: 1.10,
    SourceTier.TIER3: 0.75,
    SourceTier.TIER4: 0.55,
}

EVIDENCE_WEIGHTS = {
    "malicious_reputation_t1": 32,
    "malicious_reputation_t2": 24,
    "malicious_reputation_t3": 14,
    "in_malware_delivery": 22,
    "in_sandbox": 18,
    "in_malware_family": 20,
    "in_campaign": 18,
    "in_actor": 20,
    "in_ttp": 12,
    "multi_source_agreement": 14,
    "internal_observation": 20,
    "internal_high_volume": 8,
}

INFRA_WEIGHTS = {
    "bulletproof_asn": 10,
    "newly_registered": 8,
    "shared_cert": 6,
    "tor_exit": 10,
    "vpn_proxy": 5,
    "suspicious_tld": 6,
    "malicious_url_pattern": 9,
    "high_asn_abuse": 8,
}

PENALTY_WEIGHTS = {
    "known_fp": -40,
    "cdn": -28,
    "public_resolver": -28,
    "shared_hosting": -18,
    "greynoise_benign": -22,
    "known_scanner": -18,
    "allowlisted": -35,
    "single_community_only": -12,
    "stale_ioc": -10,
}

CASE_SEVERITY_WEIGHTS = {"critical": 18, "high": 14, "medium": 8, "low": 4}
RECENCY_BANDS = [(7, 15), (30, 10), (90, 5), (180, 0)]
STALE_THRESHOLD_DAYS = 90
CRITICAL_MIN_SOURCES = 2
CRITICAL_MIN_CONFIDENCE = 65

SOURCE_TIERS = {
    "recorded future": SourceTier.TIER1,
    "mandiant": SourceTier.TIER1,
    "mdti": SourceTier.TIER1,
    "microsoft defender ti": SourceTier.TIER1,
    "crowdstrike": SourceTier.TIER1,
    "abuseipdb": SourceTier.TIER2,
    "urlhaus": SourceTier.TIER2,
    "malwarebazaar": SourceTier.TIER2,
    "virusTotal": SourceTier.TIER2,
    "virustotal": SourceTier.TIER2,
    "alienvault otx": SourceTier.TIER2,
    "otx": SourceTier.TIER2,
    "shodan": SourceTier.TIER2,
    "urlscan.io": SourceTier.TIER2,
    "urlscan": SourceTier.TIER2,
    "censys": SourceTier.TIER2,
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".pw", ".cc", ".club", ".info", ".buzz"}
CDN_HINTS = ("cloudflare", "akamai", "fastly", "cloudfront", "cdn")
RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222", "208.67.220.220"}


def _days_since(dt: datetime | None, now: datetime) -> int | None:
    if dt is None:
        return None
    normalized = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return max(0, (now - normalized).days)


def _recency_bonus(last_seen: datetime | None, now: datetime) -> int:
    days = _days_since(last_seen, now)
    if days is None:
        return 0
    for threshold, bonus in RECENCY_BANDS:
        if days <= threshold:
            return bonus
    return 0


def _source_verdict_weight(signal: SourceSignal) -> float:
    if signal.verdict == Verdict.MALICIOUS:
        key = "malicious_reputation_t1" if signal.tier == SourceTier.TIER1 else "malicious_reputation_t2" if signal.tier == SourceTier.TIER2 else "malicious_reputation_t3"
        base = EVIDENCE_WEIGHTS[key]
    elif signal.verdict == Verdict.SUSPICIOUS:
        key = "malicious_reputation_t1" if signal.tier == SourceTier.TIER1 else "malicious_reputation_t2" if signal.tier == SourceTier.TIER2 else "malicious_reputation_t3"
        base = EVIDENCE_WEIGHTS[key] * 0.6
    else:
        base = 0.0
    return round(base * SOURCE_TIER_MULTIPLIER[signal.tier] * max(0.0, min(1.0, signal.confidence)), 2)


def _compute_confidence(ioc: IoCInput) -> float:
    score = 0.0
    tier_counts = {tier: 0 for tier in SourceTier}
    malicious_sources = 0
    for signal in ioc.sources:
        tier_counts[signal.tier] += 1
        if signal.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
            malicious_sources += 1

    score += min(tier_counts[SourceTier.TIER1] * 20, 40)
    score += min(tier_counts[SourceTier.TIER2] * 10, 30)
    score += min(tier_counts[SourceTier.TIER3] * 4, 12)
    if malicious_sources >= 3:
        score += 20
    elif malicious_sources == 2:
        score += 12
    elif malicious_sources == 1:
        score += 4

    if any(
        signal.in_malware_delivery
        or signal.in_sandbox
        or signal.in_malware_family
        or signal.in_campaign
        or signal.in_actor
        for signal in ioc.sources
    ):
        score += 15

    if ioc.internal.seen_in_siem or ioc.internal.seen_in_edr:
        score += 12
    elif ioc.internal.seen_in_firewall or ioc.internal.seen_in_dns:
        score += 6

    if ioc.fp_context.is_known_fp:
        score -= 30
    if ioc.fp_context.is_allowlisted:
        score -= 20
    if ioc.fp_context.is_cdn or ioc.fp_context.is_public_resolver:
        score -= 15
    return round(max(0.0, min(100.0, score)), 1)


def score_ioc(ioc: IoCInput) -> ScoringResult:
    now = ioc.analysis_timestamp
    evidence: dict[str, float] = {}
    penalties: dict[str, float] = {}
    tags: list[str] = []
    mitre: list[str] = []
    sources_used: list[str] = []
    malicious_sources: set[str] = set()
    last_seen_values: list[datetime] = []
    only_community = True

    for signal in ioc.sources:
        pts = _source_verdict_weight(signal)
        if pts:
            key = f"reputation:{signal.source_name}"
            evidence[key] = round(evidence.get(key, 0) + pts, 2)
        sources_used.append(signal.source_name)
        if signal.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
            malicious_sources.add(signal.source_name)
        if signal.tier in {SourceTier.TIER1, SourceTier.TIER2}:
            only_community = False
        if signal.last_seen:
            last_seen_values.append(signal.last_seen)
        tags.extend(signal.tags)
        mitre.extend(signal.mitre_techniques)

        technical_flags = {
            "malware_delivery": (signal.in_malware_delivery, "in_malware_delivery"),
            "sandbox_detection": (signal.in_sandbox, "in_sandbox"),
            "malware_family": (signal.in_malware_family, "in_malware_family"),
            "campaign_association": (signal.in_campaign, "in_campaign"),
            "actor_attribution": (signal.in_actor, "in_actor"),
            "ttp_mapping": (signal.in_ttp, "in_ttp"),
        }
        for label, (enabled, weight_key) in technical_flags.items():
            if enabled:
                multiplier = SOURCE_TIER_MULTIPLIER[signal.tier] if weight_key != "in_ttp" else 1
                evidence[label] = round(evidence.get(label, 0) + EVIDENCE_WEIGHTS[weight_key] * multiplier, 2)

    most_recent = max(last_seen_values) if last_seen_values else None
    recency = _recency_bonus(most_recent, now)
    if recency:
        evidence["recency"] = recency

    if len(malicious_sources) >= 2:
        multi = EVIDENCE_WEIGHTS["multi_source_agreement"]
        evidence["multi_source_agreement"] = int(multi * 1.3) if len(malicious_sources) >= 4 else multi

    infra_points = 0
    infra = ioc.infra
    if infra.is_bulletproof_asn:
        infra_points += INFRA_WEIGHTS["bulletproof_asn"]
    if infra.is_newly_registered:
        infra_points += INFRA_WEIGHTS["newly_registered"]
    if infra.uses_shared_cert:
        infra_points += INFRA_WEIGHTS["shared_cert"]
    if infra.is_tor_exit:
        infra_points += INFRA_WEIGHTS["tor_exit"]
    if infra.is_vpn_proxy:
        infra_points += INFRA_WEIGHTS["vpn_proxy"]
    if infra.has_suspicious_tld:
        infra_points += INFRA_WEIGHTS["suspicious_tld"]
    if infra.has_malicious_url_pattern:
        infra_points += INFRA_WEIGHTS["malicious_url_pattern"]
    if infra.asn_abuse_score > 0.7:
        infra_points += INFRA_WEIGHTS["high_asn_abuse"]
    if infra_points:
        evidence["infrastructure"] = infra_points

    internal = ioc.internal
    internal_points = 0
    if any([internal.seen_in_siem, internal.seen_in_edr, internal.seen_in_firewall, internal.seen_in_proxy, internal.seen_in_dns]):
        internal_points += EVIDENCE_WEIGHTS["internal_observation"]
    if internal.internal_hit_count > 5:
        internal_points += EVIDENCE_WEIGHTS["internal_high_volume"]
    if internal.in_previous_case and internal.case_severity:
        internal_points += CASE_SEVERITY_WEIGHTS.get(internal.case_severity.lower(), 4)
    if internal_points:
        evidence["internal_observation"] = internal_points

    fp = ioc.fp_context
    anti_fp_flags: list[str] = []
    if fp.is_known_fp:
        penalties["known_false_positive"] = PENALTY_WEIGHTS["known_fp"]
    if fp.is_cdn:
        penalties["cdn_infrastructure"] = PENALTY_WEIGHTS["cdn"]
    if fp.is_public_resolver:
        penalties["public_resolver"] = PENALTY_WEIGHTS["public_resolver"]
    if fp.is_shared_hosting:
        penalties["shared_hosting"] = PENALTY_WEIGHTS["shared_hosting"]
    if fp.is_greynoise_benign:
        penalties["greynoise_benign"] = PENALTY_WEIGHTS["greynoise_benign"]
    if fp.is_known_scanner:
        penalties["known_scanner"] = PENALTY_WEIGHTS["known_scanner"]
    if fp.is_allowlisted:
        penalties["allowlisted"] = PENALTY_WEIGHTS["allowlisted"]
    if only_community and len(malicious_sources) == 1:
        penalties["single_community_source"] = PENALTY_WEIGHTS["single_community_only"]
        anti_fp_flags.append("single_community_source")
    if _days_since(most_recent, now) is not None and (_days_since(most_recent, now) or 0) > STALE_THRESHOLD_DAYS:
        penalties["stale_ioc"] = PENALTY_WEIGHTS["stale_ioc"]

    risk_score = round(max(0.0, min(100.0, sum(evidence.values()) + sum(penalties.values()))), 1)
    confidence_score = _compute_confidence(ioc)
    risk_level = _classify(risk_score)

    if risk_level == RiskLevel.CRITICAL:
        if len(malicious_sources) < CRITICAL_MIN_SOURCES:
            risk_level = RiskLevel.HIGH
            anti_fp_flags.append(f"critical_blocked:insufficient_sources({len(malicious_sources)}<{CRITICAL_MIN_SOURCES})")
        elif confidence_score < CRITICAL_MIN_CONFIDENCE:
            risk_level = RiskLevel.HIGH
            anti_fp_flags.append(f"critical_blocked:low_confidence({confidence_score}<{CRITICAL_MIN_CONFIDENCE})")
        else:
            recent_enough = most_recent is not None and (_days_since(most_recent, now) or 999) <= 30
            has_internal = internal.seen_in_siem or internal.seen_in_edr or internal.in_previous_case
            if not recent_enough and not has_internal:
                risk_level = RiskLevel.HIGH
                anti_fp_flags.append("critical_blocked:no_recent_activity_or_internal_hit")

    if fp.is_known_fp or fp.is_allowlisted:
        verdict = Verdict.BENIGN
    elif risk_score >= 50 and confidence_score >= 50:
        verdict = Verdict.MALICIOUS
    elif risk_score >= 25 or confidence_score >= 35:
        verdict = Verdict.SUSPICIOUS
    elif sum(penalties.values()) < -20:
        verdict = Verdict.BENIGN
    else:
        verdict = Verdict.UNKNOWN

    justification = _build_justification(evidence, penalties, anti_fp_flags)
    return ScoringResult(
        risk_score=risk_score,
        confidence_score=confidence_score,
        risk_level=risk_level,
        verdict=verdict,
        evidence_breakdown={key: round(value, 1) for key, value in evidence.items() if value},
        penalties={key: round(value, 1) for key, value in penalties.items() if value},
        mitre_techniques=sorted(set(mitre)),
        tags=sorted(set(tag for tag in tags if tag)),
        justification=justification,
        recommended_actions=_recommended_actions(risk_level, ioc.ioc_type, internal),
        sources_used=sorted(set(sources_used)),
        last_seen=most_recent,
        analysis_timestamp=now,
        anti_fp_flags=anti_fp_flags,
    )


def _classify(score: float) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _recommended_actions(level: RiskLevel, ioc_type: IoCType, internal: InternalObservation) -> list[str]:
    base = {
        RiskLevel.LOW: [
            "Classificar como potencial False Positive se nao houver hit interno em DnsQuery, DestinationIP, URL ou Hash.",
            "Comparar primeira e ultima observacao do IoC com a janela temporal do alerta.",
        ],
        RiskLevel.MEDIUM: [
            "Buscar ocorrencias internas por DnsQuery, DestinationIP, DestinationPort, URL, Hash e UserAgent.",
            "Correlacionar o IoC com ProcessName, ParentProcessName, CommandLine, FilePath e usuario associado.",
            "Listar infraestrutura relacionada por passive DNS, WHOIS/RDAP, ASN, certificados e redirects.",
        ],
        RiskLevel.HIGH: [
            "Priorizar validacao de True Positive com evidencias internas de endpoint, rede e autenticacao.",
            "Buscar o mesmo IoC nos ultimos 90 dias em proxy, DNS, EDR, firewall e SIEM.",
            "Identificar hosts, usuarios, processos e portas com relacao temporal ao IoC.",
        ],
        RiskLevel.CRITICAL: [
            "Tratar como forte hipotese de True Positive ate que os eventos internos contradigam as fontes externas.",
            "Mapear escopo por SourceIP, Hostname, UserName, ProcessName, CommandLine, DestinationIP e Hash.",
            "Validar se houve payload, autenticacao anomala, execucao de processo ou persistencia no mesmo intervalo.",
        ],
    }
    type_actions = {
        IoCType.IP: ["Buscar DestinationIP e SourceIP iguais ao IoC, separando conexoes por DestinationPort e ProcessName."],
        IoCType.DOMAIN: ["Buscar DnsQuery, SNI, Host header, URL e certificados que resolvam ou referenciem o dominio."],
        IoCType.URL: ["Buscar URL completa, dominio extraido, redirects, UserAgent, status code e processo de origem."],
        IoCType.HASH: ["Buscar Hash, FilePath, ProcessName, ParentProcessName, assinatura e primeira execucao no EDR."],
        IoCType.MAC: ["Buscar MAC em DHCP, NAC, wireless controller, switch logs e inventario de ativos por Hostname e UserName."],
        IoCType.EMAIL: ["Buscar remetente, Return-Path, Message-ID, SPF/DKIM/DMARC, assunto e URLs/ anexos relacionados."],
        IoCType.REGISTRY_KEY: ["Buscar RegistryKey, RegistryValue, ProcessName, ParentProcessName e timestamp da modificacao."],
        IoCType.USER_AGENT: ["Buscar UserAgent em proxy, EDR e netflow, agrupando por Hostname, ProcessName e DestinationIP."],
        IoCType.CERTIFICATE: ["Pivotar por fingerprint, subject, issuer, serial e SAN para hosts relacionados."],
        IoCType.ASN: ["Buscar IPs do ASN em DestinationIP, SourceIP, NetFlow, proxy e DNS resolvido."],
    }
    actions = list(base[level])
    actions.extend(type_actions.get(ioc_type, []))
    if internal.seen_in_edr or internal.seen_in_siem:
        actions.insert(0, "Interpretar como prioridade de validacao porque ha observacao interna confirmada.")
    return actions


def _investigation_guide(ioc: IoCInput, result: ScoringResult) -> dict[str, list[str]]:
    sections = _typed_investigation_sections(ioc.ioc_type)
    sections["Contexto Inicial"] = [
        f"IoC analisado na aba de Investigacao: {ioc.ioc_type.value} {ioc.value}.",
        f"Veredito atual {result.verdict.value}, nivel {result.risk_level.value}, score {result.risk_score:.0f} e confianca {result.confidence_score:.0f}.",
        "Trate o indicador como nao confiavel ate correlacionar reputacao externa com telemetria interna.",
        *sections["Contexto Inicial"],
    ]
    return sections


def _typed_investigation_sections(ioc_type: IoCType) -> dict[str, list[str]]:
    common = {
        "Contexto Inicial": ["Classificacao preliminar: unknown ate validacao por telemetria interna."],
        "Validacao (Triage)": [
            "SIEM/EDR -> campos: Hostname, UserName, EventID, ProcessName, ParentProcessName, CommandLine -> criterio: evento no mesmo intervalo do alerta aumenta confianca.",
            "Rede/Proxy/DNS -> campos: SourceIP, DestinationIP, DestinationPort, DnsQuery, URL, UserAgent -> criterio: recorrencia, multiplos hosts ou processo nao-browser elevam suspeita.",
        ],
        "Pivoting / Expansao": [
            "Timeline -> cruzar primeiro evento do IoC com criacao de processo, resolucao DNS, conexao externa e autenticacao na janela de 30 minutos.",
            "Escopo -> agrupar por Hostname, UserName, SourceIP, ProcessName e DestinationIP para estimar amplitude potencial.",
        ],
        "Evidencias Esperadas": [
            "Evidencia primaria -> hit interno em endpoint, proxy, DNS ou autenticacao no mesmo timestamp do alerta.",
            "Ausencia relevante -> sem hit interno e reputacao isolada reduz sustentacao de True Positive.",
        ],
        "Hipoteses de Cenario (TTPs)": [
            "Possivel Initial Access se o IoC aparecer associado a e-mail, URL, download ou execucao de arquivo.",
            "Possivel C2 se houver periodicidade, UserAgent incomum, DestinationPort atipica ou processo nao-browser.",
            "Hipotese benigna se o IoC estiver ligado a CDN, SaaS, resolver publico, updater legitimo ou inventario corporativo.",
        ],
    }
    typed: dict[IoCType, dict[str, list[str]]] = {
        IoCType.DOMAIN: {
            "Contexto Inicial": [
                "Classificacao preliminar: phishing, C2, DGA, telemetria legitima ou unknown conforme reputacao, idade e uso interno.",
                "Base de reputacao: comparar WHOIS/RDAP, DNS, passive DNS, urlscan, OTX, VirusTotal, URLhaus e registros MX/TXT.",
                "Relevancia: dominio recente, similar ao corporativo ou resolvido por varios hosts pode indicar campanha ativa.",
            ],
            "Validacao (Triage)": [
                "DNS -> campo: DnsQuery, Hostname -> criterio: resolucao em mais de 5 hosts eleva probabilidade de escopo amplo.",
                "WHOIS/RDAP -> campo: DomainAge -> criterio: dominio com menos de 30 dias e trafego interno aumenta risco.",
                "DNS -> campo: DnsQuery -> criterio: typosquatting com 1 caractere diferente de dominio corporativo sustenta phishing.",
                "DNS -> campos: MX, TXT, SPF, DKIM, DMARC -> criterio: ausencia de SPF/DMARC em dominio remetente sustenta spoofing.",
                "DNS/Proxy -> campos: DnsAnswer, DestinationIP -> criterio: dominio limpo apontando para IP malicioso sugere fast-flux, hijack ou infra compartilhada.",
            ],
            "Pivoting / Expansao": [
                "Passive DNS -> buscar subdominios numericos ou aleatorios -> criterio: padrao DGA ou C2.",
                "WHOIS/RDAP -> campos: registrar, creation_date -> criterio: varios dominios criados na mesma janela sugerem campanha.",
                "Certificados -> campos: SSL SAN, fingerprint, issuer -> criterio: wildcard ou multi-SAN revela infraestrutura relacionada.",
                "E-mail gateway -> campos: EmailSender, EmailSubject, EmailURL -> criterio: dominio em links antes do DNS hit sugere phishing.",
                "Proxy -> campos: ProxyURL, HttpHost, DestinationIP -> criterio: acesso por IP direto pode contornar visibilidade de DNS.",
            ],
            "Evidencias Esperadas": [
                "DNS -> campo: DnsQuery timestamp -> multiplos hosts resolvendo em janela curta sustenta DGA sync ou campanha.",
                "Proxy -> campos: ProxyStatusCode, ProxyReferrer -> cadeia 301/302 sustenta redirect de phishing ou evasao.",
                "DNS -> campo: DnsAnswer historico -> troca rapida de IP sustenta fast-flux.",
                "Proxy -> campos: ProxyMethod, BytesSent -> GET seguido de POST para o dominio sustenta coleta de credenciais, exfiltracao ou C2 HTTP.",
            ],
            "Hipoteses de Cenario (TTPs)": [
                "Possivel phishing / credential harvesting | ATT&CK T1566.002 -> dominio similar ao corporativo, TLS valido e registro recente; invalida se houver historico legitimo longo e trafego organico.",
                "Possivel C2 via HTTP/HTTPS | ATT&CK T1071.001 -> beaconing, UserAgent incomum e sem Referer; invalida se for CDN ou SaaS conhecido.",
                "Possivel DGA | ATT&CK T1568.002 -> nome aleatorio, TTL baixo e sem historico; invalida se o nome tiver marca legitima e registrar esperado.",
                "Cenario benigno -> telemetria ou update de software; diferenciar por ProcessName, ParentProcessName, assinatura e documentacao do fabricante.",
            ],
        },
        IoCType.URL: {
            "Contexto Inicial": [
                "Classificacao preliminar: phishing redirect, payload delivery, C2 HTTP, telemetria legitima ou unknown.",
                "Base de reputacao: avaliar dominio base, path, parametros, redirects, urlscan, URLhaus, VirusTotal e proxy logs.",
                "Relevancia: path especifico pode ser malicioso mesmo quando o dominio base possui reputacao mista.",
            ],
            "Validacao (Triage)": [
                "Proxy -> campo: HttpHost -> criterio: separar reputacao do dominio da intencao do path.",
                "Proxy -> campo: ProxyURL -> criterio: paths como /gate.php, /panel/, /update, /check-in sustentam C2.",
                "Proxy -> campos: HttpMethod, RequestBodySize -> criterio: POST grande para URL desconhecida sustenta exfiltracao.",
                "EDR/Proxy -> campos: ProcessName, UserName, UserAgent -> criterio: processo de sistema acessando URL externa e mais suspeito que browser interativo.",
                "Proxy -> campo: UserAgent -> criterio: UserAgent hardcoded ou fora do baseline sustenta malware.",
            ],
            "Pivoting / Expansao": [
                "Proxy -> campos: ProxyURL, Hostname -> buscar path identico em outros hosts.",
                "EDR -> campos: ProcessHash, CommandLine -> identificar binario responsavel pela requisicao.",
                "Proxy -> campos: HttpHost group by ProxyURL -> mapear staging, download e C2.",
                "Proxy -> campos: ProxyReferrer, StatusCode 301/302 -> seguir cadeia ate URL final.",
                "urlscan/Sandbox -> campos: DOM, scripts, redirects -> extrair IoCs derivados sem depender apenas da reputacao.",
            ],
            "Evidencias Esperadas": [
                "Proxy -> campo: ProxyURL timestamp -> acesso periodico em intervalo fixo sustenta beaconing HTTP.",
                "Proxy -> campo: ContentType -> application/octet-stream, script ou arquivo executavel sustenta payload delivery.",
                "Proxy -> campo: RequestBody pattern -> base64/hex em POST sustenta exfiltracao ou C2.",
                "EDR/Email -> campos: ParentProcessName, EventTime delta -> macro, script ou e-mail precedendo acesso sustenta cadeia de ataque.",
            ],
            "Hipoteses de Cenario (TTPs)": [
                "Possivel download de payload | ATT&CK T1105 -> URL .exe/.ps1/.hta, processo nao-browser e pouca interacao; invalida se UserAgent/browser e horario forem compativeis com usuario.",
                "Possivel C2 HTTP | ATT&CK T1071.001 -> acesso periodico, path de check-in e resposta pequena; invalida se retornar 404 consistente ou conteudo estatico legitimo.",
                "Possivel phishing redirect | ATT&CK T1566.002 -> redirect para pagina de login semelhante a corporativa; diferenciar pelo dominio final.",
                "Cenario benigno -> telemetria ou CDN legitimo; diferenciar por ContentType, dominio de analytics e processo browser.",
            ],
        },
        IoCType.HASH: {
            "Contexto Inicial": [
                "Classificacao preliminar: malware, dropper, LOLBIN, ferramenta de TI, falso positivo ou unknown.",
                "Base de reputacao: comparar VirusTotal, MalwareBazaar, sandbox, assinatura digital, caminho e prevalencia interna.",
                "Relevancia: o mesmo hash em varios endpoints define escopo e pode revelar propagacao ou distribuicao administrativa.",
            ],
            "Validacao (Triage)": [
                "Threat Intel -> campos: VirusTotal, MalwareBazaar -> criterio: mais de 5 engines e familia identificada sustentam confirmacao forte.",
                "EDR -> campo: FilePath -> criterio: %TEMP%, %AppData% ou C:\\Users\\Public aumentam suspeita.",
                "EDR -> campos: ParentProcessName, CommandLine -> criterio: Office -> cmd/powershell -> arquivo sustenta execucao maliciosa.",
                "EDR -> campo: SignatureStatus -> criterio: assinatura ausente, desconhecida ou revogada aumenta risco.",
                "EDR -> campos: FileExtension, MagicBytes -> criterio: extensao divergente do tipo real sugere evasao.",
            ],
            "Pivoting / Expansao": [
                "EDR -> campos: FileHash, Hostname -> medir presenca em todos os endpoints.",
                "Malware analysis -> campos: Imphash, TLSH -> buscar variantes com hash diferente e estrutura semelhante.",
                "EDR/Network -> campos: ProcessHash, NetworkConnection -> extrair destinos de C2 gerados pelo processo.",
                "EDR -> campos: ParentProcessHash, FileCreated -> listar artefatos criados pelo mesmo processo pai.",
                "Sandbox -> campos: IP, dominio, mutex, RegistryKey -> coletar IoCs derivados.",
            ],
            "Evidencias Esperadas": [
                "EDR -> campos: FileHash, EventTime -> presenca em multiplos hosts em janela curta sustenta propagacao.",
                "EDR/Network -> campos: ProcessName, NetworkConnection -> processo do hash gerando conexao externa sustenta execucao ativa.",
                "EDR -> campos: RegistryKey, ScheduledTask -> persistencia criada no mesmo timestamp sustenta comprometimento.",
                "EDR -> campos: ParentProcessName, ProcessName -> svchost/explorer com comportamento anomalo sustenta injection ou hollowing.",
            ],
            "Hipoteses de Cenario (TTPs)": [
                "Possivel malware dropper | ATT&CK T1105 + T1059 -> arquivo em diretorio temporario, processo filho e conexao externa; invalida se assinatura, origem e comportamento forem legitimos.",
                "Possivel LOLBIN mal-utilizado | ATT&CK T1218 -> binario legitimo com CommandLine atipico; diferenciar pelo CommandLine completo.",
                "Possivel ransomware | ATT&CK T1486 -> I/O massivo, extensoes alteradas e shadow copies deletadas; invalida sem atividade massiva em disco.",
                "Cenario benigno -> ferramenta de TI nao catalogada; diferenciar por assinatura, origem corporativa e ausencia de rede suspeita.",
            ],
        },
        IoCType.EMAIL: {
            "Contexto Inicial": [
                "Classificacao preliminar: phishing, BEC, spoofing, newsletter legitima ou unknown.",
                "Base de reputacao: avaliar SPF/DKIM/DMARC, Return-Path, Received IP, dominio, URLs e anexos.",
                "Relevancia: remetente e dominio podem indicar campanha contra multiplos usuarios ou tentativa direcionada.",
            ],
            "Validacao (Triage)": [
                "Email gateway -> campo: EmailAuthResult -> criterio: falha SPF + DKIM sustenta spoofing.",
                "Email gateway -> campos: EmailFrom, ReturnPath -> criterio: divergencia sustenta falsificacao de remetente.",
                "Email gateway -> campo: EmailDomain -> criterio: typosquatting com 1 caractere diferente sustenta phishing.",
                "Email gateway -> campo: EmailSender group by Recipient -> criterio: multiplos destinatarios em minutos sugere campanha.",
                "Email header -> campo: EmailReceivedIP -> criterio: IP de envio fora dos MX legitimos do dominio aumenta suspeita.",
            ],
            "Pivoting / Expansao": [
                "Email -> Proxy -> campos: EmailURL, ProxyURL -> verificar clique de destinatarios.",
                "Email/EDR -> campos: EmailAttachment, FileHash -> extrair hash e consultar reputacao.",
                "Email/EDR -> campos: EmailReceived, ProcessCreated -> janela de 30 minutos apos recebimento indica possivel execucao.",
                "Email gateway -> campos: EmailSender, EmailReceivedIP -> identificar historico da campanha.",
                "WHOIS/RDAP -> campo: DomainAge -> dominio jovem com e-mail corporativo falso sustenta phishing preparado.",
            ],
            "Evidencias Esperadas": [
                "Email gateway -> campo: EmailAuthResult fail -> falha com conteudo urgente ou financeiro sustenta phishing.",
                "Email/Proxy -> campos: EmailURL, ProxyURL, HttpResponseCode -> link seguido de redirect para formulario sustenta coleta de credenciais.",
                "EDR -> campos: FileHash, ProcessName, ParentProcessName=WINWORD.EXE -> anexo com macro/script sustenta entrega de malware.",
                "Email gateway -> campos: EmailSender, EventTime -> multiplos destinatarios em minutos sustenta campanha.",
            ],
            "Hipoteses de Cenario (TTPs)": [
                "Possivel phishing de credenciais | ATT&CK T1566.001 + T1078 -> link para login falso e SPF fail; invalida se URL final for dominio legitimo e autenticado.",
                "Possivel entrega de malware via anexo | ATT&CK T1566.001 + T1059 -> anexo Office/PDF com macro, script ou exploit; invalida se arquivo for texto sem codigo executavel.",
                "Possivel BEC | ATT&CK T1566 -> remetente semelhante a executivo e solicitacao financeira; diferenciar por headers e historico do remetente.",
                "Cenario benigno -> newsletter ou marketing com SPF ruim; diferenciar por conteudo nao urgente, dominio historico e ausencia de URL suspeita.",
            ],
        },
        IoCType.MAC: {
            "Contexto Inicial": [
                "Classificacao preliminar: ativo corporativo, dispositivo nao inventariado, spoofing de MAC, movimento fisico/lateral ou unknown.",
                "Base de reputacao: comparar OUI/vendor, inventario, DHCP, NAC, wireless controller e switch logs.",
                "Relevancia: MAC ajuda a vincular atividade a dispositivo, porta, SSID/AP, Hostname e usuario autenticado.",
            ],
            "Validacao (Triage)": [
                "DHCP -> campos: ClientMAC, AssignedIP, Hostname -> criterio: MAC recebendo IP fora do inventario aumenta suspeita.",
                "NAC -> campos: MACAddress, UserName, Posture, AuthResult -> criterio: falha de postura ou usuario inesperado sustenta risco.",
                "Switch/Wireless -> campos: MACAddress, SwitchPort, SSID, APName -> criterio: mudanca rapida de porta/AP pode indicar spoofing ou roaming suspeito.",
                "Inventario -> campos: MACAddress, AssetOwner, DeviceType -> criterio: vendor/OUI incompatível com tipo de ativo sugere anomalia.",
            ],
            "Pivoting / Expansao": [
                "DHCP -> campos: MACAddress group by AssignedIP -> listar IPs associados ao MAC na janela do alerta.",
                "NAC/AD -> campos: MACAddress, UserName -> correlacionar usuarios autenticados pelo mesmo dispositivo.",
                "Switch logs -> campos: SwitchPort, VLAN, MACAddress -> mapear localizacao logica e fisica do dispositivo.",
                "Proxy/DNS -> campos: AssignedIP, DnsQuery, ProxyURL -> derivar atividade de rede a partir do IP associado ao MAC.",
            ],
            "Evidencias Esperadas": [
                "DHCP/NAC -> campos: MACAddress, Hostname -> MAC sem ativo cadastrado mas com trafego recente sustenta dispositivo nao gerenciado.",
                "Switch/Wireless -> campos: MACAddress, APName, SwitchPort -> mesma MAC em locais incompatíveis sustenta spoofing.",
                "DNS/Proxy -> campos: AssignedIP, DnsQuery, URL -> consultas ou acessos suspeitos no periodo do lease sustentam escopo.",
            ],
            "Hipoteses de Cenario (TTPs)": [
                "Possivel dispositivo nao autorizado | ATT&CK T1200 -> MAC sem inventario, DHCP ativo e trafego externo; invalida se inventario confirmar ativo legitimo.",
                "Possivel spoofing de MAC -> mesma MAC em portas/APs incompatíveis ou vendors divergentes; invalida se logs indicarem roaming legitimo.",
                "Possivel pivot interno -> MAC associada a IP que acessa recursos incomuns; diferenciar por usuario, VLAN e baseline do ativo.",
                "Cenario benigno -> troca de placa, dock, VM ou adaptador USB; diferenciar por inventario e eventos de suporte.",
            ],
        },
    }
    typed[IoCType.CERTIFICATE] = {
        "Contexto Inicial": [
            "Classificacao preliminar: C2 HTTPS, infraestrutura compartilhada, certificado corporativo interno ou unknown.",
            "Base de reputacao: avaliar CN, SAN, issuer, fingerprint, serial, notBefore, OCSP/CRL, Censys e Shodan.",
            "Relevancia: certificado permite pivot por infraestrutura mesmo quando IPs e dominios mudam.",
        ],
        "Validacao (Triage)": [
            "TLS logs -> campos: SSL.cert.subject, SSL.cert.san -> criterio: CN divergente do host ou autoassinado aumenta suspeita.",
            "TLS logs -> campo: SSL.cert.issuer -> criterio: issuer desconhecido ou Let's Encrypt em dominio jovem pode indicar infraestrutura recente.",
            "TLS logs -> campo: SSL.cert.notBefore -> criterio: emissao horas antes do evento sustenta infra de ataque recente.",
            "CRL/OCSP -> campo: SSL.cert.serial -> criterio: certificado revogado ainda em uso e anomalo.",
        ],
        "Pivoting / Expansao": [
            "Censys/Shodan -> campo: SSL.cert.fingerprint -> buscar outros IPs com o mesmo certificado.",
            "TLS logs -> campo: SSL.cert.san -> extrair dominios relacionados.",
            "Passive SSL -> campo: fingerprint historico -> verificar rotacao de IP com mesmo certificado.",
            "SIEM -> campos: SSL.cert.serial, Hostname -> medir escopo interno por hosts que viram o mesmo certificado.",
        ],
        "Evidencias Esperadas": [
            "TLS logs -> issuer self-signed e CN generico em processo de sistema sustenta C2 HTTPS.",
            "TLS logs -> mesmo fingerprint em multiplos endpoints sustenta comunicacao com mesma infraestrutura.",
        ],
        "Hipoteses de Cenario (TTPs)": [
            "Possivel C2 via HTTPS | ATT&CK T1071.001 -> autoassinado, CN generico ou dominio de dias; invalida se pertencer a SaaS legitimo com historico.",
            "Possivel infraestrutura compartilhada de ataque -> multiplos IPs com mesmo fingerprint e dominios diferentes; diferenciar por relacao legitima entre dominios.",
            "Cenario benigno -> certificado corporativo interno; diferenciar por issuer da empresa, dominio interno e processo corporativo.",
        ],
    }
    typed[IoCType.REGISTRY_KEY] = {
        "Contexto Inicial": [
            "Classificacao preliminar: persistencia, hijacking, instalacao legitima ou unknown.",
            "Base de reputacao: avaliar RegistryKey, RegistryValue, processo escritor, baseline e arquivo referenciado.",
            "Relevancia: chave de registro pode explicar persistencia ou execucao recorrente apos reinicio/login.",
        ],
        "Validacao (Triage)": [
            "EDR -> campos: RegistryKey, RegistryValue -> criterio: Run/RunOnce aponta para executavel de usuario aumenta suspeita.",
            "EDR -> campos: ProcessName, ParentProcessName -> criterio: processo de usuario modificando chave de sistema e anomalo.",
            "EDR -> campo: RegistryValue diff -> criterio: valor novo sem evento de instalacao correspondente sustenta suspeita.",
            "EDR -> campos: RegistryEventTime, ProcessCreated -> criterio: chave criada logo apos execucao suspeita sustenta persistencia.",
        ],
        "Pivoting / Expansao": [
            "EDR -> campos: RegistryKey, Hostname -> buscar mesma chave em outros endpoints.",
            "EDR -> campos: ProcessHash, FileHash -> identificar binario que escreveu a chave.",
            "EDR -> campos: ProcessName, RegistryKey timeline -> listar outras chaves modificadas pelo mesmo processo.",
            "EDR -> campos: RegistryValue, FilePath -> confirmar existencia e hash do arquivo apontado.",
        ],
        "Evidencias Esperadas": [
            "EDR -> RegistryValue apontando para %TEMP% ou AppData sustenta persistencia suspeita.",
            "EDR -> HKLM\\SYSTEM\\CurrentControlSet\\Services com ImagePath nao catalogado sustenta servico suspeito.",
            "EDR -> AppInit_DLLs, Winlogon ou CLSID alterados sustentam hijacking.",
        ],
        "Hipoteses de Cenario (TTPs)": [
            "Possivel persistencia via Run key | ATT&CK T1547.001 -> Run/RunOnce com executavel suspeito; invalida se software legitimo de TI explicar a chave.",
            "Possivel COM hijacking | ATT&CK T1546.015 -> HKCU\\Software\\Classes\\CLSID com DLL personalizada; invalida se CLSID for componente legitimo.",
            "Possivel modificacao de servico | ATT&CK T1543.003 -> ImagePath nao catalogado; diferenciar por existencia previa do servico.",
            "Cenario benigno -> instalacao legitima; diferenciar por processo assinado e evento de instalacao no mesmo timestamp.",
        ],
    }
    typed[IoCType.USER_AGENT] = {
        "Contexto Inicial": [
            "Classificacao preliminar: C2 hardcoded, spoofing de browser, aplicacao interna, telemetria legitima ou unknown.",
            "Base de reputacao: comparar baseline de browser, proxy logs, ProcessName, DestinationIP e frequencia.",
            "Relevancia: UserAgent conecta comportamento HTTP a processo, destino e possivel implant.",
        ],
        "Validacao (Triage)": [
            "Proxy -> campo: UserAgent baseline -> criterio: IE6 ou UA obsoleto em ambiente moderno e anomalia.",
            "Proxy -> campo: UserAgent string pattern -> criterio: Mozilla/4.0 generico ou string incompleta sustenta malware.",
            "EDR/Proxy -> campos: ProcessName, UserAgent -> criterio: PowerShell com UA de browser sustenta spoofing.",
            "Proxy -> campo: UserAgent group by Hostname -> criterio: UA identico em multiplos hosts sugere mesmo implant.",
        ],
        "Pivoting / Expansao": [
            "Proxy -> campos: UserAgent, ProxyURL -> mapear todas as URLs acessadas com o UA.",
            "Proxy/NetFlow -> campos: UserAgent, DestinationIP -> identificar padrao de destino.",
            "EDR/Proxy -> campos: ProcessName, UserAgent sequence -> detectar rotacao de UA por processo.",
        ],
        "Evidencias Esperadas": [
            "Proxy -> campos: UserAgent, DestinationIP group by Hostname -> UA identico em varios endpoints e mesmo destino sustenta implant.",
            "Proxy -> campos: ProxyHeaders, UserAgent -> requisicoes periodicas com headers pobres sustentam cliente automatizado.",
        ],
        "Hipoteses de Cenario (TTPs)": [
            "Possivel C2 com UA hardcoded | ATT&CK T1071.001 -> UA fixo, comunicacao periodica e processo nao-browser; invalida se browser legitimo usar UA padrao.",
            "Possivel evasao de proxy via UA spoofing | ATT&CK T1090 -> processo de sistema com UA de browser; diferenciar pelo ProcessName.",
            "Cenario benigno -> aplicacao interna com UA customizado; diferenciar por destino interno e software catalogado.",
        ],
    }
    return typed.get(ioc_type, common)


def _build_justification(evidence: dict[str, float], penalties: dict[str, float], anti_fp_flags: list[str]) -> str:
    parts: list[str] = []
    if evidence:
        top = sorted(evidence.items(), key=lambda item: item[1], reverse=True)[:4]
        parts.append("Evidencias principais: " + "; ".join(f"{key} (+{value:.0f}pts)" for key, value in top))
    if penalties:
        parts.append("Penalidades: " + "; ".join(f"{key} ({value:.0f}pts)" for key, value in penalties.items()))
    if anti_fp_flags:
        parts.append("Controles anti-FP: " + "; ".join(anti_fp_flags))
    return " | ".join(parts) or "Sem evidencias suficientes para elevar o risco."


def result_to_dict(ioc: IoCInput, result: ScoringResult) -> dict[str, Any]:
    return {
        "ioc": {"value": ioc.value, "type": ioc.ioc_type.value},
        "verdict": result.verdict.value,
        "risk_score": result.risk_score,
        "confidence_score": result.confidence_score,
        "risk_level": result.risk_level.value,
        "last_seen": result.last_seen.isoformat() if result.last_seen else None,
        "analysis_timestamp": result.analysis_timestamp.isoformat(),
        "sources": result.sources_used,
        "evidence_breakdown": result.evidence_breakdown,
        "penalties": result.penalties,
        "anti_fp_flags": result.anti_fp_flags,
        "mitre_techniques": result.mitre_techniques,
        "tags": result.tags,
        "justification": result.justification,
        "recommended_actions": result.recommended_actions,
        "investigation_guide": _investigation_guide(ioc, result),
    }


def apply_scoring(payload: dict[str, Any], ioc_type: str, ioc_value: str) -> dict[str, Any]:
    ioc = build_ioc_input(payload, ioc_type, ioc_value)
    scoring = score_ioc(ioc)
    scoring_payload = result_to_dict(ioc, scoring)
    payload["risk"] = int(round(scoring.risk_score))
    payload["level"] = scoring.risk_level.value
    payload["verdict"] = scoring.verdict.value
    payload["recommendations"] = scoring.recommended_actions
    payload["confidence_score"] = scoring.confidence_score
    payload["scoring"] = scoring_payload
    payload.setdefault("risk_meta", {})["scoring_v2"] = scoring_payload
    payload["risk_meta"]["investigation_guide"] = scoring_payload["investigation_guide"]
    if scoring.justification:
        findings = list(payload.get("findings") or [])
        findings.append(f"Scoring V2: {scoring.justification}")
        payload["findings"] = findings
    return payload


def build_ioc_input(payload: dict[str, Any], ioc_type: str, ioc_value: str) -> IoCInput:
    provider_details = payload.get("provider_details") if isinstance(payload.get("provider_details"), dict) else {}
    risk_factors = payload.get("risk_factors") if isinstance(payload.get("risk_factors"), list) else []
    source_map: dict[str, SourceSignal] = {}

    for factor in risk_factors:
        if not isinstance(factor, dict):
            continue
        source = str(factor.get("source") or "Fonte desconhecida")
        points = _as_float(factor.get("points"))
        reason = str(factor.get("reason") or "")
        signal = _get_or_create_signal(source_map, source)
        signal.verdict = Verdict.MALICIOUS if points >= 20 else Verdict.SUSPICIOUS
        signal.confidence = max(signal.confidence, _confidence_from_points(points))
        _apply_reason_context(signal, reason)

    for source, details in provider_details.items():
        if not isinstance(details, dict):
            continue
        signal = _get_or_create_signal(source_map, str(source))
        _apply_provider_context(signal, details)

    infra = _build_infra(ioc_value, provider_details)
    fp_context = _build_fp_context(ioc_value, provider_details)
    return IoCInput(
        value=ioc_value,
        ioc_type=_normalize_ioc_type(ioc_type, ioc_value),
        sources=list(source_map.values()),
        infra=infra,
        fp_context=fp_context,
    )


def _normalize_ioc_type(ioc_type: str, value: str) -> IoCType:
    normalized = ioc_type.lower()
    if normalized == "domain_email":
        normalized = "email" if "@" in value else "domain"
    if normalized == "cert":
        normalized = "certificate"
    return IoCType(normalized) if normalized in {item.value for item in IoCType} else IoCType.OTHER


def _get_or_create_signal(source_map: dict[str, SourceSignal], source: str) -> SourceSignal:
    if source not in source_map:
        source_map[source] = SourceSignal(
            source_name=source,
            tier=SOURCE_TIERS.get(source.strip().lower(), SourceTier.TIER3),
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
        )
    return source_map[source]


def _apply_reason_context(signal: SourceSignal, reason: str) -> None:
    text = reason.lower()
    if "malware" in text or "payload" in text or "url associada" in text:
        signal.in_malware_delivery = True
    if "sandbox" in text:
        signal.in_sandbox = True
    if "campaign" in text or "campanha" in text:
        signal.in_campaign = True
    if "actor" in text or "ator" in text:
        signal.in_actor = True
    if "ttp" in text or "mitre" in text or "attack" in text:
        signal.in_ttp = True


def _apply_provider_context(signal: SourceSignal, details: dict[str, Any]) -> None:
    status = str(details.get("query_status") or "").lower()
    if status == "ok" and signal.source_name in {"URLhaus", "MalwareBazaar"}:
        signal.verdict = Verdict.MALICIOUS
        signal.confidence = max(signal.confidence, 0.9)
    if signal.source_name == "AbuseIPDB":
        abuse_score = _as_float(details.get("abuseConfidenceScore") or details.get("abuse_confidence_score"))
        if abuse_score > 0:
            signal.verdict = Verdict.MALICIOUS if abuse_score >= 70 else Verdict.SUSPICIOUS
            signal.confidence = max(signal.confidence, min(abuse_score / 100, 0.98))
    if signal.source_name in {"VirusTotal", "VT"}:
        malicious = _as_float(details.get("malicious"))
        suspicious = _as_float(details.get("suspicious"))
        total = max(_as_float(details.get("total")), malicious + suspicious)
        if malicious or suspicious:
            signal.verdict = Verdict.MALICIOUS if malicious >= 2 else Verdict.SUSPICIOUS
            signal.confidence = max(signal.confidence, min((malicious + suspicious) / max(total, 1), 0.98))
    if signal.source_name in {"AlienVault OTX", "OTX"}:
        pulses = _as_float(details.get("pulse_count") or details.get("pulses"))
        if pulses:
            signal.verdict = Verdict.MALICIOUS if pulses >= 3 else Verdict.SUSPICIOUS
            signal.confidence = max(signal.confidence, min(0.45 + pulses / 10, 0.9))
    if details.get("tags") and isinstance(details["tags"], list):
        signal.tags = sorted(set(signal.tags + [str(tag) for tag in details["tags"] if tag]))
    signature = details.get("signature")
    if signature:
        signal.tags = sorted(set(signal.tags + [str(signature)]))
        signal.in_malware_family = True
    if details.get("payloads") or details.get("urls"):
        signal.in_malware_delivery = True
    if details.get("firstseen") or details.get("first_seen") or details.get("last_seen"):
        signal.last_seen = _parse_datetime(details.get("last_seen") or details.get("firstseen") or details.get("first_seen"))


def _build_infra(value: str, provider_details: dict[str, Any]) -> InfraSignal:
    text = f"{value} {provider_details}".lower()
    return InfraSignal(
        is_bulletproof_asn="bulletproof" in text,
        uses_shared_cert="shared_cert" in text or "shared certificate" in text,
        is_tor_exit="tor exit" in text,
        is_vpn_proxy="vpn" in text or "proxy" in text,
        has_suspicious_tld=any(tld in value.lower() for tld in SUSPICIOUS_TLDS),
        has_malicious_url_pattern=any(token in value.lower() for token in ("login", "payload", "loader", "gate.php", "cmd=", "c2")),
        asn_abuse_score=_extract_asn_abuse_score(provider_details),
    )


def _build_fp_context(value: str, provider_details: dict[str, Any]) -> FalsePositiveContext:
    rdap_details = provider_details.get("RDAP") if isinstance(provider_details.get("RDAP"), dict) else {}
    shodan_details = provider_details.get("Shodan") if isinstance(provider_details.get("Shodan"), dict) else {}
    internal_details = provider_details.get("InternalAllowlist") if isinstance(provider_details.get("InternalAllowlist"), dict) else {}
    greynoise_details = provider_details.get("GreyNoise") if isinstance(provider_details.get("GreyNoise"), dict) else {}
    rdap_text = f"{rdap_details}".lower()
    shodan_text = f"{shodan_details}".lower()
    return FalsePositiveContext(
        is_cdn=any(hint in rdap_text for hint in CDN_HINTS),
        is_public_resolver=value.strip() in RESOLVERS,
        is_shared_hosting="shared hosting" in rdap_text,
        is_greynoise_benign=str(greynoise_details.get("classification") or "").lower() == "benign",
        is_known_scanner=bool(shodan_details.get("known_scanner")) or "shodan crawl" in shodan_text or "censys crawl" in shodan_text,
        is_allowlisted=bool(internal_details.get("allowlisted")),
    )


def _extract_asn_abuse_score(provider_details: dict[str, Any]) -> float:
    text = str(provider_details)
    if "asn_abuse_score" not in text:
        return 0.0
    for details in provider_details.values():
        if isinstance(details, dict):
            score = _as_float(details.get("asn_abuse_score"))
            if score:
                return score
    return 0.0


def _confidence_from_points(points: float) -> float:
    if points <= 0:
        return 0.0
    return max(0.35, min(points / 30, 0.95))


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
