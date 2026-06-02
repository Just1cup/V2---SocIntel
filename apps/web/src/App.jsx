import { Suspense, lazy, useEffect, useState } from "react";
import { sleep } from "./asyncControl";
import { api } from "./api";

const MitreView = lazy(() => import("./MitreView").then((module) => ({ default: module.MitreView })));
const ThreatIntellView = lazy(() => import("./ThreatIntellView").then((module) => ({ default: module.ThreatIntellView })));

const IOC_TYPES = [
  { value: "ip", label: "IP" },
  { value: "domain_email", label: "Domain / Email" },
  { value: "url", label: "URL" },
  { value: "hash", label: "Hash" },
  { value: "mac", label: "MAC" },
];
const PROVIDER_INFO = {
  AbuseIPDB: "Base de reputacao de IPs abusivos. Indica historico de denuncias, score de abuso e confianca para enderecos IP.",
  VirusTotal: "Agregador de reputacao que correlaciona multiplos motores e observacoes para IPs, dominios, URLs e hashes.",
  RDAP: "Servico de registro que ajuda a identificar ownership, ASN, blocos IP e metadados administrativos do recurso.",
  "AlienVault OTX": "Plataforma de threat intelligence colaborativa com pulses, indicadores observados e contexto comunitario.",
  AlienVault: "Plataforma de threat intelligence colaborativa com pulses, indicadores observados e contexto comunitario.",
  urlscan: "Servico de analise e captura de paginas web que revela redirecionamentos, infraestrutura e elementos carregados.",
  "urlscan.io": "Servico de analise e captura de paginas web que revela redirecionamentos, infraestrutura e elementos carregados.",
  Shodan: "Motor de busca para ativos expostos na internet, util para banners, portas abertas e superficie de exposicao.",
  WHOIS: "Consulta de registro de dominio para ownership, datas relevantes, nameservers e informacoes de registrador.",
  DNS: "Resolucao e contexto tecnico de dominios, incluindo registros, nameservers e apontamentos observados.",
  OTX: "Fonte de intelligence comunitaria da AlienVault com indicadores e campanhas correlacionadas.",
  URLhaus: "Feed da abuse.ch focado em URLs, hosts e payloads usados para distribuicao de malware.",
  MalwareBazaar: "Repositorio comunitario da abuse.ch para correlacao de hashes, familias, tags e amostras de malware.",
};
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$/;
const SESSION_KEY = "socintel_v2_session";
const THEME_KEY = "socintel_v2_theme";
const HIDDEN_JOBS_KEY = "socintel_v2_hidden_jobs";

function readJsonStorage(storage, key, fallback) {
  try {
    const raw = storage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function readSession() {
  return readJsonStorage(localStorage, SESSION_KEY, null);
}

function writeSession(session) {
  localStorage.setItem(
    SESSION_KEY,
    JSON.stringify({
      user: session?.user || null,
      memberships: session?.memberships || [],
    }),
  );
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

function readTheme() {
  return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
}

function writeTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
}

function readHiddenJobIds() {
  const parsed = readJsonStorage(localStorage, HIDDEN_JOBS_KEY, []);
  return Array.isArray(parsed) ? parsed : [];
}

function writeHiddenJobIds(jobIds) {
  localStorage.setItem(HIDDEN_JOBS_KEY, JSON.stringify(jobIds));
}

function sanitizeEmail(value) {
  return value.trim().toLowerCase();
}

function sanitizeText(value) {
  return value.replace(/\s+/g, " ").trim();
}

function validateAuthForm({ email, password }) {
  if (!sanitizeEmail(email)) return "Email is required.";
  if (!PASSWORD_REGEX.test(password)) {
    return "Senha invalida. Use 8+ caracteres com maiuscula, minuscula e numero.";
  }
  return "";
}

function validatePasswordChangeForm({ current_password, new_password, confirm_password }) {
  if (!PASSWORD_REGEX.test(current_password)) {
    return "Senha atual invalida. Use 8+ caracteres com maiuscula, minuscula e numero.";
  }
  if (!PASSWORD_REGEX.test(new_password)) {
    return "Nova senha invalida. Use 8+ caracteres com maiuscula, minuscula e numero.";
  }
  if (new_password !== confirm_password) return "A confirmacao da nova senha nao confere.";
  if (current_password === new_password) return "A nova senha precisa ser diferente da senha atual.";
  return "";
}

function isAbortError(error) {
  return error?.name === "AbortError";
}

function mapLevel(level) {
  const normalized = String(level || "").toLowerCase();
  if (normalized.includes("critical") || normalized.includes("alto") || normalized.includes("high")) return "risk-high";
  if (normalized.includes("medium") || normalized.includes("medio") || normalized.includes("médio")) return "risk-medium";
  return "risk-low";
}

function upsertJob(list, nextJob) {
  const filtered = list.filter((item) => item.id !== nextJob.id);
  return [nextJob, ...filtered];
}

function displayIocType(type) {
  if (type === "domain_email") return "DOMAIN / EMAIL";
  return String(type || "").toUpperCase();
}

function buildOsintLinks(job) {
  if (!job) return [];
  const value = encodeURIComponent(job.ioc_value || "");
  if (job.ioc_type === "ip") {
    return [
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/ip-address/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/indicator/ip/${value}` },
      { label: "AbuseIPDB", href: `https://www.abuseipdb.com/check/${value}` },
      { label: "Shodan", href: `https://www.shodan.io/host/${value}` },
      { label: "URLhaus", href: `https://urlhaus.abuse.ch/browse.php?search=${value}` },
    ];
  }
  if (job.ioc_type === "domain_email") {
    const isEmail = String(job.ioc_value || "").includes("@");
    const domainValue = encodeURIComponent(String(job.ioc_value || "").split("@").pop() || "");
    return [
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/search/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
      ...(isEmail ? [{ label: "Hunter", href: `https://hunter.io/search/${value}` }] : []),
      { label: "WHOIS", href: `https://who.is/whois/${domainValue}` },
      { label: "URLhaus", href: `https://urlhaus.abuse.ch/browse.php?search=${domainValue}` },
    ];
  }
  if (job.ioc_type === "domain" || job.ioc_type === "url") {
    return [
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/search/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
      { label: "urlscan.io", href: `https://urlscan.io/search/#domain:${value}` },
      { label: "WHOIS", href: `https://who.is/whois/${value}` },
      { label: "URLhaus", href: `https://urlhaus.abuse.ch/browse.php?search=${value}` },
    ];
  }
  if (job.ioc_type === "email") {
    return [
      { label: "Hunter", href: `https://hunter.io/search/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
    ];
  }
  if (job.ioc_type === "hash") {
    return [
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/file/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
      { label: "URLhaus", href: `https://urlhaus.abuse.ch/browse.php?search=${value}` },
      { label: "MalwareBazaar", href: `https://bazaar.abuse.ch/browse.php?search=${value}` },
    ];
  }
  if (job.ioc_type === "mac") {
    return [{ label: "MAC Vendors", href: `https://macvendors.com/query/${value}` }];
  }
  return [];
}

function normalizeProviderName(name) {
  const normalized = String(name || "").trim();
  const aliases = {
    OTX: "AlienVault OTX",
    AlienVault: "AlienVault OTX",
    urlscan: "urlscan.io",
  };
  return aliases[normalized] || normalized;
}

function formatBytes(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return String(value);
  if (numeric < 1024) return `${numeric} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = numeric / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function formatProviderDetails(details) {
  return Object.entries(details || {})
    .filter(([, value]) => value !== null && value !== undefined && value !== "" && (!Array.isArray(value) || value.length > 0))
    .map(([key, value]) => {
      const label = key
        .replace(/_/g, " ")
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .replace(/\b\w/g, (char) => char.toUpperCase());
      const formattedValue = Array.isArray(value)
        ? value.join(", ")
        : typeof value === "object"
          ? JSON.stringify(value)
          : key.toLowerCase() === "size"
            ? formatBytes(value)
            : String(value);
      return { label, value: formattedValue };
    });
}

function providerIntegrationStatus(details) {
  const normalized = Object.fromEntries(
    Object.entries(details || {}).map(([key, value]) => [key.toLowerCase(), String(value || "").toLowerCase()]),
  );
  const status = normalized.status || normalized.query_status || normalized.querystatus || "";
  if (status === "auth_failed" || status === "unauthorized" || status === "forbidden") {
    return {
      tone: "warning",
      title: "Integração indisponível",
      message: "A consulta não foi concluída porque a credencial do provider falhou ou não está configurada.",
      action: "Verifique a API key/token deste provider no backend antes de usar esse resultado como evidência.",
    };
  }
  if (status === "error" || status === "failed") {
    return {
      tone: "warning",
      title: "Provider retornou erro",
      message: "A fonte externa respondeu com erro durante a consulta.",
      action: "Tente novamente ou confirme disponibilidade e configuração da integração.",
    };
  }
  if (status === "ok" || status === "success" || status === "found") {
    return {
      tone: "ok",
      title: "Integração consultada",
      message: "A fonte externa respondeu com dados para esta análise.",
      action: null,
    };
  }
  return null;
}

function parseFindingProvider(finding) {
  const text = String(finding || "");
  const providerMatch = text.match(/^([A-Za-z0-9./ -]{2,40}):\s*(.*)$/);
  if (!providerMatch) {
    return { provider: null, detail: text, description: null };
  }
  const provider = providerMatch[1].trim();
  const detail = providerMatch[2].trim();
  const description = PROVIDER_INFO[provider] || null;
  return { provider, detail, description };
}

function normalizeFindingText(finding) {
  return String(finding || "")
    .replace(/^[•\s]+/, "")
    .replace(/^└──\s*/, "")
    .trim();
}

function findingTone(finding) {
  const text = String(finding || "").toLowerCase();
  if (text.includes("failed") || text.includes("presente") || text.includes("suspeito") || text.includes("risco")) return "finding-warning";
  if (text.includes("nenhum") || text.includes("não foram encontrados") || text.includes("baixo")) return "finding-good";
  return "finding-neutral";
}

function compactUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return String(value || "").replace(/^https?:\/\//, "").split("/")[0] || String(value || "");
  }
}

function osintLinkMeta(link) {
  const host = compactUrl(link.href);
  const label = normalizeProviderName(link.label);
  return {
    label,
    host,
    description: PROVIDER_INFO[label] || "Abrir fonte externa para correlacao manual.",
  };
}

function shouldHideFinding(finding) {
  const normalized = String(finding || "").trim().replace(/\s+/g, " ");
  return (
    normalized.includes("===") ||
    normalized.includes("Reputação e detecções de malícia") ||
    normalized.includes("Histórico de abuso reportado") ||
    normalized.includes("Threat intel comunitário") ||
    normalized.includes("Registro do provedor") ||
    normalized.includes("Serviços expostos e vulnerabilidades")
  );
}

function buildProviderViewerData(link, findings, activeResult) {
  const providerName = normalizeProviderName(link?.label);
  const rawDetails = activeResult?.provider_details?.[providerName] || {};
  const providerFindings = findings
    .map((item) => ({ raw: item, parsed: parseFindingProvider(item) }))
    .filter((entry) => normalizeProviderName(entry.parsed.provider) === providerName);

  return {
    providerName,
    description: PROVIDER_INFO[providerName] || "Fonte OSINT utilizada na consolidacao desta analise.",
    highlights: providerFindings.map((entry) => entry.parsed.detail || entry.raw).filter(Boolean),
    details: formatProviderDetails(rawDetails),
    integrationStatus: providerIntegrationStatus(rawDetails),
    verdict: activeResult?.legacy_verdict || activeResult?.verdict || "Sem veredito consolidado.",
    recommendations: activeResult?.recommendations || [],
  };
}

export function App() {
  const [theme, setTheme] = useState(() => readTheme());
  const [session, setSession] = useState(() => {
    const stored = readSession();
    return stored ? { ...stored, token: "" } : null;
  });
  const [activeTab, setActiveTab] = useState("analysis");
  const [loginForm, setLoginForm] = useState({ email: session?.user?.email || "admin@socintel.dev", password: "" });
  const [jobForm, setJobForm] = useState({ ioc_type: "ip", ioc_value: "8.8.8.8" });
  const [activeJob, setActiveJob] = useState(null);
  const [activeResult, setActiveResult] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [passwordForm, setPasswordForm] = useState({ current_password: "", new_password: "", confirm_password: "" });
  const [hiddenJobIds, setHiddenJobIds] = useState(() => readHiddenJobIds());
  const [pendingDeleteJob, setPendingDeleteJob] = useState(null);
  const [activeOsintLink, setActiveOsintLink] = useState(null);
  const [isSocGuideCollapsed, setIsSocGuideCollapsed] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [passwordError, setPasswordError] = useState("");
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [jobError, setJobError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    writeTheme(theme);
  }, [theme]);

  useEffect(() => {
    writeHiddenJobIds(hiddenJobIds);
  }, [hiddenJobIds]);

  useEffect(() => {
    const hasOpenModal = Boolean(pendingDeleteJob || activeOsintLink);
    document.body.classList.toggle("modal-open", hasOpenModal);
    return () => document.body.classList.remove("modal-open");
  }, [pendingDeleteJob, activeOsintLink]);

  useEffect(() => {
    if (!session?.user) return;
    let ignore = false;
    const controller = new AbortController();

    async function loadJobs() {
      try {
        const payload = await api.listAnalysisJobs(session.token, { signal: controller.signal });
        if (!ignore) setJobs(payload);
      } catch (error) {
        if (isAbortError(error)) return;
        if (!ignore) setJobError(error.message);
      }
    }

    loadJobs();
    return () => {
      ignore = true;
      controller.abort();
    };
  }, [session?.user?.id, activeJob?.status]);

  useEffect(() => {
    if (!session?.user || !activeJob?.id) return;
    if (activeJob.status === "completed" || activeJob.status === "failed") return;

    let cancelled = false;
    const controller = new AbortController();

    async function pollJob() {
      let delay = 700;
      while (!cancelled) {
        try {
          const nextJob = await api.getAnalysisJob(session.token, activeJob.id, { signal: controller.signal });
          if (cancelled) return;
          setActiveJob(nextJob);
          setJobs((current) => upsertJob(current, nextJob));
          if (nextJob.status === "completed") {
            const result = await api.getAnalysisResult(session.token, nextJob.id, { signal: controller.signal });
            if (!cancelled) setActiveResult(result);
            return;
          }
          if (nextJob.status === "failed") return;
          await sleep(delay, controller.signal);
          delay = Math.min(delay + 250, 1500);
        } catch (error) {
          if (isAbortError(error)) return;
          if (!cancelled) setJobError(error.message);
          return;
        }
      }
    }

    pollJob();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [session?.user?.id, activeJob?.id]);

  useEffect(() => {
    if (!session?.user || !activeJob?.id) return;
    if (activeJob.status !== "completed" || activeResult?.job_id === activeJob.id) return;

    let cancelled = false;
    const controller = new AbortController();

    async function loadCompletedResult() {
      try {
        const result = await api.getAnalysisResult(session.token, activeJob.id, { signal: controller.signal });
        if (!cancelled) setActiveResult(result);
      } catch (error) {
        if (isAbortError(error)) return;
        if (!cancelled) setJobError(error.message);
      }
    }

    loadCompletedResult();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [session?.user?.id, activeJob?.id, activeJob?.status, activeResult?.job_id]);

  async function handleLogin(event) {
    event.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const normalized = { email: sanitizeEmail(loginForm.email), password: loginForm.password };
    const validationError = validateAuthForm(normalized);
    if (validationError) {
      setAuthError(validationError);
      setAuthLoading(false);
      return;
    }
    try {
      const payload = await api.login(normalized.email, normalized.password);
      const nextSession = {
        token: "",
        user: payload.user,
        memberships: payload.memberships,
      };
      setSession(nextSession);
      writeSession(nextSession);
      setLoginForm((current) => ({ ...current, password: "" }));
      setActiveTab("analysis");
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleSubmitAnalysis(event) {
    event.preventDefault();
    if (!session?.user) return;
    setBusy(true);
    setJobError("");
    setFormMessage("");
    setActiveResult(null);
    try {
      const created = await api.createAnalysisJob(session.token, {
        ioc_type: jobForm.ioc_type,
        ioc_value: jobForm.ioc_value,
      });
      setActiveJob(created);
      setJobs((current) => upsertJob(current, created));
      setHiddenJobIds((current) => current.filter((item) => item !== created.id));
      await sleep(250);
      const immediateJob = await api.getAnalysisJob(session.token, created.id);
      setActiveJob(immediateJob);
      setJobs((current) => upsertJob(current, immediateJob));
      if (immediateJob.status === "completed") {
        const result = await api.getAnalysisResult(session.token, immediateJob.id);
        setActiveResult(result);
      }
      setActiveTab("analysis");
    } catch (error) {
      setJobError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleChangePassword(event) {
    event.preventDefault();
    if (!session?.user) return;
    setPasswordLoading(true);
    setPasswordError("");
    setFormMessage("");
    const validationError = validatePasswordChangeForm(passwordForm);
    if (validationError) {
      setPasswordError(validationError);
      setPasswordLoading(false);
      return;
    }
    try {
      await api.changePassword(session.token, passwordForm);
      setPasswordForm({ current_password: "", new_password: "", confirm_password: "" });
      setFormMessage("Senha atualizada com sucesso.");
    } catch (error) {
      setPasswordError(error.message);
    } finally {
      setPasswordLoading(false);
    }
  }

  async function refreshResult() {
    if (!session?.user || !activeJob?.id) return;
    try {
      const nextJob = await api.getAnalysisJob(session.token, activeJob.id);
      setActiveJob(nextJob);
      setJobs((current) => upsertJob(current, nextJob));
      if (nextJob.status === "completed") {
        const result = await api.getAnalysisResult(session.token, nextJob.id);
        setActiveResult(result);
      }
    } catch (error) {
      setJobError(error.message);
    }
  }

  async function selectJob(job) {
    setActiveJob(job);
    setJobs((current) => upsertJob(current, job));
    if (!session?.user) return;
    if (job.status === "completed") {
      const result = await api.getAnalysisResult(session.token, job.id);
      setActiveResult(result);
    } else {
      setActiveResult(null);
    }
    setActiveTab("analysis");
  }

  function logout() {
    api.logout(session?.token).catch(() => null);
    clearSession();
    setSession(null);
    setJobs([]);
    setPasswordForm({ current_password: "", new_password: "", confirm_password: "" });
    setActiveJob(null);
    setActiveResult(null);
  }

  function hideJob() {
    if (!pendingDeleteJob) return;
    const job = pendingDeleteJob;
    setJobs((current) => current.filter((item) => item.id !== job.id));
    setHiddenJobIds((current) => [job.id, ...current.filter((item) => item !== job.id)]);
    if (activeJob?.id === job.id) {
      setActiveJob(null);
      setActiveResult(null);
    }
    setFormMessage(`Busca ${job.ioc_value} removida da lista.`);
    setPendingDeleteJob(null);
  }

  const visibleJobs = jobs.filter((job) => !hiddenJobIds.includes(job.id));
  const filteredFindings = activeResult?.findings?.filter((item) => !shouldHideFinding(item)) || [];
  const investigationGuide = activeResult?.scoring?.investigation_guide || activeResult?.risk_meta?.investigation_guide || null;
  const activeProviderView = activeOsintLink
    ? buildProviderViewerData(activeOsintLink, filteredFindings, activeResult)
    : null;

  if (!session?.user) {
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="auth-brand">
            <div className="brand-mark">
              <span className="brand-core" />
            </div>
            <div>
              <p className="brand-title">SOCINTEL &gt;</p>
              <p className="brand-subtitle">Open-Source Cyber Threat Intelligence Platform</p>
            </div>
          </div>
          <form className="auth-form" onSubmit={handleLogin}>
            <div className="auth-head">
              <div>
                <p className="eyebrow">Secure Login</p>
                <h1>Analysis Workspace</h1>
              </div>
              <button type="button" className="theme-toggle" onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}>
                {theme === "dark" ? "DARK" : "LIGHT"}
              </button>
            </div>
            <label>
              Email
              <input type="email" value={loginForm.email} onChange={(event) => setLoginForm((current) => ({ ...current, email: event.target.value }))} />
            </label>
            <label>
              Password
              <input type="password" autoComplete="current-password" value={loginForm.password} onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))} />
            </label>
            {authError ? <p className="error-text">{authError}</p> : null}
            <button className="primary-button" type="submit" disabled={authLoading}>
              {authLoading ? "Signing in..." : "Enter workspace"}
            </button>
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="side-nav">
        <div className="side-nav-top">
          <div className="hero-brand side-brand">
            <div className="brand-mark">
              <span className="brand-core" />
            </div>
            <div>
              <p className="brand-title">SOCINTEL &gt;</p>
              <p className="brand-subtitle">Open-Source Cyber Threat Intelligence Platform</p>
            </div>
          </div>
          <nav className="side-nav-list">
            <button type="button" className={`tab-button side-tab ${activeTab === "analysis" ? "tab-button-active" : ""}`} onClick={() => setActiveTab("analysis")}>
              Analise
            </button>
            <button type="button" className={`tab-button side-tab ${activeTab === "mitre" ? "tab-button-active" : ""}`} onClick={() => setActiveTab("mitre")}>
              MITRE ATT&CK
            </button>
            <button type="button" className={`tab-button side-tab ${activeTab === "threat" ? "tab-button-active" : ""}`} onClick={() => setActiveTab("threat")}>
              Threat Intell
            </button>
            <button type="button" className={`tab-button side-tab ${activeTab === "password" ? "tab-button-active" : ""}`} onClick={() => setActiveTab("password")}>
              Minha senha
            </button>
          </nav>
        </div>
        <div className="side-nav-bottom">
          <p className="hero-meta">{session.user?.full_name} • {session.user?.role}</p>
          <button type="button" className="theme-toggle" onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}>
            {theme === "dark" ? "DARK" : "LIGHT"}
          </button>
          <button type="button" className="ghost-button" onClick={logout}>Sign out</button>
        </div>
      </aside>

      <section className="workspace-main">
        <header className="hero-bar">
          <div>
            <p className="eyebrow">SOC Analyst Console</p>
            <h1>{activeTab === "analysis" ? "Analise" : activeTab === "mitre" ? "MITRE ATT&CK" : activeTab === "threat" ? "Threat Intell" : "Minha senha"}</h1>
          </div>
          <div className="hero-actions">
            <span className="hero-meta">IOC Enrichment</span>
            {activeJob?.status ? <span className={`status-pill status-${activeJob.status}`}>{activeJob.status}</span> : null}
          </div>
        </header>

        {activeTab === "analysis" ? (
          <section className="analysis-layout">
            <aside className="panel panel-left">
              <div className="analysis-hero">
                <p className="eyebrow">Nova analise</p>
                <h2>Executar IOC</h2>
              </div>
              <form className="analysis-form analysis-surface" onSubmit={handleSubmitAnalysis}>
                <div className="form-cluster">
                  <label>
                    Tipo de Indicador (IOC)
                    <div className="type-grid">
                      {IOC_TYPES.map((type) => (
                        <button key={type.value} type="button" className={`type-pill ${jobForm.ioc_type === type.value ? "type-pill-active" : ""}`} onClick={() => setJobForm((current) => ({ ...current, ioc_type: type.value }))}>
                          {type.label}
                        </button>
                      ))}
                    </div>
                  </label>
                  <label>
                    Valor
                    <input type="text" value={jobForm.ioc_value} onChange={(event) => setJobForm((current) => ({ ...current, ioc_value: event.target.value }))} placeholder={jobForm.ioc_type === "domain_email" ? "example.com or analyst@example.com" : "8.8.8.8"} />
                  </label>
                </div>
                {jobError ? <p className="error-text">{jobError}</p> : null}
                {formMessage ? <p className="success-text">{formMessage}</p> : null}
                <button className="primary-button action-button analysis-cta" type="submit" disabled={busy}>
                  {busy ? "Enfileirando..." : "Executar analise"}
                </button>
              </form>

              <div className="secondary-surface">
                <div className="panel-head compact-head">
                  <h3>Historico</h3>
                  <span className="muted-line">{visibleJobs.length} recentes</span>
                </div>
                <div className="job-history">
                  {visibleJobs.length ? (
                    visibleJobs.map((job) => (
                      <button key={job.id} type="button" className={`history-card ${activeJob?.id === job.id ? "history-card-active" : ""}`} onClick={() => selectJob(job)}>
                        <span className="history-card-top">
                          <strong>{displayIocType(job.ioc_type)}</strong>
                          <span className={`status-pill status-${job.status}`}>{job.status}</span>
                        </span>
                        <span>{job.ioc_value}</span>
                        <small>{job.id}</small>
                        <span className="history-card-actions">
                          <span className="ghost-link">Abrir</span>
                          <span className="ghost-link" onClick={(event) => {
                            event.preventDefault();
                            event.stopPropagation();
                            setPendingDeleteJob(job);
                          }}>
                            Ocultar
                          </span>
                        </span>
                      </button>
                    ))
                  ) : (
                    <div className="empty-state">
                      <h3>Nenhuma analise recente</h3>
                      <p className="muted-line">Execute um IOC para popular o historico.</p>
                    </div>
                  )}
                </div>
              </div>
            </aside>

            <section className="panel panel-right result-panel">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">Resultado consolidado</p>
                  <h2>{activeJob ? `${displayIocType(activeJob.ioc_type)} • ${activeJob.ioc_value}` : "Selecione uma analise"}</h2>
                </div>
                {activeJob ? <button type="button" className="ghost-button" onClick={refreshResult}>Atualizar</button> : null}
              </div>

              {activeResult ? (
                <>
                  <div className="risk-grid">
                    <article className={`risk-card ${mapLevel(activeResult.level)}`}>
                      <span className="summary-label">Nivel</span>
                      <strong>{activeResult.level}</strong>
                    </article>
                    <article className="risk-card">
                      <span className="summary-label">Score</span>
                      <strong>{activeResult.risk_score}</strong>
                    </article>
                    <article className="risk-card">
                      <span className="summary-label">Confianca</span>
                      <strong>{activeResult.confidence_score ?? "—"}</strong>
                    </article>
                    <article className="risk-card">
                      <span className="summary-label">Veredito</span>
                      <strong>{activeResult.verdict}</strong>
                    </article>
                  </div>

                  {investigationGuide ? (
                    <div className="result-section">
                      <div className="panel-head compact-head">
                        <h3>Guia SOC</h3>
                        <div className="section-head-actions">
                          <span className="muted-line">Triagem N1/N2</span>
                          <button
                            type="button"
                            className="ghost-button compact-toggle"
                            aria-expanded={!isSocGuideCollapsed}
                            onClick={() => setIsSocGuideCollapsed((current) => !current)}
                          >
                            {isSocGuideCollapsed ? "Expandir" : "Minimizar"}
                          </button>
                        </div>
                      </div>
                      {!isSocGuideCollapsed ? (
                        <div className="findings-grid">
                          {Object.entries(investigationGuide).map(([section, items]) => (
                            <article className="finding-card" key={section}>
                              <div className="finding-card-head">
                                <span className="provider-chip">{section}</span>
                              </div>
                              <ul className="provider-list">
                                {(Array.isArray(items) ? items : []).map((item, index) => (
                                  <li key={`${section}-${index}`}>{item}</li>
                                ))}
                              </ul>
                            </article>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="result-section">
                    <div className="panel-head compact-head">
                      <h3>Achados</h3>
                      <span className="muted-line">{filteredFindings.length} itens</span>
                    </div>
                    <div className="findings-grid">
                      {filteredFindings.length ? (
                        filteredFindings.map((finding, index) => {
                          const parsed = parseFindingProvider(finding);
                          const isSubitem = /^(\s*•\s*)?└──/.test(String(finding || ""));
                          const source = parsed.provider ? normalizeProviderName(parsed.provider) : isSubitem ? "Detalhe" : "Sinal";
                          const detail = normalizeFindingText(parsed.detail || finding);
                          return (
                            <article className={`finding-card ${findingTone(finding)} ${isSubitem ? "finding-card-subitem" : ""}`} key={`${finding}-${index}`}>
                              <div className="finding-card-head">
                                <span className="provider-chip">{source}</span>
                                {parsed.description ? <span className="finding-source-note">{parsed.description}</span> : null}
                              </div>
                              <p>{detail}</p>
                            </article>
                          );
                        })
                      ) : (
                        <div className="empty-state">
                          <h3>Nenhum achado estruturado</h3>
                          <p className="muted-line">O resultado ainda nao trouxe sinais consolidados para este IOC.</p>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="result-section">
                    <div className="panel-head compact-head">
                      <h3>OSINT</h3>
                      <span className="muted-line">Fontes externas</span>
                    </div>
                    <div className="osint-grid">
                      {buildOsintLinks(activeJob).map((link) => {
                        const meta = osintLinkMeta(link);
                        return (
                        <button key={link.href} type="button" className="osint-link-card" onClick={() => setActiveOsintLink(link)}>
                          <span className="osint-link-top">
                            <strong>{meta.label}</strong>
                            <span>Ver</span>
                          </span>
                          <small>{meta.host}</small>
                          <p>{meta.description}</p>
                        </button>
                        );
                      })}
                    </div>
                  </div>
                </>
              ) : activeJob ? (
                <div className="empty-state">
                  <h3>Analise em processamento</h3>
                  <p className="muted-line">O worker ainda nao retornou um resultado consolidado para este IOC.</p>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>Nenhum IOC ativo</h3>
                  <p className="muted-line">Execute uma nova analise ou abra um item do historico.</p>
                </div>
              )}
            </section>
          </section>
        ) : activeTab === "mitre" ? (
          <Suspense fallback={<section className="analysis-layout"><div className="panel"><div className="empty-state"><h3>Carregando MITRE ATT&CK</h3></div></div></section>}>
            <MitreView token={session.token} />
          </Suspense>
        ) : activeTab === "threat" ? (
          <Suspense fallback={<section className="threat-layout"><div className="panel"><div className="empty-state"><h3>Carregando Threat Intell</h3></div></div></section>}>
            <ThreatIntellView token={session.token} />
          </Suspense>
        ) : activeTab === "password" ? (
          <section className="management-layout">
            <div className="panel">
              <div className="panel-head">
                <h2>Alterar senha</h2>
                <p className="muted-line">Apenas a senha da sua propria identidade autenticada pode ser alterada.</p>
              </div>
              <form className="analysis-form" onSubmit={handleChangePassword}>
                <label>
                  Senha atual
                  <input type="password" autoComplete="current-password" value={passwordForm.current_password} onChange={(event) => setPasswordForm((current) => ({ ...current, current_password: event.target.value }))} />
                </label>
                <label>
                  Nova senha
                  <input type="password" autoComplete="new-password" value={passwordForm.new_password} onChange={(event) => setPasswordForm((current) => ({ ...current, new_password: event.target.value }))} />
                </label>
                <label>
                  Confirmar nova senha
                  <input type="password" autoComplete="new-password" value={passwordForm.confirm_password} onChange={(event) => setPasswordForm((current) => ({ ...current, confirm_password: event.target.value }))} />
                </label>
                {passwordError ? <p className="error-text">{passwordError}</p> : null}
                {formMessage ? <p className="success-text">{formMessage}</p> : null}
                <button className="primary-button" type="submit" disabled={passwordLoading}>
                  {passwordLoading ? "Atualizando..." : "Alterar senha"}
                </button>
              </form>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Sessao autenticada</h2>
                <p className="muted-line">Provisionamento de contas e privilegios permanece fora do front-end.</p>
              </div>
              <div className="security-summary">
                <div className="history-card">
                  <strong>{session.user.full_name}</strong>
                  <span>{session.user.email}</span>
                  <small>{session.user.role} • {session.user.status}</small>
                </div>
                <div className="history-card">
                  <strong>Provisionamento externo</strong>
                  <span>Contas devem ser criadas somente por administradores via terminal/CLI.</span>
                  <small>Sem rota, aba ou chamada de registro no front-end.</small>
                </div>
              </div>
            </div>
          </section>
        ) : (
          <section className="analysis-layout">
            <div className="panel">
              <div className="empty-state">
                <h3>Secao indisponivel</h3>
                <p className="muted-line">A area solicitada nao esta habilitada para esta sessao.</p>
              </div>
            </div>
          </section>
        )}
      </section>

      {pendingDeleteJob ? (
        <div className="modal-backdrop" onClick={() => setPendingDeleteJob(null)}>
          <section className="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="delete-ioc-title" onClick={(event) => event.stopPropagation()}>
            <p className="eyebrow">Confirmacao</p>
            <h2 id="delete-ioc-title">Voce quer ocultar esse IOC?</h2>
            <p className="muted-line">{displayIocType(pendingDeleteJob.ioc_type)} • {pendingDeleteJob.ioc_value}</p>
            <div className="confirm-actions">
              <button type="button" className="ghost-button" onClick={() => setPendingDeleteJob(null)}>Nao</button>
              <button type="button" className="primary-button" onClick={hideJob}>Sim, ocultar</button>
            </div>
          </section>
        </div>
      ) : null}

      {activeOsintLink ? (
        <div className="modal-backdrop" onClick={() => setActiveOsintLink(null)}>
          <section className="osint-modal" role="dialog" aria-modal="true" aria-labelledby="osint-viewer-title" onClick={(event) => event.stopPropagation()}>
            <div className="panel-head compact-head">
              <div>
                <p className="eyebrow">OSINT Viewer</p>
                <h2 id="osint-viewer-title">{activeOsintLink.label}</h2>
              </div>
              <div className="confirm-actions">
                <a className="ghost-button" href={activeOsintLink.href} target="_blank" rel="noreferrer">Abrir externo</a>
                <button type="button" className="primary-button" onClick={() => setActiveOsintLink(null)}>Fechar</button>
              </div>
            </div>
            <p className="muted-line osint-url">{activeOsintLink.href}</p>
            <div className="osint-frame-shell">
              <div className="provider-view">
                <div className="provider-view-card">
                  <p className="eyebrow">Provider info</p>
                  <h3>{activeProviderView?.providerName}</h3>
                  <p className="muted-line">{activeProviderView?.description}</p>
                </div>
                <div className="provider-view-card">
                  <p className="eyebrow">Resumo extraido</p>
                  <p>{activeProviderView?.verdict}</p>
                </div>
                {activeProviderView?.integrationStatus ? (
                  <div className={`provider-status-card provider-status-${activeProviderView.integrationStatus.tone}`}>
                    <p className="eyebrow">Status da integração</p>
                    <h3>{activeProviderView.integrationStatus.title}</h3>
                    <p>{activeProviderView.integrationStatus.message}</p>
                    {activeProviderView.integrationStatus.action ? <p className="muted-line">{activeProviderView.integrationStatus.action}</p> : null}
                  </div>
                ) : null}
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Detalhes estruturados</p>
                  {activeProviderView?.details?.length ? (
                    <div className="provider-detail-grid">
                      {activeProviderView.details.map((item) => (
                        <div className="provider-detail-row" key={`${item.label}-${item.value}`}>
                          <span className="provider-detail-label">{item.label}</span>
                          <strong className="provider-detail-value">{item.value}</strong>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-line">Nenhum detalhe estruturado adicional disponivel.</p>
                  )}
                </div>
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Achados deste provider</p>
                  {activeProviderView?.highlights?.length ? (
                    <ul className="console-list compact-list">
                      {activeProviderView.highlights.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
                    </ul>
                  ) : (
                    <p className="muted-line">Nao ha achados especificos separados para este provider.</p>
                  )}
                </div>
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Acoes sugeridas</p>
                  {activeProviderView?.recommendations?.length ? (
                    <ul className="console-list compact-list">
                      {activeProviderView.recommendations.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
                    </ul>
                  ) : (
                    <p className="muted-line">Nenhuma recomendacao adicional disponivel.</p>
                  )}
                </div>
              </div>
            </div>
          </section>
        </div>
      ) : null}
    </main>
  );
}
