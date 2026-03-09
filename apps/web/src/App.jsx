import { useEffect, useState } from "react";
import { api } from "./api";

const IOC_TYPES = ["ip", "domain", "url", "email", "hash", "mac"];
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
};
const NAME_REGEX = /^[A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9 .,'_-]{2,254}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$/;
const SESSION_KEY = "socintel_v2_session";
const THEME_KEY = "socintel_v2_theme";
const RECENT_JOBS_KEY = "socintel_v2_recent_jobs";
const TOKEN_KEY = "socintel_v2_access_token";
const HIDDEN_RECENT_JOBS_KEY = "socintel_v2_hidden_recent_jobs";

function readSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
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

function readAuthToken() {
  return sessionStorage.getItem(TOKEN_KEY) || "";
}

function writeAuthToken(token) {
  if (token) {
    sessionStorage.setItem(TOKEN_KEY, token);
  } else {
    sessionStorage.removeItem(TOKEN_KEY);
  }
}

function clearAuthToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

function readRecentJobIds() {
  try {
    const raw = sessionStorage.getItem(RECENT_JOBS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeRecentJobIds(jobIds) {
  sessionStorage.setItem(RECENT_JOBS_KEY, JSON.stringify(jobIds));
}

function clearRecentJobIds() {
  sessionStorage.removeItem(RECENT_JOBS_KEY);
}

function readHiddenRecentJobIds() {
  try {
    const raw = localStorage.getItem(HIDDEN_RECENT_JOBS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeHiddenRecentJobIds(jobIds) {
  localStorage.setItem(HIDDEN_RECENT_JOBS_KEY, JSON.stringify(jobIds));
}

function readTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  return stored === "light" ? "light" : "dark";
}

function writeTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
}

function mapLevel(level) {
  const normalized = String(level || "").toLowerCase();
  if (normalized.includes("alto")) return "risk-high";
  if (normalized.includes("médio") || normalized.includes("medio")) return "risk-medium";
  return "risk-low";
}

function buildOsintLinks(job) {
  if (!job) return [];
  const value = encodeURIComponent(job.ioc_value || "");
  const links = [];

  if (job.ioc_type === "ip") {
    links.push(
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/ip-address/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/indicator/ip/${value}` },
      { label: "AbuseIPDB", href: `https://www.abuseipdb.com/check/${value}` },
      { label: "Shodan", href: `https://www.shodan.io/host/${value}` },
    );
  }

  if (job.ioc_type === "domain" || job.ioc_type === "url") {
    links.push(
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/search/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
      { label: "urlscan.io", href: `https://urlscan.io/search/#domain:${value}` },
      { label: "WHOIS", href: `https://who.is/whois/${value}` },
    );
  }

  if (job.ioc_type === "email") {
    links.push(
      { label: "Hunter", href: `https://hunter.io/search/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
    );
  }

  if (job.ioc_type === "hash") {
    links.push(
      { label: "VirusTotal", href: `https://www.virustotal.com/gui/file/${value}` },
      { label: "AlienVault OTX", href: `https://otx.alienvault.com/browse/global/pulses?q=${value}` },
    );
  }

  if (job.ioc_type === "mac") {
    links.push({ label: "MAC Vendors", href: `https://macvendors.com/query/${value}` });
  }

  return links;
}

function upsertJob(list, nextJob) {
  const filtered = list.filter((item) => item.id !== nextJob.id);
  return [nextJob, ...filtered];
}

function normalizeProviderName(name) {
  const normalized = String(name || "").trim();
  const aliases = {
    OTX: "AlienVault OTX",
    AlienVault: "AlienVault OTX",
    "urlscan": "urlscan.io",
  };
  return aliases[normalized] || normalized;
}

function formatBytes(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return String(value);
  }
  if (numeric < 1024) {
    return `${numeric} B`;
  }
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

function shouldHideFinding(finding) {
  const text = String(finding || "").trim();
  const normalized = text.replace(/\s+/g, " ");
  if (normalized.includes("===")) {
    return true;
  }
  if (
    normalized.includes("Reputação e detecções de malícia") ||
    normalized.includes("Histórico de abuso reportado") ||
    normalized.includes("Threat intel comunitário") ||
    normalized.includes("Registro do provedor") ||
    normalized.includes("Serviços expostos e vulnerabilidades")
  ) {
    return true;
  }
  return false;
}

function buildProviderViewerData(link, findings, activeResult) {
  const providerName = normalizeProviderName(link?.label);
  const providerFindings = findings
    .map((item) => ({ raw: item, parsed: parseFindingProvider(item) }))
    .filter((entry) => normalizeProviderName(entry.parsed.provider) === providerName);

  const highlights = providerFindings
    .map((entry) => entry.parsed.detail || entry.raw)
    .filter(Boolean);

  return {
    providerName,
    description: PROVIDER_INFO[providerName] || "Fonte OSINT utilizada na consolidação desta análise.",
    highlights,
    details: formatProviderDetails(activeResult?.provider_details?.[providerName]),
    verdict: activeResult?.legacy_verdict || activeResult?.verdict || "Sem veredito consolidado.",
    recommendations: activeResult?.recommendations || [],
  };
}

function sanitizeEmail(value) {
  return value.trim().toLowerCase();
}

function sanitizeText(value) {
  return value.replace(/\s+/g, " ").trim();
}

function validateAuthForm({ email, password, full_name }) {
  if (!sanitizeEmail(email)) return "Email is required.";
  if (full_name !== undefined && !NAME_REGEX.test(sanitizeText(full_name))) {
    return "Nome completo inválido. Use ao menos 3 caracteres válidos.";
  }
  if (!PASSWORD_REGEX.test(password)) {
    return "Senha inválida. Use 8+ caracteres com maiúscula, minúscula e número.";
  }
  return "";
}

async function wait(ms) {
  await new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export function App() {
  const [theme, setTheme] = useState(() => readTheme());
  const [session, setSession] = useState(() => {
    const stored = readSession();
    return stored ? { ...stored, token: readAuthToken() } : null;
  });
  const [activeTab, setActiveTab] = useState("investigation");
  const [authView, setAuthView] = useState("login");
  const [loginForm, setLoginForm] = useState({
    email: session?.user?.email || "admin@socintel.dev",
    password: "",
  });
  const [registerForm, setRegisterForm] = useState({
    full_name: "",
    email: "",
    password: "",
  });
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [registerMessage, setRegisterMessage] = useState("");
  const [cases, setCases] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [selectedInvestigationId, setSelectedInvestigationId] = useState("");
  const [jobForm, setJobForm] = useState({
    ioc_type: "ip",
    ioc_value: "8.8.8.8",
  });
  const [caseForm, setCaseForm] = useState({
    name: "",
    description: "",
    visibility: "private",
  });
  const [investigationForm, setInvestigationForm] = useState({
    title: "",
    summary: "",
  });
  const [activeJob, setActiveJob] = useState(null);
  const [activeResult, setActiveResult] = useState(null);
  const [jobError, setJobError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [recentJobIds, setRecentJobIds] = useState(() => readRecentJobIds());
  const [hiddenRecentJobIds, setHiddenRecentJobIds] = useState(() => readHiddenRecentJobIds());
  const [users, setUsers] = useState([]);
  const [userForm, setUserForm] = useState({
    full_name: "",
    email: "",
    password: "",
    role: "minimum",
  });
  const [pendingDeleteJob, setPendingDeleteJob] = useState(null);
  const [activeOsintLink, setActiveOsintLink] = useState(null);

  useEffect(() => {
    writeRecentJobIds(recentJobIds);
  }, [recentJobIds]);

  useEffect(() => {
    writeHiddenRecentJobIds(hiddenRecentJobIds);
  }, [hiddenRecentJobIds]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    writeTheme(theme);
  }, [theme]);

  useEffect(() => {
    const hasOpenModal = Boolean(pendingDeleteJob || activeOsintLink);
    document.body.classList.toggle("modal-open", hasOpenModal);
    return () => {
      document.body.classList.remove("modal-open");
    };
  }, [pendingDeleteJob, activeOsintLink]);

  useEffect(() => {
    if (!session?.user) return;
    let ignore = false;

    async function loadCases() {
      try {
        const payload = await api.listCases(session.token);
        if (ignore) return;
        setCases(payload);
      } catch (error) {
        if (!ignore) setJobError(error.message);
      }
    }

    loadCases();
    return () => {
      ignore = true;
    };
  }, [session?.token, session?.user?.id]);

  useEffect(() => {
    if (!session?.user || !selectedCaseId) {
      setInvestigations([]);
      setSelectedInvestigationId("");
      return;
    }
    let ignore = false;

    async function loadInvestigations() {
      try {
        const payload = await api.listInvestigations(session.token, selectedCaseId);
        if (ignore) return;
        setInvestigations(payload);
        if (!selectedInvestigationId && payload.length > 0) {
          setSelectedInvestigationId(payload[0].id);
        }
      } catch (error) {
        if (!ignore) setJobError(error.message);
      }
    }

    loadInvestigations();
    return () => {
      ignore = true;
    };
  }, [session?.token, selectedCaseId]);

  useEffect(() => {
    if (!session?.user) return;
    let ignore = false;

    async function loadJobs() {
      try {
        const payload = await api.listAnalysisJobs(session.token, {
          case_id: selectedCaseId || undefined,
        });
        if (!ignore) setJobs(payload);
      } catch (error) {
        if (!ignore) setJobError(error.message);
      }
    }

    loadJobs();
    return () => {
      ignore = true;
    };
  }, [session?.token, selectedCaseId, activeJob?.status]);

  useEffect(() => {
    if (!session?.user || session.user?.role !== "admin") {
      setUsers([]);
      return;
    }
    let ignore = false;

    async function loadUsers() {
      try {
        const payload = await api.listUsers(session.token);
        if (!ignore) setUsers(payload);
      } catch (error) {
        if (!ignore) setJobError(error.message);
      }
    }

    loadUsers();
    return () => {
      ignore = true;
    };
  }, [session?.token, session?.user?.role]);

  useEffect(() => {
    if (!session?.user || !activeJob?.id) return;
    if (activeJob.status === "completed" || activeJob.status === "failed") return;

    let cancelled = false;

    async function pollJob() {
      let delay = 700;
      while (!cancelled) {
        try {
          const nextJob = await api.getAnalysisJob(session.token, activeJob.id);
          if (cancelled) return;
          if (nextJob.status === "completed") {
            const result = await api.getAnalysisResult(session.token, nextJob.id);
            if (cancelled) return;
            setActiveJob(nextJob);
            setJobs((current) => upsertJob(current, nextJob));
            setActiveResult(result);
            return;
          }
          setActiveJob(nextJob);
          setJobs((current) => upsertJob(current, nextJob));
          if (nextJob.status === "failed") {
            return;
          }
          await wait(delay);
          delay = Math.min(delay + 250, 1500);
        } catch (error) {
          if (!cancelled) setJobError(error.message);
          return;
        }
      }
    }

    pollJob();
    return () => {
      cancelled = true;
    };
  }, [session?.token, activeJob?.id]);

  useEffect(() => {
    if (!session?.token || !activeJob?.id) return;
    if (activeJob.status !== "completed" || activeResult?.job_id === activeJob.id) return;

    let cancelled = false;

    async function loadCompletedResult() {
      try {
        const result = await api.getAnalysisResult(session.token, activeJob.id);
        if (!cancelled) setActiveResult(result);
      } catch (error) {
        if (!cancelled) setJobError(error.message);
      }
    }

    loadCompletedResult();
    return () => {
      cancelled = true;
    };
  }, [session?.token, activeJob?.id, activeJob?.status, activeResult?.job_id]);

  async function handleLogin(event) {
    event.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const normalized = {
      email: sanitizeEmail(loginForm.email),
      password: loginForm.password,
    };
    const validationError = validateAuthForm(normalized);
    if (validationError) {
      setAuthError(validationError);
      setAuthLoading(false);
      return;
    }
    try {
      const payload = await api.login(normalized.email, normalized.password);
      const nextSession = {
        token: payload.access_token || "",
        user: payload.user,
        memberships: payload.memberships,
      };
      setSession(nextSession);
      writeSession(nextSession);
      writeAuthToken(nextSession.token);
      setLoginForm((current) => ({ ...current, password: "" }));
      setActiveTab("investigation");
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
        case_id: selectedCaseId || null,
        investigation_id: null,
        ioc_type: jobForm.ioc_type,
        ioc_value: jobForm.ioc_value,
      });
      setActiveJob(created);
      setJobs((current) => upsertJob(current, created));
      setHiddenRecentJobIds((current) => current.filter((item) => item !== created.id));
      if (!created.case_id) {
        setRecentJobIds((current) => [created.id, ...current.filter((item) => item !== created.id)]);
      }
      await wait(250);
      const immediateJob = await api.getAnalysisJob(session.token, created.id);
      setActiveJob(immediateJob);
      setJobs((current) => upsertJob(current, immediateJob));
      if (immediateJob.status === "completed") {
        const result = await api.getAnalysisResult(session.token, immediateJob.id);
        setActiveResult(result);
      }
      setActiveTab("investigation");
    } catch (error) {
      setJobError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    setAuthError("");
    setRegisterMessage("");
    const normalized = {
      full_name: sanitizeText(registerForm.full_name),
      email: sanitizeEmail(registerForm.email),
      password: registerForm.password,
    };
    const validationError = validateAuthForm(normalized);
    if (validationError) {
      setAuthError(validationError);
      return;
    }
    try {
      const created = await api.register(normalized);
      setRegisterForm({
        full_name: "",
        email: "",
        password: "",
      });
      setRegisterMessage(`Conta criada para ${created.email} com privilégio mínimo.`);
      setAuthView("login");
    } catch (error) {
      setAuthError(error.message);
    }
  }

  async function handleCreateCase(event) {
    event.preventDefault();
    if (!session?.user) return;
    setJobError("");
    setFormMessage("");
    try {
      const created = await api.createCase(session.token, caseForm);
      const payload = await api.listCases(session.token);
      setCases(payload);
      setSelectedCaseId(created.id);
      setCaseForm({ name: "", description: "", visibility: "private" });
      setFormMessage(`Case ${created.name} created.`);
      setActiveTab("cases");
    } catch (error) {
      setJobError(error.message);
    }
  }

  async function handleCreateInvestigation(event) {
    event.preventDefault();
    if (!session?.user || !selectedCaseId) return;
    setJobError("");
    setFormMessage("");
    try {
      const created = await api.createInvestigation(session.token, selectedCaseId, investigationForm);
      const payload = await api.listInvestigations(session.token, selectedCaseId);
      setInvestigations(payload);
      setSelectedInvestigationId(created.id);
      setInvestigationForm({ title: "", summary: "" });
      setFormMessage(`Investigation ${created.title} created.`);
      setActiveTab("cases");
    } catch (error) {
      setJobError(error.message);
    }
  }

  async function handleCreateUser(event) {
    event.preventDefault();
    if (!session?.user || session.user?.role !== "admin") return;
    setJobError("");
    setFormMessage("");
    try {
      const created = await api.createUser(session.token, userForm);
      setUsers((current) => [created, ...current]);
      setUserForm({
        full_name: "",
        email: "",
        password: "",
        role: "minimum",
      });
      setFormMessage(`Usuário ${created.email} criado com privilégio mínimo.`);
      setActiveTab("users");
    } catch (error) {
      setJobError(error.message);
    }
  }

  async function handleRoleChange(userId, role) {
    if (!session?.user || session.user.role !== "admin") return;
    setJobError("");
    try {
      const updated = await api.updateUserRole(session.token, userId, { role });
      setUsers((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      setFormMessage(`Privilégio de ${updated.email} atualizado para ${updated.role}.`);
    } catch (error) {
      setJobError(error.message);
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
    setActiveTab("investigation");
  }

  function logout() {
    api.logout().catch(() => null);
    clearSession();
    clearAuthToken();
    clearRecentJobIds();
    setSession(null);
    setCases([]);
    setInvestigations([]);
    setJobs([]);
    setRecentJobIds([]);
    setActiveJob(null);
    setActiveResult(null);
  }

  function requestHideRecentJob(event, job) {
    event.preventDefault();
    setPendingDeleteJob(job);
  }

  function hideRecentJob() {
    if (!pendingDeleteJob) return;
    const job = pendingDeleteJob;
    setJobs((current) => current.filter((item) => item.id !== job.id));
    setRecentJobIds((current) => current.filter((item) => item !== job.id));
    setHiddenRecentJobIds((current) => [job.id, ...current.filter((item) => item !== job.id)]);
    if (activeJob?.id === job.id) {
      setActiveJob(null);
      setActiveResult(null);
    }
    setFormMessage(`Busca ${job.ioc_value} removida da lista.`);
    setPendingDeleteJob(null);
  }

  const visibleJobs = jobs.filter(
    (job) => (Boolean(job.case_id) || recentJobIds.includes(job.id)) && !hiddenRecentJobIds.includes(job.id),
  );
  const filteredFindings = activeResult?.findings?.filter((item) => !shouldHideFinding(item)) || [];
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
                <p className="eyebrow">{authView === "login" ? "Secure Login" : "Self Registration"}</p>
                <h1>{authView === "login" ? "Investigation Workspace" : "Create Account"}</h1>
              </div>
              <button
                type="button"
                className="theme-toggle"
                onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
              >
                {theme === "dark" ? "DARK" : "LIGHT"}
              </button>
            </div>
            {authView === "login" ? (
              <>
                <label>
                  Email
                  <input
                    type="email"
                    value={loginForm.email}
                    onChange={(event) => setLoginForm((current) => ({ ...current, email: event.target.value }))}
                  />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    autoComplete="current-password"
                    value={loginForm.password}
                    onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
                  />
                </label>
                {authError ? <p className="error-text">{authError}</p> : null}
                {registerMessage ? <p className="success-text">{registerMessage}</p> : null}
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? "Signing in..." : "Enter workspace"}
                </button>
                <button type="button" className="ghost-button auth-switch" onClick={() => {
                  setAuthError("");
                  setRegisterMessage("");
                  setAuthView("register");
                }}>
                  Nao tem uma conta?
                </button>
              </>
            ) : null}
          </form>
          {authView === "register" ? (
            <form className="auth-form" onSubmit={handleRegister}>
              <label>
                Nome completo
                <input
                  type="text"
                  value={registerForm.full_name}
                  onChange={(event) => setRegisterForm((current) => ({ ...current, full_name: event.target.value }))}
                />
              </label>
              <label>
                Email
                <input
                  type="email"
                  value={registerForm.email}
                  onChange={(event) => setRegisterForm((current) => ({ ...current, email: event.target.value }))}
                />
              </label>
              <label>
                Senha
                <input
                  type="password"
                  autoComplete="new-password"
                  value={registerForm.password}
                  onChange={(event) => setRegisterForm((current) => ({ ...current, password: event.target.value }))}
                />
              </label>
              {authError ? <p className="error-text">{authError}</p> : null}
              <button className="primary-button" type="submit">
                Criar conta
              </button>
              <button type="button" className="ghost-button auth-switch" onClick={() => {
                setAuthError("");
                setRegisterMessage("");
                setAuthView("login");
              }}>
                Ja tem uma conta?
              </button>
            </form>
          ) : null}
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
            <button
              type="button"
              className={`tab-button side-tab ${activeTab === "investigation" ? "tab-button-active" : ""}`}
              onClick={() => setActiveTab("investigation")}
            >
              Investigação
            </button>
            <button
              type="button"
              className={`tab-button side-tab ${activeTab === "cases" ? "tab-button-active" : ""}`}
              onClick={() => setActiveTab("cases")}
            >
              Casos
            </button>
            {session.user?.role === "admin" ? (
              <button
                type="button"
                className={`tab-button side-tab ${activeTab === "users" ? "tab-button-active" : ""}`}
                onClick={() => setActiveTab("users")}
              >
                Usuários
              </button>
            ) : null}
          </nav>
        </div>
        <div className="side-nav-bottom">
          <p className="hero-meta">{session.user?.full_name} • {session.user?.role}</p>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
          >
            {theme === "dark" ? "DARK" : "LIGHT"}
          </button>
          <button type="button" className="ghost-button" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>

      <section className="workspace-main">
        <header className="hero-bar">
          <div>
            <p className="eyebrow">SOC Analyst Console</p>
            <h1>{activeTab === "investigation" ? "Investigação" : activeTab === "cases" ? "Casos" : "Usuários"}</h1>
          </div>
          <div className="hero-actions">
            <span className="hero-meta">IOC Investigation &amp; Enrichment</span>
            {activeJob?.status ? (
              <span className={`status-pill status-${activeJob.status}`}>{activeJob.status}</span>
            ) : null}
          </div>
        </header>

        {activeTab === "investigation" ? (
        <section className="investigation-layout">
          <aside className="panel panel-left">
            <div className="investigation-hero">
              <p className="eyebrow">Nova análise</p>
              <h2>Iniciar Investigação</h2>
            </div>
            <form className="analysis-form analysis-surface" onSubmit={handleSubmitAnalysis}>
              <div className="form-cluster">
                <label>
                  Tipo de Indicador (IOC)
                  <div className="type-grid">
                    {IOC_TYPES.map((type) => (
                      <button
                        key={type}
                        type="button"
                        className={`type-pill ${jobForm.ioc_type === type ? "type-pill-active" : ""}`}
                        onClick={() => setJobForm((current) => ({ ...current, ioc_type: type }))}
                      >
                        {type}
                      </button>
                    ))}
                  </div>
                </label>
              </div>
              <div className="form-cluster">
                <label>
                  Caso
                  <select value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)}>
                    <option value="">Pesquisa singular (sem caso)</option>
                    {cases.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="form-cluster">
                <label>
                  Valor do Indicador
                  <input
                    type="text"
                    value={jobForm.ioc_value}
                    onChange={(event) => setJobForm((current) => ({ ...current, ioc_value: event.target.value }))}
                    placeholder="Ex.: 8.8.8.8, example.com, hash, email"
                  />
                </label>
              </div>
              {jobError ? <p className="error-text">{jobError}</p> : null}
              <button className="primary-button action-button investigation-cta" type="submit" disabled={busy}>
                {busy ? "Enviando..." : "Executar Análise OSINT"}
              </button>
            </form>

            <div className="recent-block secondary-surface">
              <div className="panel-head compact-head">
                <h3>Buscas Recentes</h3>
                <span className="muted-line">Clique direito para remover</span>
              </div>
              <div className="job-history">
                {visibleJobs.length ? (
                  visibleJobs.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`history-card ${activeJob?.id === item.id ? "history-card-active" : ""}`}
                      onClick={() => selectJob(item)}
                      onContextMenu={(event) => requestHideRecentJob(event, item)}
                      title="Clique direito para remover da lista"
                    >
                      <div className="history-card-top">
                        <strong>{item.ioc_type.toUpperCase()}</strong>
                        <span className={`status-pill status-${item.status}`}>{item.status}</span>
                      </div>
                      <span>{item.ioc_value}</span>
                      <small>{item.id}</small>
                    </button>
                  ))
                ) : (
                  <p className="muted-line">Nenhuma busca recente.</p>
                )}
              </div>
            </div>
          </aside>

          <section className="panel panel-right">
            <div className="panel-head result-head">
              <h2>Resultado da Análise</h2>
              <span className={`risk-label ${mapLevel(activeResult?.level || "baixo")}`}>
                {activeResult?.level || "sem resultado"}
              </span>
            </div>

            <div className="links-card links-card-priority">
              <div className="panel-head compact-head">
                <h3>Links OSINT</h3>
                <button type="button" className="ghost-button" onClick={refreshResult}>
                  Refresh
                </button>
              </div>
              <div className="link-list link-list-compact">
                {buildOsintLinks(activeJob).map((item) => (
                  <button
                    key={item.label}
                    type="button"
                    className="link-item link-item-button"
                    onClick={() => setActiveOsintLink(item)}
                  >
                    <span>🔗</span>
                    <span>{item.label}</span>
                  </button>
                ))}
                {!buildOsintLinks(activeJob).length ? (
                  <p className="muted-line">Os links de investigação aparecem quando um job é selecionado.</p>
                ) : null}
              </div>
            </div>

            <div className="result-console executive-console">
              {activeResult ? (
                <>
                  <p className="console-title">
                    RISK SCORE: <strong>{activeResult.risk_score}/100</strong>
                  </p>
                  <div className="console-section">
                    <h4>Resumo executivo</h4>
                    <p>{activeResult.legacy_verdict || activeResult.verdict}</p>
                  </div>
                </>
              ) : (
                <div className="empty-state">
                  <h3>Nenhum resultado carregado</h3>
                  <p className="muted-line">Execute um IOC ou selecione uma busca recente para abrir o resumo executivo.</p>
                </div>
              )}
            </div>

            <div className="result-console">
              {activeResult ? (
                <>
                  <div className="console-section">
                    <h4>Achados por provider</h4>
                  </div>
                  <ul className="console-list">
                    {filteredFindings.map((item, index) => {
                      const parsed = parseFindingProvider(item);
                      return (
                        <li key={`${item}-${index}`}>
                          {parsed.provider ? (
                            <>
                              <span
                                className={`provider-chip ${parsed.description ? "provider-chip-info" : ""}`}
                                title={parsed.description || parsed.provider}
                                data-provider-info={parsed.description || ""}
                              >
                                {parsed.provider}
                              </span>
                              {parsed.detail ? `: ${parsed.detail}` : ""}
                            </>
                          ) : (
                            item
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </>
              ) : (
                <p className="muted-line">Os achados técnicos aparecem aqui assim que a análise for concluída.</p>
              )}
            </div>

            <div className="result-console">
              {activeResult ? (
                <div className="console-section">
                  <h4>Recomendações</h4>
                  <ul className="console-list compact-list">
                    {activeResult.recommendations?.map((item, index) => (
                      <li key={`${item}-${index}`}>{item}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="muted-line">As recomendações operacionais aparecem após a consolidação dos providers.</p>
              )}
            </div>
          </section>
        </section>
        ) : activeTab === "cases" ? (
        <section className="cases-layout">
          <div className="panel">
            <div className="panel-head">
              <h2>Casos</h2>
              <p className="muted-line">Estruture o contexto antes de enviar novos IOCs.</p>
            </div>
            <form className="analysis-form" onSubmit={handleCreateCase}>
              <label>
                Nome do caso
                <input
                  type="text"
                  value={caseForm.name}
                  onChange={(event) => setCaseForm((current) => ({ ...current, name: event.target.value }))}
                />
              </label>
              <label>
                Descrição
                <input
                  type="text"
                  value={caseForm.description}
                  onChange={(event) => setCaseForm((current) => ({ ...current, description: event.target.value }))}
                />
              </label>
              <label>
                Visibilidade
                <select
                  value={caseForm.visibility}
                  onChange={(event) => setCaseForm((current) => ({ ...current, visibility: event.target.value }))}
                >
                  <option value="private">private</option>
                  <option value="team">team</option>
                </select>
              </label>
              <button className="primary-button" type="submit">
                Criar caso
              </button>
            </form>
          </div>

          <div className="panel">
            <div className="panel-head">
              <h2>Investigações</h2>
              <p className="muted-line">Crie trilhas de análise dentro do caso selecionado.</p>
            </div>
            <form className="analysis-form" onSubmit={handleCreateInvestigation}>
              <label>
                Caso alvo
                <select value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)}>
                  <option value="">Selecione um caso</option>
                  {cases.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Título
                <input
                  type="text"
                  value={investigationForm.title}
                  onChange={(event) =>
                    setInvestigationForm((current) => ({ ...current, title: event.target.value }))
                  }
                />
              </label>
              <label>
                Resumo
                <input
                  type="text"
                  value={investigationForm.summary}
                  onChange={(event) =>
                    setInvestigationForm((current) => ({ ...current, summary: event.target.value }))
                  }
                />
              </label>
              <button className="primary-button" type="submit" disabled={!selectedCaseId}>
                Criar investigação
              </button>
            </form>

            <div className="context-lists">
              <div>
                <h3>Casos disponíveis</h3>
                <div className="job-history">
                  {cases.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`history-card ${selectedCaseId === item.id ? "history-card-active" : ""}`}
                      onClick={() => setSelectedCaseId(item.id)}
                    >
                      <strong>{item.name}</strong>
                      <span>{item.visibility} • {item.status}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <h3>Investigações do caso</h3>
                <div className="job-history">
                  {investigations.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`history-card ${
                        selectedInvestigationId === item.id ? "history-card-active" : ""
                      }`}
                      onClick={() => setSelectedInvestigationId(item.id)}
                    >
                      <strong>{item.title}</strong>
                      <span>{item.status}</span>
                    </button>
                  ))}
                  {!investigations.length ? <p className="muted-line">Nenhuma investigação para o caso selecionado.</p> : null}
                </div>
              </div>
            </div>
          </div>
        </section>
        ) : (
        <section className="cases-layout">
          <div className="panel">
            <div className="panel-head">
              <h2>Usuários</h2>
              <p className="muted-line">Novas contas sempre começam com privilégio mínimo.</p>
            </div>
            <form className="analysis-form" onSubmit={handleCreateUser}>
              <label>
                Nome completo
                <input
                  type="text"
                  value={userForm.full_name}
                  onChange={(event) => setUserForm((current) => ({ ...current, full_name: event.target.value }))}
                />
              </label>
              <label>
                Email
                <input
                  type="email"
                  value={userForm.email}
                  onChange={(event) => setUserForm((current) => ({ ...current, email: event.target.value }))}
                />
              </label>
              <label>
                Senha inicial
                <input
                  type="password"
                  autoComplete="new-password"
                  value={userForm.password}
                  onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))}
                />
              </label>
              <label>
                Papel inicial
                <select
                  value={userForm.role}
                  onChange={(event) => setUserForm((current) => ({ ...current, role: event.target.value }))}
                  disabled
                >
                  <option value="minimum">minimum</option>
                </select>
              </label>
              {formMessage ? <p className="success-text">{formMessage}</p> : null}
              {jobError ? <p className="error-text">{jobError}</p> : null}
              <button className="primary-button" type="submit">
                Criar usuário
              </button>
            </form>
          </div>

          <div className="panel">
            <div className="panel-head">
              <h2>Usuários cadastrados</h2>
              <p className="muted-line">Somente administradores podem visualizar contas e alterar privilégios.</p>
            </div>
            <div className="job-history">
              {users.map((item) => (
                <div key={item.id} className="history-card">
                  <strong>{item.full_name}</strong>
                  <span>{item.email}</span>
                  <select value={item.role} onChange={(event) => handleRoleChange(item.id, event.target.value)}>
                    <option value="minimum">minimum</option>
                    <option value="analyst">analyst</option>
                    <option value="manager">manager</option>
                    <option value="admin">admin</option>
                  </select>
                  <small>
                    {item.role} • {item.status}
                  </small>
                </div>
              ))}
              {!users.length ? <p className="muted-line">Nenhum usuário disponível.</p> : null}
            </div>
          </div>
        </section>
        )}
      </section>
      {pendingDeleteJob ? (
        <div className="modal-backdrop" onClick={() => setPendingDeleteJob(null)}>
          <section
            className="confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-ioc-title"
            onClick={(event) => event.stopPropagation()}
          >
            <p className="eyebrow">Confirmação</p>
            <h2 id="delete-ioc-title">Você quer excluir esse IOC?</h2>
            <p className="muted-line">
              {pendingDeleteJob.ioc_type.toUpperCase()} • {pendingDeleteJob.ioc_value}
            </p>
            <div className="confirm-actions">
              <button type="button" className="ghost-button" onClick={() => setPendingDeleteJob(null)}>
                Não
              </button>
              <button type="button" className="primary-button" onClick={hideRecentJob}>
                Sim, excluir
              </button>
            </div>
          </section>
        </div>
      ) : null}
      {activeOsintLink ? (
        <div className="modal-backdrop" onClick={() => setActiveOsintLink(null)}>
          <section
            className="osint-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="osint-viewer-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="panel-head compact-head">
              <div>
                <p className="eyebrow">OSINT Viewer</p>
                <h2 id="osint-viewer-title">{activeOsintLink.label}</h2>
              </div>
              <div className="confirm-actions">
                <a className="ghost-button" href={activeOsintLink.href} target="_blank" rel="noreferrer">
                  Abrir externo
                </a>
                <button type="button" className="primary-button" onClick={() => setActiveOsintLink(null)}>
                  Fechar
                </button>
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
                  <p className="eyebrow">Resumo extraído</p>
                  <p>{activeProviderView?.verdict}</p>
                </div>
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Detalhes estruturados</p>
                  {activeProviderView?.details?.length ? (
                    <div className="provider-detail-grid">
                      {activeProviderView.details.map((item) => (
                        <div key={`${item.label}-${item.value}`} className="provider-detail-row">
                          <span className="provider-detail-label">{item.label}</span>
                          <strong className="provider-detail-value">{item.value}</strong>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-line">Nenhum detalhe estruturado adicional disponível para este provider.</p>
                  )}
                </div>
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Achados deste provider</p>
                  {activeProviderView?.highlights?.length ? (
                    <ul className="console-list compact-list">
                      {activeProviderView.highlights.map((item, index) => (
                        <li key={`${item}-${index}`}>{item}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted-line">Não há achados específicos separados para este provider no resultado atual.</p>
                  )}
                </div>
                <div className="provider-view-card provider-view-card-wide">
                  <p className="eyebrow">Ações sugeridas</p>
                  {activeProviderView?.recommendations?.length ? (
                    <ul className="console-list compact-list">
                      {activeProviderView.recommendations.map((item, index) => (
                        <li key={`${item}-${index}`}>{item}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted-line">Nenhuma recomendação adicional disponível para este provider.</p>
                  )}
                </div>
              </div>
            </div>
            <p className="muted-line">
              Esta visualização usa os dados já consolidados pela análise, sem depender da página externa do provider.
            </p>
          </section>
        </div>
      ) : null}
    </main>
  );
}
