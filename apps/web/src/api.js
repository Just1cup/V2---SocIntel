function defaultApiBaseUrl() {
  if (typeof window === "undefined") {
    return "http://localhost:8000/api/v1";
  }
  const host = window.location.hostname || "localhost";
  return `http://${host}:8000/api/v1`;
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || defaultApiBaseUrl();

function buildHeaders(options = {}) {
  return {
    "Content-Type": "application/json",
    ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
    ...(options.headers || {}),
  };
}

async function request(path, options = {}) {
  const headers = buildHeaders(options);

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  let payload = null;
  if (response.status === 204) {
    return null;
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    const text = await response.text();
    payload = text || null;
  }

  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? payload.detail
        : "Request failed.";
    throw new Error(Array.isArray(detail) ? detail.map((item) => item.msg).join(" | ") : String(detail));
  }

  return payload;
}

export const api = {
  login: (email, password) =>
    request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (payload) =>
    request("/users/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  logout: (token) =>
    request("/auth/logout", {
      method: "POST",
      token,
    }),
  createAnalysisJob: (token, payload) =>
    request("/analysis-jobs/", {
      method: "POST",
      token,
      body: JSON.stringify(payload),
    }),
  listUsers: (token) =>
    request("/users/", {
      token,
    }),
  createUser: (token, payload) =>
    request("/users/", {
      method: "POST",
      token,
      body: JSON.stringify(payload),
    }),
  updateUserRole: (token, userId, payload) =>
    request(`/users/${userId}/role`, {
      method: "PATCH",
      token,
      body: JSON.stringify(payload),
    }),
  listAnalysisJobs: (token) => request("/analysis-jobs/", { token }),
  getAnalysisJob: (token, jobId) => request(`/analysis-jobs/${jobId}`, { token }),
  getAnalysisResult: (token, jobId) => request(`/analysis-jobs/${jobId}/result`, { token }),
  getMitreIndex: (token) =>
    request("/mitre/index", {
      token,
    }),
  getMitreTechniqueDetail: (token, externalId) =>
    request(`/mitre/techniques/${encodeURIComponent(externalId)}`, {
      token,
    }),
};
