const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

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
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    payload = await response.text();
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
  logout: () =>
    request("/auth/logout", {
      method: "POST",
    }),
  listCases: (token) =>
    request("/cases/", {
      token,
    }),
  createCase: (token, payload) =>
    request("/cases/", {
      method: "POST",
      token,
      body: JSON.stringify(payload),
    }),
  listInvestigations: (token, caseId) =>
    request(`/cases/${caseId}/investigations`, {
      token,
    }),
  createInvestigation: (token, caseId, payload) =>
    request(`/cases/${caseId}/investigations`, {
      method: "POST",
      token,
      body: JSON.stringify(payload),
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
  listAnalysisJobs: (token, filters = {}) => {
    const params = new URLSearchParams();
    if (filters.case_id) params.set("case_id", filters.case_id);
    if (filters.investigation_id) params.set("investigation_id", filters.investigation_id);
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request(`/analysis-jobs/${suffix}`, { token });
  },
  getAnalysisJob: (token, jobId) => request(`/analysis-jobs/${jobId}`, { token }),
  getAnalysisResult: (token, jobId) => request(`/analysis-jobs/${jobId}/result`, { token }),
};
