function defaultApiBaseUrl() {
  if (typeof window === "undefined") {
    return "http://localhost:8000/api/v1";
  }
  const host = window.location.hostname || "localhost";
  return `http://${host}:8000/api/v1`;
}

const API_BASE_URL = import.meta.env?.VITE_API_BASE_URL || defaultApiBaseUrl();

function buildHeaders(options = {}) {
  return {
    "Content-Type": "application/json",
    ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
    ...(options.headers || {}),
  };
}

export async function request(path, options = {}) {
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
  login: (email, password, requestOptions = {}) =>
    request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
      ...requestOptions,
    }),
  logout: (token, requestOptions = {}) =>
    request("/auth/logout", {
      method: "POST",
      token,
      ...requestOptions,
    }),
  changePassword: (token, payload, requestOptions = {}) =>
    request("/auth/change-password", {
      method: "POST",
      token,
      body: JSON.stringify(payload),
      ...requestOptions,
    }),
  createAnalysisJob: (token, payload, requestOptions = {}) =>
    request("/analysis-jobs/", {
      method: "POST",
      token,
      body: JSON.stringify(payload),
      ...requestOptions,
    }),
  listAnalysisJobs: (token, requestOptions = {}) => request("/analysis-jobs/", { token, ...requestOptions }),
  getAnalysisJob: (token, jobId, requestOptions = {}) => request(`/analysis-jobs/${jobId}`, { token, ...requestOptions }),
  getAnalysisResult: (token, jobId, requestOptions = {}) => request(`/analysis-jobs/${jobId}/result`, { token, ...requestOptions }),
  getMitreIndex: (token, requestOptions = {}) =>
    request("/mitre/index", {
      token,
      ...requestOptions,
    }),
  getMitreTechniqueDetail: (token, externalId, requestOptions = {}) =>
    request(`/mitre/techniques/${encodeURIComponent(externalId)}`, {
      token,
      ...requestOptions,
    }),
  listTaxiiSources: (token, requestOptions = {}) => request("/threat-feeds/taxii/sources", { token, ...requestOptions }),
  getTaxiiCollections: (token, sourceId, requestOptions = {}) =>
    request(`/threat-feeds/taxii/sources/${encodeURIComponent(sourceId)}/collections`, { token, ...requestOptions }),
  getTaxiiManifest: (token, sourceId, collectionId, params = {}, requestOptions = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value) query.set(key, value);
    });
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request(
      `/threat-feeds/taxii/sources/${encodeURIComponent(sourceId)}/collections/${encodeURIComponent(collectionId)}/manifest${suffix}`,
      { token, ...requestOptions },
    );
  },
  getTaxiiObjects: (token, sourceId, collectionId, params = {}, requestOptions = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value) query.set(key, value);
    });
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request(
      `/threat-feeds/taxii/sources/${encodeURIComponent(sourceId)}/collections/${encodeURIComponent(collectionId)}/objects${suffix}`,
      { token, ...requestOptions },
    );
  },
};
