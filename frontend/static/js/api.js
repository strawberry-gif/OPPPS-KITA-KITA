const TOKEN_KEY = "oppps.token";
const USER_KEY = "oppps.user";

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export const auth = {
  get token() {
    return localStorage.getItem(TOKEN_KEY) || "";
  },
  get user() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || "null");
    } catch {
      return null;
    }
  },
  setSession(payload) {
    localStorage.setItem(TOKEN_KEY, payload.access_token);
    localStorage.setItem(USER_KEY, JSON.stringify(payload.user));
  },
  setUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
  get isAuthenticated() {
    return Boolean(this.token);
  },
};

export function withQuery(path, params = {}) {
  const query = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    query.append(key, String(value));
  });
  const text = query.toString();
  if (!text) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${text}`;
}

function extractMessage(payload, status) {
  if (payload && typeof payload === "object") {
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.errors) && payload.errors.length) {
      return payload.errors
        .map((item) => item.message || item.msg || "Invalid value")
        .slice(0, 3)
        .join("; ");
    }
    if (payload.detail) return JSON.stringify(payload.detail);
  }
  if (typeof payload === "string" && payload.trim()) return payload.trim().slice(0, 300);
  return `Request failed (HTTP ${status})`;
}

async function rawRequest(path, options = {}) {
  const { method = "GET", body, headers = {}, signal } = options;
  const finalHeaders = { Accept: "application/json", ...headers };
  const token = auth.token;
  if (token) finalHeaders.Authorization = `Bearer ${token}`;

  let payload;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    finalHeaders["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(path, {
      method,
      headers: finalHeaders,
      body: payload,
      signal,
      credentials: "same-origin",
    });
  } catch (error) {
    if (error && error.name === "AbortError") throw error;
    throw new ApiError(
      "Cannot reach the API server. Verify that Uvicorn is running.",
      0,
      null,
    );
  }

  const contentType = response.headers.get("content-type") || "";
  let data = null;
  if (contentType.includes("application/json")) {
    data = await response.json().catch(() => null);
  } else if (response.status !== 204) {
    data = await response.text().catch(() => "");
  }

  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/api/auth/login")) {
      auth.clear();
      if (!location.pathname.startsWith("/login")) {
        location.replace("/login");
      }
    }
    throw new ApiError(extractMessage(data, response.status), response.status, data);
  }
  return data;
}

export const api = {
  request: rawRequest,
  get(path, params) {
    return rawRequest(withQuery(path, params));
  },
  post(path, body, params) {
    return rawRequest(withQuery(path, params), { method: "POST", body });
  },
  put(path, body) {
    return rawRequest(path, { method: "PUT", body });
  },
  patch(path, body) {
    return rawRequest(path, { method: "PATCH", body });
  },
  delete(path) {
    return rawRequest(path, { method: "DELETE" });
  },
};

export async function login(email, password) {
  const body = new URLSearchParams({ username: email.trim(), password });
  let response;
  try {
    response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError("Cannot reach the API server. Verify that Uvicorn is running.", 0, null);
  }
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json().catch(() => null)
    : await response.text().catch(() => "");
  if (!response.ok) {
    throw new ApiError(extractMessage(data, response.status), response.status, data);
  }
  auth.setSession(data);
  return data;
}

export function logout() {
  auth.clear();
  location.replace("/login");
}
