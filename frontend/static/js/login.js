import { api, auth, login } from "./api.js";

const form = document.getElementById("loginForm");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const errorBox = document.getElementById("loginError");
const submitButton = document.getElementById("loginSubmit");
const toggleButton = document.getElementById("togglePassword");
const healthBox = document.getElementById("loginHealth");

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.add("show");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.remove("show");
}

async function checkHealth() {
  if (!healthBox) return;
  try {
    const health = await api.get("/api/dashboard/health");
    const label = healthBox.querySelector("span:last-child");
    if (health.database === "connected" && health.models_ready) {
      label.textContent = "System online · detection models loaded";
      healthBox.classList.remove("degraded");
    } else if (health.database === "connected") {
      label.textContent = "Database connected · detection models missing";
      healthBox.classList.add("degraded");
    } else {
      label.textContent = "Database unavailable";
      healthBox.classList.add("degraded");
    }
  } catch {
    const label = healthBox.querySelector("span:last-child");
    if (label) label.textContent = "API server unreachable";
    healthBox.classList.add("degraded");
  }
}

async function redirectIfAuthenticated() {
  if (!auth.isAuthenticated) return;
  try {
    const user = await api.get("/api/auth/me");
    auth.setUser(user);
    location.replace("/app");
  } catch {
    auth.clear();
  }
}

toggleButton?.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  toggleButton.textContent = showing ? "Show" : "Hide";
  passwordInput.focus();
});

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email) {
    showError("Enter your email address.");
    emailInput.focus();
    return;
  }
  if (password.length < 8) {
    showError("Password must contain at least 8 characters.");
    passwordInput.focus();
    return;
  }
  submitButton.disabled = true;
  const original = submitButton.innerHTML;
  submitButton.innerHTML = '<span class="spinner"></span> Signing in…';
  try {
    await login(email, password);
    submitButton.innerHTML = '<span class="spinner"></span> Loading console…';
    location.replace("/app");
  } catch (error) {
    showError(error.message || "Sign-in failed.");
    submitButton.disabled = false;
    submitButton.innerHTML = original;
    passwordInput.select();
  }
});

redirectIfAuthenticated();
checkHealth();
