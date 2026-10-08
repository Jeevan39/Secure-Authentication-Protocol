/**
 * Registration View Controller
 * Handles client-side key derivation, password policy checklist, and registration flow.
 */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("register-form");
    const pwdInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm-password");
    const zkCheckbox = document.getElementById("zk-mode");
    const alertBox = document.getElementById("alert-box");
    const btn = document.getElementById("btn-register");
    const spinner = document.getElementById("spinner");

    if (!form) return;

    function updatePolicyRule(elId, isValid) {
        const el = document.getElementById(elId);
        if (!el) return;
        el.className = "policy-item " + (isValid ? "valid" : "invalid");
        const dot = el.querySelector("span");
        if (dot) dot.textContent = isValid ? "●" : "○";
    }

    if (pwdInput) {
        pwdInput.addEventListener("input", () => {
            const val = pwdInput.value;
            updatePolicyRule("rule-len", val.length >= 10 && val.length <= 128);
            updatePolicyRule("rule-upper", /[A-Z]/.test(val));
            updatePolicyRule("rule-lower", /[a-z]/.test(val));
            updatePolicyRule("rule-digit", /[0-9]/.test(val));
            updatePolicyRule("rule-special", /[!@#$%^&*()-_=+[\]{}|;:,.<>?/~`]/.test(val));
        });
    }

    function showAlert(msg, isError = true) {
        if (!alertBox) return;
        alertBox.textContent = msg;
        alertBox.className = "alert " + (isError ? "alert-error" : "alert-success");
        alertBox.classList.remove("hidden");
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (alertBox) alertBox.classList.add("hidden");

        const usernameInput = document.getElementById("username");
        const username = usernameInput ? usernameInput.value.trim() : "";
        const password = pwdInput ? pwdInput.value : "";
        const confirm = confirmInput ? confirmInput.value : "";

        if (password !== confirm) {
            showAlert("Passwords do not match.", true);
            return;
        }

        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove("hidden");

        try {
            const cryptoCheckbox = document.getElementById("client-crypto-mode") || zkCheckbox;
            if (cryptoCheckbox && cryptoCheckbox.checked) {
                // Client-side key derivation via WebCrypto
                await executeSecureRegistration(username, password);
            } else {
                // Direct enrollment
                const resp = await fetch("/api/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password }),
                });
                const data = await resp.json();
                if (!resp.ok) throw new Error(data.message || "Registration failed.");
            }

            showAlert("Account registered successfully! Redirecting to login...", false);
            setTimeout(() => {
                window.location.href = "/login";
            }, 1000);
        } catch (err) {
            showAlert(err.message || "Registration failed.", true);
            if (btn) btn.disabled = false;
            if (spinner) spinner.classList.add("hidden");
        }
    });
});

