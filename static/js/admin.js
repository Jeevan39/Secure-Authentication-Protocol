/**
 * Admin Console Controller
 * Manages tabs, account unlock mutations with CSRF validation, and DOM binding.
 */
function switchTab(tabName) {
    const tabThreats = document.getElementById("tab-threats");
    const tabVerifiers = document.getElementById("tab-verifiers");
    const tabChallenges = document.getElementById("tab-challenges");

    if (tabThreats) tabThreats.classList.toggle("hidden", tabName !== "threats");
    if (tabVerifiers) tabVerifiers.classList.toggle("hidden", tabName !== "verifiers");
    if (tabChallenges) tabChallenges.classList.toggle("hidden", tabName !== "challenges");

    const btnThreats = document.getElementById("tab-btn-threats");
    const btnVerifiers = document.getElementById("tab-btn-verifiers");
    const btnChallenges = document.getElementById("tab-btn-challenges");

    if (btnThreats) btnThreats.className = "btn " + (tabName === "threats" ? "btn-primary" : "btn-secondary") + " admin-tab-btn";
    if (btnVerifiers) btnVerifiers.className = "btn " + (tabName === "verifiers" ? "btn-primary" : "btn-secondary") + " admin-tab-btn";
    if (btnChallenges) btnChallenges.className = "btn " + (tabName === "challenges" ? "btn-primary" : "btn-secondary") + " admin-tab-btn";
}

async function unlockAccount(userId) {
    try {
        const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
        const csrfToken = match ? decodeURIComponent(match[1]) : "";
        const resp = await fetch(`/api/admin/unlock/${userId}`, {
            method: "POST",
            headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {}
        });
        const data = await resp.json();
        if (resp.ok) {
            alert("Account unlocked successfully.");
            window.location.reload();
        } else {
            alert(data.message || "Failed to unlock account.");
        }
    } catch (err) {
        alert("Error: " + err.message);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    // Bind tab buttons
    const btnThreats = document.getElementById("tab-btn-threats");
    const btnVerifiers = document.getElementById("tab-btn-verifiers");
    const btnChallenges = document.getElementById("tab-btn-challenges");

    if (btnThreats) {
        btnThreats.addEventListener("click", () => switchTab("threats"));
    }
    if (btnVerifiers) {
        btnVerifiers.addEventListener("click", () => switchTab("verifiers"));
    }
    if (btnChallenges) {
        btnChallenges.addEventListener("click", () => switchTab("challenges"));
    }

    // Bind unlock buttons
    const unlockButtons = document.querySelectorAll(".btn-unlock-account");
    unlockButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const userId = btn.getAttribute("data-user-id");
            if (userId) {
                unlockAccount(userId);
            }
        });
    });
});

