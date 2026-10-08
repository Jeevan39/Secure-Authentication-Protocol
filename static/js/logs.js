/**
 * Security Logs Controller
 * Fetches and renders security audit logs with XSS prevention and CSP compliance.
 */
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function fetchLogs() {
    const tbody = document.getElementById("logs-tbody");
    if (!tbody) return;

    try {
        const resp = await fetch("/api/auth/logs");
        if (!resp.ok) throw new Error("Failed to fetch logs");
        const data = await resp.json();

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="table-empty-cell">No audit logs recorded yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.logs.map(log => {
            const date = new Date(log.timestamp * 1000).toLocaleString();
            const badgeClass = log.success ? "badge-success" : "badge-failure";
            const badgeText = log.success ? "SUCCESS" : "BLOCKED / FAILED";

            return `
                <tr>
                    <td class="cell-mono-sec">${date}</td>
                    <td class="cell-user">${escapeHtml(log.username_attempted)}</td>
                    <td><span class="cell-mono-sm">${escapeHtml(log.event)}</span></td>
                    <td><span class="badge ${badgeClass}">${badgeText}</span></td>
                    <td class="cell-mono-muted">${escapeHtml(log.ip_address)}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="table-error-cell">Error loading audit logs: ${escapeHtml(err.message)}</td></tr>`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    fetchLogs();

    const refreshBtn = document.getElementById("btn-refresh-logs");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", (e) => {
            e.preventDefault();
            fetchLogs();
        });
    }
});

