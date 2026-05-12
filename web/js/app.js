const API_URL = "/alerts";

async function loadAlerts() {
    const ip = document.getElementById("ipFilter").value;
    const severity = document.getElementById("severityFilter").value;

    let url = API_URL + "?limit=50";

    if (ip) url += `&ip=${ip}`;
    if (severity) url += `&severity=${severity}`;

    const res = await fetch(url);
    const data = await res.json();

    renderTable(data);
}

function renderTable(alerts) {
    const table = document.getElementById("alertsTable");
    table.innerHTML = "";

    alerts.forEach(a => {
        const row = document.createElement("tr");

        const severityClass = a.Severity.toLowerCase();

        row.innerHTML = `
            <td>${new Date(a.Timestamp).toLocaleString()}</td>
            <td>${a.RuleName}</td>
            <td class="${severityClass}">${a.Severity}</td>
            <td>${a.SourceIP}</td>
            <td>${a.Username}</td>
            <td>${a.Message}</td>
            <td>${a.EventCount}</td>
        `;

        table.appendChild(row);
    });
}

// Auto-refresh every 3 seconds
setInterval(loadAlerts, 3000);

// Initial load
loadAlerts();