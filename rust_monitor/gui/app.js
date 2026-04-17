let processChart = null;
let userChart = null;
let protocolChart = null;

async function load() {
    const res = await fetch('/api/summary');
    const data = await res.json();

    processChart = drawBarChart(
        "processChart",
        data.processes,
        "process_name",
        "bytes",
        processChart
    );

    userChart = drawBarChart(
        "userChart",
        data.users,
        "user",
        "bytes",
        userChart
    );

    protocolChart = drawBarChart(
        "protocolChart",
        data.protocols,
        "protocol",
        "bytes",
        protocolChart
    );

    renderTop3("processTop3", data.processes, "process_name");
    renderTop3("userTop3", data.users, "user");
    renderTop3("protocolTop3", data.protocols, "protocol");
}

function drawBarChart(canvasId, items, labelField, valueField, oldChart) {
    if (oldChart) oldChart.destroy();

    let labels;

    if (labelField === "process_name") {
        labels = items.map(x => `${x.process_name} (${x.pid})`);
    } else {
        labels = items.map(x => x[labelField]);
    }

    const values = items.map(x => x[valueField]);

    return new Chart(document.getElementById(canvasId), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Bytes",
                data: values,
                backgroundColor: "#4e79a7"
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.raw} bytes`
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: "Bytes"
                    }
                }
            }
        }
    });
}

function renderTop3(divId, items, nameField) {
    const div = document.getElementById(divId);

    let title = "";

    if (nameField === "process_name") title = "Top 3 Processes";
    else if (nameField === "user") title = "Top 3 Users";
    else if (nameField === "protocol") title = "Top 3 Protocols";

    const top3 = [...items]
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 3);

    let html = `<h3>${title}</h3><table>
        <thead>
            <tr>
                <th>Name</th>
                ${nameField === "process_name" ? "<th>PID</th>" : ""}
                <th>Bytes</th>
                <th>Packets</th>
            </tr>
        </thead>
        <tbody>`;

    top3.forEach(item => {
        html += `
            <tr>
                <td>${item[nameField]}</td>
                ${nameField === "process_name" ? `<td>${item.pid}</td>` : ""}
                <td>${item.bytes}</td>
                <td>${item.packets}</td>
            </tr>
        `;
    });

    html += "</tbody></table>";

    div.innerHTML = html;
}

function search(type) {
    const query = document.getElementById("searchInput").value.toLowerCase();

    fetch('/api/summary')
        .then(res => res.json())
        .then(data => {

            let items = [];

            if (type === "process") {
                items = data.processes.filter(p =>
                    p.process_name.toLowerCase().includes(query)
                );
            }

            if (type === "user") {
                items = data.processes.filter(p =>
                    p.user.toLowerCase().includes(query)
                );
            }

            renderSearchTable(items, type);
        });
}
function renderSearchTable(items, type) {
    const div = document.getElementById("searchResults");

    if (items.length === 0) {
        div.innerHTML = "<p>No results found</p>";
        return;
    }

    let html = `
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>Process</th>
                    <th>PID</th>
                    <th>Bytes</th>
                    <th>Packets</th>
                </tr>
            </thead>
            <tbody>
    `;

    items.forEach(item => {
        html += `
            <tr>
                <td>${item.user}</td>
                <td>${item.process_name}</td>
                <td>${item.pid}</td>
                <td>${item.bytes}</td>
                <td>${item.packets}</td>
            </tr>
        `;
    });

    html += "</tbody></table>";

    div.innerHTML = html;
}

load();
setInterval(load, 1000);