async function load() {
  const res = await fetch('/api/summary');
  const data = await res.json();

  render("processes", data.processes, ["pid", "process_name", "user", "bytes", "packets"]);
  render("users", data.users, ["user", "bytes", "packets"]);
  render("protocols", data.protocols, ["protocol", "bytes", "packets"]);
}

function render(id, items, fields) {
  const table = document.getElementById(id);
  table.innerHTML = "";

  let header = "<tr>" + fields.map(f => `<th>${f}</th>`).join("") + "</tr>";
  let rows = items.slice(0, 5).map(item =>
    "<tr>" + fields.map(f => `<td>${item[f]}</td>`).join("") + "</tr>"
  ).join("");

  table.innerHTML = header + rows;
}

setInterval(load, 1000);