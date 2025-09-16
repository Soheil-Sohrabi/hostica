const API = "/api";
let currentFolder = "/";
let currentUser = null;

function showMsg(t) {
  const el = document.getElementById("adminMsg");
  el.textContent = t;
  setTimeout(() => el.textContent = "", 5000);
}

// بارگذاری کاربران
async function loadUsers() {
  const res = await fetch(API + "/admin/users");
  const data = await res.json();
  const cont = document.getElementById("usersList");
  cont.innerHTML = "";
  for (let u in data.users) {
    const div = document.createElement("div");
    div.className = "userItem";
    div.innerHTML = `${u} — Admin: ${data.users[u].isAdmin} 
      <button onclick="toggleAdmin('${u}', ${!data.users[u].isAdmin})">Toggle Admin</button>`;
    cont.appendChild(div);
  }
}

// تغییر ادمین بودن
async function toggleAdmin(username, isAdmin) {
  const res = await fetch(API + "/admin/setAdmin", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ user: username, isAdmin })
  });
  const data = await res.json();
  showMsg(data.message || data.error);
  loadUsers();
}

// فایل‌ها
async function loadFiles() {
  const user = document.getElementById("targetUser").value.trim();
  if (!user) return alert("Enter username first");
  currentUser = user;

  const res = await fetch(`${API}/files/list?user=${encodeURIComponent(user)}&folder=${encodeURIComponent(currentFolder)}`);
  const data = await res.json();
  const cont = document.getElementById("filesList");
  cont.innerHTML = "";
  
  if (currentFolder !== "/") {
    const backBtn = document.createElement("div");
    backBtn.className = "folder";
    backBtn.textContent = "⬅️ Back";
    backBtn.onclick = () => { goBack(); };
    cont.appendChild(backBtn);
  }

  (data.files || []).forEach(f => {
    const div = document.createElement("div");
    div.className = f.isFolder ? "folder" : "file";

    if (f.isFolder) {
      div.textContent = f.originalName;
      div.onclick = () => {
        currentFolder += f.originalName + "/";
        loadFiles();
      };
    } else {
      div.innerHTML = `${f.originalName} — ${Math.round(f.size/1024)} KB 
        <button onclick="download('${f.id}')">Download</button>
        <button onclick="del('${f.id}')">Delete</button>`;
    }
    cont.appendChild(div);
  });
}

function goBack() {
  const parts = currentFolder.split("/").filter(Boolean);
  parts.pop();
  currentFolder = "/" + (parts.length ? parts.join("/") + "/" : "");
  loadFiles();
}

async function download(id) {
  const res = await fetch(`${API}/files/download/${id}?user=${encodeURIComponent(currentUser)}&folder=${encodeURIComponent(currentFolder)}`);
  if (!res.ok) return alert("Error");
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = id;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

async function del(id) {
  if (!confirm("Delete file?")) return;
  const res = await fetch(`${API}/files/${id}?user=${encodeURIComponent(currentUser)}&folder=${encodeURIComponent(currentFolder)}`, { method: "DELETE" });
  if (!res.ok) return alert("Error");
  loadFiles();
}

// ایجاد فولدر
async function createFolder() {
  const name = document.getElementById("newFolder").value.trim();
  if (!name) return alert("Enter folder name");
  const res = await fetch(API + "/folder/create", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ folderName: name, currentFolder, user: currentUser })
  });
  const data = await res.json();
  if (res.ok) {
    document.getElementById("newFolder").value = "";
    loadFiles();
  } else alert(data.error || "Error");
}

// خروج
function logout() {
  window.location.href = "/"; // برمیگرده به صفحه اصلی
}

// بارگذاری اولیه
loadUsers();
