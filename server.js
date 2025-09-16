const express = require("express");
const fs = require("fs");
const fsPromises = require("fs").promises;
const path = require("path");
const multer = require("multer");
const session = require("express-session");

const app = express();
const PORT = 3000;

// مسیر اصلی آپلود
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// مسیر پوشه Trash
const TRASH_DIR = path.join(__dirname, "trash");
if (!fs.existsSync(TRASH_DIR)) fs.mkdirSync(TRASH_DIR, { recursive: true });

// مسیر فایل کاربران
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const USERS_FILE = path.join(DATA_DIR, "users.json");
const DELETED_USERS_FILE = path.join(DATA_DIR, "deleted_users.json");

// بارگذاری کاربران
let users = {};
if (fs.existsSync(USERS_FILE)) {
  users = JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
} else {
  fs.writeFileSync(USERS_FILE, JSON.stringify({}), "utf-8");
}

// بارگذاری کاربران حذف‌شده
let deletedUsers = [];
if (fs.existsSync(DELETED_USERS_FILE)) {
  deletedUsers = JSON.parse(fs.readFileSync(DELETED_USERS_FILE, "utf-8"));
} else {
  fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify([]), "utf-8");
}

// تابع برای ساخت مسیر Trash کاربر با نام منحصربه‌فرد
function getTrashPath(username, itemName, isFolder = false) {
  if (!username || !itemName) {
    console.error(`getTrashPath error: username=${username}, itemName=${itemName}`);
    throw new Error("Username or itemName is undefined");
  }
  const userTrashDir = path.join(TRASH_DIR, username);
  if (!fs.existsSync(userTrashDir)) fs.mkdirSync(userTrashDir, { recursive: true });
  const timestamp = Date.now();
  const uniqueName = `${itemName}_${timestamp}`;
  return path.join(userTrashDir, uniqueName);
}

// تابع برای استخراج نام اصلی از trashPath
function extractOriginalName(trashPath) {
  const basename = path.basename(trashPath);
  const parts = basename.split('_');
  if (parts.length > 1) {
    parts.pop();
    return parts.join('_');
  }
  return basename;
}

// تابع پاکسازی دوره‌ای Trash (هر 24 ساعت)
function cleanupOldTrash() {
  setInterval(async () => {
    try {
      const now = Date.now();
      const cutoff = now - (24 * 60 * 60 * 1000); // 24 ساعت قبل

      const trashUsers = fs.readdirSync(TRASH_DIR);
      for (const user of trashUsers) {
        const userTrashDir = path.join(TRASH_DIR, user);
        if (fs.statSync(userTrashDir).isDirectory()) {
          const trashItems = fs.readdirSync(userTrashDir);
          for (const item of trashItems) {
            const itemPath = path.join(userTrashDir, item);
            const stats = fs.statSync(itemPath);
            if (stats.mtimeMs < cutoff) {
              console.log(`Deleting old item from trash: ${itemPath}`);
              await fsPromises.rm(itemPath, { recursive: true, force: true });
            }
          }
          if (fs.readdirSync(userTrashDir).length === 0) {
            fs.rmdirSync(userTrashDir);
          }
        }
      }

      deletedUsers = deletedUsers.filter(u => new Date(u.deletionTime).getTime() > cutoff);
      saveDeletedUsers();
    } catch (err) {
      console.error('Cleanup error:', err);
    }
  }, 24 * 60 * 60 * 1000); // هر 24 ساعت
}

// شروع پاکسازی دوره‌ای
cleanupOldTrash();

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf-8");
}

function saveDeletedUsers() {
  fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify(deletedUsers, null, 2), "utf-8");
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({ secret: "secret-key", resave: false, saveUninitialized: true }));

// Multer – ذخیره فایل در فولدر کاربر
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // مسیر مقصد بعداً توی endpoint مشخص می‌شه
    cb(null, UPLOADS_DIR); // مسیر موقت
  },
  filename: (req, file, cb) => {
    console.log(`Server: Saving file as: ${file.originalname}`); // لاگ برای دیباگ
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// --- احراز هویت ---
app.post("/api/auth/signup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "fill all inputs please!" });
  if (users[username]) return res.status(400).json({ error: "username taken" });
  users[username] = { password, isAdmin: false };
  saveUsers();
  res.json({ message: "Registered! Please login" });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!users[username] || users[username].password !== password)
    return res.status(400).json({ error: "wrong username or password" });
  req.session.username = username;
  res.json({ token: "session-token", isAdmin: users[username].isAdmin, username });
});

// --- ایجاد فولدر ---
app.post("/api/folder/create", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.body.user && users[username]?.isAdmin) targetUser = req.body.user;

  const { folderName, currentFolder } = req.body;
  if (!folderName) return res.status(400).json({ error: "folder name required" });
  let folderPath = currentFolder || '/';
  folderPath = path.normalize(folderPath);
  if (folderPath.startsWith(path.sep)) folderPath = folderPath.slice(1);

  const userFolder = path.join(UPLOADS_DIR, targetUser, folderPath);
  const newFolder = path.join(userFolder, folderName);
  try {
    if (!fs.existsSync(newFolder)) await fsPromises.mkdir(newFolder, { recursive: true });
    res.json({ message: "Folder created" });
  } catch (err) {
    console.error(`Error creating folder: ${err}`);
    res.status(500).json({ error: "Cannot create folder" });
  }
});

// --- حذف فولدر ---
app.delete("/api/folder/:name", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });
  const folderName = req.params.name;
  if (!folderName) return res.status(400).json({ error: "folder name required" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  let folder = req.query.currentFolder || '/';
  folder = path.normalize(folder);
  if (folder.startsWith(path.sep)) folder = folder.slice(1);

  const folderPath = path.join(UPLOADS_DIR, targetUser, folder, folderName);
  const trashPath = getTrashPath(targetUser, folderName, true);
  try {
    if (!fs.existsSync(folderPath)) return res.status(404).json({ error: "Folder not found" });
    console.log(`Moving folder to trash: ${folderPath} -> ${trashPath}`);
    await fsPromises.rename(folderPath, trashPath);
    res.json({ message: "Folder moved to Trash", folderName, trashId: path.basename(trashPath) });
  } catch (err) {
    console.error(`Error moving folder to trash: ${err}`);
    res.status(500).json({ error: "Cannot move folder to Trash" });
  }
});

// --- Undo حذف فولدر ---
app.post("/api/folder/undo", async (req, res) => {
  try {
    const { folderName, currentFolder, trashId } = req.body;
    const username = req.session.username;
    if (!username) return res.status(401).json({ error: "not logged in" });
    if (!folderName || !trashId) return res.status(400).json({ error: "folder name and trashId required" });

    let targetUser = username;
    if (req.body.user && users[username]?.isAdmin) targetUser = req.body.user;

    const trashPath = path.join(TRASH_DIR, targetUser, trashId);
    const originalPath = path.join(UPLOADS_DIR, targetUser, currentFolder || '/', folderName);

    if (!fs.existsSync(trashPath)) return res.status(404).json({ error: `Folder not found in Trash: ${trashPath}` });
    console.log(`Restoring folder: ${trashPath} -> ${originalPath}`);
    await fsPromises.mkdir(path.dirname(originalPath), { recursive: true });
    await fsPromises.rename(trashPath, originalPath);
    res.json({ message: "Folder restored to dashboard" });
  } catch (err) {
    console.error(`Error restoring folder: ${err}`);
    res.status(500).json({ error: "Cannot undo folder deletion" });
  }
});

// --- آپلود فایل ---
app.post("/api/files/upload", upload.fields([{ name: 'file', maxCount: 1 }]), async (req, res) => {
  console.log(`Server: Received FormData - file=${req.files?.file?.[0]?.originalname}, folder=${req.body.folder}`); // لاگ برای دیباگ
  if (!req.files || !req.files.file) return res.status(400).json({ error: "No file uploaded" });

  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  let folder = req.body.folder || '/';
  console.log(`Server: Processing folder=${folder} for upload`); // لاگ برای دیباگ
  folder = path.normalize(folder);
  if (folder === '/' || folder === '') {
    folder = ''; // اطمینان از خالی بودن مسیر برای فولدر اصلی
  } else if (folder.startsWith(path.sep)) {
    folder = folder.slice(1);
  }

  const tempPath = req.files.file[0].path; // مسیر موقت که multer ذخیره کرده
  const finalPath = path.join(UPLOADS_DIR, targetUser, folder, req.files.file[0].originalname);
  console.log(`Server: Moving file from ${tempPath} to ${finalPath}`); // لاگ برای دیباگ

  try {
    // ایجاد پوشه مقصد اگه وجود نداره
    await fsPromises.mkdir(path.dirname(finalPath), { recursive: true });
    // جابجایی فایل از مسیر موقت به مسیر نهایی
    await fsPromises.rename(tempPath, finalPath);
    console.log(`Server: Upload completed for file=${req.files.file[0].originalname}, folder=${req.body.folder}`); // لاگ برای دیباگ
    res.json({ message: "File uploaded" });
  } catch (err) {
    console.error(`Server: Error moving file: ${err}`);
    res.status(500).json({ error: "Cannot move file to destination" });
  }
});

// --- تغییر نام فایل یا فولدر ---
app.post("/api/rename", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.body.user && users[username]?.isAdmin) targetUser = req.body.user;

  const { oldName, newName, currentFolder, isFolder } = req.body;
  if (!oldName || !newName) return res.status(400).json({ error: "oldName and newName required" });

  let folder = currentFolder || '/';
  folder = path.normalize(folder);
  if (folder === '/' || folder === '') {
    folder = '';
  } else if (folder.startsWith(path.sep)) {
    folder = folder.slice(1);
  }

  const oldPath = path.join(UPLOADS_DIR, targetUser, folder, oldName);
  const newPath = path.join(UPLOADS_DIR, targetUser, folder, newName);

  try {
    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: `${isFolder ? 'Folder' : 'File'} not found` });
    if (fs.existsSync(newPath)) return res.status(400).json({ error: `${isFolder ? 'Folder' : 'File'} with new name already exists` });

    console.log(`Server: Renaming ${isFolder ? 'folder' : 'file'} from ${oldPath} to ${newPath}`);
    await fsPromises.rename(oldPath, newPath);
    res.json({ message: `${isFolder ? 'Folder' : 'File'} renamed successfully` });
  } catch (err) {
    console.error(`Server: Error renaming ${isFolder ? 'folder' : 'file'}: ${err}`);
    res.status(500).json({ error: `Cannot rename ${isFolder ? 'folder' : 'file'}` });
  }
});

// --- انتقال فایل به فولدر یا مسیر والد ---
app.post("/api/files/move", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.body.user && users[username]?.isAdmin) targetUser = req.body.user;

  const { fileId, fileName, currentFolder, targetFolder } = req.body;
  if (!fileId || !fileName || !currentFolder) {
    return res.status(400).json({ error: "fileId, fileName, and currentFolder required" });
  }

  let currentPath = currentFolder || '/';
  currentPath = path.normalize(currentPath);
  if (currentPath === '/' || currentPath === '') {
    currentPath = '';
  } else if (currentPath.startsWith(path.sep)) {
    currentPath = currentPath.slice(1);
  }

  let targetPath = targetFolder || ''; // Empty targetFolder means parent folder
  targetPath = path.normalize(targetPath);
  if (targetPath === '/' || targetPath === '') {
    targetPath = '';
  } else if (targetPath.startsWith(path.sep)) {
    targetPath = targetPath.slice(1);
  }

  const sourcePath = path.join(UPLOADS_DIR, targetUser, currentPath, fileName);
  const destPath = path.join(UPLOADS_DIR, targetUser, targetPath, fileName);

  try {
    if (!fs.existsSync(sourcePath)) {
      return res.status(404).json({ error: "File not found in source path" });
    }
    if (fs.existsSync(destPath)) {
      return res.status(400).json({ error: "File already exists in target folder" });
    }

    console.log(`Moving file: ${sourcePath} -> ${destPath}`);
    await fsPromises.mkdir(path.dirname(destPath), { recursive: true });
    await fsPromises.rename(sourcePath, destPath);
    res.json({ message: "File moved successfully" });
  } catch (err) {
    console.error(`Error moving file: ${err}`);
    res.status(500).json({ error: "Cannot move file" });
  }
});

// --- لیست فایل‌ها و فولدرها ---
app.get("/api/files/list", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder);
  if (folder.startsWith(path.sep)) folder = folder.slice(1);

  const baseFolder = path.join(UPLOADS_DIR, targetUser, folder);
  try {
    if (!fs.existsSync(baseFolder)) return res.json({ files: [] });
    const files = (await fsPromises.readdir(baseFolder)).map(f => {
      const stats = fs.statSync(path.join(baseFolder, f));
      return { originalName: f, size: stats.size, isFolder: stats.isDirectory(), id: f };
    });
    res.json({ files });
  } catch (err) {
    console.error(`Error listing files: ${err}`);
    res.status(500).json({ error: "Cannot list files" });
  }
});

// --- دانلود فایل ---
app.get("/api/files/download/:id", (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).send("not logged in");

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder);
  if (folder.startsWith(path.sep)) folder = folder.slice(1);

  const filePath = path.join(UPLOADS_DIR, targetUser, folder, req.params.id);
  if (!fs.existsSync(filePath)) return res.status(404).send("file not found");
  res.download(filePath);
});

// --- حذف فایل ---
app.delete("/api/files/:id", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).send("not logged in");
  const fileId = req.params.id;
  if (!fileId) return res.status(400).json({ error: "file id required" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder);
  if (folder.startsWith(path.sep)) folder = folder.slice(1);

  const filePath = path.join(UPLOADS_DIR, targetUser, folder, fileId);
  const trashPath = getTrashPath(targetUser, fileId, false);
  try {
    if (!fs.existsSync(filePath)) return res.status(404).send("file not found");
    console.log(`Moving file to trash: ${filePath} -> ${trashPath}`);
    await fsPromises.rename(filePath, trashPath);
    res.json({ message: "File moved to Trash", fileId, trashId: path.basename(trashPath) });
  } catch (err) {
    console.error(`Error moving file to trash: ${err}`);
    res.status(500).json({ error: "Cannot move file to Trash" });
  }
});

// --- Undo حذف فایل ---
app.post("/api/files/undo", async (req, res) => {
  try {
    const { id, folder, trashId } = req.body;
    const username = req.session.username;
    if (!username) return res.status(401).json({ error: "not logged in" });
    if (!id || !trashId) return res.status(400).json({ error: "file id and trashId required" });

    let targetUser = username;
    if (req.body.user && users[username]?.isAdmin) targetUser = req.body.user;

    const trashPath = path.join(TRASH_DIR, targetUser, trashId);
    const originalPath = path.join(UPLOADS_DIR, targetUser, folder || '/', id);

    if (!fs.existsSync(trashPath)) return res.status(404).json({ error: `File not found in Trash: ${trashPath}` });
    console.log(`Restoring file: ${trashPath} -> ${originalPath}`);
    await fsPromises.mkdir(path.dirname(originalPath), { recursive: true });
    await fsPromises.rename(trashPath, originalPath);
    res.json({ message: "File restored to dashboard" });
  } catch (err) {
    console.error(`Error restoring file: ${err}`);
    res.status(500).json({ error: "Cannot undo file deletion" });
  }
});

// --- لیست Trash ---
app.get("/api/trash/list", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  const userTrashDir = path.join(TRASH_DIR, targetUser);
  try {
    if (!fs.existsSync(userTrashDir)) return res.json({ trashItems: [] });
    const trashItems = await fsPromises.readdir(userTrashDir);
    const items = [];
    for (const itemName of trashItems) {
      const itemPath = path.join(userTrashDir, itemName);
      const stats = fs.statSync(itemPath);
      const isFolder = stats.isDirectory();
      const originalName = extractOriginalName(itemName);
      items.push({
        id: originalName,
        originalName,
        trashId: itemName,
        size: stats.size,
        isFolder,
        deletionTime: stats.mtimeMs,
        owner: targetUser
      });
    }
    res.json({ trashItems: items });
  } catch (err) {
    console.error(`Error listing trash: ${err}`);
    res.status(500).json({ error: "Cannot list trash" });
  }
});

// --- حذف دائم از Trash ---
app.delete("/api/trash/:itemName", async (req, res) => {
  const username = req.session.username;
  if (!username) return res.status(401).json({ error: "not logged in" });
  const itemName = req.params.itemName;
  if (!itemName) return res.status(400).json({ error: "item name required" });

  let targetUser = username;
  if (req.query.user && users[username]?.isAdmin) targetUser = req.query.user;

  const trashPath = path.join(TRASH_DIR, targetUser, itemName);
  try {
    if (!fs.existsSync(trashPath)) return res.status(404).json({ error: "Item not found in trash" });
    console.log(`Permanently deleting from trash: ${trashPath}`);
    await fsPromises.rm(trashPath, { recursive: true, force: true });
    res.json({ message: "Item permanently deleted" });
  } catch (err) {
    console.error(`Error deleting from trash: ${err}`);
    res.status(500).json({ error: "Cannot delete from trash" });
  }
});

// --- Admin APIs ---
app.get("/api/admin/users", (req, res) => {
  const username = req.session.username;
  if (!username || !users[username]?.isAdmin) return res.status(403).json({ error: "Forbidden" });
  const list = Object.keys(users).map(u => ({ username: u, isAdmin: users[u].isAdmin }));
  res.json({ users: list });
});

app.delete("/api/admin/user/:username", async (req, res) => {
  const username = req.session.username;
  if (!username || !users[username]?.isAdmin) return res.status(403).json({ error: "Forbidden" });
  const delUser = req.params.username;
  if (!delUser) return res.status(400).json({ error: "username required" });
  if (users[delUser]) {
    deletedUsers.push({ username: delUser, ...users[delUser], deletionTime: Date.now() });
    saveDeletedUsers();
    
    const userDir = path.join(UPLOADS_DIR, delUser);
    const trashUserDir = getTrashPath(delUser, delUser, true);
    if (fs.existsSync(userDir)) {
      console.log(`Moving user folder to trash: ${userDir} -> ${trashUserDir}`);
      await fsPromises.rename(userDir, trashUserDir);
    }
    
    delete users[delUser];
    saveUsers();
    res.json({ message: "User moved to Trash" });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

// --- Undo حذف کاربر ---
app.post("/api/admin/user/undo", async (req, res) => {
  try {
    const { username } = req.body;
    const sessionUsername = req.session.username;
    if (!sessionUsername || !users[sessionUsername]?.isAdmin) return res.status(403).json({ error: "Forbidden" });
    if (!username) return res.status(400).json({ error: "username required" });

    const deletedUser = deletedUsers.find(u => u.username === username);
    if (!deletedUser) return res.status(404).json({ error: "User not found in deleted records" });

    users[username] = { password: deletedUser.password, isAdmin: deletedUser.isAdmin };
    saveUsers();

    const trashUserDir = path.join(TRASH_DIR, username, username + '_' + deletedUser.deletionTime);
    const userDir = path.join(UPLOADS_DIR, username);
    if (fs.existsSync(trashUserDir)) {
      console.log(`Restoring user folder: ${trashUserDir} -> ${userDir}`);
      await fsPromises.mkdir(path.dirname(userDir), { recursive: true });
      await fsPromises.rename(trashUserDir, userDir);
    }

    deletedUsers = deletedUsers.filter(u => u.username !== username);
    saveDeletedUsers();

    res.json({ message: `User ${username} restored to dashboard` });
  } catch (err) {
    console.error(`Error restoring user: ${err}`);
    res.status(500).json({ error: "Cannot undo user deletion" });
  }
});

// بستن سرور به صورت تمیز
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  process.exit(0);
});

// بررسی در دسترس بودن پورت
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Try a different port or close the existing process.`);
    process.exit(1);
  } else {
    console.error(`Server error: ${err}`);
  }
});