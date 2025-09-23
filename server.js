const express = require("express");
const fs = require("fs");
const fsPromises = require("fs").promises;
const path = require("path");
const multer = require("multer");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const fsExtra = require('fs-extra'); // اضافه شده

const app = express();
const PORT = 3000;

// مسیرهای اصلی
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const TRASH_DIR = path.join(__dirname, "trash");
if (!fs.existsSync(TRASH_DIR)) fs.mkdirSync(TRASH_DIR, { recursive: true });

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

// ذخیره توکن‌های ریست
const resetTokens = {}; // { token: { username, exp: timestamp } }

// تابع امن برای انتقال فایل/فولدر (نسخه کامل با fs-extra)
async function safeMove(sourcePath, targetPath) {
  try {
    console.log(`Attempting to move: ${sourcePath} -> ${targetPath}`);
    
    // مطمئن شو که parent directory مقصد وجود داره
    await fsPromises.mkdir(path.dirname(targetPath), { recursive: true });
    
    // بررسی نوع source
    const sourceStats = await fsPromises.stat(sourcePath);
    
    if (sourceStats.isDirectory()) {
      // فولدره - از fs-extra.move استفاده کن
      console.log(`Directory detected: ${sourcePath} -> ${targetPath}, using fs-extra.move`);
      await fsExtra.move(sourcePath, targetPath, { 
        overwrite: true,
        clobber: true 
      });
      console.log(`Directory moved successfully: ${sourcePath} -> ${targetPath}`);
    } else {
      // فایله - الگوریتم cross-device
      console.log(`File detected: ${sourcePath} -> ${targetPath}`);
      try {
        await fsPromises.rename(sourcePath, targetPath);
        console.log(`File moved (rename): ${sourcePath} -> ${targetPath}`);
      } catch (error) {
        if (error.code === 'EXDEV') {
          console.log(`Cross-device file: ${sourcePath} -> ${targetPath}, using copy+delete`);
          await fsPromises.copyFile(sourcePath, targetPath);
          await fsPromises.unlink(sourcePath);
          console.log(`File moved (copy+delete): ${sourcePath} -> ${targetPath}`);
        } else {
          throw error;
        }
      }
    }
  } catch (error) {
    console.error(`Safe move failed: ${sourcePath} -> ${targetPath}: ${error.code} - ${error.message}`);
    throw error;
  }
}

// تابع برای ساخت مسیر Trash کاربر
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

// تابع ذخیره کاربران
function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf-8");
}

// تابع ذخیره کاربران حذف‌شده
function saveDeletedUsers() {
  fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify(deletedUsers, null, 2), "utf-8");
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

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({ secret: "secret-key", resave: false, saveUninitialized: true }));

// تنظیم هدرهای CORS و CSP برای رفع خطاهای احتمالی
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'");
  if (req.method === "OPTIONS") {
    return res.status(200).json({});
  }
  next();
});

// Multer – ذخیره فایل در فولدر کاربر
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR); // مسیر موقت
  },
  filename: (req, file, cb) => {
    console.log(`Server: Saving file as: ${file.originalname}`);
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// --- احراز هویت یکپارچه ---
app.post("/api/auth/continue", async (req, res) => {
  const { username, password, secretWord } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Fill username and password" });

  if (users[username]) {
    // کاربر موجود است، تلاش برای ورود
    try {
      const user = users[username];
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).json({ error: "Invalid password" });
      req.session.username = username;
      res.json({ token: "session-token", username, isAdmin: user.isAdmin });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Login failed" });
    }
  } else {
    // کاربر جدید، نیاز به کلمه مخفی
    if (!secretWord) return res.status(400).json({ error: "New user, provide secret word" });
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const hashedSecretWord = await bcrypt.hash(secretWord, 10);
      users[username] = {
        password: hashedPassword,
        secretWord: hashedSecretWord,
        isAdmin: Object.keys(users).length === 0 // اولین کاربر ادمین می‌شود
      };
      saveUsers();
      req.session.username = username;
      res.json({ token: "session-token", username, isAdmin: users[username].isAdmin });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Signup failed" });
    }
  }
});

// --- فراموشی رمز ---
app.post("/api/auth/forgot", async (req, res) => {
  const { username, secretWord } = req.body;
  if (!username || !secretWord || !users[username]) {
    return res.status(400).json({ error: "Invalid username or secret word" });
  }
  try {
    const user = users[username];
    const match = await bcrypt.compare(secretWord, user.secretWord);
    if (!match) return res.status(400).json({ error: "Invalid secret word" });
    const token = uuidv4();
    resetTokens[token] = { username, exp: Date.now() + 10 * 60 * 1000 }; // 10 دقیقه
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to process request" });
  }
});

// --- ریست رمز ---
app.post("/api/auth/reset", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Token and new password required" });

  const tokenData = resetTokens[token];
  if (!tokenData || Date.now() > tokenData.exp) {
    delete resetTokens[token];
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    users[tokenData.username].password = hashedPassword;
    saveUsers();
    delete resetTokens[token];
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Reset failed" });
  }
});

// --- Middleware احراز هویت ---
function auth(req, res, next) {
  const username = req.session.username;
  if (!username || !users[username]) return res.status(401).json({ error: "Not logged in" });
  req.user = { username, isAdmin: users[username].isAdmin };
  next();
}

// --- ایجاد فولدر ---
app.post("/api/folder/create", auth, async (req, res) => {
  const { folderName, currentFolder } = req.body;
  if (!folderName) return res.status(400).json({ error: "Folder name required" });

  let targetUser = req.user.username;
  if (req.body.user && req.user.isAdmin) targetUser = req.body.user;

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
app.delete("/api/folder/:name", auth, async (req, res) => {
  const folderName = req.params.name;
  if (!folderName) return res.status(400).json({ error: "Folder name required" });

  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.query.currentFolder || '/';
  folder = path.normalize(folder);
  if (folder.startsWith(path.sep)) folder = folder.slice(1);

  const folderPath = path.join(UPLOADS_DIR, targetUser, folder, folderName);
  const trashPath = getTrashPath(targetUser, folderName, true);
  try {
    if (!fs.existsSync(folderPath)) return res.status(404).json({ error: "Folder not found" });
    console.log(`Moving folder to trash: ${folderPath} -> ${trashPath}`);
    
    // استفاده از safeMove به جای rename
    await safeMove(folderPath, trashPath);
    
    res.json({ message: "Folder moved to Trash", folderName, trashId: path.basename(trashPath) });
  } catch (err) {
    console.error(`Error moving folder to trash: ${err}`);
    res.status(500).json({ error: "Cannot move folder to Trash" });
  }
});

// --- Undo حذف فولدر ---
app.post("/api/folder/undo", auth, async (req, res) => {
  try {
    const { folderName, currentFolder, trashId } = req.body;
    if (!folderName || !trashId) return res.status(400).json({ error: "Folder name and trashId required" });

    let targetUser = req.user.username;
    if (req.body.user && req.user.isAdmin) targetUser = req.body.user;

    const trashPath = path.join(TRASH_DIR, targetUser, trashId);
    const originalPath = path.join(UPLOADS_DIR, targetUser, currentFolder || '/', folderName);

    if (!fs.existsSync(trashPath)) return res.status(404).json({ error: `Folder not found in Trash: ${trashPath}` });
    console.log(`Restoring folder: ${trashPath} -> ${originalPath}`);
    
    await fsPromises.mkdir(path.dirname(originalPath), { recursive: true });
    
    // استفاده از safeMove برای restore
    await safeMove(trashPath, originalPath);
    
    res.json({ message: "Folder restored to dashboard" });
  } catch (err) {
    console.error(`Error restoring folder: ${err}`);
    res.status(500).json({ error: "Cannot undo folder deletion" });
  }
});

// --- آپلود فایل ---
app.post("/api/files/upload", auth, upload.fields([{ name: 'file', maxCount: 1 }]), async (req, res) => {
  console.log(`Server: Received FormData - file=${req.files?.file?.[0]?.originalname}, folder=${req.body.folder}`);
  if (!req.files || !req.files.file) return res.status(400).json({ error: "No file uploaded" });

  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.body.folder || '/';
  folder = path.normalize(folder);
  if (folder === '/' || folder === '') {
    folder = '';
  } else if (folder.startsWith(path.sep)) {
    folder = folder.slice(1);
  }

  const tempPath = req.files.file[0].path;
  const finalPath = path.join(UPLOADS_DIR, targetUser, folder, req.files.file[0].originalname);
  console.log(`Server: Moving file from ${tempPath} to ${finalPath}`);

  try {
    await fsPromises.mkdir(path.dirname(finalPath), { recursive: true });
    
    // استفاده از safeMove برای آپلود
    await safeMove(tempPath, finalPath);
    
    console.log(`Server: Upload completed for file=${req.files.file[0].originalname}, folder=${req.body.folder}`);
    res.json({ message: "File uploaded" });
  } catch (err) {
    console.error(`Server: Error moving file: ${err}`);
    res.status(500).json({ error: "Cannot move file to destination" });
  }
});

// --- تغییر نام فایل یا فولدر ---
app.post("/api/rename", auth, async (req, res) => {
  const { oldName, newName, currentFolder, isFolder } = req.body;
  if (!oldName || !newName) return res.status(400).json({ error: "oldName and newName required" });

  let targetUser = req.user.username;
  if (req.body.user && req.user.isAdmin) targetUser = req.body.user;

  let folder = currentFolder || '/';
  folder = path.normalize(folder).replace(/\\/g, '/'); // تبدیل \ به / برای سازگاری
  if (folder === '/' || folder === '') {
    folder = '';
  } else if (folder.startsWith('/')) {
    folder = folder.slice(1);
  }

  const parentFolder = path.join(UPLOADS_DIR, targetUser, folder);
  const oldPath = path.join(parentFolder, oldName);
  const newPath = path.join(parentFolder, newName);

  try {
    console.log(`Rename request: oldPath=${oldPath}, newPath=${newPath}, isFolder=${isFolder}, user=${targetUser}, currentFolder=${folder}`);
    // بررسی وجود parentFolder
    if (!fs.existsSync(parentFolder)) {
      console.error(`Parent folder does not exist: ${parentFolder}`);
      return res.status(404).json({ error: `Parent folder not found: ${parentFolder}` });
    }
    // بررسی وجود oldPath
    if (!fs.existsSync(oldPath)) {
      console.error(`Folder/file does not exist at: ${oldPath}`);
      return res.status(404).json({ error: `${isFolder ? 'Folder' : 'File'} not found at ${oldPath}` });
    }
    // بررسی وجود newPath
    if (fs.existsSync(newPath)) {
      console.error(`Target already exists at: ${newPath}`);
      return res.status(400).json({ error: `${isFolder ? 'Folder' : 'File'} with new name already exists at ${newPath}` });
    }

    console.log(`Server: Renaming ${isFolder ? 'folder' : 'file'} from ${oldPath} to ${newPath}`);
    await fsPromises.rename(oldPath, newPath);
    res.json({ message: `${isFolder ? 'Folder' : 'File'} renamed successfully` });
  } catch (err) {
    console.error(`Server: Error renaming ${isFolder ? 'folder' : 'file'}: ${err.message}`);
    res.status(500).json({ error: `Cannot rename ${isFolder ? 'folder' : 'file'}: ${err.message}` });
  }
});

// --- انتقال فایل ---
app.post("/api/files/move", auth, async (req, res) => {
  const { fileId, fileName, currentFolder, targetFolder } = req.body;
  if (!fileId || !fileName || !currentFolder) {
    return res.status(400).json({ error: "fileId, fileName, and currentFolder required" });
  }

  let targetUser = req.user.username;
  if (req.body.user && req.user.isAdmin) targetUser = req.body.user;

  let currentPath = currentFolder || '/';
  currentPath = path.normalize(currentPath).replace(/\\/g, '/');
  if (currentPath === '/' || currentPath === '') {
    currentPath = '';
  } else if (currentPath.startsWith('/')) {
    currentPath = currentPath.slice(1);
  }

  let targetPath = targetFolder || '';
  targetPath = path.normalize(targetPath).replace(/\\/g, '/');
  if (targetPath === '/' || targetPath === '') {
    targetPath = '';
  } else if (targetPath.startsWith('/')) {
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
    
    // استفاده از safeMove برای انتقال
    await safeMove(sourcePath, destPath);
    
    res.json({ message: "File moved successfully" });
  } catch (err) {
    console.error(`Error moving file: ${err}`);
    res.status(500).json({ error: "Cannot move file" });
  }
});

// --- جستجوی فایل‌ها و فولدرها ---
app.get("/api/files/search", auth, async (req, res) => {
  const query = req.query.query ? req.query.query.toLowerCase() : '';
  if (!query) return res.status(400).json({ error: "Query parameter required" });

  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder).replace(/\\/g, '/');
  if (folder.startsWith('/')) folder = folder.slice(1);

  const baseFolder = path.join(UPLOADS_DIR, targetUser, folder);
  try {
    if (!fs.existsSync(baseFolder)) return res.json({ files: [] });
    const items = await fsPromises.readdir(baseFolder);
    const files = [];
    for (const item of items) {
      const itemPath = path.join(baseFolder, item);
      const stats = await fsPromises.stat(itemPath);
      if (item.toLowerCase().includes(query)) {
        files.push({
          originalName: item,
          size: stats.size,
          isFolder: stats.isDirectory(),
          id: item
        });
      }
    }
    res.json({ files });
  } catch (err) {
    console.error(`Error searching files: ${err}`);
    res.status(500).json({ error: "Cannot search files" });
  }
});

// --- لیست فایل‌ها و فولدرها ---
app.get("/api/files/list", auth, async (req, res) => {
  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder).replace(/\\/g, '/');
  if (folder.startsWith('/')) folder = folder.slice(1);

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
app.get("/api/files/download/:id", auth, (req, res) => {
  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder).replace(/\\/g, '/');
  if (folder.startsWith('/')) folder = folder.slice(1);

  const filePath = path.join(UPLOADS_DIR, targetUser, folder, req.params.id);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.download(filePath);
});

// --- حذف فایل ---
app.delete("/api/files/:id", auth, async (req, res) => {
  const fileId = req.params.id;
  if (!fileId) return res.status(400).json({ error: "File id required" });

  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

  let folder = req.query.folder || '/';
  folder = path.normalize(folder).replace(/\\/g, '/');
  if (folder.startsWith('/')) folder = folder.slice(1);

  const filePath = path.join(UPLOADS_DIR, targetUser, folder, fileId);
  const trashPath = getTrashPath(targetUser, fileId, false);
  try {
    if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
    console.log(`Moving file to trash: ${filePath} -> ${trashPath}`);
    
    // استفاده از safeMove به جای rename
    await safeMove(filePath, trashPath);
    
    res.json({ message: "File moved to Trash", fileId, trashId: path.basename(trashPath) });
  } catch (err) {
    console.error(`Error moving file to trash: ${err}`);
    res.status(500).json({ error: "Cannot move file to Trash" });
  }
});

// --- Undo حذف فایل ---
app.post("/api/files/undo", auth, async (req, res) => {
  try {
    const { id, folder, trashId } = req.body;
    if (!id || !trashId) return res.status(400).json({ error: "File id and trashId required" });

    let targetUser = req.user.username;
    if (req.body.user && req.user.isAdmin) targetUser = req.body.user;

    const trashPath = path.join(TRASH_DIR, targetUser, trashId);
    const originalPath = path.join(UPLOADS_DIR, targetUser, folder || '/', id);

    if (!fs.existsSync(trashPath)) return res.status(404).json({ error: `File not found in Trash: ${trashPath}` });
    console.log(`Restoring file: ${trashPath} -> ${originalPath}`);
    
    await fsPromises.mkdir(path.dirname(originalPath), { recursive: true });
    
    // استفاده از safeMove برای restore
    await safeMove(trashPath, originalPath);
    
    res.json({ message: "File restored to dashboard" });
  } catch (err) {
    console.error(`Error restoring file: ${err}`);
    res.status(500).json({ error: "Cannot undo file deletion" });
  }
});

// --- لیست Trash ---
app.get("/api/trash/list", auth, async (req, res) => {
  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

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
app.delete("/api/trash/:itemName", auth, async (req, res) => {
  const itemName = req.params.itemName;
  if (!itemName) return res.status(400).json({ error: "Item name required" });

  let targetUser = req.user.username;
  if (req.query.user && req.user.isAdmin) targetUser = req.query.user;

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
app.get("/api/admin/users", auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Forbidden" });
  const list = Object.keys(users).map(u => ({ username: u, isAdmin: users[u].isAdmin }));
  res.json({ users: list });
});

app.delete("/api/admin/user/:username", auth, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Forbidden" });
  const delUser = req.params.username;
  if (!delUser) return res.status(400).json({ error: "Username required" });
  if (users[delUser]) {
    deletedUsers.push({ username: delUser, ...users[delUser], deletionTime: Date.now() });
    saveDeletedUsers();
    
    const userDir = path.join(UPLOADS_DIR, delUser);
    const trashUserDir = getTrashPath(delUser, delUser, true);
    if (fs.existsSync(userDir)) {
      console.log(`Moving user folder to trash: ${userDir} -> ${trashUserDir}`);
      
      // استفاده از safeMove برای user folder
      await safeMove(userDir, trashUserDir);
    }
    
    delete users[delUser];
    saveUsers();
    res.json({ message: "User moved to Trash", trashId: path.basename(trashUserDir) });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

// --- Undo حذف کاربر ---
app.post("/api/admin/user/undo", auth, async (req, res) => {
  try {
    const { username } = req.body;
    if (!req.user.isAdmin) return res.status(403).json({ error: "Forbidden" });
    if (!username) return res.status(400).json({ error: "Username required" });

    const deletedUser = deletedUsers.find(u => u.username === username);
    if (!deletedUser) return res.status(404).json({ error: "User not found in deleted records" });

    users[username] = { password: deletedUser.password, secretWord: deletedUser.secretWord, isAdmin: deletedUser.isAdmin };
    saveUsers();

    const trashUserDir = path.join(TRASH_DIR, username, username + '_' + deletedUser.deletionTime);
    const userDir = path.join(UPLOADS_DIR, username);
    if (fs.existsSync(trashUserDir)) {
      console.log(`Restoring user folder: ${trashUserDir} -> ${userDir}`);
      await fsPromises.mkdir(path.dirname(userDir), { recursive: true });
      
      // استفاده از safeMove برای restore user folder
      await safeMove(trashUserDir, userDir);
    }

    deletedUsers = deletedUsers.filter(u => u.username !== username);
    saveDeletedUsers();

    res.json({ message: `User ${username} restored to dashboard` });
  } catch (err) {
    console.error(`Error restoring user: ${err}`);
    res.status(500).json({ error: "Cannot undo user deletion" });
  }
});

// --- بستن سرور ---
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  process.exit(0);
});

// --- بررسی در دسترس بودن پورت ---
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