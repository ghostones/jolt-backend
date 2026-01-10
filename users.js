/**
 * User Database Module
 * Handles loading and saving users from JSON file
 * Separated to avoid circular dependencies
 */

const fs = require('fs');
const path = require('path');

const dbFile = path.join(__dirname, 'users.json');

function loadUsers() {
  let raw = '[]';
  try {
    if (fs.existsSync(dbFile)) raw = fs.readFileSync(dbFile, 'utf8') || '[]';
    let users = JSON.parse(raw);
    if (!Array.isArray(users)) {
      users = [];
      const tmpFile = `${dbFile}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify(users, null, 2), { mode: 0o600 });
      fs.renameSync(tmpFile, dbFile);
    }
    return users;
  } catch (err) {
    console.error('Error loading users.json:', err);
    fs.writeFileSync(dbFile, JSON.stringify([], null, 2));
    return [];
  }
}

function saveUsers(users) {
  const tmp = `${dbFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
  fs.renameSync(tmp, dbFile);
}

module.exports = {
  loadUsers,
  saveUsers
};
