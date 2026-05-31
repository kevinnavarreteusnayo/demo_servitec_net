const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();

// --- Crear la carpeta /data si no existe (solución Railway) ---
if (!fs.existsSync('/data')) {
  fs.mkdirSync('/data', { recursive: true });
}

// Carpeta y ruta de la base de datos para Railway
const DB_PATH = '/data/servitec.db';

// Crear carpeta de backups si no existe
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// Crear backup de la base de datos si existe
if (fs.existsSync(DB_PATH)) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(BACKUP_DIR, `servitec-${timestamp}.db`);
  fs.copyFileSync(DB_PATH, backupPath);
}

// Archivos estáticos (imágenes, CSS, JS)
app.use(express.static('public'));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secreto-muy-seguro',
  resave: false,
  saveUninitialized: false
}));

// Conexión a la base de datos
const db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error('Error al abrir la base de datos:', err);
    throw err;
  }
  console.log('Base de datos conectada en:', DB_PATH);

  // Habilitar claves foráneas
  db.run('PRAGMA foreign_keys = ON');

  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE,
    password TEXT,
    es_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS recepciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT,
    fecha_recepcion TEXT,
    datos TEXT,
    solucion TEXT DEFAULT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS clientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_documento TEXT,
    numero_documento TEXT UNIQUE,
    nombres TEXT,
    apellidos TEXT,
    telefono TEXT,
    email TEXT,
    direccion TEXT
  )`, [], () => {
    // Migración automática de clientes previos desde recepciones
    db.all("SELECT datos FROM recepciones", [], (err, rows) => {
      if (rows && rows.length > 0) {
        rows.forEach(row => {
          try {
            const datos = JSON.parse(row.datos);
            if (!datos.numero_documento) return;
            db.get("SELECT * FROM clientes WHERE numero_documento = ?", [datos.numero_documento], (err, existe) => {
              if (!existe) {
                db.run(`INSERT INTO clientes (tipo_documento, numero_documento, nombres, apellidos, telefono, email, direccion)
                  VALUES (?, ?, ?, ?, ?, ?, ?)`, [
                  datos.tipo_documento || '',
                  datos.numero_documento,
                  datos.nombres || datos.cliente || '',
                  datos.apellidos || '',
                  datos.telefono || '',
                  datos.email || '',
                  datos.direccion || ''
                ]);
              }
            });
          } catch { }
        });
      }
    });
  });
  db.get('SELECT * FROM usuarios WHERE usuario = ?', ['104958'], (err, row) => {
    if (!row) {
      bcrypt.hash('282425', 10, (err, hash) => {
        db.run('INSERT INTO usuarios (usuario, password, es_admin) VALUES (?, ?, ?)',
          ['104958', hash, 1]);
      });
    }
  });
});

// --- Middleware de autenticación ---
function requireLogin(req, res, next) {
  if (req.session.usuario) next();
  else res.redirect('/login.html');
}
function requireAdmin(req, res, next) {
  if (req.session.usuario && req.session.es_admin) next();
  else res.redirect('/login.html');
}

// --- Rutas principales de HTML ---
app.get('/', (req, res) => {
  if (!req.session.usuario) {
    res.sendFile(path.join(__dirname, 'login.html'));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});
app.get('/index.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/recepciones.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'recepciones.html'));
});
app.get('/usuarios.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'usuarios.html'));
});
app.get('/archivos.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'archivos.html'));
});
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// --- ENDPOINTS DE LA API ---

// Info de usuario actual (sesión)
app.get('/api/yo', (req, res) => {
  if (!req.session.usuario) return res.json({});
  res.json({
    usuario: req.session.usuario,
    es_admin: req.session.es_admin || false
  });
});

// Login de usuario normal
app.post('/api/login', (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) {
    return res.json({ ok: false, error: "Completa los campos" });
  }
  db.get('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, row) => {
    if (err) return res.json({ ok: false, error: "Error interno" });
    if (!row) return res.json({ ok: false, error: "Usuario no encontrado" });
    bcrypt.compare(password, row.password, (err, result) => {
      if (result) {
        req.session.usuario = row.usuario;
        req.session.es_admin = !!row.es_admin;
        res.json({ ok: true });
      } else {
        res.json({ ok: false, error: "Contraseña incorrecta" });
      }
    });
  });
});

// Login de administrador (para secciones protegidas)
app.post('/api/admin-login', (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) {
    return res.json({ ok: false, error: "Completa los campos" });
  }
  db.get('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, row) => {
    if (err) return res.json({ ok: false, error: "Error interno" });
    if (!row || !row.es_admin) return res.json({ ok: false, error: "No es administrador" });
    bcrypt.compare(password, row.password, (err, result) => {
      if (result) {
        req.session.usuario = row.usuario;
        req.session.es_admin = !!row.es_admin;
        res.json({ ok: true });
      } else {
        res.json({ ok: false, error: "Contraseña incorrecta" });
      }
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// Crear usuario (solo admin o desde login)
app.post('/api/crear-usuario', (req, res) => {
  const { usuario, password, es_admin } = req.body;
  if (!usuario || !password) return res.json({ ok: false, error: "Completa los campos" });
  db.get('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, row) => {
    if (row) return res.json({ ok: false, error: "Usuario ya existe" });
    bcrypt.hash(password, 10, (err, hash) => {
      db.run('INSERT INTO usuarios (usuario, password, es_admin) VALUES (?, ?, ?)',
        [usuario, hash, es_admin ? 1 : 0], (err) => {
          if (err) return res.json({ ok: false, error: "Error al crear usuario" });
          res.json({ ok: true });
        });
    });
  });
});

// Resetear password (por usuario)
app.post('/api/reset-password', (req, res) => {
  const { usuario, nuevaPassword } = req.body;
  if (!usuario || !nuevaPassword) return res.json({ ok: false, error: "Completa los campos" });
  bcrypt.hash(nuevaPassword, 10, (err, hash) => {
    db.run('UPDATE usuarios SET password = ? WHERE usuario = ?', [hash, usuario], function (err) {
      if (err || this.changes === 0) return res.json({ ok: false, error: "No se pudo cambiar la contraseña" });
      res.json({ ok: true });
    });
  });
});

// --- RESET PASSWORD POR ADMIN (permite cambiar la del admin principal) ---
app.post('/api/admin-reset-password', (req, res) => {
  const { adminUsuario, adminPassword, targetUsuario, nuevoPassword } = req.body;
  if (!adminUsuario || !adminPassword || !targetUsuario || !nuevoPassword) {
    return res.json({ ok: false, error: "Completa todos los campos" });
  }
  db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUsuario], (err, adminRow) => {
    if (err || !adminRow || !adminRow.es_admin) {
      return res.json({ ok: false, error: "Admin inválido o sin permisos" });
    }
    bcrypt.compare(adminPassword, adminRow.password, (err, result) => {
      if (err || !result) {
        return res.json({ ok: false, error: "Credenciales de administrador incorrectas" });
      }
      bcrypt.hash(nuevoPassword, 10, (err, hash) => {
        if (err) return res.json({ ok: false, error: "Error interno" });
        db.run('UPDATE usuarios SET password = ? WHERE usuario = ?', [hash, targetUsuario], function (err) {
          if (err || this.changes === 0) return res.json({ ok: false, error: "No se pudo cambiar la contraseña del usuario" });
          res.json({ ok: true });
        });
      });
    });
  });
});

// Listar usuarios (solo admin)
app.get('/api/usuarios', requireAdmin, (req, res) => {
  db.all('SELECT usuario, es_admin FROM usuarios', [], (err, rows) => {
    if (err) return res.json({ ok: false, error: "Error al cargar usuarios" });
    res.json({ ok: true, usuarios: rows });
  });
});

// Eliminar usuario (solo admin)
app.post('/api/eliminar-usuario', requireAdmin, (req, res) => {
  const { usuario } = req.body;
  if (!usuario || usuario === "104958") return res.json({ ok: false, error: "No puedes eliminar el admin principal" });
  db.run('DELETE FROM usuarios WHERE usuario = ?', [usuario], function (err) {
    if (err || this.changes === 0) return res.json({ ok: false, error: "No se pudo eliminar" });
    res.json({ ok: true });
  });
});

// Cambiar estado admin de usuario (solo admin)
app.post('/api/cambiar-admin', requireAdmin, (req, res) => {
  const { usuario, es_admin } = req.body;
  if (!usuario || usuario === "104958") return res.json({ ok: false, error: "No puedes modificar el admin principal" });
  db.run('UPDATE usuarios SET es_admin = ? WHERE usuario = ?', [es_admin ? 1 : 0, usuario], function (err) {
    if (err || this.changes === 0) return res.json({ ok: false, error: "No se pudo cambiar estado" });
    res.json({ ok: true });
  });
});

// ---- CLIENTES API ----
app.get('/api/clientes', requireLogin, (req, res) => {
  db.all('SELECT * FROM clientes ORDER BY nombres ASC, apellidos ASC', [], (err, rows) => {
    if (err) {
      console.error('Error al cargar clientes:', err);
      return res.json({ ok: false, clientes: [], error: "Error al cargar clientes" });
    }
    res.json({ ok: true, clientes: rows || [] });
  });
});
app.get('/api/cliente/:id', requireLogin, (req, res) => {
  db.get('SELECT * FROM clientes WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.json({ ok: false });
    res.json({ ok: true, cliente: row });
  });
});

// ---- RECEPCIONES ----
app.post('/api/recepcion', requireLogin, (req, res) => {
  const usuario = req.session.usuario;
  const fecha_recepcion = new Date().toISOString();
  const datos = req.body;
  if (datos.numero_documento) {
    db.get('SELECT * FROM clientes WHERE numero_documento = ?', [datos.numero_documento], (err, row) => {
      if (!row) {
        db.run(`INSERT INTO clientes (tipo_documento, numero_documento, nombres, apellidos, telefono, email, direccion)
          VALUES (?, ?, ?, ?, ?, ?, ?)`, [
          datos.tipo_documento || '',
          datos.numero_documento,
          datos.nombres || datos.cliente || '',
          datos.apellidos || '',
          datos.telefono || '',
          datos.email || '',
          datos.direccion || ''
        ]);
      }
    });
  }
  db.run(
    'INSERT INTO recepciones (usuario, fecha_recepcion, datos) VALUES (?, ?, ?)',
    [usuario, fecha_recepcion, JSON.stringify(datos)],
    function (err) {
      if (err) return res.json({ ok: false, error: "Error al registrar recepción" });
      res.json({ ok: true, id: this.lastID });
    }
  );
});
app.get('/api/recepciones', requireAdmin, (req, res) => {
  db.all('SELECT * FROM recepciones ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.json({ ok: false, error: "Error al cargar recepciones" });
    const data = rows.map(r => ({
      id: r.id,
      usuario: r.usuario,
      fecha_recepcion: r.fecha_recepcion,
      datos: JSON.parse(r.datos),
      solucion: r.solucion || null,
      numero_orden: r.datos ? (JSON.parse(r.datos).numero_orden || null) : null
    }));
    res.json({ ok: true, recepciones: data });
  });
});
app.get('/api/recepciones/:id', requireAdmin, (req, res) => {
  db.get('SELECT * FROM recepciones WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.json({ ok: false });
    res.json({
      ok: true,
      recepcion: {
        id: row.id,
        usuario: row.usuario,
        fecha_recepcion: row.fecha_recepcion,
        datos: JSON.parse(row.datos),
        solucion: row.solucion || null,
        numero_orden: row.datos ? (JSON.parse(row.datos).numero_orden || null) : null
      }
    });
  });
});
app.post('/api/recepciones/:id/solucion', requireAdmin, (req, res) => {
  const id = req.params.id;
  const { solucion } = req.body;

  if (!id) {
    return res.json({ ok: false, error: "ID no válido" });
  }

  db.run('UPDATE recepciones SET solucion = ? WHERE id = ?', [solucion || null, id], function(err) {
    if (err) {
      console.error('Error al actualizar solución:', err);
      return res.json({ ok: false, error: "Error al guardar la solución" });
    }
    if (this.changes === 0) {
      return res.json({ ok: false, error: "No se encontró la recepción" });
    }
    res.json({ ok: true });
  });
});
app.delete('/api/recepciones/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM recepciones WHERE id = ?', [id], function (err) {
    if (err || this.changes === 0) return res.json({ ok: false, error: "No se pudo eliminar" });
    res.json({ ok: true });
  });
});

// ---- ARCHIVOS (explorador mínimo) ----
app.get('/api/archivos', requireAdmin, (req, res) => {
  const ruta = req.query.ruta || '/';
  const absPath = path.join(__dirname, 'public', ruta);
  fs.readdir(absPath, { withFileTypes: true }, (err, files) => {
    if (err) return res.json({ ok: false, archivos: [] });
    const archivos = files.map(f => {
      const full = path.join(absPath, f.name);
      let tamano = "";
      try {
        if (f.isFile()) {
          const stats = fs.statSync(full);
          tamano = (stats.size / 1024).toFixed(1) + " KB";
        }
      } catch { }
      return {
        nombre: f.name,
        tipo: f.isDirectory() ? 'carpeta' : 'archivo',
        ruta: path.join(ruta, f.name).replace(/\\/g, '/'),
        tamano
      };
    });
    res.json({ ok: true, archivos });
  });
});
app.get('/api/archivo-descargar', requireAdmin, (req, res) => {
  const ruta = req.query.ruta;
  if (!ruta) return res.status(400).end();
  const absPath = path.join(__dirname, 'public', ruta);
  if (fs.existsSync(absPath)) {
    res.download(absPath);
  } else {
    res.status(404).end();
  }
});
app.post('/api/archivo-eliminar', requireAdmin, (req, res) => {
  const { ruta, carpeta } = req.body;
  if (!ruta) return res.json({ ok: false });
  const absPath = path.join(__dirname, 'public', ruta);
  try {
    if (carpeta) {
      fs.rmSync(absPath, { recursive: true, force: true });
    } else {
      fs.unlinkSync(absPath);
    }
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false });
  }
});

// Fallback para rutas inexistentes (404)
app.use((req, res) => {
  res.status(404).send('Página no encontrada');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});