/**
 * Plataforma de Evaluaciones – MVP
 * Stack: Node.js + Express + SQLite + Sessions
 *
 * Características principales:
 * - Acceso para docente mediante CÓDIGO DE ACCESO (sin usuario/contraseña complicados).
 * - Publicación/edición/elim. de evaluaciones (nombre, ID, curso, fecha, puntaje, comentarios).
 * - Código de consulta por estudiante (PIN) para ver su evaluación en /ver.
 * - Búsqueda/listado para el docente y exportación CSV.
 * - Rate limit en login, sesiones con cookie segura y saneamiento básico.
 *
 * Instrucciones rápidas:
 * 1) Crea un archivo .env junto a este archivo con:
 *      PORT=3000
 *      SESSION_SECRET=cambia_esto_por_uno_largo_y_unico
 *      ACCESS_CODE_DOCENTE=TU_CODIGO_SECRETO_DEL_DOCENTE
 * 2) Instala dependencias:
 *      npm init -y
 *      npm i express express-session sqlite3 dotenv bcrypt express-rate-limit helmet xss @faker-js/faker
 * 3) Ejecuta:
 *      node server.js
 * 4) Abre: http://localhost:3000
 *
 * Despliegue:
 * - Render / Railway / Fly.io: define las 3 variables de entorno anteriores.
 * - El archivo de base de datos se crea como data.db en el directorio de trabajo.
 *
 * Nota legal/privacidad:
 * - Este MVP es educativo. Para datos personales reales, agrega HTTPS, copias de seguridad,
 *   control de acceso por cuentas, políticas de retención de datos y consentimientos.
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const xss = require('xss');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'cambia_esto_en_env';
const ACCESS_CODE_DOCENTE = process.env.ACCESS_CODE_DOCENTE || 'DOCENTE1234';

// --- Seguridad básica
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", 'data:'],
    }
  }
}));
app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// --- Sesiones
app.use(session({
  name: 'sess_eval',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // secure: true, // activa en producción detrás de HTTPS
    maxAge: 1000 * 60 * 60 * 8 // 8 horas
  }
}));

// --- DB init
const DB_PATH = path.join(process.cwd(), 'data.db');
const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS evaluations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_name TEXT NOT NULL,
      student_id TEXT,
      course TEXT,
      date TEXT,
      score REAL,
      comments TEXT,
      view_code_sha TEXT,       -- SHA256 del PIN para consulta de estudiante
      view_code_hint TEXT,      -- Para mostrar (ej. últimos 2 dígitos)
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
  )`);
});

// --- Helpers
const sha256hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function sanitize(text) {
  // Limpieza sencilla contra XSS en campos de texto largos
  return xss(text || '');
}

function requireAuth(req, res, next) {
  if (req.session && req.session.isTeacher) return next();
  return res.redirect('/login');
}

// --- Rate limit para login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 20,                  // máx. 20 intentos / 15min por IP
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Vistas minimalistas (sin motor de plantillas)
function layout(title, content, opts = {}) {
  const { isTeacher = false, flash = '' } = opts;
  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    :root{--bg:#0b1020;--card:#121933;--muted:#9fb0ff;--acc:#4f7cff;--ok:#2ecc71;--warn:#ffcc00;--bad:#e74c3c;}
    *{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif}
    body{margin:0;background:linear-gradient(120deg,#0b1020,#101a3a 60%,#0b1020);color:#e8ecff}
    header,main,footer{max-width:960px;margin:0 auto;padding:16px}
    header{display:flex;justify-content:space-between;align-items:center}
    a,button{cursor:pointer}
    .card{background:var(--card);border:1px solid #1e2a55;border-radius:16px;padding:16px;box-shadow:0 8px 20px rgba(0,0,0,.35)}
    .title{font-size:24px;margin:0 0 8px}
    .muted{color:var(--muted)}
    .grid{display:grid;gap:12px}
    .grid.cols-2{grid-template-columns:repeat(2,1fr)}
    .grid.cols-3{grid-template-columns:repeat(3,1fr)}
    .btn{padding:10px 14px;border-radius:10px;border:1px solid #2b3a75;background:#1a2652;color:#fff}
    .btn.primary{background:var(--acc);border-color:#375dd8}
    .btn.danger{background:#842029;border-color:#842029}
    .btn.link{background:transparent;border-color:transparent;text-decoration:underline}
    input,textarea,select{width:100%;padding:10px;border-radius:10px;border:1px solid #2b3a75;background:#0e1535;color:#fff}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #253363;padding:8px;text-align:left}
    .flash{margin:8px 0;padding:10px;border-radius:10px;background:#14224a;border:1px solid #24428a}
    .badge{display:inline-block;padding:4px 8px;border-radius:999px;background:#1b2b5a;border:1px solid #2d4aa1}
    .tag-ok{background:#163a2b;border-color:#1f6d4a}
  </style>
</head>
<body>
  <header>
    <div><strong>Plataforma de Evaluaciones</strong> <span class="badge">MVP</span></div>
    <nav>
      ${isTeacher ? `
        <a class="btn link" href="/admin">Panel</a>
        <form style="display:inline" method="post" action="/logout"><button class="btn">Salir</button></form>
      ` : `<a class="btn" href="/login">Docente</a>`}
    </nav>
  </header>
  <main>
    ${flash ? `<div class="flash">${flash}</div>` : ''}
    ${content}
  </main>
  <footer class="muted" style="padding-bottom:32px">© ${new Date().getFullYear()} – Proyecto educativo.</footer>
</body>
</html>`;
}

// --- Página principal
app.get('/', (req, res) => {
  const html = layout(
    'Plataforma de Evaluaciones',
    `
    <div class="grid cols-2">
      <section class="card">
        <h2 class="title">Consulta de evaluación (estudiante)</h2>
        <p class="muted">Ingresa tu código para ver tu evaluación.</p>
        <form method="get" action="/ver">
          <label>Código de consulta (PIN)</label>
          <input name="codigo" required minlength="4" maxlength="12" />
          <button class="btn primary" style="margin-top:8px">Ver evaluación</button>
        </form>
      </section>
      <section class="card">
        <h2 class="title">Acceso del docente</h2>
        <p class="muted">Publica y gestiona evaluaciones usando tu código de acceso.</p>
        <a class="btn" href="/login">Entrar</a>
      </section>
    </div>
    `,
    { isTeacher: !!req.session.isTeacher }
  );
  res.send(html);
});

// --- Login docente
app.get('/login', (req, res) => {
  if (req.session.isTeacher) return res.redirect('/admin');
  const html = layout('Login docente', `
    <section class="card">
      <h2 class="title">Código de acceso</h2>
      <form method="post" action="/login">
        <label>Introduce tu código de acceso</label>
        <input name="code" required minlength="4" maxlength="64" />
        <button class="btn primary" style="margin-top:8px">Entrar</button>
      </form>
      <p class="muted" style="margin-top:6px">Consejo: comparte SOLO con docentes autorizados.</p>
    </section>
  `);
  res.send(html);
});

app.post('/login', loginLimiter, (req, res) => {
  const code = (req.body.code || '').trim();
  if (!code) return res.redirect('/login');
  if (code === ACCESS_CODE_DOCENTE) {
    req.session.isTeacher = true;
    return res.redirect('/admin');
  }
  const html = layout('Login docente', `
    <section class="card">
      <h2 class="title">Código incorrecto</h2>
      <p class="muted">Inténtalo nuevamente.</p>
      <a class="btn" href="/login">Volver</a>
    </section>
  `);
  res.status(401).send(html);
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// --- Panel del docente
app.get('/admin', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  const params = [];
  let where = '';
  if (q) {
    where = `WHERE student_name LIKE ? OR student_id LIKE ? OR course LIKE ?`;
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  db.all(`SELECT id, student_name, student_id, course, date, score, view_code_hint, created_at
          FROM evaluations ${where} ORDER BY created_at DESC LIMIT 200`, params, (err, rows) => {
    if (err) return res.status(500).send('DB error');

    const list = rows.map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${r.student_name}</td>
        <td>${r.student_id || '-'}</td>
        <td>${r.course || '-'}</td>
        <td>${r.date || '-'}</td>
        <td>${r.score ?? '-'}</td>
        <td>${r.view_code_hint ? `<span class="badge tag-ok">…${r.view_code_hint}</span>` : '-'}</td>
        <td>
          <a class="btn" href="/evaluations/${r.id}">Abrir</a>
        </td>
      </tr>
    `).join('');

    const html = layout('Panel del docente', `
      <section class="card">
        <div style="display:flex;align-items:center;gap:8px;justify-content:space-between;flex-wrap:wrap">
          <h2 class="title" style="margin:0">Evaluaciones</h2>
          <div style="display:flex;gap:8px">
            <a class="btn primary" href="/evaluations/new">Nueva evaluación</a>
            <a class="btn" href="/admin/export.csv">Exportar CSV</a>
          </div>
        </div>
        <form method="get" action="/admin" style="margin:10px 0">
          <input name="q" value="${q}" placeholder="Buscar por nombre, ID o curso" />
        </form>
        <div style="overflow:auto">
          <table>
            <thead><tr>
              <th>#</th><th>Estudiante</th><th>ID</th><th>Curso</th><th>Fecha</th><th>Puntaje</th><th>PIN</th><th></th>
            </tr></thead>
            <tbody>${list || '<tr><td colspan="8">Sin registros</td></tr>'}</tbody>
          </table>
        </div>
      </section>
    `, { isTeacher: true });
    res.send(html);
  });
});

// --- Nueva evaluación
app.get('/evaluations/new', requireAuth, (req, res) => {
  const html = layout('Nueva evaluación', `
    <section class="card">
      <h2 class="title">Registrar evaluación</h2>
      <form method="post" action="/evaluations">
        <div class="grid cols-3">
          <div>
            <label>Nombre del estudiante</label>
            <input name="student_name" required />
          </div>
          <div>
            <label>ID del estudiante</label>
            <input name="student_id" />
          </div>
          <div>
            <label>Curso/Asignatura</label>
            <input name="course" />
          </div>
        </div>
        <div class="grid cols-3" style="margin-top:10px">
          <div>
            <label>Fecha</label>
            <input type="date" name="date" />
          </div>
          <div>
            <label>Puntaje</label>
            <input type="number" step="0.01" name="score" />
          </div>
          <div>
            <label>PIN para consulta del estudiante</label>
            <input name="view_code" required minlength="4" maxlength="12" placeholder="Ej: 4837" />
          </div>
        </div>
        <div style="margin-top:10px">
          <label>Comentarios/Retroalimentación</label>
          <textarea name="comments" rows="5" placeholder="Fortalezas, oportunidades de mejora, rúbrica, etc."></textarea>
        </div>
        <button class="btn primary" style="margin-top:12px">Guardar</button>
        <a class="btn link" href="/admin">Cancelar</a>
      </form>
    </section>
  `, { isTeacher: true });
  res.send(html);
});

app.post('/evaluations', requireAuth, (req, res) => {
  const student_name = sanitize(req.body.student_name);
  const student_id = sanitize(req.body.student_id);
  const course = sanitize(req.body.course);
  const date = sanitize(req.body.date);
  const score = req.body.score ? Number(req.body.score) : null;
  const comments = sanitize(req.body.comments);
  const view_code = (req.body.view_code || '').trim();

  if (!student_name || !view_code) {
    return res.status(400).send('Faltan campos obligatorios');
  }

  const view_code_sha = sha256hex(view_code);
  const view_code_hint = view_code.slice(-2);

  db.run(
    `INSERT INTO evaluations (student_name, student_id, course, date, score, comments, view_code_sha, view_code_hint)
     VALUES (?,?,?,?,?,?,?,?)`,
    [student_name, student_id, course, date, score, comments, view_code_sha, view_code_hint],
    function(err) {
      if (err) return res.status(500).send('Error al guardar');
      const id = this.lastID;
      const html = layout('Evaluación creada', `
        <section class="card">
          <h2 class="title">¡Evaluación guardada!</h2>
          <p>Comparte este PIN con el estudiante para que consulte su resultado:</p>
          <h3 class="title">PIN: <span class="badge tag-ok">${view_code}</span></h3>
          <p class="muted">Ruta directa: <code>/ver?codigo=${encodeURIComponent(view_code)}</code></p>
          <div style="margin-top:10px">
            <a class="btn primary" href="/evaluations/${id}">Ver ficha</a>
            <a class="btn" href="/admin">Volver al listado</a>
          </div>
        </section>
      `, { isTeacher: true });
      res.send(html);
    }
  );
});

// --- Ver/gestionar evaluación (docente)
app.get('/evaluations/:id', requireAuth, (req, res) => {
  db.get(`SELECT * FROM evaluations WHERE id = ?`, [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).send('No encontrada');
    const html = layout(`Evaluación #${row.id}`, `
      <section class="card">
        <h2 class="title">${row.student_name}</h2>
        <div class="grid cols-3">
          <div><strong>ID:</strong> ${row.student_id || '-'}</div>
          <div><strong>Curso:</strong> ${row.course || '-'}</div>
          <div><strong>Fecha:</strong> ${row.date || '-'}</div>
        </div>
        <div class="grid cols-3" style="margin-top:8px">
          <div><strong>Puntaje:</strong> ${row.score ?? '-'}</div>
          <div><strong>PIN (sufijo):</strong> ${row.view_code_hint ? '…' + row.view_code_hint : '-'}</div>
          <div><strong>Creada:</strong> ${row.created_at}</div>
        </div>
        <div style="margin-top:10px"><strong>Comentarios:</strong><br/>${row.comments || '<span class="muted">(sin comentarios)</span>'}</div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <a class="btn" href="/admin">Volver</a>
          <form method="post" action="/evaluations/${row.id}/delete" onsubmit="return confirm('¿Eliminar definitivamente?');">
            <button class="btn danger">Eliminar</button>
          </form>
        </div>
      </section>
    `, { isTeacher: true });
    res.send(html);
  });
});

app.post('/evaluations/:id/delete', requireAuth, (req, res) => {
  db.run(`DELETE FROM evaluations WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).send('Error al eliminar');
    res.redirect('/admin');
  });
});

// --- Vista de estudiante por PIN
app.get('/ver', (req, res) => {
  const codigo = (req.query.codigo || '').trim();
  if (!codigo) {
    const html = layout('Consulta', `
      <section class="card">
        <h2 class="title">Consulta</h2>
        <p>Ingresa tu PIN para ver tu evaluación.</p>
        <form method="get" action="/ver">
          <input name="codigo" required minlength="4" maxlength="12" />
          <button class="btn primary" style="margin-top:8px">Buscar</button>
        </form>
      </section>
    `, { isTeacher: !!req.session.isTeacher });
    return res.send(html);
  }
  const targetSha = sha256hex(codigo);
  db.get(`SELECT student_name, student_id, course, date, score, comments
          FROM evaluations WHERE view_code_sha = ?`, [targetSha], (err, row) => {
    if (err) return res.status(500).send('Error de búsqueda');
    if (!row) {
      const html = layout('No encontrada', `
        <section class="card">
          <h2 class="title">No se encontró una evaluación con ese PIN.</h2>
          <a class="btn" href="/">Volver</a>
        </section>
      `, { isTeacher: !!req.session.isTeacher });
      return res.status(404).send(html);
    }
    const html = layout('Resultado de evaluación', `
      <section class="card">
        <h2 class="title">Resultado de ${row.student_name}</h2>
        <div class="grid cols-3">
          <div><strong>ID:</strong> ${row.student_id || '-'}</div>
          <div><strong>Curso:</strong> ${row.course || '-'}</div>
          <div><strong>Fecha:</strong> ${row.date || '-'}</div>
        </div>
        <div class="grid cols-3" style="margin-top:8px">
          <div><strong>Puntaje:</strong> ${row.score ?? '-'}</div>
        </div>
        <div style="margin-top:10px"><strong>Comentarios del docente:</strong><br/>${row.comments || '<span class="muted">(sin comentarios)</span>'}</div>
        <div style="margin-top:12px">
          <a class="btn" href="/">Volver</a>
        </div>
      </section>
    `, { isTeacher: !!req.session.isTeacher });
    res.send(html);
  });
});

// --- Export CSV (docente)
app.get('/admin/export.csv', requireAuth, (req, res) => {
  db.all(`SELECT id, student_name, student_id, course, date, score, REPLACE(REPLACE(comments, '\n', ' '), '\r', ' ') AS comments, created_at
          FROM evaluations ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).send('Error al exportar');
    const header = 'id,student_name,student_id,course,date,score,comments,created_at\n';
    const csv = rows.map(r => [r.id, r.student_name, r.student_id || '', r.course || '', r.date || '', r.score ?? '', `"${String(r.comments || '').replace(/"/g,'""')}"`, r.created_at].join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="evaluaciones.csv"');
    res.send(header + csv);
  });
});

// --- 404
app.use((req, res) => {
  const html = layout('No encontrado', `
    <section class="card">
      <h2 class="title">404</h2>
      <p class="muted">La ruta solicitada no existe.</p>
      <a class="btn" href="/">Ir al inicio</a>
    </section>
  `, { isTeacher: !!(req.session && req.session.isTeacher) });
  res.status(404).send(html);
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});

/* =============================
   Archivo: Dockerfile
   ============================= */
# Imagen ligera de Node
FROM node:20-alpine

# Directorio de trabajo
WORKDIR /app

# Copia manifests primero para aprovechar la cache
COPY package*.json ./

# Instala deps en modo producción
RUN npm ci --omit=dev || npm i --omit=dev

# Copia el resto del código
COPY . .

# Variables y puerto
ENV NODE_ENV=production
EXPOSE 3000

# Arranque
CMD ["node", "server.js"]


/* =============================
   Archivo: .dockerignore
   ============================= */
node_modules
npm-debug.log
.DS_Store
.env
*.sqlite
*.sqlite-journal
*.db
/data*


/* =============================
   Archivo: .env.example
   (Copia como .env y rellena valores)
   ============================= */
PORT=3000
SESSION_SECRET=cambia_esto_por_uno_largo_y_unico
ACCESS_CODE_DOCENTE=DOCENTE1234


/* =============================
   Archivo: package.json
   (si no generas con `npm init -y`)
   ============================= */
{
  "name": "plataforma-evaluaciones-mvp",
  "version": "1.0.0",
  "description": "MVP para publicar y consultar evaluaciones con código de acceso.",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "NODE_ENV=development node server.js"
  },
  "keywords": ["evaluaciones", "educacion", "express", "sqlite"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "bcrypt": "^5.1.1",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "express-session": "^1.18.0",
    "helmet": "^7.1.0",
    "sqlite3": "^5.1.7",
    "xss": "^1.0.15",
    "@faker-js/faker": "^9.0.0"
  }
}


/* =============================
   Archivo: README.md
   ============================= */
# Plataforma de Evaluaciones – MVP (Node/Express + SQLite)

Sistema mínimo para **publicar evaluaciones** y **consultarlas por PIN**. Acceso del docente con **código de acceso** (sin usuarios/contraseñas).

## 1) Requisitos
- Node.js 18+ y npm

## 2) Configuración local
```bash
# Clonar o copiar archivos
npm install
# Crear .env desde .env.example y completar valores
npm run start
# Abrir http://localhost:3000
```

## 3) Variables de entorno
- `PORT` (ej. 3000)
- `SESSION_SECRET` (string largo y único)
- `ACCESS_CODE_DOCENTE` (código que usarás en /login)

## 4) Flujo de uso
1. Docente entra a `/login` con `ACCESS_CODE_DOCENTE`.
2. Crea evaluaciones en `/admin` (asigna un **PIN** por estudiante).
3. Comparte el PIN. El estudiante consulta en `/ver?codigo=PIN`.
4. Exporta CSV en `/admin/export.csv`.

## 5) Docker
```bash
docker build -t evaluaciones-mvp .
docker run --name evaluaciones \
  --env-file .env \
  -p 3000:3000 \
  -v $(pwd)/data.db:/app/data.db \
  evaluaciones-mvp
```

## 6) Despliegue (Render/Railway/Fly)
- Sube a GitHub: `server.js`, `package.json`, `Dockerfile`, `.dockerignore`, `.env.example`.
- Variables de entorno: `SESSION_SECRET`, `ACCESS_CODE_DOCENTE`, `PORT` (si aplica).
- **Persistencia**: monta un volumen para que `data.db` no se pierda tras redeploys.
- En producción activa `secure: true` en la cookie de sesión.

## 7) Seguridad y privacidad
- Usa **HTTPS** si está público.
- Cambia periódicamente `ACCESS_CODE_DOCENTE`.
- Haz **backups** de `data.db`.
- Cumple normativa de protección de datos.

## 8) Personalización
- Campos: edita el esquema en `server.js` (tabla `evaluations`) y los formularios.
- Estilo: ajusta CSS en la función `layout()`.
- Acceso: puedes filtrar por IP o añadir cuentas si lo necesitas.

---
> **Nota:** Este MVP es educativo. Antes de usar datos reales, revisa requisitos legales de tu institución.


/* =============================
   Archivo: render.yaml
   (Despliegue 1‑click en Render con volumen persistente)
   ============================= */
services:
  - type: web
    name: evaluaciones-mvp
    env: node
    region: oregon
    plan: starter
    buildCommand: npm ci --omit=dev || npm i --omit=dev
    startCommand: node server.js
    autoDeploy: true
    envVars:
      - key: NODE_ENV
        value: production
      - key: SESSION_SECRET
        sync: false # define en el panel de Render
      - key: ACCESS_CODE_DOCENTE
        sync: false # define en el panel de Render
      - key: PORT
        value: 3000
    disk:
      name: db
      mountPath: /opt/render/project/src
      sizeGB: 1

/* =============================
   Instrucciones Render (resumen)
   ============================= */
# 1) Sube el repo a GitHub con estos archivos.
# 2) En Render → New → Web Service → conecta el repo.
# 3) En "Environment" añade las env vars: SESSION_SECRET y ACCESS_CODE_DOCENTE.
# 4) Render creará el servicio. El archivo data.db quedará persistido en el disco.


/* =============================
   Archivo: docker-compose.yml
   (Levantar con un comando en tu servidor/PC)
   ============================= */
version: "3.9"
services:
  app:
    build: .
    container_name: evaluaciones-mvp
    ports:
      - "3000:3000"
    env_file:
      - .env
    volumes:
      - ./data.db:/app/data.db
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:3000',r=>process.exit(0)).on('error',()=>process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 5

/* =============================
   Instrucciones docker-compose (resumen)
   ============================= */
# 1) Copia .env desde .env.example y completa valores.
# 2) docker compose up -d --build
# 3) Abre http://localhost:3000


/* =============================
   Archivo: nginx.conf
   (Reverse proxy + HTTPS con certificados en /etc/letsencrypt)
   ============================= */
# Servir en 80 → redirigir a 443
server {
  listen 80;
  server_name tu-dominio.com;
  location / { return 301 https://$host$request_uri; }
}

# Servir en 443 con proxy hacia Node en 3000
server {
  listen 443 ssl http2;
  server_name tu-dominio.com;

  ssl_certificate     /etc/letsencrypt/live/tu-dominio.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/tu-dominio.com/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;

  # Limitar tamaño de subida (si un día agregas archivos)
  client_max_body_size 10m;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}

/* =============================
   Archivo: Caddyfile
   (Alternativa simple a Nginx: HTTPS automático con Let's Encrypt)
   ============================= */
# Reemplaza con tu dominio real
te-doy-un-ejemplo.com {
  reverse_proxy 127.0.0.1:3000
}

/* =============================
   Mejora: Rúbrica por criterios con cálculo automático
   (Parche a server.js: agrega columna y UI dinámica)
   ============================= */
# 1) Migración de base de datos (si ya tienes data.db)
#    Ejecuta estos comandos una sola vez (por ejemplo, con sqlite3):
#    ALTER TABLE evaluations ADD COLUMN rubric_json TEXT;
#    ALTER TABLE evaluations ADD COLUMN total_score REAL;
#    UPDATE evaluations SET total_score = score WHERE total_score IS NULL;

# 2) Cambios en el formulario de "Nueva evaluación" (server.js):
#    Sustituye el bloque del formulario por esta versión con rúbrica
#    (busca app.get('/evaluations/new', ...) y reemplaza el contenido `form`):

<form method="post" action="/evaluations" onsubmit="return saveRubric()">
  <div class="grid cols-3">
    <div>
      <label>Nombre del estudiante</label>
      <input name="student_name" required />
    </div>
    <div>
      <label>ID del estudiante</label>
      <input name="student_id" />
    </div>
    <div>
      <label>Curso/Asignatura</label>
      <input name="course" />
    </div>
  </div>
  <div class="grid cols-3" style="margin-top:10px">
    <div>
      <label>Fecha</label>
      <input type="date" name="date" />
    </div>
    <div>
      <label>Puntaje total (auto)</label>
      <input id="total_score" name="score" type="number" step="0.01" readonly />
    </div>
    <div>
      <label>PIN para consulta del estudiante</label>
      <input name="view_code" required minlength="4" maxlength="12" placeholder="Ej: 4837" />
    </div>
  </div>
  <div style="margin-top:10px">
    <label>Rúbrica (criterios)</label>
    <div id="rubric"></div>
    <button class="btn" type="button" onclick="addRow()">+ Criterio</button>
    <input type="hidden" name="rubric_json" id="rubric_json" />
  </div>
  <div style="margin-top:10px">
    <label>Comentarios/Retroalimentación</label>
    <textarea name="comments" rows="5" placeholder="Fortalezas, oportunidades de mejora, rúbrica, etc."></textarea>
  </div>
  <button class="btn primary" style="margin-top:12px">Guardar</button>
  <a class="btn link" href="/admin">Cancelar</a>
</form>
<script>
  const wrap = document.getElementById('rubric');
  function addRow(init){
    const row = document.createElement('div');
    row.className = 'grid cols-3';
    row.style.marginTop = '8px';
    row.innerHTML = `
      <div><input placeholder="Criterio (ej. Programación)" value="${init?.name||''}"/></div>
      <div><input type="number" step="0.01" placeholder="Peso" value="${init?.weight||1}"/></div>
      <div><input type="number" step="0.01" placeholder="Puntaje" value="${init?.score||0}" oninput="recalc()"/></div>
    `;
    wrap.appendChild(row);
    recalc();
  }
  function recalc(){
    const rows = [...wrap.querySelectorAll('.grid.cols-3')];
    let total = 0; let items = [];
    rows.forEach(r=>{
      const [nameEl, wEl, sEl] = r.querySelectorAll('input');
      const name = nameEl.value.trim();
      const weight = parseFloat(wEl.value||'1');
      const score = parseFloat(sEl.value||'0');
      if(!name) return;
      const partial = weight*score;
      total += partial;
      items.push({ name, weight, score, partial });
    });
    document.getElementById('total_score').value = Number(total.toFixed(2));
    document.getElementById('rubric_json').value = JSON.stringify(items);
  }
  function saveRubric(){
    recalc();
    return true;
  }
  // fila inicial
  addRow({name:'Programación', weight:1, score:0});
  addRow({name:'Diseño/Construcción', weight:1, score:0});
  addRow({name:'Documentación', weight:1, score:0});
</script>

# 3) Guardado en el backend (server.js):
#    En app.post('/evaluations', ...) añade la lectura de rubric_json y total_score.
#    Reemplaza esa ruta por esta versión:

app.post('/evaluations', requireAuth, (req, res) => {
  const student_name = sanitize(req.body.student_name);
  const student_id = sanitize(req.body.student_id);
  const course = sanitize(req.body.course);
  const date = sanitize(req.body.date);
  const score = req.body.score ? Number(req.body.score) : null; // total auto
  const comments = sanitize(req.body.comments);
  const rubric_json = sanitize(req.body.rubric_json);
  const view_code = (req.body.view_code || '').trim();

  if (!student_name || !view_code) {
    return res.status(400).send('Faltan campos obligatorios');
  }

  const view_code_sha = sha256hex(view_code);
  const view_code_hint = view_code.slice(-2);

  db.run(
    `INSERT INTO evaluations (student_name, student_id, course, date, score, total_score, comments, rubric_json, view_code_sha, view_code_hint)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [student_name, student_id, course, date, score, score, comments, rubric_json, view_code_sha, view_code_hint],
    function(err) {
      if (err) return res.status(500).send('Error al guardar');
      const id = this.lastID;
      const html = layout('Evaluación creada', `
        <section class="card">
          <h2 class="title">¡Evaluación guardada!</h2>
          <p>Comparte este PIN con el estudiante para que consulte su resultado:</p>
          <h3 class="title">PIN: <span class="badge tag-ok">${view_code}</span></h3>
          <p class="muted">Ruta directa: <code>/ver?codigo=${encodeURIComponent(view_code)}</code></p>
          <div style="margin-top:10px">
            <a class="btn primary" href="/evaluations/${id}">Ver ficha</a>
            <a class="btn" href="/admin">Volver al listado</a>
          </div>
        </section>
      `, { isTeacher: true });
      res.send(html);
    }
  );
});

# 4) Mostrar la rúbrica (server.js):
#    En la vista de docente (app.get('/evaluations/:id', ...)) y la de estudiante (/ver),
#    imprime la tabla si existe rubric_json.
#    Inserta este fragmento donde se muestran los detalles:

<div style="margin-top:10px"><strong>Rúbrica:</strong>
  <div id="rubrica">
    ${(() => { try {
      const items = JSON.parse(row.rubric_json || '[]');
      if(!items.length) return '<span class="muted">(sin rúbrica)</span>';
      const rows = items.map(it => `<tr><td>${it.name}</td><td>${it.weight}</td><td>${it.score}</td><td>${(it.partial||0).toFixed(2)}</td></tr>`).join('');
      return `<div style="overflow:auto"><table><thead><tr><th>Criterio</th><th>Peso</th><th>Puntaje</th><th>Parcial</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    } catch(e){ return '<span class="muted">(rúbrica no válida)</span>'; } })()}
  </div>
</div>
