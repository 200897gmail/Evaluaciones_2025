# Plataforma de Evaluaciones – MVP 📚

Este proyecto es un **MVP (Producto Mínimo Viable)** para gestionar y consultar evaluaciones escolares con acceso por código.  
Permite a los docentes publicar evaluaciones y a los estudiantes consultarlas con un PIN seguro.

---

## 🚀 Características principales
- Acceso del **docente** con un código secreto (definido en variable de entorno).
- Creación, listado y eliminación de evaluaciones.
- Generación de **PIN** único para que el estudiante consulte su resultado.
- Consulta de evaluación en `/ver?codigo=PIN`.
- Exportación de todas las evaluaciones a CSV.
- Uso de **SQLite** (base de datos ligera, en archivo `data.db`).
- Seguridad básica con sesiones, rate limit y sanitización.

---

## 📂 Estructura de archivos

- `server.js` → servidor principal (Node + Express).
- `package.json` → dependencias y scripts.
- `Dockerfile` → despliegue con Docker/Render.
- `.gitignore` → evita subir archivos sensibles o innecesarios.
- `README.md` → este documento.

---

## ⚙️ Variables de entorno

Debes configurar las siguientes variables (en `.env` o en el panel de Render):

- `NODE_ENV=production`
- `PORT=3000`
- `SESSION_SECRET` → cadena larga y aleatoria.
- `ACCESS_CODE_DOCENTE` → código de acceso para el panel docente.

Ejemplo `.env`:
