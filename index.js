const express = require('express');
const cors = require('cors');
const db = require('./config/db');
require('dotenv').config();


const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Expresiones regulares para validación
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

// ============================================================
// 🔐 MIDDLEWARE DE SEGURIDAD: CONTROL DE ROLES (Admin)
// ============================================================
const esAdmin = (req, res, next) => {
  const { admin_id } = req.headers;

  if (!admin_id) {
    return res.status(403).json({ error: "Acceso denegado. Se requiere ID de administrador." });
  }

  db.query('SELECT rol FROM usuarios WHERE id = ?', [admin_id], (err, results) => {
    if (err) {
      console.error("Error en DB:", err);
      return res.status(500).json({ error: "Error de base de datos." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    const usuario = results[0];
    const rolUsuario = usuario.rol;

    console.log("Rol detectado:", rolUsuario);

    if (rolUsuario === 'admin') {
      next();
    } else {
      res.status(403).json({
        error: "Permiso denegado. Rol de administrador no verificado.",
        rol_detectado: rolUsuario
      });
    }
  });
};


// ============================================================
// 👤 GESTIÓN DE USUARIOS (CP-01, 02, 03)
// ============================================================

app.post('/usuarios', (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'El correo electrónico no tiene un formato válido' });
  }

  if (!passwordRegex.test(password)) {
    return res.status(400).json({ error: 'La contraseña debe contener al menos 8 caracteres, incluyendo mayúsculas, números y símbolos' });
  }

  const sql = 'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)';
  db.query(sql, [nombre, email, password], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Este correo ya está registrado.' });
      return res.status(500).json({ error: 'Error técnico al registrar.' });
    }
    res.status(201).json({ mensaje: 'Registro exitoso' });
  });
});

app.get('/usuarios', (req, res) => {
  db.query('SELECT id, nombre, email, rol FROM usuarios', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener usuarios.' });
    res.json(results);
  });
});

app.put('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  const { nombre, email } = req.body;
  const sql = 'UPDATE usuarios SET nombre = ?, email = ? WHERE id = ?';
  db.query(sql, [nombre, email, id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Error al actualizar.' });
    res.json({ mensaje: 'Usuario actualizado correctamente' });
  });
});

app.delete('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM usuarios WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Error al eliminar.' });
    res.json({ mensaje: 'Usuario eliminado exitosamente' });
  });
});

// ============================================================
// 🔑 LOGIN (CP-04, CP-05 y CP-06)
// ============================================================
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña requeridos' });
  }

  const sql = 'SELECT * FROM usuarios WHERE email = ?';

  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error en el servidor');
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // CORRECCIÓN: results es un array, necesitamos el primer objeto
    const usuario = results[0];

    if (usuario.password !== password) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    res.json({
      mensaje: 'Login exitoso',
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol
      }
    });
  });
});

// ============================================================
// 📨 CP-06: RECUPERACIÓN DE CONTRASEÑA
// ============================================================
app.post('/recuperar-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Por favor, ingresa tu correo electrónico.' });
  }

  const sql = 'SELECT * FROM usuarios WHERE email = ?';
  db.query(sql, [email.trim()], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error técnico en el servidor.' });

    if (results.length === 0) {
      return res.status(404).json({ error: 'El correo electrónico no está registrado en nuestro sistema.' });
    }

    res.json({
      mensaje: 'Se ha enviado un enlace de recuperación',
      info: 'Revisa tu bandeja de entrada para restablecer tu contraseña.',
      enlace_simulado: `http://localhost:3000/restablecer?token=tk_${Math.random().toString(36).substr(2, 9)}`
    });
  });
});

// ============================================================
// 🔄 CONTINUACIÓN CP-06: RESTABLECER CONTRASEÑA NUEVA
// ============================================================
app.put('/restablecer-password', (req, res) => {
  const { email, nuevaPassword } = req.body;

  if (!email || !nuevaPassword) {
    return res.status(400).json({ error: 'El email y la nueva contraseña son obligatorios.' });
  }

  if (!passwordRegex.test(nuevaPassword)) {
    return res.status(400).json({ error: 'La nueva contraseña no cumple con los requisitos de seguridad.' });
  }

  const sql = 'UPDATE usuarios SET password = ? WHERE email = ?';
  db.query(sql, [nuevaPassword, email], (err, result) => {
    if (err) return res.status(500).json({ error: 'Error al actualizar la contraseña.' });
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'No se pudo encontrar el usuario.' });
    }

    res.json({ mensaje: 'Contraseña restablecida con éxito. Ya puedes iniciar sesión.' });
  });
});

// ============================================================
// 👕 GESTIÓN DE PRODUCTOS
// ============================================================

app.post('/productos', esAdmin, (req, res) => {
    const { nombre, descripcion, precio, stock, categoria, imagen_url } = req.body;
    if (!nombre || !precio || !stock || !categoria) {
        return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    }
    const sql = 'INSERT INTO productos (nombre, descripcion, precio, stock, categoria, imagen_url) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [nombre, descripcion, precio, stock, categoria, imagen_url], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al guardar el producto.' });
        res.status(201).json({ mensaje: 'Producto creado exitosamente', id: result.insertId });
    });
});

app.get('/productos', (req, res) => {
    const { categoria } = req.query;
    let sql = 'SELECT * FROM productos';
    let params = [];
    if (categoria) {
        sql += ' WHERE TRIM(categoria) = ?';
        params.push(categoria.trim());
    }
    db.query(sql, params, (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al obtener productos.' });
        res.json(results);
    });
});

app.delete('/productos/:id', esAdmin, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM productos WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al eliminar.' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Producto no encontrado.' });
        res.json({ mensaje: 'Producto eliminado correctamente.' });
    });
});

app.put('/productos/:id', esAdmin, (req, res) => {
    const { id } = req.params;
    const { nombre, descripcion, precio, stock, categoria, imagen_url } = req.body;
    if (!nombre || !precio || !stock) {
        return res.status(400).json({ error: 'Nombre, precio y stock son obligatorios.' });
    }
    const sql = `UPDATE productos SET nombre = ?, descripcion = ?, precio = ?, stock = ?, categoria = ?, imagen_url = ? WHERE id = ?`;
    db.query(sql, [nombre, descripcion, precio, stock, categoria, imagen_url, id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al actualizar.' });
        res.json({ mensaje: 'Producto actualizado exitosamente.' });
    });
});

app.get('/productos/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM productos WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al buscar el producto.' });
        if (result.length === 0) return res.status(404).json({ error: `No se encontró el ID: ${id}` });
        res.json(result);
    });
});

// ============================================================
// 🛒 PROCESAMIENTO DE COMPRAS
// ============================================================
app.post('/pedidos', (req, res) => {
    const { usuario_id, productos, direccion, telefono } = req.body;
    if (!usuario_id || !productos || productos.length === 0 || !direccion || !telefono) {
        return res.status(400).json({ error: 'Datos incompletos.' });
    }
    db.query('SELECT id, precio, stock, nombre FROM productos', (err, filasBD) => {
        if (err) return res.status(500).json({ error: 'Error al consultar productos.' });
        let totalCompra = 0;
        const productosValidados = [];
        for (let item of productos) {
            const productoReal = filasBD.find(p => p.id === item.id);
            if (!productoReal) return res.status(404).json({ error: `ID ${item.id} no existe.` });
            if (item.cantidad <= 0) return res.status(400).json({ error: `Cantidad inválida.` });
            if (productoReal.stock < item.cantidad) return res.status(400).json({ error: `Sin stock de ${productoReal.nombre}.` });
            totalCompra += (parseFloat(productoReal.precio) * item.cantidad);
            productosValidados.push({ ...item, precio: productoReal.precio, nombre: productoReal.nombre });
        }
        const sqlPedido = 'INSERT INTO pedidos (usuario_id, total, estado) VALUES (?, ?, "Pendiente")';
        db.query(sqlPedido, [usuario_id, totalCompra], (err, resultadoPedido) => {
            if (err) return res.status(500).json({ error: 'Error al registrar pedido.' });
            const pedidoId = resultadoPedido.insertId;
            productosValidados.forEach(p => {
                db.query('INSERT INTO detalles_pedidos (pedido_id, producto_id, cantidad, precio_unitario) VALUES (?, ?, ?, ?)', 
                [pedidoId, p.id, p.cantidad, p.precio]);
                db.query('UPDATE productos SET stock = stock - ? WHERE id = ?', [p.cantidad, p.id]);
            });
            res.status(201).json({
                mensaje: 'Compra realizada con éxito.',
                pedido_id: pedidoId,
                total_final: totalCompra.toFixed(2),
                notificacion: {
                    asunto: `Confirmación de Pedido Noir #${pedidoId}`,
                    enviado_a: "correo_confirmado@usuario.com",
                    cuerpo: `Tu pedido será enviado a: ${direccion}.`,
                    estado_correo: 'Enviado'
                }
            });
        });
    });
});

// 🚀 Servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

app.get('/', (req, res) => {
  res.json({ mensaje: "¡Bienvenido a la API de NOIR! El servidor está funcionando." });
});