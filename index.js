const express = require('express');
const cors = require('cors');
const db = require('./config/db');
require('dotenv').config();   

const app = express();

app.use(cors({
    origin: [
        'https://noir-frontend-sable.vercel.app',
        'https://noir-frontend-git-main-cristian23.vercel.app',
        'http://localhost:5500',
        'http://127.0.0.1:5500'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());

const PORT = process.env.PORT || 3000;

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

// ============================================================
// 🔐 MIDDLEWARE DE SEGURIDAD: CONTROL DE ROLES (Admin)
// ============================================================
const esAdmin = async (req, res, next) => {
    const { admin_id } = req.headers;
    if (!admin_id) return res.status(403).json({ error: "Acceso denegado. Se requiere ID de administrador." });

    try {
        const result = await db.query('SELECT rol FROM usuarios WHERE id = $1', [admin_id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado." });
        if (result.rows[0].rol === 'admin') next();
        else res.status(403).json({ error: "Permiso denegado.", rol_detectado: result.rows[0].rol });
    } catch (err) {
        console.error("Error en DB:", err);
        res.status(500).json({ error: "Error de base de datos." });
    }
};

// ============================================================
// 🗄️ CREAR TABLAS AL INICIAR
// ============================================================
const crearTablas = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                rol VARCHAR(20) DEFAULT 'cliente',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS productos (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                descripcion TEXT,
                precio DECIMAL(10,2) NOT NULL,
                stock INT NOT NULL,
                categoria VARCHAR(50),
                imagen_url VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS pedidos (
                id SERIAL PRIMARY KEY,
                usuario_id INT NOT NULL,
                total DECIMAL(10,2) NOT NULL,
                estado VARCHAR(50) DEFAULT 'Pendiente',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS detalles_pedidos (
                id SERIAL PRIMARY KEY,
                pedido_id INT NOT NULL,
                producto_id INT NOT NULL,
                cantidad INT NOT NULL,
                precio_unitario DECIMAL(10,2) NOT NULL
            );
        `);
        console.log('Tablas creadas/verificadas correctamente');
    } catch (err) {
        console.error('Error creando tablas:', err);
    }
};

// ============================================================
// 👤 GESTIÓN DE USUARIOS
// ============================================================
app.post('/usuarios', async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'El correo electrónico no tiene un formato válido' });
    if (!passwordRegex.test(password)) return res.status(400).json({ error: 'La contraseña debe contener al menos 8 caracteres, incluyendo mayúsculas, números y símbolos' });

    try {
        await db.query('INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3)', [nombre, email, password]);
        res.status(201).json({ mensaje: 'Registro exitoso' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Este correo ya está registrado.' });
        res.status(500).json({ error: 'Error técnico al registrar.' });
    }
});

app.get('/usuarios', async (req, res) => {
    try {
        const result = await db.query('SELECT id, nombre, email, rol FROM usuarios');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios.' });
    }
});

app.put('/usuarios/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, email } = req.body;
    try {
        await db.query('UPDATE usuarios SET nombre = $1, email = $2 WHERE id = $3', [nombre, email, id]);
        res.json({ mensaje: 'Usuario actualizado correctamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar.' });
    }
});

app.delete('/usuarios/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM usuarios WHERE id = $1', [id]);
        res.json({ mensaje: 'Usuario eliminado exitosamente' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar.' });
    }
});

// ============================================================
// 🔑 LOGIN
// ============================================================
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

    try {
        const result = await db.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const usuario = result.rows[0];
        if (usuario.password !== password) return res.status(401).json({ error: 'Contraseña incorrecta' });

        res.json({
            mensaje: 'Login exitoso',
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                email: usuario.email,
                rol: usuario.rol
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// ============================================================
// 📨 RECUPERACIÓN DE CONTRASEÑA
// ============================================================
app.post('/recuperar-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Por favor, ingresa tu correo electrónico.' });

    try {
        const result = await db.query('SELECT * FROM usuarios WHERE email = $1', [email.trim()]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'El correo electrónico no está registrado.' });

        res.json({
            mensaje: 'Se ha enviado un enlace de recuperación',
            enlace_simulado: `https://noir-frontend-sable.vercel.app/restablecer?token=tk_${Math.random().toString(36).substr(2, 9)}`
        });
    } catch (err) {
        res.status(500).json({ error: 'Error técnico en el servidor.' });
    }
});

app.put('/restablecer-password', async (req, res) => {
    const { email, nuevaPassword } = req.body;
    if (!email || !nuevaPassword) return res.status(400).json({ error: 'El email y la nueva contraseña son obligatorios.' });
    if (!passwordRegex.test(nuevaPassword)) return res.status(400).json({ error: 'La nueva contraseña no cumple con los requisitos de seguridad.' });

    try {
        const result = await db.query('UPDATE usuarios SET password = $1 WHERE email = $2', [nuevaPassword, email]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'No se pudo encontrar el usuario.' });
        res.json({ mensaje: 'Contraseña restablecida con éxito.' });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar la contraseña.' });
    }
});

// ============================================================
// 👕 GESTIÓN DE PRODUCTOS
// ============================================================
app.post('/productos', esAdmin, async (req, res) => {
    const { nombre, descripcion, precio, stock, categoria, imagen_url } = req.body;
    if (!nombre || !precio || !stock || !categoria) return res.status(400).json({ error: 'Faltan campos obligatorios.' });

    try {
        const result = await db.query(
            'INSERT INTO productos (nombre, descripcion, precio, stock, categoria, imagen_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [nombre, descripcion, precio, stock, categoria, imagen_url]
        );
        res.status(201).json({ mensaje: 'Producto creado exitosamente', id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar el producto.' });
    }
});

app.get('/productos', async (req, res) => {
    const { categoria } = req.query;
    try {
        let result;
        if (categoria) {
            result = await db.query('SELECT * FROM productos WHERE TRIM(categoria) = $1', [categoria.trim()]);
        } else {
            result = await db.query('SELECT * FROM productos');
        }
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener productos.' });
    }
});

app.delete('/productos/:id', esAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('DELETE FROM productos WHERE id = $1', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Producto no encontrado.' });
        res.json({ mensaje: 'Producto eliminado correctamente.' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar.' });
    }
});

app.put('/productos/:id', esAdmin, async (req, res) => {
    const { id } = req.params;
    const { nombre, descripcion, precio, stock, categoria, imagen_url } = req.body;
    if (!nombre || !precio || !stock) return res.status(400).json({ error: 'Nombre, precio y stock son obligatorios.' });

    try {
        await db.query(
            'UPDATE productos SET nombre = $1, descripcion = $2, precio = $3, stock = $4, categoria = $5, imagen_url = $6 WHERE id = $7',
            [nombre, descripcion, precio, stock, categoria, imagen_url, id]
        );
        res.json({ mensaje: 'Producto actualizado exitosamente.' });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar.' });
    }
});

app.get('/productos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('SELECT * FROM productos WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: `No se encontró el ID: ${id}` });
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al buscar el producto.' });
    }
});

// ============================================================
// 🛒 PROCESAMIENTO DE COMPRAS
// ============================================================
app.post('/pedidos', async (req, res) => {
    const { usuario_id, productos, direccion, telefono } = req.body;
    if (!usuario_id || !productos || productos.length === 0 || !direccion || !telefono) {
        return res.status(400).json({ error: 'Datos incompletos.' });
    }

    try {
        const filas = await db.query('SELECT id, precio, stock, nombre FROM productos');
        const filasBD = filas.rows;
        let totalCompra = 0;
        const productosValidados = [];

        for (let item of productos) {
            const productoReal = filasBD.find(p => p.id === item.id);
            if (!productoReal) return res.status(404).json({ error: `ID ${item.id} no existe.` });
            if (item.cantidad <= 0) return res.status(400).json({ error: 'Cantidad inválida.' });
            if (productoReal.stock < item.cantidad) return res.status(400).json({ error: `Sin stock de ${productoReal.nombre}.` });
            totalCompra += (parseFloat(productoReal.precio) * item.cantidad);
            productosValidados.push({ ...item, precio: productoReal.precio, nombre: productoReal.nombre });
        }

        const pedidoResult = await db.query(
            'INSERT INTO pedidos (usuario_id, total, estado) VALUES ($1, $2, $3) RETURNING id',
            [usuario_id, totalCompra, 'Pendiente']
        );
        const pedidoId = pedidoResult.rows[0].id;

        for (let p of productosValidados) {
            await db.query(
                'INSERT INTO detalles_pedidos (pedido_id, producto_id, cantidad, precio_unitario) VALUES ($1, $2, $3, $4)',
                [pedidoId, p.id, p.cantidad, p.precio]
            );
            await db.query('UPDATE productos SET stock = stock - $1 WHERE id = $2', [p.cantidad, p.id]);
        }

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
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al procesar el pedido.' });
    }
});

// ============================================================
// 🚀 SERVIDOR
// ============================================================
app.listen(PORT, async () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
    await crearTablas();
});

app.get('/', (req, res) => {
    res.json({ mensaje: "¡Bienvenido a la API de NOIR! El servidor está funcionando." });
});