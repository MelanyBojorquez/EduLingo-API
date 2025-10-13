require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');

const protect = require('./middleware/auth');
const roleProtect = require('./middleware/roleProtect');
const db = require('./config/db'); 

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- ENDPOINTS DE USUARIO (Login y Registro) ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.query('SELECT id, password, role, learning_language, name, email, profile_picture_url FROM users WHERE email = ?', [email]);
        const user = rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Correo o contraseña incorrectos.' });
        }
        const token = jwt.sign({ id: user.id, role: user.role, language: user.learning_language }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user });
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.post('/api/register', upload.single('profilePicture'), async (req, res) => {
    const { name, email, password, native_language, learning_language } = req.body;
    try {
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const profilePictureUrl = req.file ? req.file.path.replace(/\\/g, "/") : null;
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, native_language, learning_language, role, profile_picture_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, native_language, learning_language, 'Alumno', profilePictureUrl]
        );
        const userId = result.insertId;
        const token = jwt.sign({ id: userId, role: 'Alumno', language: learning_language }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(201).json({ 
            token, 
            user: { id: userId, role: 'Alumno', name, email, profile_picture_url: profilePictureUrl }
        });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


// --- ENDPOINTS DE MÓDULOS/LECCIONES ---

// GET para el ALUMNO (HomeScreen)
app.get('/api/lessons', protect, async (req, res) => {
    const targetLanguage = req.user.language;
    try {
        const [lessons] = await db.query(
            'SELECT id, title, objectives, target_language, content_json, category FROM lessons WHERE target_language = ?', 
            [targetLanguage]
        );
        res.json({ lessons });
    } catch (error) {
        console.error('Error al obtener lecciones:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// GET para el ADMIN (Lista de todos los cursos en ModulesScreen)
app.get('/api/admin/courses', roleProtect(['Administrador']), async (req, res) => {
    try {
        const [courses] = await db.query('SELECT id, title, target_language, category FROM lessons ORDER BY created_at DESC');
        res.json({ courses });
    } catch (error) {
        console.error('Error al obtener lista de cursos:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// GET para el ADMIN (Detalles de un curso para CourseEditScreen)
app.get('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('SELECT * FROM lessons WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Curso no encontrado.' });
        }
        res.json({ course: rows[0] });
    } catch (error) {
        console.error('Error al obtener curso por ID:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// POST para el ADMIN (Crear curso)
app.post('/api/admin/courses', roleProtect(['Administrador']), async (req, res) => {
    const { title, target_language, objectives, lessons, category } = req.body;
    if (!title || !category || !target_language || !objectives || !lessons || lessons.length === 0) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }
    try {
        const contentJson = JSON.stringify(lessons);
        const [result] = await db.query(
            'INSERT INTO lessons (title, target_language, objectives, content_json, category) VALUES (?, ?, ?, ?, ?)',
            [title, target_language, objectives, contentJson, category]
        );
        res.status(201).json({ 
            message: `Módulo '${title}' creado exitosamente.`,
            courseId: result.insertId
        });
    } catch (error) {
        console.error('Error al crear curso:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// PUT para el ADMIN (Actualizar curso)
app.put('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;
    const { title, target_language, objectives, lessons, category } = req.body; 
    if (!title || !category || !target_language || !objectives) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }
    try {
        const contentJson = JSON.stringify(lessons); 
        const [result] = await db.query(
            'UPDATE lessons SET title = ?, target_language = ?, objectives = ?, content_json = ?, category = ? WHERE id = ?',
            [title, target_language, objectives, contentJson, category, id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Curso no encontrado para actualizar.' });
        }
        res.json({ message: `Curso ID ${id} actualizado exitosamente.` });
    } catch (error) {
        console.error('Error al actualizar curso:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// DELETE para el ADMIN (Eliminar curso)
app.delete('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await db.query('DELETE FROM lessons WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Curso no encontrado para eliminar.' });
        }
        res.json({ message: `Curso ID ${id} eliminado exitosamente.` });
    } catch (error) {
        console.error('Error al eliminar curso:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// --- ENDPOINTS DE ADMIN (Alumnos) ---
app.get('/api/admin/students', roleProtect(['Administrador']), async (req, res) => {
    try {
        const [students] = await db.query('SELECT id, name, email, native_language, learning_language FROM users WHERE role = ?', ['Alumno']);
        res.json({ students: students });
    } catch (error) {
        console.error('Error al obtener lista de alumnos:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


app.listen(PORT, () => {
    console.log(`Servidor de EduLingo corriendo en http://localhost:${PORT}`);
});