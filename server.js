// Archivo: server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const protect = require('./middleware/auth')
require('dotenv').config();

// Importar la conexión a la base de datos
const db = require('./config/db'); 

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Permite peticiones desde React Native
app.use(express.json()); // Permite parsear el body de las peticiones como JSON

// ------------------------------------------
// ENDPOINT DE LOGIN (POST /api/login)
// ------------------------------------------
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Buscar usuario en la DB
        const [rows] = await db.query('SELECT id, password, role, learning_language, name FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Correo o contraseña incorrectos.' });
        }

        // 2. Comparar la contraseña hasheada
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Correo o contraseña incorrectos.' });
        }

        // 3. Si las credenciales son correctas, generar el JWT
        const token = jwt.sign(
            { id: user.id, role: user.role, language: user.learning_language }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1d' } // Token válido por 1 día
        );
        
        // 4. Devolver el token y datos relevantes del usuario (sin el hash de la contraseña)
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                role: user.role, 
                learning_language: user.learning_language, 
                name: user.name 
            } 
        });

    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// ------------------------------------------
// INICIO DEL SERVIDOR
// ------------------------------------------
app.listen(PORT, () => {
    console.log(`Servidor de EduLingo corriendo en http://localhost:${PORT}`);
});



// ------------------------------------------
// ENDPOINT DE REGISTRO (POST /api/register)
// ------------------------------------------
app.post('/api/register', async (req, res) => {
    const { name, email, password, native_language, learning_language } = req.body;
    
    // **Validación simple de campos**
    if (!name || !email || !password || !native_language || !learning_language) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios para el registro.' });
    }

    try {
        // 1. Verificar si el email ya existe
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }

        // 2. Hashear la contraseña de forma segura
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 3. Definir el rol por defecto (Todo nuevo registro es un Alumno)
        const role = 'Alumno';
        
        // 4. Insertar el nuevo usuario en la base de datos
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, native_language, learning_language, role) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, native_language, learning_language, role]
        );

        // 5. Opcional: Generar token e iniciar sesión automáticamente
        const userId = result.insertId;
        const token = jwt.sign(
            { id: userId, role: role, language: learning_language }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1d' }
        );

        // Devolver la respuesta de éxito
        res.status(201).json({ 
            message: 'Usuario registrado exitosamente.', 
            token, 
            user: { id: userId, role, learning_language, name }
        });

    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor al intentar registrar.' });
    }
});

// ------------------------------------------
// ENDPOINT DE LECCIONES (GET /api/lessons)
// ------------------------------------------
app.get('/api/lessons', protect, async (req, res) => {
    // El middleware 'protect' ya verificó el token y puso los datos en req.user
    const targetLanguage = req.user.language; // Ej: 'Ingles' o 'Español'

    try {
        // 1. Consultar la DB filtrando por el idioma que el usuario está aprendiendo
        const [lessons] = await db.query(
            'SELECT id, title_es, title_en, type, difficulty, content_json FROM lessons WHERE target_language = ?', 
            [targetLanguage]
        );

        // 2. Devolver las lecciones encontradas
        res.json({ 
            message: `Lecciones encontradas para el idioma: ${targetLanguage}`,
            lessons: lessons
        });

    } catch (error) {
        console.error('Error al obtener lecciones:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener lecciones.' });
    }
});

// ------------------------------------------
// INICIO DEL SERVIDOR (app.listen)
// ------------------------------------------
app.listen(PORT, () => {
    console.log(`Servidor de EduLingo corriendo en http://localhost:${PORT}`);
});