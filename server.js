require('dotenv').config();


const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const protect = require('./middleware/auth')
const roleProtect = require('./middleware/roleProtect');
const adminProtect = require('./middleware/adminProtect');

//require('dotenv').config();

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
    const { name, email, password, native_language, learning_language} = req.body;
    
    const role ='Alumno';
    /*if (role !== 'Profesor' && role !== 'Alumno') {
        return res.status(403).json({ message: 'El rol especificado no está permitido en esta ruta de registro.' });
    }*/

   
    if (!name || !email || !password || !native_language || !learning_language) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios para el registro.' });
    }

    try {
        // Verificar si el email ya existe
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }

        // 2. Hashear la contraseña 
        const hashedPassword = await bcrypt.hash(password, 10);
        
       // Insertar el nuevo usuario con el rol proporcionado (que ya validamos)
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, native_language, learning_language, role) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, native_language, learning_language, role]
        );

        
        //Generar token e iniciar sesión automáticamente
        const userId = result.insertId;
        const token = jwt.sign(
            { id: userId, role: role, language: learning_language }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1d' }
        );

        
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

// En server.js

// ------------------------------------------
// ENDPOINT: CREACIÓN DE USUARIOS POR ADMIN/PROFESOR
// ------------------------------------------
// Solo permitido para Administrador O Profesor
app.post('/api/admin/users', roleProtect(['Administrador', 'Profesor']), async (req, res) => {
    const { name, email, password, native_language, learning_language, role } = req.body;
    
    // Validar que el rol proporcionado para la creación exista en la DB
    if (!['Administrador', 'Profesor', 'Alumno'].includes(role)) {
        return res.status(400).json({ message: 'Rol proporcionado no válido.' });
    }

    // Lógica para hashear, verificar y guardar en DB (la misma que antes)

    try {
        // ... (Verificar email, hashear password) ...
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Insertar el nuevo usuario con el rol especificado
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, native_language, learning_language, role) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, native_language, learning_language, role]
        );

        res.status(201).json({ 
            message: `Usuario ${role} creado exitosamente.`,
            userId: result.insertId
        });
        // ...

    } catch (error) {
        console.error('Error al crear usuario de administración:', error);
        res.status(500).json({ message: 'Error interno del servidor al crear usuario.' });
    }
});

// En server.js

// ------------------------------------------
// ENDPOINT: OBTENER DATOS DEL USUARIO ACTUAL (Para perfil/dashboards)
// ------------------------------------------
app.get('/api/users/me', protect, async (req, res) => {
    // El 'protect' middleware ya nos dio el ID en req.user.id
    const userId = req.user.id; 

    try {
        // Obtenemos todos los datos (excepto el password hash)
        const [rows] = await db.query('SELECT id, name, email, role, native_language, learning_language FROM users WHERE id = ?', [userId]);
        const user = rows[0];

        if (!user) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error al obtener datos del usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// ------------------------------------------
// ENDPOINT DE CREACIÓN DE USUARIOS POR ADMIN (POST /api/admin/users)
// ------------------------------------------
app.post('/api/admin/users', adminProtect, async (req, res) => {
    // Solo un usuario 'Profesor' autenticado puede acceder a esta ruta
    const { name, email, password, native_language, learning_language, role } = req.body;
    
    // Validación de rol (Asegurar que no envíen roles inválidos)
    if (role !== 'Profesor' && role !== 'Alumno') {
        return res.status(400).json({ message: 'Rol inválido proporcionado.' });
    }
    
    // Validación de campos (copiado del registro normal)
    if (!name || !email || !password || !native_language || !learning_language) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    try {
        // 1. Verificar si el email ya existe
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }

        // 2. Hashear la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Insertar el nuevo usuario con el rol especificado
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, native_language, learning_language, role) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, native_language, learning_language, role]
        );

        res.status(201).json({ 
            message: `Usuario ${role} creado exitosamente.`,
            userId: result.insertId
        });

    } catch (error) {
        console.error('Error al crear usuario de administración:', error);
        res.status(500).json({ message: 'Error interno del servidor al crear usuario.' });
    }
});


// ------------------------------------------
// ENDPOINT: LISTA DE ALUMNOS (GET /api/admin/students)
// ------------------------------------------
app.get('/api/admin/students', roleProtect(['Administrador']), async (req, res) => {
    try {
        // Consultar solo usuarios con rol 'Alumno'
        const [students] = await db.query(
            'SELECT id, name, email, native_language, learning_language FROM users WHERE role = ?', 
            ['Alumno']
        );

        res.json({ students: students });

    } catch (error) {
        console.error('Error al obtener lista de alumnos:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


// ------------------------------------------
// ENDPOINT:(POST /api/admin/courses)
// 
// ------------------------------------------
app.post('/api/admin/courses', roleProtect(['Administrador']), async (req, res) => {
    // Desestructurar los datos del body
    const { title, target_language, objectives, lessons } = req.body;
    
    
    if (!title || !target_language || !objectives || !lessons || lessons.length === 0) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios, y el curso debe tener al menos una lección.' });
    }

    
    if (target_language !== 'Ingles' && target_language !== 'Español') {
        return res.status(400).json({ message: 'Idioma objetivo no válido.' });
    }

    try {
        // Convertir el arreglo de lecciones (lessons) a formato JSON para guardar
        const contentJson = JSON.stringify(lessons);

        // Insertar el nuevo curso en la tabla 'lessons'
        const [result] = await db.query(
            'INSERT INTO lessons (title, target_language, objectives, content_json) VALUES (?, ?, ?, ?)',
            [title, target_language, objectives, contentJson]
        );

        res.status(201).json({ 
            message: `Curso '${title}' creado exitosamente.`,
            courseId: result.insertId
        });

    } catch (error) {
        console.error('Error al crear curso:', error);
        res.status(500).json({ message: 'Error interno del servidor al crear el curso.' });
    }
});

// ------------------------------------------
// ENDPOINT: LISTAR TODOS LOS CURSOS (GET /api/admin/courses)
// RUTA PROTEGIDA: Solo Administradores
// ------------------------------------------
app.get('/api/admin/courses', roleProtect(['Administrador']), async (req, res) => {
    try {
        const [courses] = await db.query(
            'SELECT id, title, target_language, objectives FROM lessons ORDER BY created_at DESC'
        );

        res.json({ courses: courses });

    } catch (error) {
        console.error('Error al obtener lista de cursos:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// ------------------------------------------
// ENDPOINT: OBTENER CURSO POR ID (GET /api/admin/courses/:id)
// RUTA PROTEGIDA: Solo Administradores
// ------------------------------------------
app.get('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;
    
    try {
        const [rows] = await db.query(
            'SELECT id, title, target_language, objectives, content_json FROM lessons WHERE id = ?',
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Curso no encontrado.' });
        }

         const rawContent = rows[0].content_json;
        let lessonsArray = [];
        if (rawContent) {
            try {
                const parsedContent = JSON.parse(rawContent);
                lessonsArray = parsedContent.courses || []; 
            } catch (jsonError) {
                console.error(`Error al parsear JSON (Propiedad 'courses') para el curso ID ${id}:`, jsonError);
                // Si el JSON está mal, usamos un array vacío para que el frontend no falle.
            }
        }
        
        const course = {
            id: rows[0].id,
            title: rows[0].title,
            target_language: rows[0].target_language,
            objectives: rows[0].objectives,
            
            lessons: lessonsArray 
        };

        res.json({ course: course });

    } catch (error) {
        console.error('Error al obtener curso por ID (General):', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener curso.' });
    }
});

// ------------------------------------------
// ENDPOINT: ACTUALIZAR CURSO (PUT /api/admin/courses/:id)
// RUTA PROTEGIDA: Solo Administradores
// ------------------------------------------
app.put('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;
    // Obtener los datos a actualizar del BODY:
    const { title, target_language, objectives, lessons } = req.body; 
    
    // Validar datos esenciales
    if (!title || !target_language || !objectives) {
        return res.status(400).json({ message: 'El título, idioma y objetivos son obligatorios.' });
    }

    try {
        // Convertir lecciones a JSON para actualizar
        const contentJson = JSON.stringify({ lecciones: lessons }); 

        const [result] = await db.query(
            'UPDATE lessons SET title = ?, target_language = ?, objectives = ?, content_json = ? WHERE id = ?',
            [title, target_language, objectives, contentJson, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Curso no encontrado para actualizar.' });
        }

        res.json({ message: `Curso ID ${id} actualizado exitosamente.` });

    } catch (error) {
        console.error('Error al actualizar curso:', error);
        res.status(500).json({ message: 'Error interno del servidor al actualizar.' });
    }
});

// ------------------------------------------
// ENDPOINT: ELIMINAR CURSO (DELETE /api/admin/courses/:id)
// RUTA PROTEGIDA: Solo Administradores
// ------------------------------------------
app.delete('/api/admin/courses/:id', roleProtect(['Administrador']), async (req, res) => {
    const { id } = req.params;

    try {
        const [result] = await db.query(
            'DELETE FROM lessons WHERE id = ?',
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Curso no encontrado para eliminar.' });
        }

        res.json({ message: `Curso ID ${id} eliminado exitosamente.` });

    } catch (error) {
        console.error('Error al eliminar curso:', error);
        res.status(500).json({ message: 'Error interno del servidor al eliminar.' });
    }
});