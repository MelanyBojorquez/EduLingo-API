// middleware/adminProtect.js
const protect = require('./auth'); // Importa tu middleware de autenticación
const db = require('../config/db'); // Importa la conexión a la DB

const adminProtect = async (req, res, next) => {
    // 1. Ejecutar el middleware de autenticación (verifica el token)
    protect(req, res, async () => {
        try {
            // El usuario ya está autenticado y su ID está en req.user.id
            const userId = req.user.id; 
            
            // 2. Consulta la DB para obtener el rol del usuario actual
            const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
            const user = rows[0];

            if (user && user.role === 'Profesor') {
                // Si el usuario es Profesor, continúa
                next();
            } else {
                // Si no es Profesor, error 403
                res.status(403).json({ message: 'Acceso denegado. Se requiere rol de Profesor.' });
            }
        } catch (error) {
            console.error('Error de verificación de rol:', error);
            res.status(500).json({ message: 'Error interno de verificación de rol.' });
        }
    });
};

module.exports = adminProtect;