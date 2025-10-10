// middleware/roleProtect.js
const protect = require('./auth'); // Importa tu middleware de autenticación (que verifica el token)
const db = require('../config/db'); 

// Esta función devuelve un middleware que verifica los roles
const roleProtect = (allowedRoles) => (req, res, next) => {
    // 1. Primero, ejecutar la verificación del token (middleware 'protect')
    protect(req, res, async () => {
        try {
            // El token ya está verificado, obtenemos el ID del usuario
            const userId = req.user.id; 
            
            // 2. Consulta la DB para obtener el rol del usuario actual
            const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
            const user = rows[0];

            // 3. Verificar si el rol del usuario está incluido en los roles permitidos (allowedRoles)
            if (user && allowedRoles.includes(user.role)) {
                next(); // Rol permitido, continuar con el endpoint
            } else {
                // Rol no permitido
                res.status(403).json({ message: 'Acceso denegado. Rol insuficiente.' });
            }
        } catch (error) {
            console.error('Error de verificación de rol:', error);
            res.status(500).json({ message: 'Error interno de verificación de rol.' });
        }
    });
};

module.exports = roleProtect;