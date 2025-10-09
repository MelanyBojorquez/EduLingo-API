// Archivo: middleware/auth.js
const jwt = require('jsonwebtoken');
require('dotenv').config();

const protect = (req, res, next) => {
    // 1. Obtener el token del encabezado 'Authorization'
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        // Formato: Bearer <token>
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado. No hay token.' });
    }

    try {
        // 2. Verificar el token y decodificar el payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // 3. Agregar los datos del usuario decodificado a la petición (req.user)
        req.user = decoded; 
        
        next(); // Continuar con el endpoint
    } catch (error) {
        console.error('Token inválido:', error);
        res.status(401).json({ message: 'Token inválido o expirado.' });
    }
};

module.exports = protect;