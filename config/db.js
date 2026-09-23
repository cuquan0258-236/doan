const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI);
        console.log(`[SOAR] MongoDB đã kết nối: ${conn.connection.host}`);
        return conn;
    } catch (error) {
        console.error(`[SOAR] Lỗi kết nối MongoDB: ${error.message}`);
        process.exit(1);
    }
};

module.exports = { connectDB };
