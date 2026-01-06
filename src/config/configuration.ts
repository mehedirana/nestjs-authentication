export default () => ({
    //app
    port: parseInt(process.env.PORT, 10) || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
    appUrl: process.env.APP_URL,
    frontendUrl: process.env.FRONTEND_URL,

    //database
    database: {
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT, 10) || 5432,
        username: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        name: process.env.DB_DATABASE,
    },

    //jwt
    jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRATION || '1h',
        refreshSecret: process.env.JWT_REFRESH_SECRET,
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '786400s',
    },

    //email
    email: {
        host: process.env.MAIL_HOST,
        port: parseInt(process.env.MAIL_PORT, 10) || 2525,
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
        from: process.env.MAIL_FROM || 'noreply@yourapp.com',
    },

    // Oath
    google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },

    //  throttle
    throttle: {
        ttl: parseInt(process.env.THROTTLE_TTL, 10) || 60,
        limit: parseInt(process.env.THROTTLE_LIMIT, 10) || 10,
    }


})