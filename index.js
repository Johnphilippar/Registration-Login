const express = require('express');
const dotenv = require('dotenv')
const sql = require('./config/db')

dotenv.config()

const app = express();

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

app.get('/', async (req, res) => {
  try {
    const result = await sql`SELECT * FROM teleo_users`; // this verifies DB connection
    console.log('DATABASE is connected');
    res.send(result,'DATABASE is connected ✅');
  } catch (error) {
    console.error('DATABASE connection failed ❌', error);
    res.status(500).send('Failed to connect to database');
  }
});

// Init Middleware
app.use(express.json({ extended: false }));

app.use('/api/users',require('./API/users'))
app.use('/api/auth',require('./API/auth'))