import bcrypt from 'bcrypt';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'iam_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
});

async function seedAdmin() {
  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash('admin123', salt);

    const email = 'benone.marcos@colegiohenriques.ao';
    const role = 'admin';
    const first_name = 'Benone';
    const last_name = 'Marcos';

    const res = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (res.rows.length > 0) {
      await pool.query('UPDATE users SET role = $1, is_active = true WHERE email = $2', [role, email]);
      console.log('✅ A conta benone.marcos@colegiohenriques.ao já existia e foi atualizada para admin global.');
      return;
    }

    await pool.query(
      `INSERT INTO users (email, password_hash, role, first_name, last_name, is_active) 
       VALUES ($1, $2, $3, $4, $5, true)`,
      [email, password_hash, role, first_name, last_name]
    );

    console.log('✅ Conta de Administrador Global provisionada com sucesso!');
    console.log('📧 Email: benone.marcos@colegiohenriques.ao');
    console.log('🔑 Password: admin123');
  } catch (err) {
    console.error('❌ Erro ao criar conta de admin:', err);
  } finally {
    pool.end();
  }
}

seedAdmin();
