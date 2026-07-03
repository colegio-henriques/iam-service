import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// No ambiente Google Cloud (Cloud Run), conectaremos via unix sockets na produção (se aplicável),
// ou via TCP no ambiente de desenvolvimento local.
export const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'iam_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  // max: 20 // Cloud SQL limits
});

export const query = (text: string, params?: any[]) => pool.query(text, params);
