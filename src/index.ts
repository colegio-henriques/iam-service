import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { query } from './config/db';
import { generateToken } from './utils/jwt';
import { authenticate, requireRole } from './middlewares/auth';

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

// Health Check Endpoint (Obrigatório para o Cloud Run)
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'UP', service: 'iam-service' });
});

// Endpoint de Registo de Utilizadores (Simplificado)
app.post('/register', async (req: Request, res: Response) => {
  try {
    const { email, password, role, first_name, last_name } = req.body;
    
    // Na prática, validar input com Joi ou Zod
    if (!email || !password || !role) {
      res.status(400).json({ error: 'Campos obrigatórios em falta.' });
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const result = await query(
      `INSERT INTO users (email, password_hash, role, first_name, last_name) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role`,
      [email, password_hash, role, first_name || '', last_name || '']
    );

    const user = result.rows[0];
    res.status(201).json({ message: 'Utilizador criado com sucesso', user });
  } catch (error: any) {
    console.error('Erro no registo:', error);
    res.status(500).json({ error: 'Erro ao registar utilizador.' });
  }
});

// Endpoint de Login
app.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const result = await query('SELECT * FROM users WHERE email = $1 AND is_active = true', [email]);
    if (result.rows.length === 0) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Rota protegida de exemplo (apenas Admins)
app.get('/users/me', authenticate, (req: Request, res: Response) => {
  res.status(200).json({ user: req.user });
});

// Rota protegida com RBAC
app.get('/admin/dashboard', authenticate, requireRole(['admin']), (req: Request, res: Response) => {
  res.status(200).json({ message: 'Bem-vindo ao painel de administração.' });
});

app.listen(PORT, () => {
  console.log(`[iam-service] Servidor a correr na porta ${PORT}`);
});
