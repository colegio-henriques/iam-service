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

import { OAuth2Client } from 'google-auth-library';

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Endpoint de Autenticação Google OAuth2
app.post('/auth/google', async (req: Request, res: Response) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      res.status(400).json({ error: 'Token Google não fornecido.' });
      return;
    }

    // Verificar e desencriptar o ID Token do Google
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID || undefined,
    } as any);

    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      res.status(401).json({ error: 'Token Google inválido.' });
      return;
    }

    const { email, given_name, family_name, hd } = payload;

    // RESTRIÇÃO OBRIGATÓRIA DE DOMÍNIO
    const REQUIRED_DOMAIN = 'colegiohenriques.ao';
    const emailDomain = email.split('@')[1];

    if (emailDomain !== REQUIRED_DOMAIN && hd !== REQUIRED_DOMAIN) {
      res.status(403).json({ 
        error: `Acesso negado. Apenas utilizadores com conta @${REQUIRED_DOMAIN} podem aceder ao sistema.` 
      });
      return;
    }

    // Verificar se o utilizador já existe na base de dados
    let userResult = await query('SELECT * FROM users WHERE email = $1', [email]);
    let user;

    if (userResult.rows.length === 0) {
      // Criar automaticamente a conta para utilizadores válidos do domínio
      const newUser = await query(
        `INSERT INTO users (email, password_hash, role, first_name, last_name, is_active)
         VALUES ($1, $2, $3, $4, $5, true) RETURNING id, email, role, first_name, last_name`,
        [email, 'OAUTH2_GOOGLE_NO_PASSWORD', 'admin', given_name || 'Utilizador', family_name || 'Google']
      );
      user = newUser.rows[0];
    } else {
      user = userResult.rows[0];
    }

    if (!user.is_active) {
      res.status(403).json({ error: 'Conta suspensa. Contacte a administração.' });
      return;
    }

    // Gerar JWT interno da plataforma
    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    res.status(200).json({ 
      token, 
      user: { id: user.id, email: user.email, role: user.role, first_name: user.first_name, last_name: user.last_name } 
    });
  } catch (error: any) {
    console.error('Erro na autenticação Google OAuth2:', error);
    res.status(401).json({ error: 'Falha na autenticação Google OAuth2: ' + (error.message || 'Token inválido') });
  }
});

// Listar todos os utilizadores (Apenas Admins)
app.get('/users', authenticate, requireRole(['admin']), async (req: Request, res: Response) => {
  try {
    const result = await query(
      'SELECT id, email, role, first_name, last_name, is_active, created_at FROM users ORDER BY created_at DESC'
    );
    res.status(200).json({ users: result.rows });
  } catch (error) {
    console.error('Erro ao listar utilizadores:', error);
    res.status(500).json({ error: 'Erro interno ao procurar utilizadores.' });
  }
});

// Atualizar Papel/Permissão de um Utilizador (Apenas Admins)
app.put('/users/:id/role', authenticate, requireRole(['admin']), async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    const VALID_ROLES = ['admin', 'professor', 'encarregado', 'aluno', 'staff'];
    if (!role || !VALID_ROLES.includes(role)) {
      res.status(400).json({ error: 'Papel/Função inválida.' });
      return;
    }

    const result = await query(
      'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, role',
      [role, id]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Utilizador não encontrado.' });
      return;
    }

    res.status(200).json({ message: 'Papel atualizado com sucesso.', user: result.rows[0] });
  } catch (error) {
    console.error('Erro ao atualizar papel do utilizador:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Alterar Estado (Ativo/Inativo) de um Utilizador (Apenas Admins)
app.put('/users/:id/status', authenticate, requireRole(['admin']), async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { is_active } = req.body;

    if (typeof is_active !== 'boolean') {
      res.status(400).json({ error: 'Estado inválido.' });
      return;
    }

    const result = await query(
      'UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, is_active',
      [is_active, id]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Utilizador não encontrado.' });
      return;
    }

    res.status(200).json({ message: 'Estado atualizado com sucesso.', user: result.rows[0] });
  } catch (error) {
    console.error('Erro ao atualizar estado do utilizador:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Rota protegida com RBAC
app.get('/admin/dashboard', authenticate, requireRole(['admin']), (req: Request, res: Response) => {
  res.status(200).json({ message: 'Bem-vindo ao painel de administração.' });
});

app.listen(PORT, () => {
  console.log(`[iam-service] Servidor a correr na porta ${PORT}`);
});
