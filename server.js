const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar o Sequelize para conectar ao PostgreSQL
const sequelize = new Sequelize('ambuhub', 'postgres', '1234', {
  host: 'localhost',
  dialect: 'postgres',
});

// Testar a conexão com o banco de dados
sequelize.authenticate()
  .then(() => console.log('Conectado ao PostgreSQL'))
  .catch(err => console.error('Não foi possível conectar ao PostgreSQL:', err));

// Definir modelo de usuário
const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    defaultValue: 'usuario_padrão',
  },
}, {
  tableName: 'users',
  timestamps: false, // Desativa timestamps se não necessário
});

// Sincronizar o modelo com o banco de dados
sequelize.sync();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Configurar middleware de sessão
app.use(session({
  secret: 'your-secret-key', // Altere isso para um valor seguro
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Para HTTPS, deve ser true
}));

// Middleware para proteger rotas
function ensureAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Middleware para verificar a role do usuário
function checkUserRole(role) {
  return function (req, res, next) {
    if (req.session.userRole === role) {
      return next();
    }
    res.status(403).send('Acesso negado. Você não tem permissão para visualizar esta página.');
  };
}

// Rotas
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Proteger as rotas de usuário com middleware
app.get('/usuario_padrao', ensureAuthenticated, checkUserRole('usuario_padrão'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'usuario_padrao.html'));
});

app.get('/usuario_ambulante', ensureAuthenticated, checkUserRole('usuario_ambulante'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'usuario_ambulante.html'));
});

// Rota de cadastro de usuário
app.post('/signup', async (req, res) => {
  try {
    const { email, password, advertiser } = req.body;
    const role = advertiser === 'on' ? 'usuario_ambulante' : 'usuario_padrão';

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar novo usuário
    const user = await User.create({ email, password: hashedPassword, role });

    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.status(500).send('Erro ao criar conta');
  }
});

// Rota de login de usuário
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuário no banco de dados
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).send('Usuário não encontrado');
    }

    // Comparar senha
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).send('Senha incorreta');
    }

    // Armazenar informações na sessão
    req.session.userId = user.id;
    req.session.userRole = user.role;

    // Redirecionar com base na role
    if (user.role === 'usuario_ambulante') {
      res.redirect('/usuario_ambulante');
    } else {
      res.redirect('/usuario_padrao');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Erro ao fazer login');
  }
});

// Rota de logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Erro ao fazer logout');
    }
    res.redirect('/login');
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
