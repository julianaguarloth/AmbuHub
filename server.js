const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
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

    res.send(`Bem-vindo, ${user.role}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Erro ao fazer login');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
