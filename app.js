const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require("socket.io");
const storage = multer.memoryStorage();
const upload = multer({ storage });
const Image = require('./models/image');
const cookie = require('cookie');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const {log} = require("debug");
const privateKey = fs.readFileSync('./certs/key.pem', 'utf8');
const certificate = fs.readFileSync('./certs/cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };
const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: ['http://localhost:4200', 'http://127.0.0.1:4200'], // фронт должен быть на этом порту
  credentials: true,
}));
app.use(cookieParser());
const httpsServer = https.createServer(credentials, app);
const io = new Server(httpsServer, {
  cors: {
    origin: ['http://localhost:4200', 'http://127.0.0.1:4200'],
    credentials: true
  }
});





mongoose.connect('mongodb://localhost:27017/userdb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  name: String,
  lastName: String,
  role: String,
  questions: {
    pair: String,
    maxMates: String,
    maxMoney: String,
    possPlace: String,
    cleanfulness: String,
    pets: String,
    alco: String,
    smoke: String
  },
  avatar: { type: mongoose.Schema.Types.ObjectId, ref: 'Image' },
  chats: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Chat' }],
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  content: {
    text: { type: String },
  },
}, { timestamps: true });

const chatSchema = new mongoose.Schema({
  title: { type: String, required: false },
  type: {
    type: String,
    enum: ['direct', 'group'],
    required: true
  },
  avatar: { type: mongoose.Schema.Types.ObjectId, ref: 'Image' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);
const User = mongoose.model('User', userSchema);
// app.use((req, res, next) => {
//   console.log('Request Origin:', req.headers.origin);
//   console.log('Request Method:', req.method);
//   next();
// });
const authMiddleware = (req, res, next) => {
  if (req.path === '/login' || req.path === '/register') {
    return next();
  }
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).send({message: 'Authorization required'});
  }
  try {
    const decoded = jwt.verify(token, 'secret_key');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({message: 'Invalid token'});
  }
};

app.use(authMiddleware);



app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');
    const user = await User.findById(req.user.id);
    const image = new Image({
      filename: req.file.originalname,
      contentType: req.file.mimetype,
      data: req.file.buffer,
    });
    await image.save();

    if (user.avatar) {
      await Image.deleteOne(user.avatar);
    }
    await User.findByIdAndUpdate(user._id, { avatar: image._id });

    res.status(201).json({ message: 'File uploaded and linked to user', imageId: image._id });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).send({message: 'Upload failed'});
  }
});

app.get('/image/:id', async (req, res) => {
  try {
    const image = await Image.findById(req.params.id);
    if (!image) return res.status(404).send('Image not found');

    res.set('Content-Type', image.contentType);
    res.send(image.data);
  } catch (err) {
    res.status(500).send({message: 'Failed to load image'});
  }
});

app.post('/register', async (req, res) => {
  try {
    const { name, lastName, role, questions, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, lastName, role, questions, email, password: hashedPassword });
    await user.save();
    res.status(201).send({message: 'User registered'});
  } catch (err) {
    res.status(400).send(err);
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).send({message: 'User not found'});

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send({message: 'Invalid credentials'});

    const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '30d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // true в проде с https
      sameSite: 'None',
      maxAge: 3600000000, // 1 час
      path: '/'
    });

    res.json({ message: 'Login successful' });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send(err);
  }
});

app.get('/me', async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).send('User not found');
    res.json(user);
  } catch (err) {
    res.status(401).send({message: 'Invalid request'});
  }
});

app.get('/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).send({message: 'User not found'});
    res.json(user);
  } catch (err) {
    res.status(401).send({message: 'Invalid request'});
  }
});

app.get('/users/all', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    if (users.length === 0) return res.status(404).send({message: 'No users found'});
    res.json(users);
  } catch (err) {
    res.status(500).send({message: 'Server error'});
  }
});



app.get('/checkchat', async (req, res) => {
  try {
    const { firstUser, secondUser } = req.query;

    const chat = await Chat.findOne({
      members: { $all: [firstUser, secondUser] },
      type: 'direct',
    });

    if (!chat) {
      const chat = new Chat({type: 'direct', members: [firstUser, secondUser], admins: [firstUser, secondUser] });
      await chat.save();
    }
    res.json(chat._id);
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});

app.get('/mychats', async (req, res) => {
  try {
    const userId = req.user.id;

    const chats = await Chat.aggregate([
      { $match: { members: new mongoose.Types.ObjectId(userId) } },
      {
        $lookup: {
          from: 'messages',
          let: { chatId: '$_id' },
          pipeline: [
            { $match: { $expr: { $eq: ['$chatId', '$$chatId'] } } },
            { $sort: { createdAt: -1 } },
            { $limit: 1 }
          ],
          as: 'lastMessage'
        }
      },
      { $unwind: { path: '$lastMessage', preserveNullAndEmptyArrays: true } },
      { $sort: { 'lastMessage.createdAt': -1 } }
    ]);

    if (chats.length===0) {
     res.send({message: 'Вы ни с кем не общаетесь, пока что'});
    }
    res.json(chats);
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});

app.get('/getlastmessage', async (req, res) => {
  try {
    const {chatId} = req.query;

    const message = await Message.findOne({ chatId })
        .sort({ createdAt: -1 });
    if (!message) {
      return res.send({ message: 'Сообщений пока нет' });
    }
    const formattedMessage = {
      ...message.toObject(),
      time: new Date(message.createdAt).toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit',
      })
    };



    res.json(formattedMessage);
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});



// app.get('/chat/:id', async (req, res) => {
//   try {
//     const id  = req.params.id;
//
//     const [messages, chat] = await Promise.all([
//       Message.find({ chatId: id }).sort({ createdAt: -1 }).limit(200),
//       Chat.findById(id),
//     ]);
//     res.json({ messages, chat });
//   } catch (err) {
//     console.error(err);
//     res.status(500).send('Server error');
//   }
// });



app.get('/chat/:id/messages', async (req, res) => {
  try {
    let skip = 0
    if (req.query.skip!='undefined') {
      skip = +req.query.skip;
    }
    const id  = req.params.id;

    const messages = await Message.find({ chatId: id }).sort({ createdAt: -1 }).skip(skip).limit(30)
    res.json({ messages });
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});
app.get('/chat/:id/info', async (req, res) => {
  try {
    const id  = req.params.id;

    const chat = await Chat.findById(id);
    res.json({ chat });
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});


// app.post('/createmessage', async (req, res) => {
//   try {
//     const text = req.body.content.text
//     const chatId = req.body.chatId;
//     console.log(text, chatId)
//     if (!text || !chatId) {
//       return res.status(400).send('Missing required fields');
//     }
//     const message = new Message({
//       content: {text: text},
//       chatId: chatId,
//       sender: req.user.id,
//     });
//     await message.save();
//     res.status(201).json(message);
//   } catch (err) {
//     res.status(500).send('Failed to load image');
//   }
// });

io.use((socket, next) => {
  const cookies = socket.handshake.headers.cookie;

  if (!cookies) return next(new Error('Нет cookie'));

  const parsedCookies = cookie.parse(cookies);
  const token = parsedCookies.token;

  if (!token) return next(new Error('Нет токена'));

  try {
    const decoded = jwt.verify(token, 'secret_key');
    socket.user = decoded; // Сохраняем в сокете
    next();
  } catch (err) {
    console.error('JWT ошибка:', err);
    next(new Error('Невалидный токен'));
  }
});


io.on('connection', (socket) => {
  console.log('🔌 Подключился пользователь:', socket.user.id);

  socket.on('joinChat', (chatId) => {
    socket.join(chatId);
    console.log(`✅ Пользователь ${socket.user.id} вошёл в комнату ${chatId}`);
  });


  socket.on('sendMessage', async ({ chatId, text }) => {
    try {
      const message = new Message({
        content: { text },
        chatId,
        sender: socket.user.id // <-- безопасно
      });

      await message.save();

      const formattedMessage = {
        ...message.toObject(),
        time: new Date(message.createdAt).toLocaleTimeString('ru-RU', {
          hour: '2-digit',
          minute: '2-digit',
        })
      };

      io.to(chatId).emit('receiveMessage', formattedMessage);
    } catch (err) {
      console.error('Ошибка при отправке сообщения:', err);
    }
  });
});
app.post("/logout", (req, res) => {
  console.log('3980093809')
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/", // ← обязательно!
  });
  res.sendStatus(200);
});


app.post('/editquestions', async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).send({message: 'User not found'});
    }

    if (!req.body.questions) {
      return res.status(400).send({message: 'No questions provided'});
    }

    user.questions = req.body.questions;
    await user.save();

    res.status(201).send({data: 'User questions updated'});
  } catch (err) {
    console.error(err);
    res.status(500).send({message: 'Server error'});
  }
});
app.post("/kys", async (req, res) => {
  try {
    if (!req.user || !req.user.id) {
      return res.status(400).send({message: 'Invalid user'});
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).send({message: 'User not found'});
    }

    await User.findByIdAndDelete(req.user.id);
    return res.status(200).send({message: 'User deleted successfully'});
  } catch (err) {
    console.error(err);
    return res.status(500).send({message: 'Server error'});
  }
});


app.post('/users/filtered', async (req, res) => {
  try {
    const filterFields = req.body; // Пример: { age: "18-25", gender: "Мужской" }

    const mongoQuery = {};

    for (const key in filterFields) {
      if (filterFields[key]) {
        mongoQuery[`questions.${key}`] = filterFields[key];
      }
    }
    console.log(mongoQuery)
    const users = await User.find(mongoQuery).select('-password');

    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Server error' });
  }
});




httpsServer.listen(3001, () => {
  console.log('HTTPS server running on https://localhost:3001');
});
module.exports = app;