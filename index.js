require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Bağlantısı (Coolify'dan alacağınız URL)
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Bağlandı'))
  .catch(err => console.error(err));

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'active', 
    uptime: process.uptime(),
    timestamp: Date.now(),
    message: 'FindYourSize API Systems Operational'
  });
});

// --- KAYIT OL (REGISTER) ---
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // E-posta kontrolü
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Bu e-posta zaten kayıtlı.' });

    // Şifreleme
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Token oluştur
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({ token, user: { name: user.name, email: user.email, isPro: user.isPro } });
  } catch (error) {
    res.status(500).json({ message: 'Sunucu hatası.' });
  }
});

// --- GİRİŞ YAP (LOGIN) ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Kullanıcı bulunamadı.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Hatalı şifre.' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, user: { name: user.name, email: user.email, isPro: user.isPro } });
  } catch (error) {
    res.status(500).json({ message: 'Sunucu hatası.' });
  }
});

// --- KULLANICI BİLGİSİ ---
app.get('/api/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Yetkisiz erişim.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(401).json({ message: 'Geçersiz token.' });
  }
});

app.post('/api/usage', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Yetkisiz' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });

    // Eğer Pro değilse ve limiti (5) dolmuşsa hata dön
    if (!user.isPro && user.usageCount >= 5) {
      return res.status(403).json({ 
        message: 'LIMIT_REACHED', 
        usageCount: user.usageCount 
      });
    }

    // Kullanımı artır
    user.usageCount += 1;
    await user.save();

    res.json({ usageCount: user.usageCount, isPro: user.isPro });
  } catch (error) {
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// --- YENİ: PREMIUM SATIN ALMA (Simülasyon) ---
app.post('/api/upgrade', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Yetkisiz' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findByIdAndUpdate(decoded.id, { isPro: true }, { new: true });
    
    res.json({ success: true, user: { name: user.name, email: user.email, isPro: user.isPro } });
  } catch (error) {
    res.status(500).json({ message: 'İşlem başarısız' });
  }
});


app.listen(3000, () => {
  console.log('Sunucu 0.0.0.0:3000 üzerinde çalışıyor.');
});

