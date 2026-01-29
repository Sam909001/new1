// ============================================================================
// MINING IDLE PRO - BACKEND API
// Full-stack game server with authentication, cloud saves & leaderboards
// ============================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(cors());
app.use(express.json());

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// ============================================================================
// IN-MEMORY DATABASE (Use PostgreSQL/MongoDB in production)
// ============================================================================

const database = {
  users: new Map(),
  saves: new Map(),
  leaderboard: new Map(),
  dailyRewards: new Map(),
  events: []
};

// ============================================================================
// ANTI-CHEAT VALIDATION
// ============================================================================

class AntiCheat {
  static validateSave(saveData, previousSave) {
    const errors = [];
    
    // Check for impossible progress
    if (previousSave) {
      const timeDiff = (saveData.timestamp - previousSave.timestamp) / 1000; // seconds
      const coinDiff = saveData.coins - previousSave.coins;
      
      // Calculate maximum possible earnings
      const maxAutoEarnings = this.calculateMaxAutoEarnings(previousSave, timeDiff);
      const maxClickEarnings = this.calculateMaxClickEarnings(previousSave, timeDiff);
      const maxTotalEarnings = maxAutoEarnings + maxClickEarnings;
      
      if (coinDiff > maxTotalEarnings * 1.5) { // 50% tolerance
        errors.push('Impossible coin gain detected');
      }
    }
    
    // Validate upgrade costs
    const expectedCosts = this.calculateUpgradeCosts(saveData.upgrades);
    const totalSpent = this.calculateTotalSpent(saveData.upgrades);
    
    if (totalSpent > saveData.stats.totalEarned) {
      errors.push('Spent more than earned');
    }
    
    // Check for negative values
    if (saveData.coins < 0 || saveData.prestigePoints < 0) {
      errors.push('Negative values detected');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
  
  static calculateMaxAutoEarnings(save, seconds) {
    const autoRate = save.upgrades.autoMiner * 1; // base rate
    return autoRate * seconds * 2; // 2x multiplier buffer
  }
  
  static calculateMaxClickEarnings(save, seconds) {
    const clickPower = 1 + (save.upgrades.pickaxe - 1) * 0.5;
    const maxClicks = seconds * 20; // Max 20 clicks per second
    return clickPower * maxClicks * 5; // 5x multiplier buffer
  }
  
  static calculateUpgradeCosts(upgrades) {
    let total = 0;
    
    // Pickaxe
    for (let i = 1; i < upgrades.pickaxe; i++) {
      total += Math.floor(10 * Math.pow(1.15, i - 1));
    }
    
    // Auto Miner
    for (let i = 0; i < upgrades.autoMiner; i++) {
      total += Math.floor(100 * Math.pow(1.3, i));
    }
    
    // Multiplier
    for (let i = 0; i < upgrades.multiplier; i++) {
      total += Math.floor(1000 * Math.pow(2.0, i));
    }
    
    // Efficiency
    for (let i = 0; i < upgrades.efficiency; i++) {
      total += Math.floor(5000 * Math.pow(1.5, i));
    }
    
    return total;
  }
  
  static calculateTotalSpent(upgrades) {
    return this.calculateUpgradeCosts(upgrades);
  }
}

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user exists
    const existingUser = Array.from(database.users.values()).find(
      u => u.username === username || u.email === email
    );
    
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const userId = Date.now().toString();
    const user = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      gems: 50, // Starting gems
      isPremium: false
    };
    
    database.users.set(userId, user);
    
    // Generate token
    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '30d' });
    
    res.status(201).json({
      token,
      user: {
        id: userId,
        username,
        email,
        gems: user.gems,
        isPremium: user.isPremium
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = Array.from(database.users.values()).find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        gems: user.gems,
        isPremium: user.isPremium
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// GAME SAVE ROUTES
// ============================================================================

app.post('/api/save', authenticateToken, (req, res) => {
  try {
    const saveData = req.body;
    const userId = req.user.id;
    
    // Get previous save for validation
    const previousSave = database.saves.get(userId);
    
    // Validate save data
    const validation = AntiCheat.validateSave(saveData, previousSave);
    
    if (!validation.valid) {
      console.warn(`Cheat detected for user ${userId}:`, validation.errors);
      return res.status(400).json({ 
        error: 'Invalid save data',
        details: validation.errors 
      });
    }
    
    // Add metadata
    const enrichedSave = {
      ...saveData,
      userId,
      savedAt: new Date(),
      version: '1.0'
    };
    
    database.saves.set(userId, enrichedSave);
    
    // Update leaderboard
    updateLeaderboard(userId, saveData);
    
    res.json({ success: true, message: 'Game saved successfully' });
  } catch (error) {
    console.error('Save error:', error);
    res.status(500).json({ error: 'Failed to save game' });
  }
});

app.get('/api/save', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const saveData = database.saves.get(userId);
    
    if (!saveData) {
      return res.status(404).json({ error: 'No save data found' });
    }
    
    res.json(saveData);
  } catch (error) {
    console.error('Load error:', error);
    res.status(500).json({ error: 'Failed to load game' });
  }
});

// ============================================================================
// LEADERBOARD ROUTES
// ============================================================================

function updateLeaderboard(userId, saveData) {
  const user = database.users.get(userId);
  
  const leaderboardEntry = {
    userId,
    username: user.username,
    coins: saveData.coins,
    prestigePoints: saveData.prestigePoints,
    totalEarned: saveData.stats.totalEarned,
    totalClicks: saveData.stats.totalClicks,
    updatedAt: new Date()
  };
  
  database.leaderboard.set(userId, leaderboardEntry);
}

app.get('/api/leaderboard/:category', (req, res) => {
  try {
    const { category } = req.params;
    const limit = parseInt(req.query.limit) || 100;
    
    const entries = Array.from(database.leaderboard.values());
    
    // Sort based on category
    let sorted;
    switch (category) {
      case 'coins':
        sorted = entries.sort((a, b) => b.coins - a.coins);
        break;
      case 'prestige':
        sorted = entries.sort((a, b) => b.prestigePoints - a.prestigePoints);
        break;
      case 'earned':
        sorted = entries.sort((a, b) => b.totalEarned - a.totalEarned);
        break;
      case 'clicks':
        sorted = entries.sort((a, b) => b.totalClicks - a.totalClicks);
        break;
      default:
        sorted = entries.sort((a, b) => b.coins - a.coins);
    }
    
    // Add rank
    const withRank = sorted.slice(0, limit).map((entry, index) => ({
      ...entry,
      rank: index + 1
    }));
    
    res.json(withRank);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

app.get('/api/leaderboard/:category/rank/:userId', (req, res) => {
  try {
    const { category, userId } = req.params;
    
    const entries = Array.from(database.leaderboard.values());
    
    // Sort based on category
    let sorted;
    switch (category) {
      case 'coins':
        sorted = entries.sort((a, b) => b.coins - a.coins);
        break;
      case 'prestige':
        sorted = entries.sort((a, b) => b.prestigePoints - a.prestigePoints);
        break;
      default:
        sorted = entries.sort((a, b) => b.coins - a.coins);
    }
    
    const rank = sorted.findIndex(e => e.userId === userId) + 1;
    const entry = database.leaderboard.get(userId);
    
    res.json({
      rank: rank || 'Unranked',
      entry
    });
  } catch (error) {
    console.error('Rank error:', error);
    res.status(500).json({ error: 'Failed to fetch rank' });
  }
});

// ============================================================================
// DAILY REWARDS & EVENTS
// ============================================================================

app.post('/api/daily-reward', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date().toDateString();
    
    const lastClaim = database.dailyRewards.get(userId);
    
    if (lastClaim && lastClaim.date === today) {
      return res.status(400).json({ error: 'Daily reward already claimed' });
    }
    
    // Calculate streak
    let streak = 1;
    if (lastClaim) {
      const yesterday = new Date(Date.now() - 86400000).toDateString();
      if (lastClaim.date === yesterday) {
        streak = lastClaim.streak + 1;
      }
    }
    
    // Calculate reward (increases with streak, caps at 7)
    const baseReward = 100;
    const streakBonus = Math.min(streak - 1, 6) * 50;
    const reward = baseReward + streakBonus;
    
    database.dailyRewards.set(userId, {
      date: today,
      streak,
      reward
    });
    
    res.json({
      reward,
      streak,
      message: `Day ${streak} reward claimed!`
    });
  } catch (error) {
    console.error('Daily reward error:', error);
    res.status(500).json({ error: 'Failed to claim reward' });
  }
});

app.get('/api/events', (req, res) => {
  try {
    // Example events (could be time-based, seasonal, etc.)
    const events = [
      {
        id: 'weekend_bonus',
        name: '2x Weekend!',
        description: 'Double earnings all weekend',
        multiplier: 2,
        active: new Date().getDay() === 0 || new Date().getDay() === 6,
        startDate: new Date().toISOString(),
        endDate: new Date(Date.now() + 86400000 * 2).toISOString()
      },
      {
        id: 'golden_hour',
        name: 'Golden Hour',
        description: '3x earnings for 1 hour!',
        multiplier: 3,
        active: new Date().getHours() === 20, // 8 PM
        startDate: new Date().toISOString(),
        endDate: new Date(Date.now() + 3600000).toISOString()
      }
    ];
    
    res.json(events.filter(e => e.active));
  } catch (error) {
    console.error('Events error:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// ============================================================================
// IAP & GEMS ROUTES
// ============================================================================

app.post('/api/purchase/gems', authenticateToken, async (req, res) => {
  try {
    const { package: packageName } = req.body;
    const userId = req.user.id;
    
    const packages = {
      small: { gems: 100, price: 0.99 },
      medium: { gems: 500, price: 4.99 },
      large: { gems: 1200, price: 9.99 },
      mega: { gems: 3000, price: 19.99 }
    };
    
    const purchasePackage = packages[packageName];
    
    if (!purchasePackage) {
      return res.status(400).json({ error: 'Invalid package' });
    }
    
    // In production, integrate with payment processor (Stripe, PayPal, etc.)
    // For demo, just add gems
    
    const user = database.users.get(userId);
    user.gems += purchasePackage.gems;
    database.users.set(userId, user);
    
    res.json({
      success: true,
      gems: user.gems,
      message: `Purchased ${purchasePackage.gems} gems!`
    });
  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({ error: 'Purchase failed' });
  }
});

app.post('/api/spend-gems', authenticateToken, (req, res) => {
  try {
    const { amount, item } = req.body;
    const userId = req.user.id;
    
    const user = database.users.get(userId);
    
    if (user.gems < amount) {
      return res.status(400).json({ error: 'Insufficient gems' });
    }
    
    user.gems -= amount;
    database.users.set(userId, user);
    
    res.json({
      success: true,
      remainingGems: user.gems,
      message: `Purchased ${item}!`
    });
  } catch (error) {
    console.error('Spend gems error:', error);
    res.status(500).json({ error: 'Failed to spend gems' });
  }
});

// ============================================================================
// ADMIN ROUTES (Add proper admin auth in production)
// ============================================================================

app.get('/api/admin/stats', (req, res) => {
  res.json({
    totalUsers: database.users.size,
    totalSaves: database.saves.size,
    activePlayers: database.leaderboard.size,
    timestamp: new Date()
  });
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date(),
    uptime: process.uptime()
  });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   MINING IDLE PRO - Backend API       ║
  ║   Server running on port ${PORT}        ║
  ╚════════════════════════════════════════╝
  `);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

// ============================================================================
// EXPORT FOR TESTING
// ============================================================================

module.exports = app;
