const fs = require('fs');
const path = require('path');
const { exec, execSync, spawn } = require('child_process');

// --- FILE CONTENTS ---
// Upgraded with Approval Workflow, Diff Viewer, and UI Overhaul

const fileContents = {
  'docker-compose.yml': `
services:
  mongo:
    image: mongo:latest
    ports:
      - '27017:27017'
    volumes:
      - mongo-data:/data/db
    networks:
      - feature-flag-net

  redis:
    image: redis:latest
    ports:
      - '6379:6379'
    networks:
      - feature-flag-net

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - '5001:5001'
    depends_on:
      - mongo
      - redis
    environment:
      - MONGO_URI=mongodb://mongo:27017/featureflags
      - REDIS_URI=redis://redis:6379
      - JWT_SECRET=your_jwt_secret_key_here_please_change_me
      - PORT=5001
    networks:
      - feature-flag-net
    restart: unless-stopped
    # volumes:
    #   - ./backend:/app
    #   # Add this to avoid node_modules being overwritten by the volume mount
    #   - /app/node_modules

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - '3000:80'
    depends_on:
      - backend
    networks:
      - feature-flag-net
    # The harmful volume mount has been REMOVED.
    # The Dockerfile's COPY command now handles serving the built files.

networks:
  feature-flag-net:
    driver: bridge

volumes:
  mongo-data:
`,

  'backend/package.json': `
{
  "name": "feature-flag-backend",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-validator": "^7.1.0",
    "ioredis": "^5.4.1",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.4.1",
    "murmurhash3js": "^3.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.1.2"
  }
}
`,

  'backend/Dockerfile': `
# Use an official Node runtime as a parent image
FROM node:20-slim

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install app dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Make port 5001 available to the world outside this container
EXPOSE 5001

# Define environment variable
ENV NODE_ENV production

# Run server.js when the container launches
CMD ["node", "server.js"]
`,

  'backend/server.js': `
const express = require('express');
const mongoose = require('mongoose');
const Redis = require('ioredis');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const murmurhash = require('murmurhash3js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');

// --- CONFIGURATION ---
require('dotenv').config();
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/featureflags';
const REDIS_URI = process.env.REDIS_URI || 'redis://127.0.0.1:6379';
const JWT_SECRET = process.env.JWT_SECRET || 'your_default_secret';

if (JWT_SECRET === 'your_default_secret' || JWT_SECRET === 'your_jwt_secret_key_here_please_change_me') {
  console.warn('WARNING: JWT_SECRET is not set. Using default secret. PLEASE SET THIS IN PRODUCTION.');
}

const REDIS_CACHE_PREFIX = 'flag:';
const REDIS_SEGMENT_CACHE_PREFIX = 'segment:';
const REDIS_CACHE_TTL = 3600; // 1 hour
const REDIS_PUB_CHANNEL = 'flag_updates';
const REDIS_SEGMENT_PUB_CHANNEL = 'segment_updates';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- IN-MEMORY CACHES ---
const flagCache = new Map();
const segmentCache = new Map();

// --- DATABASE & CACHE CONNECTIONS ---

// ** MODIFIED ** MongoDB Connection with Retry
const connectWithRetry = () => {
  console.log('Attempting MongoDB connection...');
  mongoose.connect(MONGO_URI)
    .then(() => {
      console.log('MongoDB connected');
    })
    .catch(err => {
      console.error('MongoDB connection error:', err.message, '- Retrying in 5 sec...');
      setTimeout(connectWithRetry, 5000); // Retry after 5 seconds
    });
};

connectWithRetry(); // Initial connection attempt

// Redis Clients
const redisCache = new Redis(REDIS_URI);
const redisSubscriber = new Redis(REDIS_URI);

redisCache.on('connect', () => console.log('Redis Cache client connected'));
redisSubscriber.on('connect', () => console.log('Redis Subscriber client connected'));
redisCache.on('error', err => console.error('Redis Cache Error:', err.message));
redisSubscriber.on('error', err => console.error('Redis Subscriber Error:', err.message));


// --- REDIS PUB/SUB ---
redisSubscriber.subscribe(REDIS_PUB_CHANNEL, REDIS_SEGMENT_PUB_CHANNEL, (err, count) => {
  if (err) {
    console.error('Failed to subscribe to Redis channels:', err);
    return;
  }
  console.log(\`Subscribed to \${count} Redis channel(s)\`);
});

redisSubscriber.on('message', (channel, message) => {
  // Handle Flag Updates
  if (channel === REDIS_PUB_CHANNEL) {
    console.log(\`Received update for flag: \${message}\`);
    const cacheKey = \`\${REDIS_CACHE_PREFIX}\${message}\`;
    redisCache.get(cacheKey)
      .then(result => {
        if (result) {
          const flag = JSON.parse(result);
          flagCache.set(flag.key, flag);
          console.log(\`In-memory flag cache updated for: \${flag.key}\`);
        } else {
          flagCache.delete(message);
          console.log(\`In-memory flag cache invalidated for: \${message}\`);
        }
      })
      .catch(err => console.error('Error fetching updated flag from Redis cache:', err));
  }

  // Handle Segment Updates
  if (channel === REDIS_SEGMENT_PUB_CHANNEL) {
    console.log(\`Received update for segment: \${message}\`);
    const cacheKey = \`\${REDIS_SEGMENT_CACHE_PREFIX}\${message}\`;
    redisCache.get(cacheKey)
      .then(result => {
        if (result) {
          const segment = JSON.parse(result);
          segmentCache.set(segment.key, segment);
          console.log(\`In-memory segment cache updated for: \${segment.key}\`);
        } else {
          segmentCache.delete(message);
          console.log(\`In-memory segment cache invalidated for: \${message}\`);
        }
      })
      .catch(err => console.error('Error fetching updated segment from Redis cache:', err));
  }
});

// --- MONGOOSE MODELS ---

// User Model
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Viewer', 'Editor', 'Admin'], default: 'Editor' }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// Segment Model
const SegmentRuleSchema = new mongoose.Schema({
  attribute: { type: String, required: true },
  operator: { type: String, required: true, enum: ['=', '!=', '>', '<', 'contains', 'not_contains'] },
  value: { type: mongoose.Schema.Types.Mixed, required: true }
}, { _id: false });

const SegmentSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  description: { type: String },
  rules: [SegmentRuleSchema],
  version: { type: Number, default: 1 }
}, { timestamps: true });

const Segment = mongoose.model('Segment', SegmentSchema);

// Flag Models
const variationSchema = new mongoose.Schema({
  value: { type: mongoose.Schema.Types.Mixed, required: true },
  name: { type: String },
  description: { type: String },
}, { _id: false });

const targetingRuleSchema = new mongoose.Schema({
  // 'percentage', 'attribute' (was 'segment'), or 'segment' (new)
  type: { type: String, required: true, enum: ['percentage', 'attribute', 'segment'] },
  variationValue: { type: mongoose.Schema.Types.Mixed },
  // For 'percentage'
  rollout: { type: Number, min: 0, max: 100 },
  // For 'attribute' (direct attribute match)
  attributes: { type: mongoose.Schema.Types.Mixed },
  // For 'segment' (references a Segment key)
  segmentKey: { type: String }
}, { _id: false });

const environmentSchema = new mongoose.Schema({
  active: { type: Boolean, default: false },
  defaultVariationValue: { type: mongoose.Schema.Types.Mixed, required: true },
  offVariationValue: { type: mongoose.Schema.Types.Mixed, required: true },
  rules: [targetingRuleSchema],
}, { _id: false });

const FlagSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, index: true },
  description: { type: String, default: '' },
  owner: { type: String, default: '' },
  tags: [String],
  flagType: { type: String, required: true, enum: ['boolean', 'multivariate'] },
  variations: [variationSchema],
  lifecycle: { type: String, default: 'draft', enum: ['draft', 'active', 'archived'] },
  version: { type: Number, default: 1 },
  environments: {
    dev: { type: environmentSchema },
    stage: { type: environmentSchema },
    prod: { type: environmentSchema },
  }
}, { timestamps: true });

const Flag = mongoose.model('Flag', FlagSchema);

// Audit Log Model
const AuditLogSchema = new mongoose.Schema({
  flagKey: { type: String, index: true },
  segmentKey: { type: String, index: true },
  changeId: { type: String, index: true },
  user: { type: String, required: true }, // user email
  action: { type: String, required: true },
  diff: { type: mongoose.Schema.Types.Mixed },
}, { timestamps: true });

const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

// Pending Change Model (for Approval Workflow)
const PendingChangeSchema = new mongoose.Schema({
  flagKey: { type: String, required: true, index: true },
  requestedBy: { type: String, required: true }, // user email
  environment: { type: String, default: 'prod' },
  // The state we want the environment to have
  changes: { type: environmentSchema },
  // The state of the environment *before* the change
  original: { type: environmentSchema },
}, { timestamps: true });

const PendingChange = mongoose.model('PendingChange', PendingChangeSchema);


// --- HELPER FUNCTIONS ---

async function createAuditLog(user, action, details) {
  try {
    await AuditLog.create({
      user: user.email, // Use user email
      action,
      ...details
    });
  } catch (err) {
    console.error(\`Failed to create audit log:\`, err);
  }
}

// Pub/Sub & Caching
async function publishFlagUpdate(flagKey, flagDoc) {
  try {
    const cacheKey = \`\${REDIS_CACHE_PREFIX}\${flagKey}\`;
    if (flagDoc) {
      const flagJson = JSON.stringify(flagDoc);
      await redisCache.set(cacheKey, flagJson, 'EX', REDIS_CACHE_TTL);
      flagCache.set(flagKey, flagDoc); 
    } else {
      await redisCache.del(cacheKey);
      flagCache.delete(flagKey);
    }
    await redisCache.publish(REDIS_PUB_CHANNEL, flagKey);
  } catch (err) {
    console.error('Error publishing flag update:', err.message);
  }
}

async function publishSegmentUpdate(segmentKey, segmentDoc) {
  try {
    const cacheKey = \`\${REDIS_SEGMENT_CACHE_PREFIX}\${segmentKey}\`;
    if (segmentDoc) {
      const segmentJson = JSON.stringify(segmentDoc);
      await redisCache.set(cacheKey, segmentJson, 'EX', REDIS_CACHE_TTL);
      segmentCache.set(segmentKey, segmentDoc); 
    } else {
      await redisCache.del(cacheKey);
      segmentCache.delete(segmentKey);
    }
    await redisCache.publish(REDIS_SEGMENT_PUB_CHANNEL, segmentKey);
  } catch (err) {
    console.error('Error publishing segment update:', err.message);
  }
}

// Getters with Cache Fallback
async function getFlag(flagKey) {
  if (flagCache.has(flagKey)) {
    return flagCache.get(flagKey);
  }
  const cacheKey = \`\${REDIS_CACHE_PREFIX}\${flagKey}\`;
  try {
    const cachedFlag = await redisCache.get(cacheKey);
    if (cachedFlag) {
      const flag = JSON.parse(cachedFlag);
      flagCache.set(flagKey, flag);
      return flag;
    }
  } catch (err) { console.error('Redis GET error:', err.message); }

  try {
    const flag = await Flag.findOne({ key: flagKey }).lean();
    if (flag) {
      await redisCache.set(cacheKey, JSON.stringify(flag), 'EX', REDIS_CACHE_TTL);
      flagCache.set(flagKey, flag);
    }
    return flag;
  } catch (err) { console.error('MongoDB GET error:', err.message); return null; }
}

async function getSegment(segmentKey) {
  if (segmentCache.has(segmentKey)) {
    return segmentCache.get(segmentKey);
  }
  const cacheKey = \`\${REDIS_SEGMENT_CACHE_PREFIX}\${segmentKey}\`;
  try {
    const cachedSegment = await redisCache.get(cacheKey);
    if (cachedSegment) {
      const segment = JSON.parse(cachedSegment);
      segmentCache.set(segmentKey, segment);
      return segment;
    }
  } catch (err) { console.error('Redis GET error:', err.message); }

  try {
    const segment = await Segment.findOne({ key: segmentKey }).lean();
    if (segment) {
      await redisCache.set(cacheKey, JSON.stringify(segment), 'EX', REDIS_CACHE_TTL);
      segmentCache.set(segmentKey, segment);
    }
    return segment;
  } catch (err) { console.error('MongoDB GET error:', err.message); return null; }
}

// --- EVALUATION LOGIC ---

function getHashBucket(seed, userId) {
  const key = \`\${seed}:\${userId}\`;
  const hash = murmurhash.v3(key);
  return (hash % 100) + 1;
}

/**
 * Evaluates a set of segment rules against a user context.
 * @param {Array} rules - The array of segment rules.
 * @param {object} user - The user context object.
 * @returns {boolean} - True if all rules match, false otherwise.
 */
function evaluateSegmentRules(rules, user) {
  if (!user) return false;
  for (const rule of rules) {
    const userValue = user[rule.attribute];
    const ruleValue = rule.value;

    let match = false;
    switch (rule.operator) {
      case '=':
        match = userValue == ruleValue;
        break;
      case '!=':
        match = userValue != ruleValue;
        break;
      case '>':
        match = userValue > ruleValue;
        break;
      case '<':
        match = userValue < ruleValue;
        break;
      case 'contains':
        match = userValue && userValue.includes && userValue.includes(ruleValue);
        break;
      case 'not_contains':
        match = !userValue || !userValue.includes || !userValue.includes(ruleValue);
        break;
      default:
        match = false;
    }
    // If any rule fails, the segment doesn't match
    if (!match) return false;
  }
  // If all rules passed
  return true;
}

/**
 * The core evaluation logic.
 * @param {object} flag - The flag object.
 * @param {object} context - The evaluation context (e.g., { env: 'prod', user: { id: '...', role: '...' } }).
 * @returns {Promise<any>} The resolved variation value.
 */
async function evaluateFlag(flag, context) {
  const { env, user } = context;

  if (!flag || !env || !flag.environments[env]) {
    return null;
  }

  const envConfig = flag.environments[env];

  if (flag.lifecycle === 'archived' || !envConfig.active) {
    return envConfig.offVariationValue;
  }

  // Iterate through rules
  for (const rule of envConfig.rules) {
    let match = false;

    if (rule.type === 'attribute') {
      match = true;
      if (rule.attributes && user) {
        for (const attrKey in rule.attributes) {
          if (!user[attrKey] || user[attrKey] !== rule.attributes[attrKey]) {
            match = false;
            break;
          }
        }
      } else {
        match = false;
      }
    } else if (rule.type === 'percentage') {
      if (user && user.id) {
        const bucket = getHashBucket(flag.key, user.id);
        if (bucket <= rule.rollout) {
          match = true;
        }
      }
    } else if (rule.type === 'segment') {
      if (user && rule.segmentKey) {
        const segment = await getSegment(rule.segmentKey);
        if (segment) {
          match = evaluateSegmentRules(segment.rules, user);
        }
      }
    }

    if (match) {
      return rule.variationValue;
    }
  }

  return envConfig.defaultVariationValue;
}

// --- AUTH & RBAC MIDDLEWARE ---
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized: User not found' });
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Unauthorized: Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ message: 'Forbidden: Admin access required' });
  }
  next();
};

const editorOrAdmin = (req, res, next) => {
  if (req.user.role === 'Viewer') {
    return res.status(403).json({ message: 'Forbidden: Editor or Admin access required' });
  }
  next();
};

// --- VALIDATION MIDDLEWARE ---
const validateFlag = [
  check('key').isString().notEmpty().isLength({ min: 3, max: 100 }).matches(/^[a-zA-Z0-9_-]+$/).withMessage('Key must be 3-100 chars, alphanumeric with hyphens/underscores'),
  check('description').isString().isLength({ max: 500 }).withMessage('Description must be less than 500 chars'),
  check('flagType').isIn(['boolean', 'multivariate']).withMessage('Invalid flag type'),
  check('lifecycle').isIn(['draft', 'active', 'archived']).withMessage('Invalid lifecycle state'),
  check('variations').isArray({ min: 1 }).withMessage('At least one variation is required'),
];

const validateSegment = [
  check('key').isString().notEmpty().isLength({ min: 3, max: 100 }).matches(/^[a-zA-Z0-9_-]+$/).withMessage('Key must be 3-100 chars, alphanumeric with hyphens/underscores'),
  check('name').isString().notEmpty().isLength({ max: 100 }).withMessage('Name is required and max 100 chars'),
  check('rules').isArray().withMessage('Rules must be an array'),
];

// --- API ROUTES ---

// == Auth Routes ==
app.post('/api/auth/register', [
  check('email').isEmail().withMessage('Please provide a valid email'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user = new User({ email, password: hashedPassword, role: 'Editor' });

    const userCount = await User.countDocuments();
    if (userCount === 0) {
      user.role = 'Admin';
      console.log(\`First user registered, setting role to Admin for: \${email}\`);
    }

    await user.save();
    const payload = { id: user.id, email: user.email, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
    res.status(201).json({ token, user: payload });

  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', [
  check('email').isEmail().withMessage('Please provide a valid email'),
  check('password').isString().notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = { id: user.id, email: user.email, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: payload });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// == Flag CRUD (Protected) ==
app.get('/api/flags', authMiddleware, async (req, res) => {
  try {
    const flags = await Flag.find({}, 'key description flagType lifecycle tags owner').lean();
    res.json(flags);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching flags' });
  }
});

app.get('/api/flags/:key', authMiddleware, async (req, res) => {
  try {
    const flag = await getFlag(req.params.key);
    if (!flag) { return res.status(404).json({ message: 'Flag not found' }); }
    res.json(flag);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching flag' });
  }
});

app.post('/api/flags', authMiddleware, editorOrAdmin, validateFlag, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { return res.status(400).json({ errors: errors.array() }); }

  try {
    const newFlag = new Flag(req.body);
    const savedFlag = await newFlag.save();
    
    await createAuditLog(req.user, 'create_flag', { flagKey: savedFlag.key, diff: { after: savedFlag } });
    await publishFlagUpdate(savedFlag.key, savedFlag.toObject());
    
    res.status(201).json(savedFlag);
  } catch (err) {
    if (err.code === 11000) { return res.status(409).json({ message: 'A flag with this key already exists' }); }
    res.status(400).json({ message: 'Error creating flag', error: err.message });
  }
});

app.put('/api/flags/:key', authMiddleware, editorOrAdmin, validateFlag, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { return res.status(400).json({ errors: errors.array() }); }

  const { key } = req.params;
  const updateData = req.body;
  
  try {
    const originalFlag = await Flag.findOne({ key });
    if (!originalFlag) { return res.status(404).json({ message: 'Flag not found' }); }

    if (originalFlag.version !== updateData.version) {
      return res.status(409).json({ message: 'Conflict: This flag was updated by someone else. Please reload and re-apply your changes.' });
    }
    
    let pendingChangeCreated = false;
    const prodChange = JSON.stringify(originalFlag.environments.prod) !== JSON.stringify(updateData.environments.prod);

    // ** APPROVAL WORKFLOW LOGIC **
    if (prodChange && req.user.role === 'Editor') {
      // Check for existing pending change
      const existingChange = await PendingChange.findOne({ flagKey: key, environment: 'prod' });
      if (existingChange) {
        return res.status(409).json({ message: \`Conflict: A pending change for 'prod' already exists for this flag. It must be approved or denied first.\` });
      }

      // Create a pending change
      const pendingChange = new PendingChange({
        flagKey: key,
        requestedBy: req.user.email,
        environment: 'prod',
        changes: updateData.environments.prod, // The new state
        original: originalFlag.environments.prod // The state before this request
      });
      await pendingChange.save();
      
      // Revert the 'prod' environment in updateData to its original state
      updateData.environments.prod = originalFlag.environments.prod;
      pendingChangeCreated = true;

      await createAuditLog(req.user, 'request_change', { flagKey: key, changeId: pendingChange._id.toString() });
    }

    // Update the flag with (potentially modified) data
    updateData.version = (originalFlag.version || 1) + 1;
    
    const updatedFlag = await Flag.findByIdAndUpdate(originalFlag._id, updateData, { new: true, runValidators: true }).lean();
    
    await createAuditLog(req.user, 'update_flag', { flagKey: key, diff: { before: originalFlag.toObject(), after: updatedFlag } });
    await publishFlagUpdate(key, updatedFlag);
    
    res.json({ flag: updatedFlag, pendingChangeCreated });
  } catch (err) {
    res.status(400).json({ message: 'Error updating flag', error: err.message });
  }
});

app.delete('/api/flags/:key', authMiddleware, adminOnly, async (req, res) => {
  const { key } = req.params;
  try {
    const originalFlag = await Flag.findOne({ key });
    if (!originalFlag) { return res.status(404).json({ message: 'Flag not found' }); }

    originalFlag.lifecycle = 'archived';
    originalFlag.version = (originalFlag.version || 1) + 1;
    const archivedFlag = await originalFlag.save();

    await createAuditLog(req.user, 'archive_flag', { flagKey: key, diff: { before: originalFlag.toObject(), after: archivedFlag.toObject() } });
    await publishFlagUpdate(key, archivedFlag.toObject());

    res.json({ message: 'Flag archived successfully', flag: archivedFlag });
  } catch (err) {
    res.status(500).json({ message: 'Error archiving flag' });
  }
});

// == Segment CRUD (Protected) ==
app.get('/api/segments', authMiddleware, async (req, res) => {
  try {
    const segments = await Segment.find({}, 'key name description').lean();
    res.json(segments);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching segments' });
  }
});

app.get('/api/segments/:key', authMiddleware, async (req, res) => {
  try {
    const segment = await getSegment(req.params.key);
    if (!segment) { return res.status(404).json({ message: 'Segment not found' }); }
    res.json(segment);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching segment' });
  }
});

app.post('/api/segments', authMiddleware, editorOrAdmin, validateSegment, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { return res.status(400).json({ errors: errors.array() }); }

  try {
    const newSegment = new Segment(req.body);
    const savedSegment = await newSegment.save();
    
    await createAuditLog(req.user, 'create_segment', { segmentKey: savedSegment.key, diff: { after: savedSegment } });
    await publishSegmentUpdate(savedSegment.key, savedSegment.toObject());
    
    res.status(201).json(savedSegment);
  } catch (err) {
    if (err.code === 11000) { return res.status(409).json({ message: 'A segment with this key already exists' }); }
    res.status(400).json({ message: 'Error creating segment', error: err.message });
  }
});

app.put('/api/segments/:key', authMiddleware, editorOrAdmin, validateSegment, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { return res.status(400).json({ errors: errors.array() }); }

  const { key } = req.params;
  const updateData = req.body;
  
  try {
    const originalSegment = await Segment.findOne({ key });
    if (!originalSegment) { return res.status(404).json({ message: 'Segment not found' }); }

    if (originalSegment.version !== updateData.version) {
      return res.status(409).json({ message: 'Conflict: This segment was updated. Please reload.' });
    }
    
    updateData.version = (originalSegment.version || 1) + 1;
    
    const updatedSegment = await Segment.findByIdAndUpdate(originalSegment._id, updateData, { new: true, runValidators: true }).lean();
    
    await createAuditLog(req.user, 'update_segment', { segmentKey: key, diff: { before: originalSegment.toObject(), after: updatedSegment } });
    await publishSegmentUpdate(key, updatedSegment);
    
    res.json(updatedSegment);
  } catch (err) {
    res.status(400).json({ message: 'Error updating segment', error: err.message });
  }
});

app.delete('/api/segments/:key', authMiddleware, adminOnly, async (req, res) => {
  const { key } = req.params;
  try {
    const segment = await Segment.findOne({ key });
    if (!segment) { return res.status(4404).json({ message: 'Segment not found' }); }

    // Check if segment is in use by any flag in any environment
    const flagInUse = await Flag.findOne({ 
      $or: [
        { "environments.dev.rules.segmentKey": key },
        { "environments.stage.rules.segmentKey": key },
        { "environments.prod.rules.segmentKey": key }
      ] 
    });
    if (flagInUse) {
      return res.status(400).json({ message: \`Cannot delete segment: It is in use by flag '\${flagInUse.key}'.\` });
    }

    await Segment.findByIdAndDelete(segment._id);

    await createAuditLog(req.user, 'delete_segment', { segmentKey: key, diff: { before: segment.toObject() } });
    await publishSegmentUpdate(key, null); // Publish deletion

    res.json({ message: 'Segment deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting segment' });
  }
});


// == Evaluation API (Public) ==
app.post('/api/eval/:key', async (req, res) => {
  const { key } = req.params;
  const { context } = req.body;

  if (!context || !context.env) {
    return res.status(400).json({ message: 'Invalid evaluation context. "env" is required.' });
  }

  try {
    const flag = await getFlag(key);
    if (!flag) { return res.status(404).json({ message: 'Flag not found' }); }
    
    const result = await evaluateFlag(flag, context);
    res.json({ key, value: result });

  } catch (err) {
    res.status(500).json({ message: 'Error evaluating flag' });
  }
});

app.post('/api/eval/batch', async (req, res) => {
  const { keys, context } = req.body;
  if (!context || !context.env || !Array.isArray(keys)) {
    return res.status(400).json({ message: 'Invalid request. "context" (with "env") and "keys" array are required.' });
  }

  try {
    const results = {};
    const promises = keys.map(async (key) => {
      const flag = await getFlag(key);
      if (flag) {
        results[key] = await evaluateFlag(flag, context);
      } else {
        results[key] = null;
      }
    });
    
    await Promise.all(promises);
    res.json(results);

  } catch (err) {
    res.status(500).json({ message: 'Error performing batch evaluation' });
  }
});

// == Audit Log & Change Request API (Protected) ==
app.get('/api/audit/flag/:key', authMiddleware, async (req, res) => {
  try {
    const logs = await AuditLog.find({ flagKey: req.params.key }).sort({ createdAt: -1 });
    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching audit logs' });
  }
});

app.get('/api/changes', authMiddleware, async (req, res) => {
  try {
    const changes = await PendingChange.find().sort({ createdAt: -1 });
    res.json(changes);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching pending changes' });
  }
});

app.post('/api/changes/:id/approve', authMiddleware, adminOnly, async (req, res) => {
  try {
    const change = await PendingChange.findById(req.params.id);
    if (!change) { return res.status(404).json({ message: 'Pending change not found' }); }

    const flag = await Flag.findOne({ key: change.flagKey });
    if (!flag) { return res.status(404).json({ message: 'Flag not found' }); }

    // Apply the change
    flag.environments.prod = change.changes;
    flag.version = (flag.version || 1) + 1;
    const updatedFlag = await flag.save();

    // Delete the pending change
    await PendingChange.findByIdAndDelete(req.params.id);

    // Create audit log
    await createAuditLog(req.user, 'approve_change', {
      flagKey: flag.key,
      changeId: change._id.toString(),
      diff: { before: change.original, after: change.changes }
    });
    
    // Publish update
    await publishFlagUpdate(flag.key, updatedFlag.toObject());

    res.json(updatedFlag);
  } catch (err) {
    res.status(500).json({ message: 'Error approving change' });
  }
});

app.delete('/api/changes/:id/deny', authMiddleware, adminOnly, async (req, res) => {
  try {
    const change = await PendingChange.findByIdAndDelete(req.params.id);
    if (!change) { return res.status(404).json({ message: 'Pending change not found' }); }

    // Create audit log
    await createAuditLog(req.user, 'deny_change', {
      flagKey: change.flagKey,
      changeId: change._id.toString()
    });

    res.json({ message: 'Change denied and removed' });
  } catch (err) {
    res.status(500).json({ message: 'Error denying change' });
  }
});


// --- SERVER START ---
async function primeCaches() {
  try {
    console.log('Priming caches...');
    // Prime Flags
    const flags = await Flag.find({ lifecycle: { $ne: 'archived' } }).lean();
    let flagCount = 0;
    for (const flag of flags) {
      const cacheKey = \`\${REDIS_CACHE_PREFIX}\${flag.key}\`;
      await redisCache.set(cacheKey, JSON.stringify(flag), 'EX', REDIS_CACHE_TTL);
      flagCache.set(flag.key, flag);
      flagCount++;
    }
    // Prime Segments
    const segments = await Segment.find().lean();
    let segmentCount = 0;
    for (const segment of segments) {
      const cacheKey = \`\${REDIS_SEGMENT_CACHE_PREFIX}\${segment.key}\`;
      await redisCache.set(cacheKey, JSON.stringify(segment), 'EX', REDIS_CACHE_TTL);
      segmentCache.set(segment.key, segment);
      segmentCount++;
    }
    console.log(\`Successfully primed \${flagCount} flags and \${segmentCount} segments.\`);
  } catch (err) {
    console.error('Failed to prime caches:', err);
  }
}

const server = http.createServer(app);

// Wait for MongoDB to be connected before starting the server
mongoose.connection.once('open', () => {
    console.log('MongoDB connection established, starting server...');
    server.listen(PORT, async () => {
        await primeCaches();
        console.log(\`Backend server running on port \${PORT}\`);
    });
});

mongoose.connection.on('error', err => {
    console.error('MongoDB connection error event:', err.message);
});
`,

  'frontend/package.json': `
{
  "name": "feature-flag-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@heroicons/react": "^2.1.4",
    "@tailwindcss/forms": "^0.5.7",
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "scripts": {
    "start": "vite",
    "build": "vite build",
    "serve": "vite preview"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.0",
    "autoprefixer": "^10.4.19",
    "postcss": "^8.4.38",
    "tailwindcss": "^3.4.3",
    "vite": "^5.2.11"
  }
}
`,

  'frontend/index.html': `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Feature Flag Admin</title>
    <style>
      body {
        font-family: 'Inter', sans-serif;
      }
    </style>
  </head>
  <body class="bg-gray-100">
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
`,

  'frontend/src/main.jsx': `
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css'; // This will import Tailwind's base styles

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
`,

  'frontend/src/index.css': `
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom toast styles for smooth transitions */
.toast-enter {
  opacity: 0;
  transform: translateY(-20px);
}
.toast-enter-active {
  opacity: 1;
  transform: translateY(0);
  transition: opacity 300ms, transform 300ms;
}
.toast-exit {
  opacity: 1;
  transform: translateY(0);
}
.toast-exit-active {
  opacity: 0;
  transform: translateY(-20px);
  transition: opacity 300ms, transform 300ms;
}

/* Simple Diff Viewer Styles */
.diff-add {
    background-color: #e6ffed; /* bg-green-50 */
    color: #065f46; /* text-green-800 */
}
.diff-remove {
    background-color: #ffeeee; /* bg-red-50 */
    color: #991b1b; /* text-red-800 */
}
.diff-line {
    white-space: pre-wrap;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 0.875rem;
}
.diff-line-number {
    display: inline-block;
    width: 2.5rem;
    padding-right: 0.5rem;
    text-align: right;
    color: #6b7280; /* text-gray-500 */
    opacity: 0.7;
}
`,

  'frontend/tailwind.config.js': `
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      keyframes: {
        'toast-in': {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'toast-out': {
            '0%': { transform: 'translateY(0)', opacity: '1' },
            '100%': { transform: 'translateY(-100%)', opacity: '0' },
          }
      },
      animation: {
        'toast-in': 'toast-in 0.5s ease-out forwards',
        'toast-out': 'toast-out 0.5s ease-in forwards',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
`,

  'frontend/Dockerfile': `
# Stage 1: Build the React application
FROM node:20-slim AS build

WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the app
RUN npm run build

# Stage 2: Serve the built app with Nginx
FROM nginx:alpine

# Copy the built files from the 'build' stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy our custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
`,

  'frontend/nginx.conf': `
server {
    listen 80;
    server_name localhost;

    # Root directory for static files
    root /usr/share/nginx/html;
    index index.html index.htm;

    # Handle API requests by proxying to the backend service
    location /api/ {
        # The backend service is named 'backend' in docker-compose.yml
        # and it runs on port 5001
        proxy_pass http://backend:5001/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Handle all other requests (for React SPA)
    location / {
        # Try to serve the file directly, then as a directory,
        # then fall back to index.html for React Router to handle
        try_files $uri $uri/ /index.html;
    }
}
`,

  'frontend/srcR/App.jsx': `
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  CheckCircleIcon,
  XCircleIcon,
  PencilIcon,
  TrashIcon,
  PlusIcon,
  EyeIcon,
  CodeBracketIcon,
  ExclamationTriangleIcon,
  ArchiveBoxIcon,
  InformationCircleIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  BookOpenIcon,
  WrenchScrewdriverIcon,
  ArrowPathIcon,
  UserCircleIcon,
  LockClosedIcon,
  ShieldExclamationIcon,
  RectangleStackIcon,
  CogIcon,
  InboxIcon,
  AdjustmentsHorizontalIcon,
  BeakerIcon,
  ClockIcon,
  PaperAirplaneIcon,
  InboxStackIcon
} from '@heroicons/react/24/outline';
import { TagIcon as TagSolidIcon } from '@heroicons/react/24/solid';

// --- API Configuration ---
const API_URL = '/api';

/**
 * Parses a fetch error into a readable string.
 * Handles:
 * - { message: "..." }
 * - { errors: [{ msg: "..." }] }
 * - "Conflict: ..."
 * - Plain text
 * @param {string} errorString - The error message from catch(err)
 * @returns {string} A human-readable error message
 */
const parseApiError = (errorString) => {
  try {
    if (typeof errorString !== 'string') {
        errorString = errorString.message || 'Unknown error';
    }
    if (errorString.toLowerCase().includes('conflict')) return errorString;

    const error = JSON.parse(errorString);
    if (error.message) {
      return error.message;
    }
    if (error.errors && Array.isArray(error.errors) && error.errors.length > 0) {
      return error.errors.map(e => e.msg).join(', ');
    }
    return 'An unknown error occurred.';
  } catch (e) {
    // It was just a plain string (e.g., "Unauthorized: Invalid token")
    return String(errorString);
  }
};


// --- API Helper ---
const api = {
  get: async (path) => {
    const res = await fetch(\`\${API_URL}\${path}\`, {
      headers: { 'Authorization': \`Bearer \${localStorage.getItem('token')}\` }
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  post: async (path, body) => {
    const res = await fetch(\`\${API_URL}\${path}\`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': \`Bearer \${localStorage.getItem('token')}\`
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
        const errBody = await res.text();
        try {
            const errJson = JSON.parse(errBody);
            throw new Error(JSON.stringify(errJson));
        } catch(e) {
            throw new Error(errBody);
        }
    }
    return res.json();
  },
  put: async (path, body) => {
    const res = await fetch(\`\${API_URL}\${path}\`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': \`Bearer \${localStorage.getItem('token')}\`
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
        const errBody = await res.text();
        try {
            const errJson = JSON.parse(errBody);
            throw new Error(JSON.stringify(errJson));
        } catch(e) {
            throw new Error(errBody);
        }
    }
    return res.json();
  },
  delete: async (path) => {
    const res = await fetch(\`\${API_URL}\${path}\`, {
      method: 'DELETE',
      headers: { 'Authorization': \`Bearer \${localStorage.getItem('token')}\` }
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }
};

// --- Helper & UI Components ---

const LoadingSpinner = () => (
  <div className="flex justify-center items-center p-8">
    <ArrowPathIcon className="w-8 h-8 text-blue-600 animate-spin" />
  </div>
);

const Modal = ({ show, onClose, title, children, size = 'lg' }) => {
  if (!show) return null;
  const sizes = {
      lg: 'max-w-lg',
      '3xl': 'max-w-3xl',
      '5xl': 'max-w-5xl'
  }
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-75 flex justify-center items-center z-50 p-4">
      <div className={\`bg-white rounded-lg shadow-xl p-6 w-full \${sizes[size]} max-h-[90vh] flex flex-col\`}>
        <div className="flex justify-between items-center mb-4 flex-shrink-0">
          <h3 className="text-lg font-medium text-gray-900">{title}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XCircleIcon className="w-6 h-6" />
          </button>
        </div>
        <div className="overflow-y-auto">{children}</div>
      </div>
    </div>
  );
};

const Tag = ({ children, color = 'gray' }) => {
  const colors = {
    gray: 'bg-gray-100 text-gray-800',
    green: 'bg-green-100 text-green-800',
    yellow: 'bg-yellow-100 text-yellow-800',
    red: 'bg-red-100 text-red-800',
    blue: 'bg-blue-100 text-blue-800',
  };
  return (
    <span className={'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium \${colors[color]}'}>
      {children}
    </span>
  );
};

// --- Toast Notification System ---
const ToastContext = React.createContext();

const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = 'success') => {
    const id = Math.random().toString(36).substr(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    // Auto-remove after 5 seconds
    setTimeout(() => {
      removeToast(id);
    }, 5000);
  }, []);

  const removeToast = (id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <Toast key={toast.id} message={toast.message} type={toast.type} onClose={() => removeToast(toast.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
};

const useToasts = () => React.useContext(ToastContext);

const Toast = ({ message, type, onClose }) => {
  const [show, setShow] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setShow(false);
      setTimeout(onClose, 500); // Wait for fade-out
    }, 4500);
    return () => clearTimeout(timer);
  }, [onClose]);

  const handleClose = () => {
    setShow(false);
    setTimeout(onClose, 500);
  };

  const colors = {
    success: 'bg-green-500',
    error: 'bg-red-500',
    warning: 'bg-yellow-500',
  };
  const Icon = type === 'success' ? CheckCircleIcon : (type === 'error' ? ExclamationTriangleIcon : InformationCircleIcon);

  return (
    <div
      className={
        \`relative w-full max-w-sm rounded-md shadow-lg p-4 \${colors[type]} text-white
        transition-all duration-500 \${show ? 'animate-toast-in' : 'animate-toast-out'}\`
      }
    >
      <div className="flex items-center">
        <Icon className="w-6 h-6 mr-3" />
        <p className="text-sm font-medium">{message}</p>
        <button onClick={handleClose} className="ml-auto p-1 text-white opacity-80 hover:opacity-100">
          <XCircleIcon className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
};

// --- Auth Component ---
const LoginView = ({ onLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoginView, setIsLoginView] = useState(true);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToasts();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    
    const url = isLoginView ? '/auth/login' : '/auth/register';
    try {
      const data = await api.post(url, { email, password });
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      addToast(isLoginView ? 'Login successful' : 'Registration successful', 'success');
      onLogin(data.token, data.user);
    } catch (err) {
      const msg = parseApiError(err.message);
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center">
      <div className="max-w-md w-full bg-white shadow-lg rounded-lg p-8">
        <div className="flex justify-center mb-6">
          <WrenchScrewdriverIcon className="w-12 h-12 text-blue-600" />
        </div>
        <h2 className="text-2xl font-bold text-center text-gray-900 mb-4">
          {isLoginView ? 'Sign in to your account' : 'Create an account'}
        </h2>
        <p className="text-center text-sm text-gray-600 mb-6">
          {isLoginView ? 'Welcome back!' : 'First user to register becomes Admin.'}
        </p>
        <form className="space-y-6" onSubmit={handleSubmit}>
          <div>
            <label className="block text-sm font-medium text-gray-700">Email address</label>
            <div className="mt-1">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Password</label>
            <div className="mt-1">
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
              />
            </div>
          </div>
          
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm">
              {error}
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? (isLoginView ? 'Signing in...' : 'Registering...') : (isLoginView ? 'Sign in' : 'Register')}
            </button>
          </div>
        </form>
        <p className="mt-6 text-center text-sm text-gray-600">
          {isLoginView ? "Don't have an account?" : "Already have an account?"}
          <button
            onClick={() => { setIsLoginView(!isLoginView); setError(null); }}
            className="font-medium text-blue-600 hover:text-blue-500 ml-1"
          >
            {isLoginView ? 'Register here' : 'Sign in'}
          </button>
        </p>
      </div>
    </div>
  );
}

// --- Main App Components ---

const Header = ({ user, onLogout, onNavigate, page }) => {
  const [reviewCount, setReviewCount] = useState(0);
  const { addToast } = useToasts();
  
  const isActive = (p) => {
    if (p === 'dashboard') return ['dashboard', 'flagDetail', 'newFlag'].includes(page);
    if (p === 'segments') return ['segments', 'segmentDetail', 'newSegment'].includes(page);
    if (p === 'reviewQueue') return ['reviewQueue'].includes(page);
    return false;
  }
  
  useEffect(() => {
    // Fetch review count for the badge
    api.get('/changes')
      .then(data => setReviewCount(data.length))
      .catch(err => addToast(parseApiError(err.message), 'error'));
  }, [page, addToast]); // Refetch when page changes (e.g., after approving)

  return (
    <header className="bg-white shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <WrenchScrewdriverIcon className="w-8 h-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">Feature Flag</h1>
            </div>
            <nav className="flex space-x-4">
              <button 
                onClick={() => onNavigate('dashboard')} 
                className={\`px-3 py-2 rounded-md text-sm font-medium \${isActive('dashboard') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-100'}\`}
              >
                <RectangleStackIcon className="w-5 h-5 inline-block mr-1 -mt-1" />
                Flags
              </button>
              <button 
                onClick={() => onNavigate('segments')} 
                className={\`px-3 py-2 rounded-md text-sm font-medium \${isActive('segments') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-100'}\`}
              >
                <AdjustmentsHorizontalIcon className="w-5 h-5 inline-block mr-1 -mt-1" />
                Segments
              </button>
              <button 
                onClick={() => onNavigate('reviewQueue')} 
                className={\`relative px-3 py-2 rounded-md text-sm font-medium \${isActive('reviewQueue') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-100'}\`}
              >
                <InboxStackIcon className="w-5 h-5 inline-block mr-1 -mt-1" />
                Review Queue
                {reviewCount > 0 && (
                    <span className="absolute -top-2 -right-2 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-xs font-bold text-white">
                        {reviewCount}
                    </span>
                )}
              </button>
            </nav>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-600">
              <span className="font-medium">{user.email}</span> ({user.role})
            </span>
            <button onClick={onLogout} className="text-sm text-gray-600 hover:text-gray-900">Log out</button>
          </div>
        </div>
      </div>
    </header>
  );
};

const Dashboard = ({ user, onSelectFlag, onNewFlag }) => {
  const [flags, setFlags] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({ active: 0, draft: 0, archived: 0, total: 0, review: 0 });
  const { addToast } = useToasts();

  const isViewer = user.role === 'Viewer';

  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [flagsData, changesData] = await Promise.all([
        api.get('/flags'),
        api.get('/changes')
      ]);
      setFlags(flagsData);
      
      const newStats = { active: 0, draft: 0, archived: 0, total: flagsData.length, review: changesData.length };
      for (const flag of flagsData) {
        if (newStats[flag.lifecycle] !== undefined) {
          newStats[flag.lifecycle]++;
        }
      }
      setStats(newStats);

    } catch (err) {
      const msg = \`Failed to fetch dashboard data: \${parseApiError(err.message)}\`;
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const myFlags = useMemo(() => {
    return flags.filter(f => f.owner === user.email);
  }, [flags, user.email]);

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Flags Dashboard</h2>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-white shadow rounded-lg p-4">
          <p className="text-sm font-medium text-gray-500">Total Flags</p>
          <p className="text-3xl font-bold text-gray-900">{stats.total}</p>
        </div>
        <div className="bg-white shadow rounded-lg p-4">
          <p className="text-sm font-medium text-gray-500">Active</p>
          <p className="text-3xl font-bold text-green-600">{stats.active}</p>
        </div>
        <div className="bg-white shadow rounded-lg p-4">
          <p className="text-sm font-medium text-gray-500">Draft</p>
          <p className="text-3xl font-bold text-yellow-600">{stats.draft}</p>
        </div>
        <div className="bg-white shadow rounded-lg p-4">
          <p className="text-sm font-medium text-gray-500">Archived</p>
          <p className="text-3xl font-bold text-red-600">{stats.archived}</p>
        </div>
        <div className="bg-white shadow rounded-lg p-4 border-2 border-blue-500">
          <p className="text-sm font-medium text-blue-600">In Review</p>
          <p className="text-3xl font-bold text-blue-600">{stats.review}</p>
        </div>
      </div>
      
      {/* My Flags Section */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">My Flags ({myFlags.length})</h2>
        {loading && <LoadingSpinner />}
        {!loading && myFlags.length === 0 && (
            <p className="text-center text-gray-500 py-4">You do not own any flags.</p>
        )}
        {!loading && myFlags.length > 0 && (
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    {/* ... FlagList table head ... */}
                    <tbody className="bg-white divide-y divide-gray-200">
                        {myFlags.map(flag => (
                            <FlagListRow key={flag.key} flag={flag} onSelectFlag={onSelectFlag} isViewer={isViewer} />
                        ))}
                    </tbody>
                </table>
            </div>
        )}
      </div>

      <FlagList
        flags={flags}
        loading={loading}
        error={error}
        onSelectFlag={onSelectFlag}
        onNewFlag={onNewFlag}
        isViewer={isViewer}
      />
    </div>
  );
};

const FlagListRow = ({ flag, onSelectFlag, isViewer }) => {
  const getLifecycleColor = (lifecycle) => {
    if (lifecycle === 'active') return 'green';
    if (lifecycle === 'draft') return 'yellow';
    if (lifecycle === 'archived') return 'red';
    return 'gray';
  };
  
  return (
    <tr key={flag.key} className="hover:bg-gray-50">
      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-600">{flag.key}</td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 max-w-xs truncate">{flag.description}</td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{flag.flagType}</td>
      <td className="px-6 py-4 whitespace-nowrap">
        <Tag color={getLifecycleColor(flag.lifecycle)}>{flag.lifecycle}</Tag>
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 space-x-1">
        {flag.tags?.map(tag => <Tag key={tag}>{tag}</Tag>)}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
        <button
          onClick={() => onSelectFlag(flag.key)}
          className="text-blue-600 hover:text-blue-900"
        >
          {isViewer ? <EyeIcon className="w-5 h-5" /> : <PencilIcon className="w-5 h-5" />}
        </button>
      </td>
    </tr>
  );
}

const FlagList = ({ onSelectFlag, onNewFlag, flags, error, loading, isViewer }) => {
  const [filter, setFilter] = useState('');

  const filteredFlags = useMemo(() => {
    if (!flags) return [];
    return flags.filter(flag =>
      flag.key.toLowerCase().includes(filter.toLowerCase()) ||
      (flag.description && flag.description.toLowerCase().includes(filter.toLowerCase()))
    );
  }, [flags, filter]);

  return (
    <div className="bg-white shadow rounded-lg p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">All Flags ({flags.length})</h2>
        <div className="flex space-x-4">
          <input
            type="text"
            placeholder="Search by key or description..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          />
          {!isViewer && (
            <button
              onClick={onNewFlag}
              className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-blue-700"
            >
              <PlusIcon className="w-5 h-5 mr-2" />
              New Flag
            </button>
          )}
        </div>
      </div>

      {loading && <LoadingSpinner />}
      {error && !loading && <div className="text-red-600 text-center py-4">{error}</div>}
      {!loading && !error && (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tags</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredFlags.length === 0 && (
                  <tr>
                    <td colSpan="6" className="text-center text-gray-500 py-8">
                      <InboxIcon className="w-12 h-12 mx-auto text-gray-400" />
                      No flags found.
                    </td>
                  </tr>
              )}
              {filteredFlags.map(flag => (
                <FlagListRow key={flag.key} flag={flag} onSelectFlag={onSelectFlag} isViewer={isViewer} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const createEmptyFlag = () => {
  const emptyEnv = {
    active: false,
    defaultVariationValue: false,
    offVariationValue: false,
    rules: []
  };
  return {
    key: '',
    description: '',
    owner: JSON.parse(localStorage.getItem('user'))?.email || '',
    tags: [],
    flagType: 'boolean',
    variations: [
      { value: true, name: 'On', description: 'Enabled' },
      { value: false, name: 'Off', description: 'Disabled' }
    ],
    lifecycle: 'draft',
    version: 0, // Will be set to 1 on create
    environments: {
      dev: { ...emptyEnv, offVariationValue: false, defaultVariationValue: false },
      stage: { ...emptyEnv, offVariationValue: false, defaultVariationValue: false },
      prod: { ...emptyEnv, offVariationValue: false, defaultVariationValue: false }
    }
  };
};

const createEmptyRule = () => ({
  type: 'percentage',
  variationValue: false,
  rollout: 50,
  attributes: {},
  segmentKey: '',
});

const FlagDetail = ({ flagKey, onBack, onSave, isNew, user }) => {
  const [flag, setFlag] = useState(null);
  const [originalFlag, setOriginalFlag] = useState(null); // For conflict detection
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currentTab, setCurrentTab] = useState('prod');
  const [auditLogs, setAuditLogs] = useState([]);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showSimulator, setShowSimulator] = useState(false);
  const [showDiffModal, setShowDiffModal] = useState(false);
  const [diffData, setDiffData] = useState({ before: {}, after: {} });
  
  const { addToast } = useToasts();
  
  const isViewer = user.role === 'Viewer';
  const isAdmin = user.role === 'Admin';
  
  // --- Form Handlers ---
  const handleFlagChange = (field, value) => setFlag(prev => ({ ...prev, [field]: value }));
  const handleEnvChange = (env, field, value) => {
    setFlag(prev => ({
      ...prev,
      environments: { ...prev.environments, [env]: { ...prev.environments[env], [field]: value }}
    }));
  };
  const handleRuleChange = (env, ruleIndex, field, value) => {
    const newRules = [...flag.environments[env].rules];
    newRules[ruleIndex] = { ...newRules[ruleIndex], [field]: value };
    if (field === 'type') {
      newRules[ruleIndex] = {
        ...createEmptyRule(),
        type: value,
        variationValue: flag.environments[env].offVariationValue
      };
    }
    handleEnvChange(env, 'rules', newRules);
  };
  const handleAddRule = (env) => {
    const newRule = { ...createEmptyRule(), variationValue: flag.environments[env].offVariationValue };
    handleEnvChange(env, 'rules', [...flag.environments[env].rules, newRule]);
  };
  const handleRemoveRule = (env, ruleIndex) => {
    const newRules = [...flag.environments[env].rules];
    newRules.splice(ruleIndex, 1);
    handleEnvChange(env, 'rules', newRules);
  };
  const handleFlagTypeChange = (e) => {
    const newType = e.target.value;
    handleFlagChange('flagType', newType);
    if (newType === 'boolean') {
      handleFlagChange('variations', [
        { value: true, name: 'On', description: 'Enabled' },
        { value: false, name: 'Off', description: 'Disabled' }
      ]);
      ['dev', 'stage', 'prod'].forEach(env => {
        handleEnvChange(env, 'offVariationValue', false);
        handleEnvChange(env, 'defaultVariationValue', false);
      });
    } else {
      handleFlagChange('variations', [
        { value: 'A', name: 'Variation A', description: '' },
        { value: 'B', name: 'Variation B', description: '' }
      ]);
      ['dev', 'stage', 'prod'].forEach(env => {
        handleEnvChange(env, 'offVariationValue', 'A');
        handleEnvChange(env, 'defaultVariationValue', 'A');
      });
    }
  };
  const handleVariationChange = (index, field, value) => {
    const newVariations = [...flag.variations];
    newVariations[index] = { ...newVariations[index], [field]: value };
    handleFlagChange('variations', newVariations);
  };
  const handleAddVariation = () => {
    handleFlagChange('variations', [...flag.variations, { value: 'New', name: 'New Variation', description: '' }]);
  };
  const handleRemoveVariation = (index) => {
    handleFlagChange('variations', flag.variations.filter((_, i) => i !== index));
  };
  const handleTagsChange = (newTags) => handleFlagChange('tags', newTags);

  // --- Data Fetching ---
  const fetchFlagData = useCallback(() => {
    if (isNew) {
      setFlag(createEmptyFlag());
      setOriginalFlag(createEmptyFlag());
    } else if (flagKey) {
      setLoading(true);
      setError(null);
      const p1 = api.get(\`/flags/\${flagKey}\`);
      const p2 = api.get(\`/audit/flag/\${flagKey}\`);
      Promise.all([p1, p2])
        .then(([flagData, auditData]) => {
          setFlag(flagData);
          setOriginalFlag(flagData); // Store the pristine version for conflict checking
          setAuditLogs(auditData);
        })
        .catch(err => {
            const msg = \`Failed to fetch flag data: \${parseApiError(err.message)}\`;
            setError(msg);
            addToast(msg, 'error');
        })
        .finally(() => setLoading(false));
    }
  }, [flagKey, isNew, addToast]);

  useEffect(() => {
    fetchFlagData();
  }, [fetchFlagData]);

  // --- API Actions ---
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isViewer) return; 
    setLoading(true);
    setError(null);
    try {
      // Send the current flag state, which includes the version from originalFlag
      const payload = { ...flag, version: originalFlag.version };

      const res = isNew
        ? await api.post('/flags', { ...payload, version: 1 })
        : await api.put(\`/flags/\${flag.key}\`, payload);
      
      if (res.pendingChangeCreated) {
        addToast(\`Flag '\${res.flag.key}' saved. Prod change sent for review.\`, 'success');
      } else {
        addToast(\`Flag '\${res.flag.key}' saved successfully\`, 'success');
      }
      onSave(res.flag); // onSave expects the flag object
    } catch (err) {
      const msg = parseApiError(err.message);
      setError(msg);
      addToast(msg, 'error');
      if (msg.toLowerCase().includes('conflict')) {
        addToast('Data was out of date. Reloading...', 'warning');
        fetchFlagData(); // Reload data
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!isAdmin) return;
    setError(null);
    try {
      await api.delete(\`/flags/\${flag.key}\`);
      addToast('Flag archived successfully', 'success');
      setShowDeleteModal(false);
      onSave();
    } catch (err) {
      const msg = \`Failed to archive: \${parseApiError(err.message)}\`;
      setError(msg);
      addToast(msg, 'error');
    }
  };
  
  const handleShowDiff = (before, after) => {
    setDiffData({ before, after });
    setShowDiffModal(true);
  };

  // --- Render ---
  if (loading && !flag) return <LoadingSpinner />;
  if (error && !flag) return <div className="text-red-600 p-4">{error}</div>;
  if (!flag) return null;

  const envTabs = [
    { name: 'prod', label: 'Production', icon: ShieldExclamationIcon },
    { name: 'stage', label: 'Staging', icon: BeakerIcon },
    { name: 'dev', label: 'Development', icon: CodeBracketIcon },
    { name: 'settings', label: 'Settings', icon: CogIcon },
    { name: 'audit', label: 'Audit Log', icon: BookOpenIcon },
  ];
  const possibleValues = flag.variations.map(v => v.value);

  return (
    <form onSubmit={handleSubmit}>
      <div className="flex justify-between items-center mb-4">
        <div>
          <button type="button" onClick={onBack} className="flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2">
            <ChevronLeftIcon className="w-5 h-5 mr-1" />
            Back to dashboard
          </button>
          {isNew ? (
            <h2 className="text-2xl font-bold">Create New Flag</h2>
          ) : (
            <div className="flex items-center space-x-4">
              <h2 className="text-2xl font-bold">{flag.key}</h2>
              <Tag color={flag.lifecycle === 'active' ? 'green' : (flag.lifecycle === 'draft' ? 'yellow' : 'red')}>
                {flag.lifecycle}
              </Tag>
              <Tag color="blue">v{flag.version}</Tag>
            </div>
          )}
        </div>
        <div className="flex space-x-3">
          <button
            type="button"
            onClick={() => setShowSimulator(true)}
            className="flex items-center bg-white text-gray-700 px-4 py-2 rounded-md shadow-sm border border-gray-300 hover:bg-gray-50"
          >
            <EyeIcon className="w-5 h-5 mr-2" />
            Simulate
          </button>
          {!isViewer && (
            <button
              type="submit"
              disabled={loading}
              className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          )}
        </div>
      </div>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
          <ExclamationTriangleIcon className="w-5 h-5 inline-block -mt-1 mr-2" />
          <span className="block sm:inline">{error}</span>
        </div>
      )}

      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8" aria-label="Tabs">
          {envTabs.map((tab) => (
            <button
              key={tab.name}
              type="button"
              onClick={() => setCurrentTab(tab.name)}
              className={
                \`flex items-center \${
                currentTab === tab.name
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm\`
              }
            >
              <tab.icon className="w-5 h-5 mr-2" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="space-y-6">
        {['dev', 'stage', 'prod'].includes(currentTab) && (
          <EnvironmentEditor
            env={currentTab}
            config={flag.environments[currentTab]}
            possibleValues={possibleValues}
            onEnvChange={handleEnvChange}
            onRuleChange={handleRuleChange}
            onAddRule={handleAddRule}
            onRemoveRule={handleRemoveRule}
            disabled={isViewer}
          />
        )}
        {currentTab === 'settings' && (
          <FlagSettings
            flag={flag}
            isNew={isNew}
            onFlagChange={handleFlagChange}
            onFlagTypeChange={handleFlagTypeChange}
            onVariationChange={handleVariationChange}
            onAddVariation={handleAddVariation}
            onRemoveVariation={handleRemoveVariation}
            onTagsChange={handleTagsChange}
            onArchive={() => setShowDeleteModal(true)}
            disabled={isViewer}
            isAdmin={isAdmin}
          />
        )}
        {currentTab === 'audit' && (
          <AuditLogViewer logs={auditLogs} onShowDiff={handleShowDiff} />
        )}
      </div>

      <Modal show={showDeleteModal} onClose={() => setShowDeleteModal(false)} title="Archive Flag">
        <p>Are you sure you want to archive the flag "<strong>{flag.key}</strong>"? This will turn it off in all environments.</p>
        <div className="flex justify-end space-x-4 mt-6">
          <button type="button" onClick={() => setShowDeleteModal(false)} className="bg-white text-gray-700 px-4 py-2 rounded-md shadow-sm border border-gray-300 hover:bg-gray-50">Cancel</button>
          <button type="button" onClick={handleDelete} className="bg-red-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-red-700">Archive Flag</button>
        </div>
      </Modal>

      <EvaluationSimulator
        show={showSimulator}
        onClose={() => setShowSimulator(false)}
        flagKey={flag.key}
      />
      
      <Modal show={showDiffModal} onClose={() => setShowDiffModal(false)} title="View Changes" size="5xl">
          <DiffViewer before={diffData.before} after={diffData.after} />
      </Modal>
    </form>
  );
};

const EnvironmentEditor = ({ env, config, possibleValues, onEnvChange, onRuleChange, onAddRule, onRemoveRule, disabled }) => {
  return (
    <div className="bg-white shadow rounded-lg p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium text-gray-900 capitalize">{env} Environment</h3>
        <div className="flex items-center space-x-3">
          <span className="text-sm font-medium text-gray-700">Active</span>
          <button
            type="button"
            disabled={disabled}
            onClick={() => onEnvChange(env, 'active', !config.active)}
            className={
              \`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out
              \${config.active ? 'bg-blue-600' : 'bg-gray-200'} \${disabled ? 'opacity-50 cursor-not-allowed' : 'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'}\`
            }
          >
            <span
              className={
                \`\${config.active ? 'translate-x-5' : 'translate-x-0'} 
                inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out\`
              }
            />
          </button>
        </div>
      </div>

      <div className="border-t border-gray-200 pt-6">
        <h4 className="text-md font-medium text-gray-800 mb-4">Targeting Rules</h4>
        <div className="space-y-4">
          {config.rules.map((rule, index) => (
            <RuleEditor
              key={index}
              rule={rule}
              index={index}
              env={env}
              possibleValues={possibleValues}
              onRuleChange={onRuleChange}
              onRemoveRule={onRemoveRule}
              disabled={disabled}
            />
          ))}
          {!disabled && (
            <button
              type="button"
              onClick={() => onAddRule(env)}
              className="flex items-center text-sm text-blue-600 hover:text-blue-800"
            >
              <PlusIcon className="w-5 h-5 mr-1" />
              Add Rule
            </button>
          )}
        </div>
      </div>

      <div className="border-t border-gray-200 pt-6 space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Default Variation (if no rules match)</label>
          <SelectVariation
            value={config.defaultVariationValue}
            onChange={(val) => onEnvChange(env, 'defaultVariationValue', val)}
            possibleValues={possibleValues}
            disabled={disabled}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Off Variation (when flag is inactive)</label>
          <SelectVariation
            value={config.offVariationValue}
            onChange={(val) => onEnvChange(env, 'offVariationValue', val)}
            possibleValues={possibleValues}
            disabled={disabled}
          />
        </div>
      </div>
    </div>
  );
};

const RuleEditor = ({ rule, index, env, possibleValues, onRuleChange, onRemoveRule, disabled }) => {
  const [attrKey, setAttrKey] = useState('');
  const [attrVal, setAttrVal] = useState('');
  const [segments, setSegments] = useState([]);
  const { addToast } = useToasts();

  useEffect(() => {
    if (rule.type === 'segment') {
      api.get('/segments')
        .then(data => setSegments(data))
        .catch(err => addToast(parseApiError(err.message), 'error'));
    }
  }, [rule.type, addToast]);

  const handleAddAttribute = () => {
    if (attrKey && attrVal) {
      onRuleChange(env, index, 'attributes', { ...rule.attributes, [attrKey]: attrVal });
      setAttrKey('');
      setAttrVal('');
    }
  };
  const handleRemoveAttribute = (key) => {
    const newAttributes = { ...rule.attributes };
    delete newAttributes[key];
    onRuleChange(env, index, 'attributes', newAttributes);
  };

  return (
    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-4">
      <div className="flex justify-between items-center">
        <h5 className="font-medium text-gray-800">Rule {index + 1}</h5>
        {!disabled && (
          <button type="button" onClick={() => onRemoveRule(env, index)} className="text-gray-400 hover:text-red-600">
            <TrashIcon className="w-5 h-5" />
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Type</label>
          <select
            value={rule.type}
            onChange={(e) => onRuleChange(env, index, 'type', e.target.value)}
            disabled={disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
          >
            <option value="percentage">Percentage Rollout</option>
            <option value="attribute">Attribute</option>
            <option value="segment">Segment</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Serve Variation</label>
          <SelectVariation
            value={rule.variationValue}
            onChange={(val) => onRuleChange(env, index, 'variationValue', val)}
            possibleValues={possibleValues}
            disabled={disabled}
          />
        </div>

        {rule.type === 'percentage' && (
          <div>
            <label className="block text-sm font-medium text-gray-700">Rollout %</label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <input
                type="number"
                min="0"
                max="100"
                value={rule.rollout}
                onChange={(e) => onRuleChange(env, index, 'rollout', parseInt(e.target.value) || 0)}
                disabled={disabled}
                className="flex-1 min-w-0 block w-full rounded-none rounded-l-md border-gray-300 sm:text-sm disabled:bg-gray-100"
              />
              <span className="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">%</span>
            </div>
          </div>
        )}
      </div>

      {rule.type === 'attribute' && (
        <div className="border-t border-gray-200 pt-4 space-y-3">
          <h6 className="text-sm font-medium text-gray-700">Match Attributes</h6>
          {Object.entries(rule.attributes || {}).map(([key, val]) => (
            <div key={key} className="flex items-center space-x-2">
              <span className="text-sm font-mono bg-gray-200 px-2 py-1 rounded">{key}</span>
              <span className="text-sm">=</span>
              <span className="text-sm font-mono bg-gray-200 px-2 py-1 rounded">{String(val)}</span>
              {!disabled && (
                <button type="button" onClick={() => handleRemoveAttribute(key)} className="text-gray-400 hover:text-red-600">
                  <XCircleIcon className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
          {!disabled && (
            <div className="flex space-x-2">
              <input type="text" placeholder="Attribute Key" value={attrKey} onChange={e => setAttrKey(e.target.value)} className="rounded-md border-gray-300 shadow-sm sm:text-sm" />
              <input type="text" placeholder="Attribute Value" value={attrVal} onChange={e => setAttrVal(e.target.value)} className="rounded-md border-gray-300 shadow-sm sm:text-sm" />
              <button type="button" onClick={handleAddAttribute} className="bg-blue-100 text-blue-700 px-3 py-1 rounded-md text-sm hover:bg-blue-200">Add</button>
            </div>
          )}
        </div>
      )}
      
      {rule.type === 'segment' && (
        <div className="border-t border-gray-200 pt-4">
          <label className="block text-sm font-medium text-gray-700">Select Segment</label>
          <select
            value={rule.segmentKey}
            onChange={(e) => onRuleChange(env, index, 'segmentKey', e.target.value)}
            disabled={disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
          >
            <option value="">-- Select a Segment --</option>
            {segments.map(s => (
              <option key={s.key} value={s.key}>{s.name} ({s.key})</option>
            ))}
          </select>
        </div>
      )}
    </div>
  );
};

const SelectVariation = ({ value, onChange, possibleValues, disabled }) => {
  const handleChange = (e) => {
    const val = e.target.value;
    let originalVal = possibleValues.find(v => String(v) === val);
    if (originalVal === undefined) {
      if (val === 'true') originalVal = true;
      if (val === 'false') originalVal = false;
    }
    onChange(originalVal);
  };
  const displayValue = (value === true) ? 'true' : (value === false) ? 'false' : String(value);

  return (
    <select
      value={displayValue}
      onChange={handleChange}
      disabled={disabled}
      className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
    >
      {possibleValues.map(val => (
        <option key={String(val)} value={String(val)}>{String(val)}</option>
      ))}
    </select>
  );
};

const TagInput = ({ tags, onChange, disabled }) => {
  const [input, setInput] = useState('');

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const newTag = input.trim();
      if (newTag && !tags.includes(newTag)) {
        onChange([...tags, newTag]);
      }
      setInput('');
    }
  };

  const removeTag = (tagToRemove) => {
    onChange(tags.filter(tag => tag !== tagToRemove));
  };

  return (
    <div>
        <div className={\`flex flex-wrap gap-2 p-2 border border-gray-300 rounded-md \${disabled ? 'bg-gray-100' : 'bg-white'}\`}>
            {tags.map(tag => (
            <span key={tag} className="flex items-center bg-blue-100 text-blue-800 text-sm font-medium px-2.5 py-0.5 rounded-full">
                {tag}
                {!disabled && (
                <button
                    type="button"
                    onClick={() => removeTag(tag)}
                    className="ml-1.5 -mr-0.5 text-blue-600 hover:text-blue-800"
                >
                    <XCircleIcon className="w-4 h-4" />
                </button>
                )}
            </span>
            ))}
            {!disabled && (
            <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={disabled}
                placeholder="Add a tag..."
                className="flex-1 border-none focus:ring-0 p-0 sm:text-sm"
            />
            )}
        </div>
        <p className="mt-2 text-xs text-gray-500">Press Enter or Comma to add a tag.</p>
    </div>
  );
};

const FlagSettings = ({ flag, isNew, onFlagChange, onFlagTypeChange, onVariationChange, onAddVariation, onRemoveVariation, onTagsChange, onArchive, disabled, isAdmin }) => (
  <div className="bg-white shadow rounded-lg p-6 space-y-6">
    <div>
      <h3 className="text-lg font-medium text-gray-900">General Settings</h3>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700">Flag Key</label>
          <input
            type="text"
            value={flag.key}
            onChange={(e) => onFlagChange('key', e.target.value)}
            disabled={!isNew || disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
            placeholder="e.g., new-checkout-flow"
          />
          {isNew && <p className="mt-2 text-xs text-gray-500">The key cannot be changed after creation.</p>}
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Flag Type</label>
          <select
            value={flag.flagType}
            onChange={onFlagTypeChange}
            disabled={!isNew || disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
          >
            <option value="boolean">Boolean (On/Off)</option>
            <option value="multivariate">Multivariate (String, Number)</option>
          </select>
        </div>
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-700">Description</label>
          <textarea
            value={flag.description}
            onChange={(e) => onFlagChange('description', e.target.value)}
            disabled={disabled}
            rows="3"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
          ></textarea>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Owner</label>
          <input
            type="text"
            value={flag.owner}
            onChange={(e) => onFlagChange('owner', e.target.value)}
            disabled={disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
            placeholder="e.g., team-alpha@example.com"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Lifecycle Status</label>
          <select
            value={flag.lifecycle}
            onChange={(e) => onFlagChange('lifecycle', e.target.value)}
            disabled={disabled}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
          >
            <option value="draft">Draft</option>
            <option value="active">Active</option>
            {isAdmin && <option value="archived">Archived</option>}
          </select>
        </div>
        <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-700">Tags</label>
            <TagInput tags={flag.tags || []} onChange={onTagsChange} disabled={disabled} />
        </div>
      </div>
    </div>

    <div className="border-t border-gray-200 pt-6">
      <h3 className="text-lg font-medium text-gray-900">Variations</h3>
      <div className="mt-4 space-y-4">
        {flag.variations.map((v, index) => (
          <div key={index} className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 border border-gray-200 rounded-md">
            <input
              type="text"
              placeholder="Value (e.g., true, 'red', 10)"
              value={v.value}
              onChange={(e) => onVariationChange(index, 'value', e.target.value)}
              disabled={flag.flagType === 'boolean' || disabled}
              className="rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
            />
            <input
              type="text"
              placeholder="Name (e.g., On, Off)"
              value={v.name}
              onChange={(e) => onVariationChange(index, 'name', e.target.value)}
              disabled={disabled}
              className="rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
            />
            <div className="flex items-center space-x-2">
              <input
                type="text"
                placeholder="Description"
                value={v.description}
                onChange={(e) => onVariationChange(index, 'description', e.target.value)}
                disabled={disabled}
                className="flex-1 rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
              />
              {flag.flagType === 'multivariate' && !disabled && (
                <button type="button" onClick={() => onRemoveVariation(index)} className="text-gray-400 hover:text-red-600">
                  <TrashIcon className="w-5 h-5" />
                </button>
              )}
            </div>
          </div>
        ))}
        {flag.flagType === 'multivariate' && !disabled && (
          <button
            type="button"
            onClick={onAddVariation}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800"
          >
            <PlusIcon className="w-5 h-5 mr-1" />
            Add Variation
          </button>
        )}
      </div>
    </div>

    {!isNew && isAdmin && (
      <div className="border-t border-gray-200 pt-6">
        <h3 className="text-lg font-medium text-red-600">Danger Zone</h3>
        <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-4 flex justify-between items-center">
          <div>
            <h4 className="font-medium text-red-800">Archive this flag</h4>
            <p className="text-sm text-red-700">Archiving a flag will permanently disable it in all environments.</p>
          </div>
          <button
            type="button"
            onClick={onArchive}
            className="bg-red-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-red-700"
          >
            <ArchiveBoxIcon className="w-5 h-5 mr-2 inline" />
            Archive
          </button>
        </div>
      </div>
    )}
  </div>
);

// --- NEW COMPONENT ---
const DiffViewer = ({ before, after }) => {
  // Simple diff function
  const createDiff = (beforeObj, afterObj) => {
    const beforeLines = JSON.stringify(beforeObj, null, 2).split('\\n');
    const afterLines = JSON.stringify(afterObj, null, 2).split('\\n');

    // This is a basic line-by-line diff, not a full LCS diff,
    // but it's good enough for this UI without new libraries.
    const diff = [];
    const maxLines = Math.max(beforeLines.length, afterLines.length);

    for (let i = 0; i < maxLines; i++) {
      const lineBefore = beforeLines[i];
      const lineAfter = afterLines[i];

      if (lineBefore === lineAfter) {
        diff.push({ type: 'equal', line: lineAfter, num: i + 1 });
      } else {
        if (lineBefore !== undefined) {
          diff.push({ type: 'remove', line: lineBefore, num: i + 1 });
        }
        if (lineAfter !== undefined) {
          diff.push({ type: 'add', line: lineAfter, num: i + 1 });
        }
      }
    }
    return diff;
  };
  
  const diffLines = createDiff(before, after);

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="grid grid-cols-2 bg-gray-50 border-b border-gray-200">
            <h4 className="p-3 text-sm font-medium text-gray-700">Before</h4>
            <h4 className="p-3 text-sm font-medium text-gray-700 border-l border-gray-200">After</h4>
        </div>
        <div className="font-mono text-sm">
            {/* This is a simplified diff render. A real one would align lines. */}
            {diffLines.map((line, index) => (
                <div 
                    key={index} 
                    className={
                        \`
                        \${line.type === 'add' ? 'diff-add' : (line.type === 'remove' ? 'diff-remove' : '')}
                        \${line.type === 'remove' ? 'col-span-1' : 'col-start-2 col-span-1'}
                    \`}
                >
                    {line.type === 'remove' ? (
                        <div className="diff-line">
                            <span className="diff-line-number">{line.num}</span>
                            <span>- </span>
                            {line.line}
                        </div>
                    ) : line.type === 'add' ? (
                        <div className="diff-line border-l border-gray-200">
                            <span className="diff-line-number">{line.num}</span>
                            <span>+ </span>
                            {line.line}
                        </div>
                    ) : (
                        <div className="grid grid-cols-2">
                            <div className="diff-line">
                                <span className="diff-line-number">{line.num}</span>
                                {line.line}
                            </div>
                            <div className="diff-line border-l border-gray-200">
                                <span className="diff-line-number">{line.num}</span>
                                {line.line}
                            </div>
                        </div>
                    )}
                </div>
            ))}
        </div>
    </div>
  );
};


const AuditLogViewer = ({ logs, onShowDiff }) => (
  <div className="bg-white shadow rounded-lg p-6">
    <h3 className="text-lg font-medium text-gray-900 mb-4">Audit Log</h3>
    <div className="flow-root">
      <ul className="-mb-8">
        {logs.length === 0 && <p className="text-gray-500">No audit history for this flag.</p>}
        {logs.map((log, index) => (
          <li key={log._id}>
            <div className="relative pb-8">
              {index !== logs.length - 1 && (
                <span className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true" />
              )}
              <div className="relative flex space-x-3">
                <div>
                  <span className="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center ring-8 ring-white">
                    <UserCircleIcon className="h-5 w-5 text-gray-500" />
                  </span>
                </div>
                <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                  <div>
                    <p className="text-sm text-gray-500">
                      <span className="font-medium text-gray-900">{log.user}</span>
                      {' '}performed action{' '}
                      <span className="font-medium text-gray-900">{log.action}</span>
                    </p>
                    {log.diff && (
                        <button
                            onClick={() => onShowDiff(log.diff.before, log.diff.after)}
                            className="text-sm text-blue-600 hover:underline"
                        >
                            View Diff
                        </button>
                    )}
                  </div>
                  <div className="text-right text-sm whitespace-nowrap text-gray-500">
                    <time dateTime={log.createdAt}>{new Date(log.createdAt).toLocaleString()}</time>
                  </div>
                </div>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  </div>
);

const EvaluationSimulator = ({ show, onClose, flagKey }) => {
  const [env, setEnv] = useState('prod');
  const [userId, setUserId] = useState('user-123');
  const [attributes, setAttributes] = useState('{\n  "role": "guest",\n  "region": "us-east"\n}');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const { addToast } = useToasts();

  const handleEvaluate = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    let userContext;
    try {
      userContext = JSON.parse(attributes);
    } catch (e) {
      setError('Invalid JSON in attributes');
      setLoading(false);
      return;
    }

    const context = {
      env,
      user: {
        id: userId,
        ...userContext
      }
    };

    try {
      const res = await api.post(\`/eval/\${flagKey}\`, { context });
      setResult(res);
      addToast('Evaluation successful', 'success');
    } catch (e) {
      const msg = parseApiError(e.message);
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal show={show} onClose={onClose} title="Evaluate Flag">
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Flag Key</label>
          <input type="text" value={flagKey} disabled className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm bg-gray-100" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Environment</label>
            <select value={env} onChange={e => setEnv(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm">
              <option value="prod">Production</option>
              <option value="stage">Staging</option>
              <option value="dev">Development</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">User ID</label>
            <input type="text" value={userId} onChange={e => setUserId(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">User Attributes (JSON)</label>
          <textarea
            rows="4"
            value={attributes}
            onChange={e => setAttributes(e.target.value)}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm font-mono"
          ></textarea>
        </div>
        <button
          onClick={handleEvaluate}
          disabled={loading}
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Evaluating...' : 'Evaluate'}
        </button>
        {error && <div className="text-red-600 text-sm">{error}</div>}
        {result && (
          <div className="bg-gray-50 rounded-lg p-4">
            <h4 className="font-medium text-gray-900">Result</h4>
            <pre className="text-sm font-mono bg-white p-2 rounded mt-2">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </Modal>
  );
};

// --- Segment Components ---

const SegmentList = ({ user, onSelectSegment, onNewSegment }) => {
  const [segments, setSegments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');
  const { addToast } = useToasts();
  
  const isViewer = user.role === 'Viewer';

  const fetchSegments = useCallback(() => {
    setLoading(true);
    setError(null);
    api.get('/segments')
      .then(data => setSegments(data))
      .catch(err => {
        const msg = \`Failed to fetch segments: \${parseApiError(err.message)}\`;
        setError(msg);
        addToast(msg, 'error');
      })
      .finally(() => setLoading(false));
  }, [addToast]);

  useEffect(() => {
    fetchSegments();
  }, [fetchSegments]);
  
  const filteredSegments = useMemo(() => {
    if (!segments) return [];
    return segments.filter(s => 
      s.key.toLowerCase().includes(filter.toLowerCase()) || 
      s.name.toLowerCase().includes(filter.toLowerCase())
    );
  }, [segments, filter]);

  return (
    <div className="bg-white shadow rounded-lg p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">Segments ({segments.length})</h2>
        <div className="flex space-x-4">
          <input
            type="text"
            placeholder="Search by key or name..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="rounded-md border-gray-300 shadow-sm sm:text-sm"
          />
          {!isViewer && (
            <button
              onClick={onNewSegment}
              className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-blue-700"
            >
              <PlusIcon className="w-5 h-5 mr-2" />
              New Segment
            </button>
          )}
        </div>
      </div>
      {loading && <LoadingSpinner />}
      {error && !loading && <div className="text-red-600 text-center py-4">{error}</div>}
      {!loading && !error && (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredSegments.length === 0 && (
                  <tr>
                    <td colSpan="4" className="text-center text-gray-500 py-8">
                      <InboxIcon className="w-12 h-12 mx-auto text-gray-400" />
                      No segments found.
                    </td>
                  </tr>
              )}
              {filteredSegments.map(seg => (
                <tr key={seg.key} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{seg.name}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-600">{seg.key}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 max-w-xs truncate">{seg.description}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => onSelectSegment(seg.key)}
                      className="text-blue-600 hover:text-blue-900"
                    >
                      {isViewer ? <EyeIcon className="w-5 h-5" /> : <PencilIcon className="w-5 h-5" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const createEmptySegment = () => ({
  key: '',
  name: '',
  description: '',
  rules: [],
  version: 0
});

const SegmentDetail = ({ segmentKey, onBack, onSave, isNew, user }) => {
  const [segment, setSegment] = useState(null);
  const [originalSegment, setOriginalSegment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const { addToast } = useToasts();
  
  const isViewer = user.role === 'Viewer';
  const isAdmin = user.role === 'Admin';
  
  const handleSegmentChange = (field, value) => setSegment(prev => ({ ...prev, [field]: value }));
  
  const handleRuleChange = (index, field, value) => {
    const newRules = [...segment.rules];
    newRules[index] = { ...newRules[index], [field]: value };
    handleSegmentChange('rules', newRules);
  };
  const handleAddRule = () => {
    const newRule = { attribute: '', operator: '=', value: '' };
    handleSegmentChange('rules', [...segment.rules, newRule]);
  };
  const handleRemoveRule = (index) => {
    const newRules = [...segment.rules];
    newRules.splice(index, 1);
    handleSegmentChange('rules', newRules);
  };
  
  const fetchSegmentData = useCallback(() => {
    if (isNew) {
      const empty = createEmptySegment();
      setSegment(empty);
      setOriginalSegment(empty);
    } else if (segmentKey) {
      setLoading(true);
      setError(null);
      api.get(\`/segments/\${segmentKey}\`)
        .then(data => {
            setSegment(data);
            setOriginalSegment(data);
        })
        .catch(err => {
          const msg = \`Failed to fetch segment: \${parseApiError(err.message)}\`;
          setError(msg);
          addToast(msg, 'error');
        })
        .finally(() => setLoading(false));
    }
  }, [segmentKey, isNew, addToast]);

  useEffect(() => {
    fetchSegmentData();
  }, [fetchSegmentData]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isViewer) return;
    setLoading(true);
    setError(null);
    try {
      const payload = { ...segment, version: originalSegment.version };
      const savedSegment = isNew
        ? await api.post('/segments', { ...payload, version: 1 })
        : await api.put(\`/segments/\${segment.key}\`, payload);
      addToast(\`Segment '\${savedSegment.key}' saved successfully\`, 'success');
      onSave(savedSegment);
    } catch (err) {
      const msg = parseApiError(err.message);
      setError(msg);
      addToast(msg, 'error');
      if (msg.toLowerCase().includes('conflict')) {
        addToast('Data was out of date. Reloading...', 'warning');
        fetchSegmentData();
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!isAdmin) return;
    setError(null);
    try {
      await api.delete(\`/segments/\${segment.key}\`);
      addToast('Segment deleted successfully', 'success');
      setShowDeleteModal(false);
      onSave();
    } catch (err) {
      const msg = \`Failed to delete: \${parseApiError(err.message)}\`;
      setError(msg);
      addToast(msg, 'error');
    }
  };

  if (loading && !segment) return <LoadingSpinner />;
  if (error && !segment) return <div className="text-red-600 p-4">{error}</div>;
  if (!segment) return null;
  
  const operators = ['=', '!=', '>', '<', 'contains', 'not_contains'];

  return (
    <form onSubmit={handleSubmit}>
      <div className="flex justify-between items-center mb-4">
        <div>
          <button type="button" onClick={onBack} className="flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2">
            <ChevronLeftIcon className="w-5 h-5 mr-1" />
            Back to segments
          </button>
          {isNew ? (
            <h2 className="text-2xl font-bold">Create New Segment</h2>
          ) : (
            <div className="flex items-center space-x-4">
              <h2 className="text-2xl font-bold">{segment.name}</h2>
              <Tag color="blue">v{segment.version}</Tag>
            </div>
          )}
        </div>
        {!isViewer && (
          <button
            type="submit"
            disabled={loading}
            className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? 'Saving...' : 'Save Changes'}
          </button>
        )}
      </div>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
          <ExclamationTriangleIcon className="w-5 h-5 inline-block -mt-1 mr-2" />
          <span className="block sm:inline">{error}</span>
        </div>
      )}

      <div className="bg-white shadow rounded-lg p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">Segment Name</label>
            <input
              type="text"
              value={segment.name}
              onChange={(e) => handleSegmentChange('name', e.target.value)}
              disabled={isViewer}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
              placeholder="e.g., Beta Testers"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Segment Key</label>
            <input
              type="text"
              value={segment.key}
              onChange={(e) => handleSegmentChange('key', e.target.value)}
              disabled={!isNew || isViewer}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
              placeholder="e.g., beta-testers"
            />
            {isNew && <p className="mt-2 text-xs text-gray-500">The key cannot be changed after creation.</p>}
          </div>
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-700">Description</label>
            <textarea
              value={segment.description}
              onChange={(e) => handleSegmentChange('description', e.target.value)}
              disabled={isViewer}
              rows="2"
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
            ></textarea>
          </div>
        </div>
        
        <div className="border-t border-gray-200 pt-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Segment Rules</h3>
          <p className="text-sm text-gray-600 mb-4">A user is in this segment if **ALL** of the following rules match.</p>
          <div className="space-y-4">
            {segment.rules.length === 0 && !isViewer && (
                <p className="text-gray-500 text-sm">No rules defined. Click "Add Rule" to get started.</p>
            )}
            {segment.rules.length === 0 && isViewer && (
                <p className="text-gray-500 text-sm">No rules defined for this segment.</p>
            )}
            {segment.rules.map((rule, index) => (
              <div key={index} className="grid grid-cols-3 gap-2 p-3 bg-gray-50 rounded-md">
                <input
                  type="text"
                  placeholder="Attribute (e.g., role)"
                  value={rule.attribute}
                  onChange={(e) => handleRuleChange(index, 'attribute', e.target.value)}
                  disabled={isViewer}
                  className="rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
                />
                <select
                  value={rule.operator}
                  onChange={(e) => handleRuleChange(index, 'operator', e.target.value)}
                  disabled={isViewer}
                  className="rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
                >
                  {operators.map(op => <option key={op} value={op}>{op}</option>)}
                </select>
                <div className="flex">
                  <input
                    type="text"
                    placeholder="Value (e.g., admin)"
                    value={rule.value}
                    onChange={(e) => handleRuleChange(index, 'value', e.target.value)}
                    disabled={isViewer}
                    className="flex-1 rounded-md border-gray-300 shadow-sm sm:text-sm disabled:bg-gray-100"
                  />
                  {!isViewer && (
                    <button type="button" onClick={() => handleRemoveRule(index)} className="ml-2 text-gray-400 hover:text-red-600">
                      <TrashIcon className="w-5 h-5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
            {!isViewer && (
              <button
                type="button"
                onClick={handleAddRule}
                className="flex items-center text-sm text-blue-600 hover:text-blue-800"
              >
                <PlusIcon className="w-5 h-5 mr-1" />
                Add Rule
              </button>
            )}
          </div>
        </div>
        
        {!isNew && isAdmin && (
          <div className="border-t border-gray-200 pt-6">
            <h3 className="text-lg font-medium text-red-600">Danger Zone</h3>
            <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-4 flex justify-between items-center">
              <div>
                <h4 className="font-medium text-red-800">Delete this segment</h4>
                <p className="text-sm text-red-700">This action cannot be undone. Segments in use by flags cannot be deleted.</p>
              </div>
              <button
                type="button"
                onClick={() => setShowDeleteModal(true)}
                className="bg-red-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-red-700"
              >
                <TrashIcon className="w-5 h-5 mr-2 inline" />
                Delete
              </button>
            </div>
          </div>
        )}
      </div>

      <Modal show={showDeleteModal} onClose={() => setShowDeleteModal(false)} title="Delete Segment">
        <p>Are you sure you want to delete the segment "<strong>{segment.name}</strong>"? This action cannot be undone.</p>
        <div className="flex justify-end space-x-4 mt-6">
          <button type="button" onClick={() => setShowDeleteModal(false)} className="bg-white text-gray-700 px-4 py-2 rounded-md shadow-sm border border-gray-300 hover:bg-gray-50">Cancel</button>
          <button type="button" onClick={handleDelete} className="bg-red-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-red-700">Delete Segment</button>
        </div>
      </Modal>
    </form>
  );
};

// --- NEW COMPONENT ---
const ReviewQueue = ({ user, onNavigate }) => {
    const [changes, setChanges] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showDiffModal, setShowDiffModal] = useState(false);
    const [currentChange, setCurrentChange] = useState(null);
    
    const { addToast } = useToasts();
    const isAdmin = user.role === 'Admin';
    
    const fetchChanges = useCallback(() => {
        setLoading(true);
        setError(null);
        api.get('/changes')
            .then(data => setChanges(data))
            .catch(err => {
                const msg = \`Failed to fetch review queue: \${parseApiError(err.message)}\`;
                setError(msg);
                addToast(msg, 'error');
            })
            .finally(() => setLoading(false));
    }, [addToast]);
    
    useEffect(() => {
        fetchChanges();
    }, [fetchChanges]);
    
    const handleShowDiff = (change) => {
        setCurrentChange(change);
        setShowDiffModal(true);
    };
    
    const handleApprove = async () => {
        if (!isAdmin || !currentChange) return;
        try {
            await api.post(\`/changes/\${currentChange._id}/approve\`, {});
            addToast(\`Change for '\${currentChange.flagKey}' approved.\`, 'success');
            setShowDiffModal(false);
            setCurrentChange(null);
            fetchChanges(); // Refresh list
        } catch (err) {
            addToast(parseApiError(err.message), 'error');
        }
    };
    
    const handleDeny = async () => {
        if (!isAdmin || !currentChange) return;
        try {
            await api.delete(\`/changes/\${currentChange._id}/deny\`);
            addToast(\`Change for '\${currentChange.flagKey}' denied.\`, 'success');
            setShowDiffModal(false);
            setCurrentChange(null);
            fetchChanges(); // Refresh list
        } catch (err) {
            addToast(parseApiError(err.message), 'error');
        }
    };

    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">Production Review Queue ({changes.length})</h2>
            
            {loading && <LoadingSpinner />}
            {error && !loading && <div className="text-red-600 text-center py-4">{error}</div>}
            {!loading && !error && (
                <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Flag Key</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Requested By</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Environment</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Requested At</th>
                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                    {changes.length === 0 && (
                        <tr>
                            <td colSpan="5" className="text-center text-gray-500 py-8">
                                <CheckCircleIcon className="w-12 h-12 mx-auto text-green-500" />
                                The review queue is empty.
                            </td>
                        </tr>
                    )}
                    {changes.map(change => (
                        <tr key={change._id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-600">{change.flagKey}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{change.requestedBy}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                            <Tag color="red">{change.environment}</Tag>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(change.createdAt).toLocaleString()}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <button
                            onClick={() => handleShowDiff(change)}
                            className="text-blue-600 hover:text-blue-900"
                            >
                            View Diff
                            </button>
                        </td>
                        </tr>
                    ))}
                    </tbody>
                </table>
                </div>
            )}
            
            <Modal show={showDiffModal} onClose={() => setShowDiffModal(false)} title="Review Production Change" size="5xl">
                {currentChange && (
                    <div className="space-y-4">
                        <p>
                            <strong>Flag:</strong> {currentChange.flagKey} <br/>
                            <strong>Requested by:</strong> {currentChange.requestedBy}
                        </p>
                        <DiffViewer before={currentChange.original} after={currentChange.changes} />
                        {isAdmin && (
                            <div className="flex justify-end space-x-4 pt-4 border-t border-gray-200">
                                <button
                                    onClick={handleDeny}
                                    className="bg-red-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-red-700"
                                >
                                    Deny
                                </button>
                                <button
                                    onClick={handleApprove}
                                    className="bg-green-600 text-white px-4 py-2 rounded-md shadow-sm hover:bg-green-700"
                                >
                                    Approve
                                </button>
                            </div>
                        )}
                        {!isAdmin && (
                            <p className="text-sm text-gray-600">You are viewing a pending change. An Admin must approve or deny it.</p>
                        )}
                    </div>
                )}
            </Modal>
        </div>
    );
};


/**
 * Main App
 */
export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('user');
    return savedUser ? JSON.parse(savedUser) : null;
  });

  // 'dashboard', 'flagDetail', 'newFlag', 'segments', 'segmentDetail', 'newSegment', 'reviewQueue'
  const [page, setPage] = useState('dashboard');
  const [selectedKey, setSelectedKey] = useState(null);

  const handleLogin = (newToken, newUser) => {
    setToken(newToken);
    setUser(newUser);
    setPage('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
  };

  const handleNavigate = (targetPage) => {
    setPage(targetPage);
    setSelectedKey(null);
  };

  const handleSelectFlag = (key) => {
    setSelectedKey(key);
    setPage('flagDetail');
  };
  const handleNewFlag = () => {
    setSelectedKey(null);
    setPage('newFlag');
  };
  const handleSelectSegment = (key) => {
    setSelectedKey(key);
    setPage('segmentDetail');
  };
  const handleNewSegment = () => {
    setSelectedKey(null);
    setPage('newSegment');
  };

  const handleBack = () => {
    if (page === 'flagDetail' || page === 'newFlag') {
      setPage('dashboard');
    } else if (page === 'segmentDetail' || page === 'newSegment') {
      setPage('segments');
    } else if (page === 'reviewQueue') {
        setPage('dashboard');
    }
    setSelectedKey(null);
  };

  const handleSave = () => {
    if (page === 'newFlag' || page === 'flagDetail') {
      setPage('dashboard');
    } else if (page === 'newSegment' || page === 'segmentDetail') {
      setPage('segments');
    }
    setSelectedKey(null);
  };

  if (!token || !user) {
    return (
        <ToastProvider>
            <LoginView onLogin={handleLogin} />
        </ToastProvider>
    );
  }

  const renderPage = () => {
    switch (page) {
      case 'dashboard':
        return <Dashboard user={user} onSelectFlag={handleSelectFlag} onNewFlag={handleNewFlag} />;
      case 'flagDetail':
        return <FlagDetail user={user} flagKey={selectedKey} onBack={handleBack} onSave={handleSave} isNew={false} />;
      case 'newFlag':
        return <FlagDetail user={user} flagKey={null} onBack={handleBack} onSave={handleSave} isNew={true} />;
      case 'segments':
        return <SegmentList user={user} onSelectSegment={handleSelectSegment} onNewSegment={handleNewSegment} />;
      case 'segmentDetail':
        return <SegmentDetail user={user} segmentKey={selectedKey} onBack={handleBack} onSave={handleSave} isNew={false} />;
      case 'newSegment':
        return <SegmentDetail user={user} segmentKey={null} onBack={handleBack} onSave={handleSave} isNew={true} />;
      case 'reviewQueue':
        return <ReviewQueue user={user} onNavigate={handleNavigate} />;
      default:
        return <Dashboard user={user} onSelectFlag={handleSelectFlag} onNewFlag={handleNewFlag} />;
    }
  };

  return (
    <ToastProvider>
      <Header user={user} onLogout={handleLogout} onNavigate={handleNavigate} page={page} />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {renderPage()}
      </main>
    </ToastProvider>
  );
}
`,
};

// --- HELPER FUNCTIONS ---

/**
 * Synchronously checks if a command exists.
 * @param {string} command - The command to check (e.g., 'docker', 'node').
 * @returns {boolean} - True if the command exists, false otherwise.
 */
function commandExists(command) {
  try {
    // Using 'which' for Unix-like systems and 'where' for Windows
    const checkCmd = process.platform === 'win32' ? 'where' : 'which';
    execSync(`${checkCmd} ${command}`, { stdio: 'ignore' });
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Checks for all required prerequisites (Node, Docker, Docker Compose).
 */
function checkPrerequisites() {
  console.log('Checking prerequisites...');
  let allGood = true;

  if (commandExists('node')) {
    console.log('✅ Node.js is installed.');
  } else {
    console.error('❌ Node.js is NOT installed. Please install it to continue.');
    allGood = false;
  }

  if (commandExists('docker')) {
    console.log('✅ Docker is installed.');
  } else {
    console.error('❌ Docker is NOT installed. Please install and start it to continue.');
    allGood = false;
  }
  
  // Check for docker-compose (v1) or docker compose (v2)
  const composeV1 = commandExists('docker-compose');
  let composeV2 = false;
  try {
    if (commandExists('docker')) {
      execSync('docker compose version', { stdio: 'ignore' });
      composeV2 = true;
    }
  } catch (e) {
    // docker compose not available or errored
  }
  
  let composeCmd = '';
  if (composeV1) {
    composeCmd = 'docker-compose';
    console.log('✅ docker-compose (v1) is installed.');
  } else if (composeV2) {
    composeCmd = 'docker compose';
    console.log('✅ docker compose (v2) is installed.');
  } else {
    console.error('❌ Docker Compose is NOT installed. Please install it to continue.');
    allGood = false;
  }

  if (!allGood) {
    console.error('Please install all missing prerequisites and try again.');
    process.exit(1);
  }
  
  // Check if Docker Daemon is running
  try {
    execSync('docker info', { stdio: 'ignore' });
    console.log('✅ Docker Daemon is running.');
  } catch (error) {
    console.error('❌ Docker Daemon is NOT running. Please start your Docker desktop application.');
    process.exit(1);
  }
  
  return composeCmd; // Return the correct command to use
}

/**
 * Creates all the directories and files.
 */
function createFiles() {
  console.log('\nCreating project files...');
  const projectRoot = process.cwd();

  for (const [filePath, content] of Object.entries(fileContents)) {
    const fullPath = path.join(projectRoot, filePath);
    const dirName = path.dirname(fullPath);

    try {
      // Ensure directory exists
      if (!fs.existsSync(dirName)) {
        fs.mkdirSync(dirName, { recursive: true });
      }
      
      // Write the file
      // Trim leading/trailing whitespace from the template strings
      fs.writeFileSync(fullPath, content.trim());
      console.log(`  ✓ Created ${filePath}`);

    } catch (error) {
      console.error(`❌ Failed to create file ${filePath}: ${error.message}`);
      process.exit(1);
    }
  }
  console.log('✅ All files created successfully.');
}

/**
 * Runs the Docker Compose command to build and start the app.
 * @param {string} composeCmd - The correct Docker Compose command ('docker-compose' or 'docker compose').
 */
function runDocker(composeCmd) {
  console.log('\nStarting application with Docker Compose...');
  console.log(`(This may take several minutes to build and download images...)\n`);

  const args = [...composeCmd.split(' '), 'up', '--build'];
  
  const dockerProcess = spawn(args[0], args.slice(1), {
    stdio: 'inherit', // Show Docker's output directly in the terminal
    shell: true
  });

  dockerProcess.on('close', (code) => {
    if (code !== 0) {
      console.error(`\n❌ Docker Compose process exited with code ${code}.`);
    } else {
      console.log('\n✅ Application containers are running!');
    }
  });

  dockerProcess.on('error', (err) => {
    console.error(`\n❌ Failed to start Docker Compose: ${err.message}`);
    console.error('Please ensure Docker is running and you have the necessary permissions.');
  });
}

// --- MAIN EXECUTION ---
function main() {
  console.log('--- MERN Feature Flag System Setup ---');
  try {
    const composeCmd = checkPrerequisites();
    createFiles();
    runDocker(composeCmd);
  } catch (error) {
    console.error(`\nAn unexpected error occurred: ${error.message}`);
    process.exit(1);
  }
}

main();

