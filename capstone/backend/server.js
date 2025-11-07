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
  console.log(`Subscribed to ${count} Redis channel(s)`);
});

redisSubscriber.on('message', (channel, message) => {
  // Handle Flag Updates
  if (channel === REDIS_PUB_CHANNEL) {
    console.log(`Received update for flag: ${message}`);
    const cacheKey = `${REDIS_CACHE_PREFIX}${message}`;
    redisCache.get(cacheKey)
      .then(result => {
        if (result) {
          const flag = JSON.parse(result);
          flagCache.set(flag.key, flag);
          console.log(`In-memory flag cache updated for: ${flag.key}`);
        } else {
          flagCache.delete(message);
          console.log(`In-memory flag cache invalidated for: ${message}`);
        }
      })
      .catch(err => console.error('Error fetching updated flag from Redis cache:', err));
  }

  // Handle Segment Updates
  if (channel === REDIS_SEGMENT_PUB_CHANNEL) {
    console.log(`Received update for segment: ${message}`);
    const cacheKey = `${REDIS_SEGMENT_CACHE_PREFIX}${message}`;
    redisCache.get(cacheKey)
      .then(result => {
        if (result) {
          const segment = JSON.parse(result);
          segmentCache.set(segment.key, segment);
          console.log(`In-memory segment cache updated for: ${segment.key}`);
        } else {
          segmentCache.delete(message);
          console.log(`In-memory segment cache invalidated for: ${message}`);
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
    console.error(`Failed to create audit log:`, err);
  }
}

// Pub/Sub & Caching
async function publishFlagUpdate(flagKey, flagDoc) {
  try {
    const cacheKey = `${REDIS_CACHE_PREFIX}${flagKey}`;
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
    const cacheKey = `${REDIS_SEGMENT_CACHE_PREFIX}${segmentKey}`;
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
  const cacheKey = `${REDIS_CACHE_PREFIX}${flagKey}`;
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
  const cacheKey = `${REDIS_SEGMENT_CACHE_PREFIX}${segmentKey}`;
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
  const key = `${seed}:${userId}`;
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
      console.log(`First user registered, setting role to Admin for: ${email}`);
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
        return res.status(409).json({ message: `Conflict: A pending change for 'prod' already exists for this flag. It must be approved or denied first.` });
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
      return res.status(400).json({ message: `Cannot delete segment: It is in use by flag '${flagInUse.key}'.` });
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
      const cacheKey = `${REDIS_CACHE_PREFIX}${flag.key}`;
      await redisCache.set(cacheKey, JSON.stringify(flag), 'EX', REDIS_CACHE_TTL);
      flagCache.set(flag.key, flag);
      flagCount++;
    }
    // Prime Segments
    const segments = await Segment.find().lean();
    let segmentCount = 0;
    for (const segment of segments) {
      const cacheKey = `${REDIS_SEGMENT_CACHE_PREFIX}${segment.key}`;
      await redisCache.set(cacheKey, JSON.stringify(segment), 'EX', REDIS_CACHE_TTL);
      segmentCache.set(segment.key, segment);
      segmentCount++;
    }
    console.log(`Successfully primed ${flagCount} flags and ${segmentCount} segments.`);
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
        console.log(`Backend server running on port ${PORT}`);
    });
});

mongoose.connection.on('error', err => {
    console.error('MongoDB connection error event:', err.message);
});