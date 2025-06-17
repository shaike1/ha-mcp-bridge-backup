#!/usr/bin/env node

// Load environment variables
try {
    require('dotenv').config();
} catch (error) {
    console.log('⚠️  dotenv not found, using environment variables only');
}

const express = require('express');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();

// Configuration with fallbacks
const PORT = process.env.PORT || 3001;
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const DEBUG = process.env.DEBUG === 'true';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const MULTI_TENANT = process.env.MULTI_TENANT !== 'false';
const ENABLE_USER_REGISTRATION = process.env.ENABLE_USER_REGISTRATION !== 'false';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-' + crypto.randomBytes(16).toString('hex');
const MCP_API_KEY = process.env.MCP_API_KEY;

// Paths
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Enhanced logging
function log(level, message, data = null) {
    const levels = { error: 0, warn: 1, info: 2, debug: 3 };
    const currentLevel = levels[LOG_LEVEL] || 2;
    
    if (levels[level] <= currentLevel) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] ${level.toUpperCase()}: ${message}`, data ? JSON.stringify(data, null, 2) : '');
    }
}

// Initialize directories
async function initializeDataDir() {
    try {
        await fs.access(DATA_DIR);
    } catch {
        await fs.mkdir(DATA_DIR, { recursive: true });
        log('info', 'Created data directory');
    }
    
    try {
        await fs.access(PUBLIC_DIR);
    } catch {
        await fs.mkdir(PUBLIC_DIR, { recursive: true });
        log('info', 'Created public directory');
    }
}

// User management class
class UserManager {
    constructor() {
        this.users = new Map();
        this.loadUsers();
    }

    async loadUsers() {
        try {
            const data = await fs.readFile(USERS_FILE, 'utf8');
            const users = JSON.parse(data);
            this.users = new Map(Object.entries(users));
            log('info', `Loaded ${this.users.size} users`);
        } catch (error) {
            if (error.code !== 'ENOENT') {
                log('error', 'Failed to load users', error.message);
            }
            this.users = new Map();
        }
    }

    async saveUsers() {
        try {
            const users = Object.fromEntries(this.users);
            await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        } catch (error) {
            log('error', 'Failed to save users', error.message);
        }
    }

    generateApiKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    async createUser(email, haUrl, haToken) {
        const apiKey = this.generateApiKey();
        const user = {
            id: crypto.randomUUID(),
            email,
            apiKey,
            haUrl,
            haToken,
            createdAt: new Date().toISOString(),
            lastUsed: null,
            requestCount: 0
        };

        this.users.set(apiKey, user);
        await this.saveUsers();
        
        log('info', 'User created', { email, apiKey: apiKey.substring(0, 8) + '...' });
        return user;
    }

    getUser(apiKey) {
        return this.users.get(apiKey);
    }

    async updateLastUsed(apiKey) {
        const user = this.users.get(apiKey);
        if (user) {
            user.lastUsed = new Date().toISOString();
            user.requestCount = (user.requestCount || 0) + 1;
        }
    }

    getAllUsers() {
        return Array.from(this.users.values()).map(user => ({
            id: user.id,
            email: user.email,
            createdAt: user.createdAt,
            lastUsed: user.lastUsed,
            requestCount: user.requestCount || 0,
            haUrl: user.haUrl
        }));
    }

    async deleteUser(apiKey) {
        const deleted = this.users.delete(apiKey);
        if (deleted) {
            await this.saveUsers();
        }
        return deleted;
    }
}

// Initialize user manager
const userManager = new UserManager();

// Startup logging
log('info', '🚀 Starting HA MCP Bridge (Multi-tenant)');
log('info', `🌐 SERVER_URL: ${SERVER_URL}`);
log('info', `🔐 Multi-tenant: ${MULTI_TENANT}`);
log('info', `📝 User registration: ${ENABLE_USER_REGISTRATION}`);

// Express middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.text({ type: 'application/jsonrpc' }));
app.use(express.static(PUBLIC_DIR));

// CORS
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-API-Key, HA-URL, HA-Token');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    next();
});

// Authentication middleware
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'] || req.query.api_key;
    const token = authHeader?.replace('Bearer ', '');
    const userApiKey = token || apiKey;

    // Admin authentication
    if (userApiKey === ADMIN_API_KEY) {
        req.isAdmin = true;
        return next();
    }

    // Multi-tenant mode
    if (MULTI_TENANT && userApiKey) {
        const user = userManager.getUser(userApiKey);
        if (user) {
            req.user = user;
            req.haConfig = {
                url: user.haUrl,
                token: user.haToken
            };
            userManager.updateLastUsed(userApiKey);
            return next();
        }
    }

    // Check for MCP_API_KEY (for mcp-remote)
    if (MCP_API_KEY && userApiKey === MCP_API_KEY) {
        const firstUser = userManager.users.values().next().value;
        if (firstUser) {
            req.user = firstUser;
            req.haConfig = {
                url: firstUser.haUrl,
                token: firstUser.haToken
            };
            return next();
        }
    }

    // Liberal authentication for MCP clients
    if (req.headers['user-agent']?.includes('Claude') || 
        req.headers['user-agent']?.includes('mcp-remote') ||
        req.path === '/health' || 
        req.path === '/' && req.method === 'GET') {
        return next();
    }

    return res.status(401).json({ 
        error: 'Unauthorized. Please provide a valid API key.',
        endpoints: {
            register: ENABLE_USER_REGISTRATION ? '/register' : 'disabled',
            health: '/health'
        }
    });
}

// Home Assistant API functions
async function callHomeAssistant(endpoint, method = 'GET', data = null, config = null) {
    if (!config?.url || !config?.token) {
        throw new Error('Home Assistant configuration required');
    }

    const url = `${config.url}${endpoint}`;
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${config.token}`,
            'Content-Type': 'application/json',
        }
    };

    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(url, options);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HA API error: ${response.status} ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        log('error', 'HA API call failed', error.message);
        throw error;
    }
}

// Routes
app.get('/', (req, res) => {
    res.json({
        name: 'HA MCP Bridge',
        version: '2.0.0',
        description: 'Multi-tenant Home Assistant MCP Bridge for Claude',
        status: 'running',
        features: {
            multiTenant: MULTI_TENANT,
            userRegistration: ENABLE_USER_REGISTRATION
        },
        endpoints: {
            health: '/health',
            register: ENABLE_USER_REGISTRATION ? '/register' : 'disabled',
            mcp: 'POST /'
        },
        statistics: {
            totalUsers: userManager.users.size
        }
    });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        server: {
            url: SERVER_URL,
            multiTenant: MULTI_TENANT,
            userRegistration: ENABLE_USER_REGISTRATION
        },
        statistics: {
            totalUsers: userManager.users.size
        },
        tools: ['get_entities', 'call_service', 'get_automations', 'get_lights', 'get_switches']
    });
});

// User registration
app.post('/register', async (req, res) => {
    if (!ENABLE_USER_REGISTRATION) {
        return res.status(403).json({ 
            error: 'User registration is currently disabled'
        });
    }

    const { email, haUrl, haToken } = req.body;

    if (!email || !haUrl || !haToken) {
        return res.status(400).json({ 
            error: 'Missing required fields',
            required: ['email', 'haUrl', 'haToken']
        });
    }

    try {
        // Test HA connection
        await callHomeAssistant('/api/', 'GET', null, { url: haUrl, token: haToken });
        
        const user = await userManager.createUser(email, haUrl, haToken);
        
        res.json({
            success: true,
            apiKey: user.apiKey,
            message: 'Registration successful! Save your API key securely.',
            nextSteps: {
                claudeConfig: {
                    mcpServers: {
                        homeassistant: {
                            command: "npx",
                            args: ["mcp-remote", SERVER_URL],
                            env: {
                                MCP_API_KEY: user.apiKey
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        res.status(400).json({ 
            error: 'Failed to connect to Home Assistant',
            details: error.message
        });
    }
});

// JSON-RPC message handler
async function handleJsonRpcMessage(body, haConfig = null, user = null) {
    const { method, params, id } = body;
    
    let result;

    switch (method) {
        case 'initialize':
            result = {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {}, resources: {}, prompts: {} },
                serverInfo: {
                    name: "HA MCP Bridge (Multi-tenant)",
                    version: "2.0.0",
                    userMode: !!user
                }
            };
            break;

        case 'tools/list':
            result = {
                tools: [
                    {
                        name: 'get_entities',
                        description: 'Get all Home Assistant entities or filter by domain',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                domain: { type: 'string', description: 'Filter by domain (light, switch, sensor, etc.)' }
                            }
                        }
                    },
                    {
                        name: 'call_service',
                        description: 'Call a Home Assistant service to control devices',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                domain: { type: 'string', description: 'Service domain' },
                                service: { type: 'string', description: 'Service name' },
                                entity_id: { type: 'string', description: 'Target entity ID' },
                                data: { type: 'object', description: 'Additional service data' }
                            },
                            required: ['domain', 'service']
                        }
                    },
                    {
                        name: 'get_automations',
                        description: 'Get all Home Assistant automations',
                        inputSchema: { type: 'object', properties: {} }
                    },
                    {
                        name: 'get_lights',
                        description: 'Get all light entities',
                        inputSchema: { type: 'object', properties: {} }
                    },
                    {
                        name: 'get_switches',
                        description: 'Get all switch entities',
                        inputSchema: { type: 'object', properties: {} }
                    }
                ]
            };
            break;

        case 'prompts/list':
            result = { prompts: [] };
            break;

        case 'resources/list':
            result = { resources: [] };
            break;

        case 'tools/call':
            if (!haConfig) {
                throw new Error('Home Assistant configuration required for tool calls');
            }

            const { name, arguments: args } = params;

            try {
                let toolResult;
                const entities = await callHomeAssistant('/api/states', 'GET', null, haConfig);

                switch (name) {
                    case 'get_entities':
                        toolResult = args?.domain ? 
                            entities.filter(e => e.entity_id.startsWith(args.domain + '.')) : 
                            entities;
                        break;
                    case 'call_service':
                        const serviceData = { ...args.data };
                        if (args.entity_id) serviceData.entity_id = args.entity_id;
                        toolResult = await callHomeAssistant(`/api/services/${args.domain}/${args.service}`, 'POST', serviceData, haConfig);
                        break;
                    case 'get_automations':
                        toolResult = entities.filter(e => e.entity_id.startsWith('automation.'));
                        break;
                    case 'get_lights':
                        toolResult = entities.filter(e => e.entity_id.startsWith('light.'));
                        break;
                    case 'get_switches':
                        toolResult = entities.filter(e => e.entity_id.startsWith('switch.'));
                        break;
                    default:
                        throw new Error(`Unknown tool: ${name}`);
                }

                result = {
                    content: [{
                        type: 'text',
                        text: JSON.stringify(toolResult, null, 2)
                    }]
                };

            } catch (error) {
                result = {
                    content: [{
                        type: 'text',
                        text: `Error executing ${name}: ${error.message}`
                    }]
                };
            }
            break;

        case 'notifications/initialized':
            return {};

        default:
            throw new Error(`Unknown JSON-RPC method: ${method}`);
    }

    return { jsonrpc: "2.0", id, result };
}

// Main JSON-RPC endpoint
app.post('/', authenticate, async (req, res) => {
    try {
        const response = await handleJsonRpcMessage(req.body, req.haConfig, req.user);
        res.json(response);
    } catch (error) {
        res.json({
            jsonrpc: "2.0",
            id: req.body?.id,
            error: { 
                code: -32603, 
                message: error.message
            }
        });
    }
});

// Admin endpoints
app.get('/admin/users', authenticate, (req, res) => {
    if (!req.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }

    res.json({
        users: userManager.getAllUsers(),
        total: userManager.users.size
    });
});

// OAuth endpoints (for compatibility)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
    res.json({
        issuer: SERVER_URL,
        authorization_endpoint: `${SERVER_URL}/oauth/authorize`,
        token_endpoint: `${SERVER_URL}/oauth/token`,
        registration_endpoint: `${SERVER_URL}/oauth/register`,
        scopes_supported: ["homeassistant:read", "homeassistant:write"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"]
    });
});

// Initialize and start server
async function startServer() {
    try {
        await initializeDataDir();
        
        app.listen(PORT, '0.0.0.0', () => {
            log('info', `✅ HA MCP Bridge Server running on port ${PORT}`);
            log('info', `🌐 Server URL: ${SERVER_URL}`);
            log('info', `👥 Users: ${userManager.users.size}`);
            
            if (ENABLE_USER_REGISTRATION) {
                log('info', `🚀 Users can register at: ${SERVER_URL}/register`);
            }
        });

    } catch (error) {
        log('error', 'Failed to start server', error);
        process.exit(1);
    }
}

startServer();