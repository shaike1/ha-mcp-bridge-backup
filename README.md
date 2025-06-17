# 🏠 HA MCP Bridge - Multi-tenant

**Multi-tenant Home Assistant MCP Bridge** - Connect your Home Assistant smart home to Claude via the Model Context Protocol (MCP).

## ✨ Features

- 🔌 **Multi-tenant Support** - Multiple users can connect their own Home Assistant
- 🛡️ **Secure Authentication** - Individual API keys for each user
- 🚀 **Easy Deployment** - Docker support with Traefik integration
- 📊 **Usage Analytics** - Track requests and monitor usage
- 🌐 **Production Ready** - SSL, rate limiting, monitoring

## 🚀 Quick Start

### 1. Register Your Home Assistant

```bash
curl -X POST https://your-domain.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your@email.com",
    "haUrl": "https://your-homeassistant.com",
    "haToken": "your_long_lived_access_token"
  }'
```

### 2. Configure Claude Desktop

Add this to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "homeassistant": {
      "command": "npx",
      "args": ["mcp-remote", "https://your-domain.com"],
      "env": {
        "MCP_API_KEY": "your_generated_api_key_here"
      }
    }
  }
}
```

## 🐳 Docker Deployment

1. **Clone the repository:**
```bash
git clone https://github.com/shaike1/ha-mcp-bridge-backup.git
cd ha-mcp-bridge-backup
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Deploy:**
```bash
docker-compose up -d
```

## 🔧 Available Tools

- **get_entities** - Get all entities or filter by domain
- **call_service** - Control devices and automations
- **get_lights** - Get all light entities
- **get_switches** - Get all switch entities
- **get_automations** - Get all automations

## 📊 Monitoring

- Health endpoint: `/health`
- Admin interface: `/admin/users`
- User registration: `/register`

## 🛡️ Security Features

- Individual API keys per user
- Encrypted data storage
- Rate limiting and CORS protection
- Admin interface for management

## 📝 Environment Variables

```bash
PORT=3001
SERVER_URL=https://your-domain.com
MULTI_TENANT=true
ENABLE_USER_REGISTRATION=true
ADMIN_API_KEY=your_admin_key
MCP_API_KEY=your_mcp_key
```

## 📈 Usage Example

Once configured, ask Claude:
- "Show me all my lights"
- "Turn on the living room lights"
- "What's the status of my Home Assistant?"

## 🔐 Security Notes

- Never commit API keys or passwords to the repository
- Use environment variables for all sensitive configuration
- Generate strong API keys: `openssl rand -hex 32`
- Keep your `.env` file secure and never share it

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details.

---

**Made with ❤️ for the smart home community**