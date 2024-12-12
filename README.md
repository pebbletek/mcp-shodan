# Shodan MCP Server

A Model Context Protocol (MCP) server for querying the [Shodan API](https://shodan.io). This server provides tools for IP lookups, device searches, DNS lookups, vulnerability queries, and more. It is designed to integrate seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

## Features

- **IP Lookup**: Retrieve detailed information about an IP address
- **Search**: Search for devices on Shodan matching specific queries
- **Ports**: Get a list of ports that Shodan is scanning
- **Vulnerabilities**: Fetch information about known vulnerabilities (CVE)
- **DNS Lookup**: Resolve hostnames to IP addresses

## Tools

### 1. IP Lookup Tool
- Name: `ip_lookup`
- Description: Retrieve detailed information about an IP address
- Parameters:
  * `ip` (required): IP address to lookup

### 2. Search Tool
- Name: `search`
- Description: Search for devices on Shodan
- Parameters:
  * `query` (required): Shodan search query
  * `max_results` (optional, default: 10): Number of results to return

### 3. Vulnerabilities Tool
- Name: `vulnerabilities`
- Description: Fetch information about known vulnerabilities
- Parameters:
  * `cve` (required): CVE identifier

### 4. DNS Lookup Tool
- Name: `dns_lookup`
- Description: Resolve hostnames to IP addresses
- Parameters:
  * `hostnames` (required): Array of hostnames to resolve

## Requirements

- Node.js (v18 or later)
- A valid [Shodan API Key](https://account.shodan.io/)

## Setup Guide

### 1. Installation

```bash
git clone <repository_url>
cd mcp-shodan
npm install
```

### 2. Configuration

Create a `.env` file in the root directory:
```
SHODAN_API_KEY=your_shodan_api_key
```

### 3. Build and Run

```bash
npm run build
npm start
```

### 4. Configure Claude Desktop

There are two ways to configure the Shodan MCP server in Claude Desktop:

#### Option 1: Direct Node Execution (Local Development)
```json
{
  "mcpServers": {
    "shodan-mcp": {
      "command": "node",
      "args": ["path/to/mcp-shodan/build/index.js"],
      "env": {
        "SHODAN_API_KEY": "your_shodan_api_key",
        "DEBUG": "*"
      }
    }
  }
}
```

#### Option 2: NPX Installation (Recommended for Users)
```json
{
  "mcpServers": {
    "shodan-mcp": {
      "command": "npx",
      "args": ["@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "your_shodan_api_key",
        "DEBUG": "*"
      }
    }
  }
}
```

The npx method automatically downloads and runs the latest version of the package from npm.

Configuration file location:

Windows: %APPDATA%\Claude\claude_desktop_config.json
macOS: ~/Library/Application Support/Claude/claude_desktop_config.json

## Usage

1. Start the MCP server:
```bash
npm start
```

2. Launch Claude Desktop and ensure the Shodan MCP server is detected
3. Use any of the available tools through the Claude interface

## Development

To run in development mode with hot reloading:
```bash
npm run dev
```

## Error Handling

The server includes comprehensive error handling for:
- Invalid API keys
- Rate limiting
- Network errors
- Invalid input parameters

## Version History

- v1.0.0: Initial release with core functionality

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.