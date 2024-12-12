# Shodan MCP Server

A Model Context Protocol (MCP) server for querying the [Shodan API](https://shodan.io) and [Shodan CVEDB](https://cvedb.shodan.io). This server provides tools for IP lookups, device searches, DNS lookups, vulnerability queries, CPE lookups, and more. It is designed to integrate seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

## Features

- **IP Lookup**: Retrieve detailed information about an IP address
- **Search**: Search for devices on Shodan matching specific queries
- **Ports**: Get a list of ports that Shodan is scanning
- **CVE Lookup**: Fetch detailed information about specific CVEs using Shodan's CVEDB
- **CPE Lookup**: Search for Common Platform Enumeration (CPE) entries by product name
- **CVEs by Product**: Search for all CVEs affecting a specific product or CPE
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

### 3. CVE Lookup Tool
- Name: `cve_lookup`
- Description: Fetch detailed information about CVEs using Shodan's CVEDB
- Parameters:
  * `cve` (required): CVE identifier in format CVE-YYYY-NNNNN (e.g., CVE-2021-44228)
- Returns:
  * CVE details including:
    - CVSS v2 and v3 scores
    - EPSS score and ranking
    - KEV status
    - Proposed action
    - Ransomware campaign information
    - Affected products (CPEs)
    - References

### 4. CPE Lookup Tool
- Name: `cpe_lookup`
- Description: Search for Common Platform Enumeration (CPE) entries by product name
- Parameters:
  * `product` (required): Name of the product to search for
  * `count` (optional, default: false): If true, returns only the count of matching CPEs
  * `skip` (optional, default: 0): Number of CPEs to skip (for pagination)
  * `limit` (optional, default: 1000): Maximum number of CPEs to return
- Returns:
  * When count is true: Total number of matching CPEs
  * When count is false: List of CPEs with pagination details

### 5. CVEs by Product Tool
- Name: `cves_by_product`
- Description: Search for CVEs affecting a specific product or CPE
- Parameters:
  * `cpe23` (optional): CPE 2.3 identifier (format: cpe:2.3:part:vendor:product:version)
  * `product` (optional): Name of the product to search for CVEs
  * `count` (optional, default: false): If true, returns only the count of matching CVEs
  * `is_kev` (optional, default: false): If true, returns only CVEs with KEV flag set
  * `sort_by_epss` (optional, default: false): If true, sorts CVEs by EPSS score
  * `skip` (optional, default: 0): Number of CVEs to skip (for pagination)
  * `limit` (optional, default: 1000): Maximum number of CVEs to return
  * `start_date` (optional): Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
  * `end_date` (optional): End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
- Notes:
  * Must provide either cpe23 or product, but not both
  * Date filtering uses published time of CVEs
- Returns:
  * When count is true: Total number of matching CVEs
  * When count is false: List of CVEs with pagination details and query parameters

### 6. DNS Lookup Tool
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
      "command": "npm",
      "args": ["exec", "@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "your_shodan_api_key",
        "DEBUG": "*"
      }
    }
  }
}
```

The npm exec method automatically downloads and runs the latest version of the package from npm.

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
- Invalid CVE formats
- Invalid CPE lookup parameters
- Invalid date formats
- Mutually exclusive parameter validation

## Version History

- v1.0.7: Added CVEs by Product search functionality and renamed vulnerabilities tool to cve_lookup
- v1.0.6: Added CVEDB integration for enhanced CVE lookups and CPE search functionality
- v1.0.0: Initial release with core functionality

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
