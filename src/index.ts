#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import dotenv from "dotenv";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import fs from "fs";
import path from "path";
import os from "os";

dotenv.config();

const logFilePath = path.join(os.tmpdir(), "mcp-shodan-server.log");
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
if (!SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required.");
}

const API_BASE_URL = "https://api.shodan.io";
const CVEDB_API_URL = "https://cvedb.shodan.io";

// Logging Helper Function
function logToFile(message: string) {
  try {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFilePath, formattedMessage, "utf8");
    console.error(formattedMessage.trim()); // Use stderr for logging to avoid interfering with stdout
  } catch (error) {
    console.error(`Failed to write to log file: ${error}`);
  }
}

// Tool Schemas
const IpLookupArgsSchema = z.object({
  ip: z.string().describe("The IP address to query."),
});

const SearchArgsSchema = z.object({
  query: z.string().describe("Search query for Shodan."),
  max_results: z
    .number()
    .optional()
    .default(10)
    .describe("Maximum results to return."),
});

const CVELookupArgsSchema = z.object({
  cve: z.string()
    .regex(/^CVE-\d{4}-\d{4,}$/i, "Must be a valid CVE ID format (e.g., CVE-2021-44228)")
    .describe("The CVE identifier to query (format: CVE-YYYY-NNNNN)."),
});

const DnsLookupArgsSchema = z.object({
  hostnames: z.array(z.string()).describe("List of hostnames to resolve."),
});

const CpeLookupArgsSchema = z.object({
  product: z.string().describe("The name of the product to search for CPEs."),
  count: z.boolean().optional().default(false).describe("If true, returns only the count of matching CPEs."),
  skip: z.number().optional().default(0).describe("Number of CPEs to skip (for pagination)."),
  limit: z.number().optional().default(1000).describe("Maximum number of CPEs to return (max 1000)."),
});

const CVEsByProductArgsSchema = z.object({
  cpe23: z.string().optional().describe("The CPE version 2.3 identifier (format: cpe:2.3:part:vendor:product:version)."),
  product: z.string().optional().describe("The name of the product to search for CVEs."),
  count: z.boolean().optional().default(false).describe("If true, returns only the count of matching CVEs."),
  is_kev: z.boolean().optional().default(false).describe("If true, returns only CVEs with the KEV flag set."),
  sort_by_epss: z.boolean().optional().default(false).describe("If true, sorts CVEs by EPSS score in descending order."),
  skip: z.number().optional().default(0).describe("Number of CVEs to skip (for pagination)."),
  limit: z.number().optional().default(1000).describe("Maximum number of CVEs to return (max 1000)."),
  start_date: z.string().optional().describe("Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)."),
  end_date: z.string().optional().describe("End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS).")
}).refine(
  data => !(data.cpe23 && data.product),
  { message: "Cannot specify both cpe23 and product. Use only one." }
).refine(
  data => data.cpe23 || data.product,
  { message: "Must specify either cpe23 or product." }
);

// Helper Function to Query Shodan API
async function queryShodan(endpoint: string, params: Record<string, any>) {
  try {
    const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
      params: { ...params, key: SHODAN_API_KEY },
      timeout: 10000,
    });
    return response.data;
  } catch (error: any) {
    const errorMessage = error.response?.data?.error || error.message;
    logToFile(`Shodan API error: ${errorMessage}`);
    throw new Error(`Shodan API error: ${errorMessage}`);
  }
}

// Helper Function for CVE lookups using CVEDB
async function queryCVEDB(cveId: string) {
  try {
    logToFile(`Querying CVEDB for: ${cveId}`);
    const response = await axios.get(`${CVEDB_API_URL}/cve/${cveId}`);
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid CVE ID format: ${cveId}`);
    }
    if (error.response?.status === 404) {
      throw new Error(`CVE not found: ${cveId}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Helper Function for CPE lookups using CVEDB
async function queryCPEDB(params: {
  product: string;
  count?: boolean;
  skip?: number;
  limit?: number;
}) {
  try {
    logToFile(`Querying CVEDB for CPEs with params: ${JSON.stringify(params)}`);
    const response = await axios.get(`${CVEDB_API_URL}/cpes`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Helper Function for CVEs by product/CPE lookups using CVEDB
async function queryCVEsByProduct(params: {
  cpe23?: string;
  product?: string;
  count?: boolean;
  is_kev?: boolean;
  sort_by_epss?: boolean;
  skip?: number;
  limit?: number;
  start_date?: string;
  end_date?: string;
}) {
  try {
    logToFile(`Querying CVEDB for CVEs with params: ${JSON.stringify(params)}`);
    const response = await axios.get(`${CVEDB_API_URL}/cves`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Server Setup
const server = new Server(
  {
    name: "shodan-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
  }
);

// Handle Initialization
server.setRequestHandler(InitializeRequestSchema, async (request) => {
  logToFile("Received initialize request.");
  return {
    protocolVersion: "2024-11-05",
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
    serverInfo: {
      name: "shodan-mcp",
      version: "1.0.0",
    },
    instructions:
      "This server provides tools for querying Shodan, including IP lookups, searches, CVE lookups, CPE lookups, and CVE searches by product/CPE.",
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
    {
      name: "ip_lookup",
      description: "Retrieve information about an IP address.",
      inputSchema: zodToJsonSchema(IpLookupArgsSchema),
    },
    {
      name: "search",
      description: "Search for devices on Shodan.",
      inputSchema: zodToJsonSchema(SearchArgsSchema),
    },
    {
      name: "cve_lookup",
      description: "Retrieve vulnerability information for a CVE. Use format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)",
      inputSchema: zodToJsonSchema(CVELookupArgsSchema),
    },
    {
      name: "dns_lookup",
      description: "Perform DNS lookups using Shodan.",
      inputSchema: zodToJsonSchema(DnsLookupArgsSchema),
    },
    {
      name: "cpe_lookup",
      description: "Search for Common Platform Enumeration (CPE) entries by product name.",
      inputSchema: zodToJsonSchema(CpeLookupArgsSchema),
    },
    {
      name: "cves_by_product",
      description: "Search for CVEs affecting a specific product or CPE. Provide either product name or CPE 2.3 identifier.",
      inputSchema: zodToJsonSchema(CVEsByProductArgsSchema),
    },
  ];

  logToFile("Registered tools.");
  return { tools };
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logToFile(`Tool called: ${request.params.name}`);

  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "ip_lookup": {
        const parsedIpArgs = IpLookupArgsSchema.safeParse(args);
        if (!parsedIpArgs.success) {
          throw new Error("Invalid ip_lookup arguments");
        }
        const result = await queryShodan(`/shodan/host/${parsedIpArgs.data.ip}`, {});
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case "search": {
        const parsedSearchArgs = SearchArgsSchema.safeParse(args);
        if (!parsedSearchArgs.success) {
          throw new Error("Invalid search arguments");
        }
        const result = await queryShodan("/shodan/host/search", {
          query: parsedSearchArgs.data.query,
          limit: parsedSearchArgs.data.max_results,
        });
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case "cve_lookup": {
        const parsedCveArgs = CVELookupArgsSchema.safeParse(args);
        if (!parsedCveArgs.success) {
          throw new Error("Invalid CVE format. Please use format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)");
        }

        const cveId = parsedCveArgs.data.cve.toUpperCase();
        logToFile(`Looking up CVE: ${cveId}`);
        
        try {
          const result = await queryCVEDB(cveId);
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  cve_id: result.cve_id,
                  summary: result.summary,
                  cvss_v3: result.cvss_v3,
                  cvss_v2: result.cvss_v2,
                  epss: result.epss,
                  ranking_epss: result.ranking_epss,
                  kev: result.kev,
                  propose_action: result.propose_action,
                  ransomware_campaign: result.ransomware_campaign,
                  published: result.published_time,
                  references: result.references,
                  affected_products: result.cpes
                }, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      case "dns_lookup": {
        const parsedDnsArgs = DnsLookupArgsSchema.safeParse(args);
        if (!parsedDnsArgs.success) {
          throw new Error("Invalid dns_lookup arguments");
        }
        
        // Ensure proper formatting of hostnames for the API request
        const hostnamesString = parsedDnsArgs.data.hostnames.join(",");
        
        // Log the request parameters for debugging
        logToFile(`DNS lookup request parameters: ${JSON.stringify({ hostnames: hostnamesString })}`);
        
        const result = await queryShodan("/dns/resolve", {
          hostnames: hostnamesString
        });
        
        // Log the raw response for debugging
        logToFile(`DNS lookup raw response: ${JSON.stringify(result)}`);
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2)
            },
          ],
        };
      }

      case "cpe_lookup": {
        const parsedCpeArgs = CpeLookupArgsSchema.safeParse(args);
        if (!parsedCpeArgs.success) {
          throw new Error("Invalid cpe_lookup arguments");
        }

        try {
          const result = await queryCPEDB({
            product: parsedCpeArgs.data.product,
            count: parsedCpeArgs.data.count,
            skip: parsedCpeArgs.data.skip,
            limit: parsedCpeArgs.data.limit
          });

          // Format the response based on whether it's a count request or full CPE list
          const formattedResult = parsedCpeArgs.data.count
            ? { total_cpes: result.total }
            : {
                cpes: result.cpes,
                skip: parsedCpeArgs.data.skip,
                limit: parsedCpeArgs.data.limit,
                total_returned: result.cpes.length
              };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      case "cves_by_product": {
        const parsedArgs = CVEsByProductArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid arguments. Must provide either cpe23 or product name, but not both.");
        }

        try {
          const result = await queryCVEsByProduct({
            cpe23: parsedArgs.data.cpe23,
            product: parsedArgs.data.product,
            count: parsedArgs.data.count,
            is_kev: parsedArgs.data.is_kev,
            sort_by_epss: parsedArgs.data.sort_by_epss,
            skip: parsedArgs.data.skip,
            limit: parsedArgs.data.limit,
            start_date: parsedArgs.data.start_date,
            end_date: parsedArgs.data.end_date
          });

          // Format the response based on whether it's a count request or full CVE list
          const formattedResult = parsedArgs.data.count
            ? { total_cves: result.total }
            : {
                cves: result.cves,
                skip: parsedArgs.data.skip,
                limit: parsedArgs.data.limit,
                total_returned: result.cves.length,
                query_params: {
                  cpe23: parsedArgs.data.cpe23,
                  product: parsedArgs.data.product,
                  is_kev: parsedArgs.data.is_kev,
                  sort_by_epss: parsedArgs.data.sort_by_epss,
                  start_date: parsedArgs.data.start_date,
                  end_date: parsedArgs.data.end_date
                }
              };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logToFile(`Error handling tool call: ${errorMessage}`);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the Server
async function runServer() {
  logToFile("Starting Shodan MCP Server...");

  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logToFile("Shodan MCP Server is running.");
  } catch (error: any) {
    logToFile(`Error connecting server: ${error.message}`);
    process.exit(1);
  }
}

// Handle process events
process.on('uncaughtException', (error) => {
  logToFile(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

runServer().catch((error: any) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
