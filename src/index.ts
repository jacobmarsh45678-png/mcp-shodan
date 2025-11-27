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

// Shodan API Response Types
interface DnsResponse {
  [hostname: string]: string;  // Maps hostname to IP address
}

interface ReverseDnsResponse {
  [ip: string]: string[];  // Maps IP address to array of hostnames
}

interface SearchLocation {
  city: string | null;
  region_code: string | null;
  area_code: number | null;
  longitude: number;
  latitude: number;
  country_code: string;
  country_name: string;
}

interface SearchMatch {
  product?: string;
  hash: number;
  tags?: string[]; // <--- ADD THIS
  opts?: {         // <--- ADD THIS BLOCK
    screenshot?: boolean;
    [key: string]: any;
  };
  ip: number;
  ip_str: string;
  org: string;
  isp: string;
  transport: string;
  cpe?: string[];
  vulns?: string[];
  version?: string;
  hostnames: string[];
  domains: string[];
  snmp?: {
    sysDescr?: string;
    sysContact?: string;
    sysLocation?: string;
  };
  rfb?: {
    authentication?: string; // "disabled" or "vnc"
    version?: string;
  };
  location: SearchLocation;
  timestamp: string;
  port: number;
  mqtt?: {
    topics?: Record<string, string>; // Shodan returns topic: payload pairs
  };
  coap?: {
    resources?: Record<string, string>; // resource_path: title
  };
  data: string;
  asn: string;
  bacnet?: {
    instance_id?: number;
    object_id?: number;
    vendor_id?: number;
    vendor_name?: string;
    model_name?: string;
    firmware_revision?: string;
    application_software_revision?: string;
  };
  ssl?: {
    cert?: {
      serial?: string;
      subject?: {
        CN?: string;
        O?: string;
      };
      issuer?: {
        CN?: string;
        O?: string;
      };
      expired?: boolean;
      fingerprint?: {
        sha1?: string;
      };
    };
    cipher?: {
      name?: string;
      version?: string;
    };
  };
  http?: {
    server?: string;
    title?: string;
    favicon?: {
      hash?: number;
      location?: string;
    };
    components?: Record<string, { categories: string[] }>;
    robots?: string | null;
    sitemap?: string | null;
  };
}

interface SearchResponse {
  matches: SearchMatch[];
  facets: {
    country?: Array<{
      count: number;
      value: string;
    }>;
  };
  total: number;
}

interface ShodanService {
  port: number;
  transport: string;
  data?: string;
  http?: {
    server?: string;
    title?: string;
  };
  cloud?: {
    provider: string;
    service: string;
    region: string;
  };
}

interface CveResponse {
  cve_id: string;
  summary: string;
  cvss: number;
  cvss_version: number;
  cvss_v2: number;
  cvss_v3: number;
  epss: number;
  ranking_epss: number;
  kev: boolean;
  propose_action: string;
  ransomware_campaign: string;
  references: string[];
  published_time: string;
  cpes: string[];
}

interface ShodanHostResponse {
  ip_str: string;
  org: string;
  isp: string;
  asn: string;
  last_update: string;
  country_name: string;
  city: string;
  latitude: number;
  longitude: number;
  region_code: string;
  ports: number[];
  data: ShodanService[];
  hostnames: string[];
  domains: string[];
  tags: string[];
  vulns?: string[];
}

dotenv.config();

const logFilePath = path.join(os.tmpdir(), "mcp-shodan-server.log");
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
if (!SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required.");
}

const API_BASE_URL = "https://api.shodan.io";
const CVEDB_API_URL = "https://cvedb.shodan.io";
const DEFAULT_CREDS_DB: Record<string, string[]> = {
    "Moxa": ["admin:moxa", "admin:(blank)"],
    "Tridium": ["tridium:niagara", "admin:(blank)", "sysmik:intesa"],
    "Rockwell": ["Administrator:(blank)", "admin:password"],
    "Siemens": ["admin:(blank)", "Everybody:(no password)"],
    "Schneider": ["admin:admin", "Administrator:Administrator"],
    "WAGO": ["admin:wago", "user:user"],
    "Hirschmann": ["admin:private"],
    "Niagara": ["station:station", "admin:admin"]
};

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

const ShodanSearchArgsSchema = z.object({
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

const ReverseDnsLookupArgsSchema = z.object({
  ips: z.array(z.string()).describe("List of IP addresses to perform reverse DNS lookup on."),
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

function extractLeaks(data: string | undefined) {
    if (!data) return null;

    // 1. Network Leaks (Existing)
    const privateIpRegex = /(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}/g;
    const emailRegex = /[\w\.-]+@[\w\.-]+\.\w{2,}/g;
    
    // 2. Secret Leaks (New)
    // Detect RSA/DSA Private Keys
    const keyRegex = /-----BEGIN [A-Z]+ PRIVATE KEY-----/g;
    // Detect Basic Auth strings or API tokens (Heuristic)
    const tokenRegex = /(Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+|AKIA[0-9A-Z]{16})/g;
    // Detect Database Connection Strings
    const dbRegex = /(postgres|mysql|mongodb):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@/g;

    const ips = data.match(privateIpRegex) || [];
    const emails = data.match(emailRegex) || [];
    const keys = data.match(keyRegex) || [];
    const tokens = data.match(tokenRegex) || [];
    const dbs = data.match(dbRegex) || [];

    // Deduplicate
    const uniqueIPs = [...new Set(ips)];
    const uniqueEmails = [...new Set(emails)];
    const uniqueSecrets = [...new Set([...keys, ...tokens, ...dbs])];

    if (uniqueIPs.length === 0 && uniqueEmails.length === 0 && uniqueSecrets.length === 0) return null;

    return {
        "Internal IP Leaks": uniqueIPs.length > 0 ? uniqueIPs : "None",
        "Leaked Emails": uniqueEmails.length > 0 ? uniqueEmails : "None",
        // CRITICAL FINDINGS
        "Exposed Secrets": uniqueSecrets.length > 0 ? "🚨 CRITICAL: KEYS/TOKENS FOUND IN BANNER" : "None",
        "Secret Snippets": uniqueSecrets // Shows the actual leaked string (Be careful with this in reports)
    };
}

function parseS7Banner(banner: string | undefined) {
    if (!banner) return null;
   
    // Extract key OT details using Regex
    const moduleMatch = banner.match(/Module type:\s*([^\n]+)/);
    const firmwareMatch = banner.match(/Basic Firmware:\s*v\.?([\d\.]+)/);
    const serialMatch = banner.match(/Serial number of module:\s*([^\n]+)/);
    const plantIdMatch = banner.match(/Plant identification:\s*([^\n]+)/);

    if (!moduleMatch && !firmwareMatch) return null; // Not an S7 banner

    return {
        "Hardware Module": moduleMatch ? moduleMatch[1].trim() : "Unknown",
        "Firmware Version": firmwareMatch ? firmwareMatch[1].trim() : "Unknown",
        "Serial Number": serialMatch ? serialMatch[1].trim() : "Unknown",
        "Plant ID": plantIdMatch ? plantIdMatch[1].trim() : "None"
    };
}

function identifyDefaultCreds(product: string | undefined, org: string | undefined) {
    if (!product && !org) return null;
    const targets = [];
    for (const [vendor, creds] of Object.entries(DEFAULT_CREDS_DB)) {
        if (product?.toLowerCase().includes(vendor.toLowerCase()) || 
            org?.toLowerCase().includes(vendor.toLowerCase())) {
            targets.push(...creds);
        }
    }
    return targets.length > 0 ? targets : null;
}

function generateExploitLinks(cves: string[] | undefined) {
    if (!cves || cves.length === 0) return null;
    return cves.slice(0, 3).map(cve => ({
        "CVE": cve,
        "ExploitDB": `https://www.exploit-db.com/search?cve=${cve.replace("CVE-", "")}`,
        "PacketStorm": `https://packetstormsecurity.com/search/?q=${cve}`
    }));
}

// THE HEURISTIC BRIDGE (Option 2)
function guessCPE(product: string | undefined) {
    if (!product) return null;
    const p = product.toLowerCase();

    // Heuristics for common OT gear that Shodan often misses
    if (p.includes("s7-1200")) return "cpe:2.3:h:siemens:s7_1200:-:*:*:*:*:*:*:*";
    if (p.includes("s7-1500")) return "cpe:2.3:h:siemens:s7_1500:-:*:*:*:*:*:*:*";
    if (p.includes("s7-300")) return "cpe:2.3:h:siemens:s7_300:-:*:*:*:*:*:*:*";
    if (p.includes("niagara")) return "cpe:2.3:a:tridium:niagara:-:*:*:*:*:*:*:*";
    if (p.includes("micrologix")) return "cpe:2.3:h:rockwellautomation:micrologix:-:*:*:*:*:*:*:*";
    if (p.includes("controllogix")) return "cpe:2.3:h:rockwellautomation:controllogix:-:*:*:*:*:*:*:*";
    
    return null;
}

function extractEngineeringArtifacts(data: string | undefined) {
    if (!data) return null;

    // Regex for Critical ICS Project Files
    const artifactRegex = /[\w-]+\.(acd|ap[1-9][0-9]|pro|opt|v1[0-9]|pwx|scd|cid|mer|apa)/gi;
    
    const artifacts = data.match(artifactRegex);
    
    if (!artifacts) return null;

    // Deduplicate found files
    const uniqueArtifacts = [...new Set(artifacts)];

    return {
        "Artifacts Found": uniqueArtifacts,
        "Significance": "🚨 CRITICAL: Engineering/Project Files Detected. Source Code Leakage.",
        "File Types": uniqueArtifacts.map(f => f.split('.').pop()?.toUpperCase()).join(", ")
    };
}

function classifyInfrastructure(isp: string | undefined, org: string | undefined) {
    const s = (isp + " " + org).toLowerCase();
    
    // 1. Check for Cellular/Mobile (Remote Stations)
    if (s.match(/(wireless|mobility|cellular|4g|5g|lte|vodafone|t-mobile|verizon wireless|att mobility)/)) {
        return "📡 CELLULAR / REMOTE STATION (High Likelihood of Unmanned Site)";
    }

    // 2. Check for Residential (Shadow OT)
    if (s.match(/(cable|dsl|fios|residential|consumer|home|broadband|telekom|sky)/)) {
        return "🏠 RESIDENTIAL / SHADOW OT (Likely Engineer's Home)";
    }

    // 3. Check for Cloud/Hosting (Honeypot Risk)
    if (s.match(/(amazon|azure|digitalocean|google cloud|alibaba|tencent|oracle|hosting|vps)/)) {
        return "☁️ CLOUD HOSTING (High Risk of Honeypot)";
    }

    // 4. Default
    return "🏢 Enterprise / Business ISP";
}

function parseDNP3Banner(banner: string | undefined) {
    if (!banner) return null;

    // DNP3 often returns source/destination addresses in the raw hex or banner text
    // Shodan DNP3 banners usually look like "DNP3 Application Layer: ..."
    const sourceMatch = banner.match(/Source:\s*(\d+)/);
    const destMatch = banner.match(/Destination:\s*(\d+)/);
    
    // Check for "Controller" or "Outstation" strings common in DNP3 responses
    const typeMatch = banner.match(/(Outstation|Master|Controller)/i);

    if (!sourceMatch && !typeMatch) return null;

    return {
        "Role": typeMatch ? typeMatch[0] : "Unknown (Likely Outstation)",
        "Source Address": sourceMatch ? sourceMatch[1] : "Unknown",
        "Destination Address": destMatch ? destMatch[1] : "Unknown",
        "Protocol Warning": "Cleartext SCADA Protocol (No Auth)"
    };
}

function parseSNMPDetails(snmp: any) {
    if (!snmp) return null;

    return {
        "System Description": snmp.sysDescr || "None",
        "Location (Physical)": snmp.sysLocation || "Unknown",
        "Contact Person": snmp.sysContact || "Unknown"
    };
}

function predictOperationalRole(match: any) {
    // Combine all text sources into one searchable string
    const combinedData = JSON.stringify({
        data: match.data,
        org: match.org,
        products: match.product,
        webTitle: match.http?.title,
        snmpLoc: match.snmp?.sysLocation
    }).toLowerCase();

    // 1. Sector Prediction
    let sector = "Unknown / Generic";
    if (combinedData.match(/(water|pump|tank|sewage|waste|flow|valve|pipe)/)) sector = "💧 WATER / WASTEWATER";
    if (combinedData.match(/(volt|amp|grid|substation|solar|wind|energy|meter|power|hz)/)) sector = "⚡ ENERGY / POWER GRID";
    if (combinedData.match(/(hvac|chiller|boiler|temp|air|building|floor|room|door|access)/)) sector = "🏢 BUILDING AUTOMATION";
    if (combinedData.match(/(robot|arm|conveyor|factory|machine|production|line|plc)/)) sector = "🏭 MANUFACTURING";
    if (combinedData.match(/(traffic|light|cam|road|intersection|transit)/)) sector = "🚦 TRANSPORTATION / CITY";

    // 2. Physical Role Prediction
    let role = "General Automation Device";
    if (combinedData.includes("hmi") || combinedData.includes("scada") || combinedData.includes("visu")) role = "🖥️ Human-Machine Interface (HMI)";
    if (combinedData.includes("cam") || combinedData.includes("dvr") || combinedData.includes("nvr")) role = "📷 Surveillance System";
    if (combinedData.includes("printer") || combinedData.includes("copier")) role = "🖨️ Industrial Printer (High Leak Risk)";
    if (combinedData.includes("master")) role = "👑 Master Controller / Head End";
    if (combinedData.includes("sensor") || combinedData.includes("monitor")) role = "📡 Sensor / Monitor";

    // Only return if we found something interesting
    if (sector === "Unknown / Generic" && role === "General Automation Device") return null;

    return {
        "Predicted Sector": sector,
        "Physical Function": role,
        "Context Source": "Keyword Analysis of Banners"
    };
}

function parseVNCDetails(rfb: any) {
    if (!rfb) return null;

    const isAuthDisabled = rfb.authentication === "disabled";
    
    return {
        "Protocol Version": rfb.version || "Unknown",
        "Authentication Status": isAuthDisabled 
            ? "🚨 DISABLED (Unrestricted Access)" 
            : "Enabled",
        "Risk Assessment": isAuthDisabled 
            ? "CRITICAL - Direct Visual Control Possible" 
            : "Medium (Brute-force target)"
    };
}

function generatePivots(match: SearchMatch) {
    const pivots: Record<string, string> = {};

    // 1. Pivot by Favicon (Visual Signature)
    if (match.http?.favicon?.hash) {
        pivots["Find similar Web Interfaces"] = `http.favicon.hash:${match.http.favicon.hash}`;
    }

    // 2. Pivot by SSL Serial (Identity Signature)
    if (match.ssl?.cert?.serial) {
        // Shodan uses decimal format for serial searches usually, ensuring it's a string
        pivots["Find same Cert Authority"] = `ssl.cert.serial:${match.ssl.cert.serial}`;
    }

    // 3. Pivot by Organization (Network Block)
    if (match.org) {
        pivots["Find all Org Assets"] = `org:"${match.org}"`;
    }

    // 4. Pivot by Engineering Artifact (Software Version)
    // If we found a .ACD file, search for others leaking files
    if (match.data && match.data.includes(".acd")) {
        pivots["Find Rockwell Source Code Leaks"] = 'port:80,443,8080,21 ".acd"';
    }

    return Object.keys(pivots).length > 0 ? pivots : "No pivot points found";
}

function extractSBOM(http: any) {
    if (!http || !http.components) return null;

    // Convert Shodan's component map to a readable list
    const stack = Object.keys(http.components).map(comp => {
        const categories = http.components[comp].categories || [];
        return `${comp} (${categories.join(", ")})`;
    });

    // Check for high-risk legacy libraries
    const riskyLibs = stack.filter(s => 
        s.includes("jQuery 1.") || 
        s.includes("OpenSSL 1.0") || 
        s.includes("PHP 5")
    );

    return {
        "Full Stack": stack,
        "Supply Chain Risks": riskyLibs.length > 0 ? riskyLibs : "No obvious legacy libs"
    };
}

function analyzeWebStack(http: any) {
    if (!http) return null;

    const server = http.server || "Unknown";
    const title = http.title || "No Title";
    
    // Tactical Web Intelligence
    const dangerousServers: Record<string, string> = {
        "RomPager": "⚠️ Vulnerable to 'Misfortune Cookie' (CVE-2014-9222)",
        "GoAhead-Webs": "⚠️ Common IoT Target (Check CVE-2017-17562)",
        "Boa": "⚠️ Discontinued/Legacy (High Risk)",
        "MicroHttpd": "⚠️ Minimal IoT Server (Often Fuzzable)"
    };

    // Check if the server string matches any known bad targets
    const threatIntel = Object.entries(dangerousServers).find(([k, v]) => server.includes(k));

    return {
        "Server Software": server,
        "Page Title": title,
        "Vulnerability Hint": threatIntel ? threatIntel[1] : "Standard Web Stack",
        "Components": http.components ? Object.keys(http.components).join(", ") : "None detected"
    };
}

function parseModbusBanner(banner: string | undefined) {
    if (!banner) return null;

    // Modbus banners in Shodan data often look like: "Unit ID: 1\nSlave ID Data: ..."
    const unitIdMatch = banner.match(/Unit ID:\s*(\d+)/);
    const slaveIdMatch = banner.match(/Slave ID Data:\s*([^\n]+)/);
    const funcCodeMatch = banner.match(/Function Code:\s*(\d+)/);
    const exceptionMatch = banner.match(/Exception Code:\s*(\d+)/);

    if (!unitIdMatch && !slaveIdMatch) return null;

    return {
        "Unit ID": unitIdMatch ? unitIdMatch[1] : "Unknown",
        "Slave Data": slaveIdMatch ? slaveIdMatch[1].trim() : "None",
        "Response Type": exceptionMatch ? `⚠️ Exception Error (${exceptionMatch[1]})` : "Normal Response"
    };
}

function parseBACnetDetails(bacnet: any) {
    if (!bacnet) return null;

    return {
        "Device Instance": bacnet.instance_id || "Unknown",
        "Vendor": bacnet.vendor_name || `Vendor ID ${bacnet.vendor_id}` || "Unknown",
        "Model": bacnet.model_name || "Unknown",
        "Firmware": bacnet.firmware_revision || "Unknown",
        "Application Software": bacnet.application_software_revision || "None"
    };
}

function analyzeCertificate(ssl: any) {
    if (!ssl || !ssl.cert) return null;

    const subject = ssl.cert.subject || {};
    const issuer = ssl.cert.issuer || {};
    const isSelfSigned = subject.CN === issuer.CN && subject.O === issuer.O;
    const isExpired = ssl.cert.expired;

    let hygieneScore = "GOOD";
    if (isExpired) hygieneScore = "POOR (Expired)";
    if (isSelfSigned) hygieneScore = "RISKY (Self-Signed)";

    return {
        "Owner (Subject)": subject.O || subject.CN || "Unknown",
        "Issuer": issuer.O || issuer.CN || "Unknown",
        "Status": isExpired ? "⚠️ EXPIRED" : "Valid",
        "Type": isSelfSigned ? "⚠️ Self-Signed (Internal Use?)" : "Public CA",
        "Hygiene Check": hygieneScore
    };
}

function parseEtherNetIPBanner(banner: string | undefined) {
    if (!banner) return null;

    // Rockwell/EtherNet-IP banners usually contain these fields
    const productMatch = banner.match(/Product Name:\s*([^\n]+)/);
    const vendorMatch = banner.match(/Vendor ID:\s*([^\n]+)/);
    const serialMatch = banner.match(/Serial Number:\s*0x([0-9A-Fa-f]+)/);
    const deviceTypeMatch = banner.match(/Device Type:\s*([^\n]+)/);

    // If we don't find a product name, it's likely not a rich EtherNet/IP banner
    if (!productMatch) return null;

    return {
        "Vendor": vendorMatch ? vendorMatch[1].trim() : "Unknown (Likely Rockwell)",
        "Product": productMatch[1].trim(), // e.g., "1769-L30ER"
        "Device Type": deviceTypeMatch ? deviceTypeMatch[1].trim() : "Unknown",
        "Serial Hex": serialMatch ? serialMatch[1] : "Unknown"
    };
}

function analyzeHardwareProfile(product: string | undefined, banner: string | undefined) {
    const text = ((product || "") + " " + (banner || "")).toLowerCase();
    
    // 1. "Muscle" - Kinetic Hazards (Motors, Drives, Servos)
    // These devices physically move things. High danger.
    if (text.match(/(powerflex|kinetix|altivar|sinamics|micromaster|variator|drive|servo|motion)/)) {
        return {
            "Class": "⚙️ MOTOR DRIVE / VFD (The 'Muscle')",
            "Kinetic Risk": "🚨 HIGH - Can cause physical destruction (Over-speed/Torque)",
            "Role": "Controls physical motion of pumps, fans, or robots."
        };
    }

    // 2. "Nervous System" - Network Infrastructure
    // These connect the plant. Disruption causes loss of view.
    if (text.match(/(stratix|scalance|moxa nport|eds-|cisco ie|hirschmann|transceiver|gateway|router|switch)/)) {
        return {
            "Class": "🌐 INDUSTRIAL SWITCH / GATEWAY (The 'Nervous System')",
            "Kinetic Risk": "Low - Primary risk is Denial of Service (Blindness)",
            "Role": "Connects OT assets to the network."
        };
    }

    // 3. "Face" - Human Machine Interfaces
    // These allow operators to click buttons.
    if (text.match(/(panelview|simatic hmi|comfort panel|magelis|pro-face|factorytalk|wincc|visu)/)) {
        return {
            "Class": "🖥️ HMI PANEL (The 'Face')",
            "Kinetic Risk": "Medium - Depends on available buttons/screens",
            "Role": "Operator visualization and manual control."
        };
    }

    // 4. "Brain" - Controllers (Default if identifying as ICS)
    if (text.match(/(plc|controller|logix|simatic|modicon|micro800|s7-|crio|rtu)/)) {
        return {
            "Class": "🧠 PLC / CONTROLLER (The 'Brain')",
            "Kinetic Risk": "High - Controls logic and safety overrides",
            "Role": "Executes the automation logic."
        };
    }

    return {
        "Class": "Unknown Industrial Device",
        "Kinetic Risk": "Unknown",
        "Role": "General Automation"
    };
}

function parseMQTTDetails(mqtt: any) {
    if (!mqtt || !mqtt.topics) return null;

    const topics = Object.keys(mqtt.topics);
    // Topics often look like path/to/device/variable
    // We analyze the path depth to guess the complexity of the facility
    const pathDepth = topics.map(t => t.split('/').length).reduce((a, b) => a + b, 0) / topics.length;

    return {
        "Topic Count": topics.length,
        "Structure Leaks": topics.slice(0, 5), // Show top 5 topics for context
        "Complexity Score": pathDepth > 3 ? "HIGH (Deep Hierarchy Leaked)" : "Low",
        "Raw Topics": topics.length > 5 ? `${topics.length - 5} more...` : "All listed"
    };
}

function parseCoAPDetails(coap: any) {
    if (!coap || !coap.resources) return null;
    
    const resources = Object.keys(coap.resources);
    
    return {
        "Resource Count": resources.length,
        "Endpoints": resources.slice(0, 5),
        "Device Hint": resources.some(r => r.includes("meter") || r.includes("grid")) 
            ? "Likely Smart Meter/Grid" 
            : "Generic IoT"
    };
}

function calculateHoneypotRisk(host: any): string {
    let riskScore = 0;
    const cloudProviders = ["Amazon", "DigitalOcean", "Google", "Microsoft", "Alibaba", "Tencent", "Oracle"];
    
    // Known Honeypot Artifacts (e.g., Default Conpot S7 Serial Number)
    const knownHoneypotSerials = ["88111222", "00000000"]; 
    
    // CHECK 1: Cloud Hosting
    if (cloudProviders.some(provider => host.org?.includes(provider) || host.isp?.includes(provider))) {
        riskScore += 50;
    }

    // CHECK 2: Port Noise
    if (host.ports && host.ports.length > 5) {
        riskScore += 30;
    }

    // CHECK 3: Artifact Detection (Deep Inspection)
    const bannerStr = JSON.stringify(host.data);
    if (knownHoneypotSerials.some(serial => bannerStr.includes(serial))) {
        riskScore += 100; // Immediate flag
    }

    // CHECK 4: Tag check
    if (host.tags && host.tags.includes("honeypot")) {
        riskScore += 100;
    }

    if (riskScore >= 100) return "CRITICAL (Confirmed Honeypot Artifact)";
    if (riskScore >= 50) return "HIGH (Likely Honeypot)";
    if (riskScore >= 30) return "MEDIUM (Suspicious)";
    return "LOW (Likely Real Asset)";
}

function assessThreatLevel(cve: any) {
    const epssScore = cve.epss || 0;
    const isKEV = cve.kev === true;
    const cvssScore = cve.cvss_v3 || cve.cvss_v2 || 0;
    const ransomware = cve.ransomware_campaign;

    let riskLevel = "LOW";
    let recommendation = "Monitor during routine maintenance.";
    let justification = [];

    // 1. Criticality Check (The "House is on Fire" Check)
    if (isKEV || ransomware) {
        riskLevel = "CRITICAL (Active Threat)";
        recommendation = "IMMEDIATE ISOLATION OR PATCH REQUIRED.";
        if (isKEV) justification.push("Listed in CISA Known Exploited Vulnerabilities.");
        if (ransomware) justification.push(`Associated with ransomware campaign: ${ransomware}.`);
    } 
    // 2. High Probability Check (The "Smoking Gun" Check)
    else if (epssScore > 0.1 || cvssScore >= 9.0) {
        riskLevel = "HIGH";
        recommendation = "Prioritize patching in next cycle.";
        if (epssScore > 0.1) justification.push(`High probability of exploitation (${(epssScore * 100).toFixed(2)}%).`);
        if (cvssScore >= 9.0) justification.push("Critical severity score.");
    }
    // 3. Medium Risk
    else if (cvssScore >= 7.0) {
        riskLevel = "MEDIUM";
        justification.push("High severity, but low current exploit probability.");
    }

    return {
        "Risk Level": riskLevel,
        "Recommendation": recommendation,
        "Key Factors": justification
    };
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
    instructions: `This MCP server provides comprehensive access to Shodan's network intelligence and security services:

- Network Reconnaissance: Query detailed information about IP addresses, including open ports, services, and vulnerabilities
- DNS Operations: Forward and reverse DNS lookups for domains and IP addresses
- Vulnerability Intelligence: Access to Shodan's CVEDB for detailed vulnerability information, CPE lookups, and product-specific CVE tracking
- Device Discovery: Search Shodan's database of internet-connected devices with advanced filtering

Each tool provides structured, formatted output for easy analysis and integration.`,
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
    {
      name: "ip_lookup",
      description: "Retrieve comprehensive information about an IP address, including geolocation, open ports, running services, SSL certificates, hostnames, and cloud provider details if available. Returns service banners and HTTP server information when present.",
      inputSchema: zodToJsonSchema(IpLookupArgsSchema),
    },
    {
      name: "shodan_search",
      description: "Search Shodan's database of internet-connected devices. Returns detailed information about matching devices including services, vulnerabilities, and geographic distribution. Supports advanced search filters and returns country-based statistics.",
      inputSchema: zodToJsonSchema(ShodanSearchArgsSchema),
    },
    {
      name: "ot_asset_search",
      description: "Specialized search for Industrial Control Systems (OT). Maps high-level device types to specific, high-fidelity Shodan queries (ports, tags, and product names). Use this for finding PLCs, HMIs, or specific protocols.",
      inputSchema: zodToJsonSchema(z.object({
        asset_type: z.enum(["siemens_s7", "modbus_generic", "niagara_building", "bacnet_building", "ethernet_ip", "omron_plc", "mqtt_iiot", "coap_smartgrid", "vnc_hmi", "snmp_infrastructure", "general_ics"])
          .describe("The specific class of OT device to hunt for."),
        country: z.string().length(2).optional().describe("2-letter country code (e.g., 'DE', 'US')."),
        org: z.string().optional().describe("Filter by specific organization name."),
      })),
    },
    {
      name: "cve_lookup",
      description: "Query detailed vulnerability information from Shodan's CVEDB. Returns comprehensive CVE details including CVSS scores (v2/v3), EPSS probability and ranking, KEV status, proposed mitigations, ransomware associations, and affected products (CPEs).",
      inputSchema: zodToJsonSchema(CVELookupArgsSchema),
    },
    {
      name: "dns_lookup",
      description: "Resolve domain names to IP addresses using Shodan's DNS service. Supports batch resolution of multiple hostnames in a single query. Returns IP addresses mapped to their corresponding hostnames.",
      inputSchema: zodToJsonSchema(DnsLookupArgsSchema),
    },
    {
      name: "cpe_lookup",
      description: "Search for Common Platform Enumeration (CPE) entries by product name in Shodan's CVEDB. Supports pagination and can return either full CPE details or just the total count. Useful for identifying specific versions and configurations of software and hardware.",
      inputSchema: zodToJsonSchema(CpeLookupArgsSchema),
    },
    {
      name: "cves_by_product",
      description: "Search for vulnerabilities affecting specific products or CPEs. Supports filtering by KEV status, sorting by EPSS score, date ranges, and pagination. Can search by product name or CPE 2.3 identifier. Returns detailed vulnerability information including severity scores and impact assessments.",
      inputSchema: zodToJsonSchema(CVEsByProductArgsSchema),
    },
    {
      name: "reverse_dns_lookup",
      description: "Perform reverse DNS lookups to find hostnames associated with IP addresses. Supports batch lookups of multiple IP addresses in a single query. Returns all known hostnames for each IP address, with clear indication when no hostnames are found.",
      inputSchema: zodToJsonSchema(ReverseDnsLookupArgsSchema),
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
        
        // Format the response in a user-friendly way
        const formattedResult = {
          "IP Information": {
            "IP Address": result.ip_str,
            "Organization": result.org,
            "ISP": result.isp,
            "ASN": result.asn,
            "Last Update": result.last_update
          },
          "OT Security Context": {
              "Honeypot Risk": calculateHoneypotRisk(result), // Pass the host object here
              "Cloud Hosted": result.org // Useful context
          },
          "Vulnerabilities": result.vulns && result.vulns.length > 0 
            ? result.vulns 
            : "No vulnerabilities found",
          "Location": {
            "Country": result.country_name,
            "City": result.city,
            "Coordinates": `${result.latitude}, ${result.longitude}`,
            "Region": result.region_code
          },
          "Services": result.ports.map((port: number) => {
            const service = result.data.find((d: ShodanService) => d.port === port);
            return {
              "Port": port,
              "Protocol": service?.transport || "unknown",
              "Service": service?.data?.trim() || "No banner",
              ...(service?.http ? {
                "HTTP": {
                  "Server": service.http.server,
                  "Title": service.http.title,
                }
              } : {})
            };
          }),
          "Cloud Provider": result.data[0]?.cloud ? {
            "Provider": result.data[0].cloud.provider,
            "Service": result.data[0].cloud.service,
            "Region": result.data[0].cloud.region
          } : "Not detected",
          "Hostnames": result.hostnames || [],
          "Domains": result.domains || [],
          "Tags": result.tags || []
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2),
            },
          ],
        };
      }

      case "shodan_search": {
        const parsedSearchArgs = ShodanSearchArgsSchema.safeParse(args);
        if (!parsedSearchArgs.success) {
          throw new Error("Invalid search arguments");
        }
        const result: SearchResponse = await queryShodan("/shodan/host/search", {
          query: parsedSearchArgs.data.query,
          limit: parsedSearchArgs.data.max_results,
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "Search Summary": {
            "Query": parsedSearchArgs.data.query,
            "Total Results": result.total,
            "Results Returned": result.matches.length
          },
          "Country Distribution": result.facets?.country?.map(country => ({
            "Country": country.value,
            "Count": country.count,
            "Percentage": `${((country.count / result.total) * 100).toFixed(2)}%`
          })) || [],
          "Matches": result.matches.map(match => ({
            "Basic Information": {
              "IP Address": match.ip_str,
              "Organization": match.org,
              "ISP": match.isp,
              "ASN": match.asn,
              "Last Update": match.timestamp
            },
            "Location": {
              "Country": match.location.country_name,
              "City": match.location.city || "Unknown",
              "Region": match.location.region_code || "Unknown",
              "Coordinates": `${match.location.latitude}, ${match.location.longitude}`
            },
            "OT Security Context": {
                "Honeypot Risk": calculateHoneypotRisk(match), // Pass the host object here
                "Cloud Hosted": match.org // Useful context
            },
            "Service Details": {
              "Port": match.port,
              "Transport": match.transport,
              "Product": match.product || "Unknown",
              "Version": match.version || "Unknown",
              "CPE": match.cpe || []
            },
            "Vulnerabilities": match.vulns && match.vulns.length > 0 
              ? match.vulns 
              : "None detected",
            "Web Information": match.http ? {
              "Server": match.http.server,
              "Title": match.http.title,
              "Robots.txt": match.http.robots ? "Present" : "Not found",
              "Sitemap": match.http.sitemap ? "Present" : "Not found"
            } : "No HTTP information",
            "Hostnames": match.hostnames,
            "Domains": match.domains
          }))
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2),
            },
          ],
        };
      }

      case "ot_asset_search": {
          // 1. Parse Arguments
          const parsedArgs = z.object({
            asset_type: z.enum(["siemens_s7", "modbus_generic", "niagara_building", "bacnet_building", "ethernet_ip", "omron_plc", "mqtt_iiot", "coap_smartgrid", "vnc_hmi", "dnp3_energy", "snmp_infrastructure", "general_ics"]),
            country: z.string().length(2).optional(),
            org: z.string().optional(),
          }).safeParse(args);

          if (!parsedArgs.success) {
            throw new Error("Invalid arguments for ot_asset_search");
          }

          // 2. Build Query
          const queryMap: Record<string, string> = {
              "siemens_s7": 'port:102 "Original Siemens Equipment"',
              "modbus_generic": 'port:502',
              "niagara_building": 'port:1911,4911 product:"Niagara"',
              "bacnet_building": 'port:47808',
              "dnp3_energy": 'port:20000 source address',
              "ethernet_ip": 'port:44818',
              "omron_plc": 'port:9600 response:"OMRON"',
              "mqtt_iiot": 'port:1883',
              "coap_smartgrid": 'port:5683',
              "vnc_hmi": 'port:5900',
              "snmp_infrastructure": 'port:161',
              "general_ics": 'tag:ics'
          };

          let finalQuery = queryMap[parsedArgs.data.asset_type];
          if (parsedArgs.data.country) finalQuery += ` country:"${parsedArgs.data.country}"`;
          if (parsedArgs.data.org) finalQuery += ` org:"${parsedArgs.data.org}"`;

          // 3. Execute Query
          const result: SearchResponse = await queryShodan("/shodan/host/search", {
              query: finalQuery,
              limit: 10,
          });

          // 4. Format Output
          const formattedResult = {
            "OT Hunt Summary": {
                "Target": parsedArgs.data.asset_type,
                "Query Used": finalQuery,
                "Total Found": result.total
            },
            "Assets Found": result.matches.map(match => {
                // Run Heuristics & Helpers
                const guessedCPE = guessCPE(match.product);
                const defaultCreds = identifyDefaultCreds(match.product, match.org);
                const exploits = generateExploitLinks(match.vulns);
                const infraType = classifyInfrastructure(match.isp, match.org);
                const pivots = generatePivots(match);
                const sbom = match.http ? extractSBOM(match.http) : "No Web Components";

                return {
                    "IP": match.ip_str,
                    "Organization": match.org,
                    "Location": {
                        "City": `${match.location.city}, ${match.location.country_name}`,
                        "Coordinates": `${match.location.latitude}, ${match.location.longitude}`,
                        "Map View": `https://www.google.com/maps?q=${match.location.latitude},${match.location.longitude}`                    },
                    "Risk Analysis": {
                        "Honeypot Level": calculateHoneypotRisk(match),
                        "Critical Threats": match.tags && match.tags.includes("kev") 
                            ? "⚠️ CONTAINS KNOWN EXPLOITED VULNERABILITIES" 
                            : "No active exploitation tags",
                        "Open Ports": match.port
                    },
                    "Tactical Intelligence": {
                        "Potential Defaults": defaultCreds 
                            ? `⚠️ TRY: ${defaultCreds.join(" | ")}` 
                            : "None identified",
                        "Vulnerability Status": match.vulns ? `${match.vulns.length} CVEs identified` : "None listed",
                        "Automated Research": match.cpe && match.cpe.length > 0
                            ? `Use tool 'cves_by_product' with cpe23: '${match.cpe[0]}'`
                            : (guessedCPE 
                                ? `⚠️ Shodan missed the CPE. My heuristic suggests: '${guessedCPE}'`
                                : "No CPE match found"),
                        "Exploit Resources": exploits || "No CVEs mapped"
                    },
                    "Infrastructure Type": classifyInfrastructure(match.isp, match.org),
                    "HMI Screenshot": match.opts && match.opts.screenshot ? "📸 YES (View on Shodan Website)" : "No image captured",
                    "Pivot Points (Lateral Movement)": generatePivots(match),
                    "Software Supply Chain": match.http ? extractSBOM(match.http) : "No Web Components",
                    "Operational Context": predictOperationalRole(match) || "Insufficient Data to Predict Role",
                    "Hardware Profile": analyzeHardwareProfile(match.product, match.data),
                    "OT Details": {
                        "Product": match.product || "Unknown",
                        "Protocol": match.transport,
                        
                        // --- PROTOCOL PARSERS ---
                        ...(match.port === 102 ? { "Siemens Internals": parseS7Banner(match.data) } : {}),
                        ...(match.port === 44818 ? { "Rockwell Internals": parseEtherNetIPBanner(match.data) } : {}),
                        ...(match.port === 502 ? { "Modbus Internals": parseModbusBanner(match.data) } : {}),
                        ...(match.port === 20000 ? { "DNP3 Details": parseDNP3Banner(match.data) } : {}), // <--- Wired DNP3
                        ...(match.port === 47808 ? { "BACnet Details": parseBACnetDetails(match.bacnet) } : {}),
                    
                        // --- HMI / IoT PARSERS ---
                        ...(match.port === 1883 ? { "MQTT Broker (IIoT)": parseMQTTDetails(match.mqtt) } : {}),
                        ...(match.port === 5683 ? { "CoAP Device": parseCoAPDetails(match.coap) } : {}),
                        ...(match.port === 5900 ? { "VNC / HMI Panel": parseVNCDetails(match.rfb) } : {}),
                        ...(match.port === 161 ? { "SNMP Details": parseSNMPDetails(match.snmp) } : {}),
                      
                        // --- WEB FORENSICS ---
                        ...(match.http ? { "Web Interface Intel": analyzeWebStack(match.http) } : {}),

                        // --- ARTIFACTS & LEAKS ---
                        ...(extractEngineeringArtifacts(match.data) ? { "Engineering Artifacts": extractEngineeringArtifacts(match.data) } : {}),
                        ...(extractLeaks(match.data) ? { "Information Leakage": extractLeaks(match.data) } : {}),

                        // --- IDENTITY ---
                        ...(match.ssl ? { "Digital Identity (SSL)": analyzeCertificate(match.ssl) } : {}),

                        "Raw Banner Snippet": match.data ? match.data.substring(0, 50) + "..." : "Empty"
                    }
                };
            })
          };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
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

          // Helper function to format CVSS score severity
          const getCvssSeverity = (score: number) => {
            if (score >= 9.0) return "Critical";
            if (score >= 7.0) return "High";
            if (score >= 4.0) return "Medium";
            if (score >= 0.1) return "Low";
            return "None";
          };

          // Format the response in a user-friendly way
          const formattedResult = {
            "Basic Information": {
              "CVE ID": result.cve_id,
              "Published": new Date(result.published_time).toLocaleString(),
              "Summary": result.summary
            },
            "Severity Scores": {
              "CVSS v3": result.cvss_v3 ? {
                "Score": result.cvss_v3,
                "Severity": getCvssSeverity(result.cvss_v3)
              } : "Not available",
              "CVSS v2": result.cvss_v2 ? {
                "Score": result.cvss_v2,
                "Severity": getCvssSeverity(result.cvss_v2)
              } : "Not available",
              "EPSS": result.epss ? {
                "Score": `${(result.epss * 100).toFixed(2)}%`,
                "Ranking": `Top ${(result.ranking_epss * 100).toFixed(2)}%`
              } : "Not available"
            },
            "Threat Intelligence & Strategy": {
                ...assessThreatLevel(result), // Injects Risk Level, Recommendation, and Factors
                "Context": {
                    "Known Exploited (KEV)": result.kev ? "⚠️ YES - CISA LISTED" : "No",
                    "Ransomware Link": result.ransomware_campaign ? `⚠️ ${result.ransomware_campaign}` : "None known",
                    "Exploit Prediction (EPSS)": result.epss ? `${(result.epss * 100).toFixed(2)}% chance of exploitation` : "N/A"
                }
            },
            "Affected Products": result.cpes?.length > 0 ? result.cpes : ["No specific products listed"],
            "Additional Information": {
              "References": result.references?.length > 0 ? result.references : ["No references provided"]
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

      case "dns_lookup": {
        const parsedDnsArgs = DnsLookupArgsSchema.safeParse(args);
        if (!parsedDnsArgs.success) {
          throw new Error("Invalid dns_lookup arguments");
        }
        
        // Join hostnames with commas for the API request
        const hostnamesString = parsedDnsArgs.data.hostnames.join(",");
        
        const result: DnsResponse = await queryShodan("/dns/resolve", {
          hostnames: hostnamesString
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "DNS Resolutions": Object.entries(result).map(([hostname, ip]) => ({
            "Hostname": hostname,
            "IP Address": ip
          })),
          "Summary": {
            "Total Lookups": Object.keys(result).length,
            "Queried Hostnames": parsedDnsArgs.data.hostnames
          }
        };
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2)
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

          // Helper function to format CVSS score severity
          const getCvssSeverity = (score: number) => {
            if (score >= 9.0) return "Critical";
            if (score >= 7.0) return "High";
            if (score >= 4.0) return "Medium";
            if (score >= 0.1) return "Low";
            return "None";
          };

          // Format the response based on whether it's a count request or full CVE list
          const formattedResult = parsedArgs.data.count
            ? {
                "Query Information": {
                  "Product": parsedArgs.data.product || "N/A",
                  "CPE 2.3": parsedArgs.data.cpe23 || "N/A",
                  "KEV Only": parsedArgs.data.is_kev ? "Yes" : "No",
                  "Sort by EPSS": parsedArgs.data.sort_by_epss ? "Yes" : "No"
                },
                "Results": {
                  "Total CVEs Found": result.total
                }
              }
            : {
                "Query Information": {
                  "Product": parsedArgs.data.product || "N/A",
                  "CPE 2.3": parsedArgs.data.cpe23 || "N/A",
                  "KEV Only": parsedArgs.data.is_kev ? "Yes" : "No",
                  "Sort by EPSS": parsedArgs.data.sort_by_epss ? "Yes" : "No",
                  "Date Range": parsedArgs.data.start_date ? 
                    `${parsedArgs.data.start_date} to ${parsedArgs.data.end_date || 'now'}` : 
                    "All dates"
                },
                "Results Summary": {
                  "Total CVEs Found": result.total,
                  "CVEs Returned": result.cves.length,
                  "Page": `${Math.floor(parsedArgs.data.skip! / parsedArgs.data.limit!) + 1}`,
                  "CVEs per Page": parsedArgs.data.limit
                },
                "Vulnerabilities": result.cves.map((cve: CveResponse) => ({
                  "Basic Information": {
                    "CVE ID": cve.cve_id,
                    "Published": new Date(cve.published_time).toLocaleString(),
                    "Summary": cve.summary
                  },
                  "Severity Scores": {
                    "CVSS v3": cve.cvss_v3 ? {
                      "Score": cve.cvss_v3,
                      "Severity": getCvssSeverity(cve.cvss_v3)
                    } : "Not available",
                    "CVSS v2": cve.cvss_v2 ? {
                      "Score": cve.cvss_v2,
                      "Severity": getCvssSeverity(cve.cvss_v2)
                    } : "Not available",
                    "EPSS": cve.epss ? {
                      "Score": `${(cve.epss * 100).toFixed(2)}%`,
                      "Ranking": `Top ${(cve.ranking_epss * 100).toFixed(2)}%`
                    } : "Not available"
                  },
                  "Impact Assessment": {
                    "Known Exploited Vulnerability": cve.kev ? "Yes" : "No",
                    "Proposed Action": cve.propose_action || "No specific action proposed",
                    "Ransomware Campaign": cve.ransomware_campaign || "No known ransomware campaigns"
                  },
                  "References": cve.references?.length > 0 ? cve.references : ["No references provided"]
                }))
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

      case "reverse_dns_lookup": {
        const parsedArgs = ReverseDnsLookupArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid reverse_dns_lookup arguments");
        }
        
        // Join IPs with commas for the API request
        const ipsString = parsedArgs.data.ips.join(",");
        
        const result: ReverseDnsResponse = await queryShodan("/dns/reverse", {
          ips: ipsString
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "Reverse DNS Resolutions": Object.entries(result).map(([ip, hostnames]) => ({
            "IP Address": ip,
            "Hostnames": hostnames.length > 0 ? hostnames : ["No hostnames found"]
          })),
          "Summary": {
            "Total IPs Queried": parsedArgs.data.ips.length,
            "IPs with Results": Object.keys(result).length,
            "Queried IP Addresses": parsedArgs.data.ips
          }
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2)
            },
          ],
        };
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
