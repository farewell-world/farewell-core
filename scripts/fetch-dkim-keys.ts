import dns from "node:dns/promises";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { buildPoseidon } from "circomlibjs";

const SELECTORS_PATH = path.join(__dirname, "dkim-selectors.json");
const REGISTRY_PATH = path.join(__dirname, "dkim-registry.json");

const N = 121; // bits per chunk
const K = 17; // number of chunks

interface SelectorEntry {
  domain: string;
  selector: string;
  status: string;
}

interface RegistryEntry {
  domain: string;
  selector: string;
  status: string;
  pubkeyHashDecimal: string;
  pubkeyHashHex: string;
  modulusHex: string;
  fetchedAt: string;
}

function parseDkimTxtRecord(txtParts: string[]): string | null {
  const joined = txtParts.join("");
  const match = joined.match(/p=([A-Za-z0-9+/=\s]+)/);
  if (!match) return null;
  return match[1].replace(/\s+/g, "");
}

function extractRsaModulus(base64Pubkey: string): bigint {
  const der = Buffer.from(base64Pubkey, "base64");

  // Parse DER-encoded SubjectPublicKeyInfo for RSA
  // The modulus is the first INTEGER inside the BIT STRING
  const pubkey = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  const jwk = pubkey.export({ format: "jwk" });
  if (!jwk.n) throw new Error("Not an RSA key");

  // JWK 'n' is base64url-encoded big-endian modulus
  const modBytes = Buffer.from(jwk.n, "base64url");
  let modulus = 0n;
  for (const byte of modBytes) {
    modulus = (modulus << 8n) + BigInt(byte);
  }
  return modulus;
}

function bigintToChunks(num: bigint, bitsPerChunk: number, numChunks: number): bigint[] {
  const chunks: bigint[] = [];
  const mask = (1n << BigInt(bitsPerChunk)) - 1n;
  for (let i = 0; i < numChunks; i++) {
    chunks.push((num >> BigInt(i * bitsPerChunk)) & mask);
  }
  return chunks;
}

async function computePubkeyHash(modulus: bigint): Promise<bigint> {
  const poseidon = await buildPoseidon();

  // Replicate PoseidonLarge(121, 17) from @zk-email/circuits/utils/hash.circom
  const chunks = bigintToChunks(modulus, N, K);

  // halfChunkSize = 17 >> 1 = 8, + 1 (odd) = 9
  const halfChunkSize = (K >> 1) + (K % 2 === 1 ? 1 : 0);
  const poseidonInput: bigint[] = [];

  for (let i = 0; i < halfChunkSize; i++) {
    if (i === halfChunkSize - 1 && K % 2 === 1) {
      poseidonInput.push(chunks[2 * i]);
    } else {
      poseidonInput.push(chunks[2 * i] + (1n << BigInt(N)) * chunks[2 * i + 1]);
    }
  }

  // Poseidon(9)(poseidonInput)
  const hash = poseidon(poseidonInput);
  return poseidon.F.toObject(hash);
}

async function fetchDkimKeyViaDoh(name: string): Promise<string | null> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`;
  const resp = await fetch(url);
  if (!resp.ok) return null;
  const json: any = await resp.json();
  if (json.Status !== 0 || !json.Answer) return null;
  const txtAnswers = json.Answer.filter((a: any) => a.type === 16);
  if (txtAnswers.length === 0) return null;
  const data = txtAnswers.map((a: any) => a.data.replace(/^"|"$/g, "")).join("");
  return data;
}

async function fetchDkimKey(
  domain: string,
  selector: string,
): Promise<{ modulus: bigint; base64Key: string } | null> {
  const name = `${selector}._domainkey.${domain}`;

  let fullRecord: string | null = null;

  // Try native DNS first, fall back to DNS-over-HTTPS
  try {
    const records = await dns.resolveTxt(name);
    fullRecord = records.map((parts) => parts.join("")).join("");
  } catch {
    // Native DNS failed, try DoH
  }

  if (!fullRecord) {
    try {
      fullRecord = await fetchDkimKeyViaDoh(name);
    } catch {
      // DoH also failed
    }
  }

  if (!fullRecord) {
    console.error(`  DNS lookup failed for ${name} (both native and DoH)`);
    return null;
  }

  const base64Key = parseDkimTxtRecord([fullRecord]);
  if (!base64Key) {
    console.error(`  No p= tag found in TXT record for ${name}`);
    return null;
  }
  const modulus = extractRsaModulus(base64Key);
  return { modulus, base64Key };
}

async function main() {
  const isRefresh = process.argv.includes("--refresh");
  const selectors: SelectorEntry[] = JSON.parse(fs.readFileSync(SELECTORS_PATH, "utf-8"));

  let existingRegistry: RegistryEntry[] = [];
  if (isRefresh && fs.existsSync(REGISTRY_PATH)) {
    existingRegistry = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf-8"));
  }

  const registry: RegistryEntry[] = [];
  const changes: string[] = [];

  for (const entry of selectors) {
    const key = `${entry.selector}._domainkey.${entry.domain}`;
    console.log(`Fetching ${key} ...`);

    const result = await fetchDkimKey(entry.domain, entry.selector);
    if (!result) {
      const existing = existingRegistry.find(
        (e) => e.domain === entry.domain && e.selector === entry.selector,
      );
      if (existing) {
        changes.push(`NXDOMAIN: ${key} (was ${existing.pubkeyHashHex})`);
      }
      continue;
    }

    const hash = await computePubkeyHash(result.modulus);
    const hashHex = "0x" + hash.toString(16).padStart(64, "0");
    const modulusHex = "0x" + result.modulus.toString(16);

    const registryEntry: RegistryEntry = {
      domain: entry.domain,
      selector: entry.selector,
      status: entry.status,
      pubkeyHashDecimal: hash.toString(),
      pubkeyHashHex: hashHex,
      modulusHex,
      fetchedAt: new Date().toISOString(),
    };
    registry.push(registryEntry);

    if (isRefresh) {
      const existing = existingRegistry.find(
        (e) => e.domain === entry.domain && e.selector === entry.selector,
      );
      if (!existing) {
        changes.push(`NEW: ${key} → ${hashHex}`);
      } else if (existing.pubkeyHashHex !== hashHex) {
        changes.push(`ROTATED: ${key} ${existing.pubkeyHashHex} → ${hashHex}`);
      }
    }

    console.log(`  ✓ ${entry.domain} / ${entry.selector} → ${hashHex}`);
  }

  fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2) + "\n");
  console.log(`\nRegistry written to ${REGISTRY_PATH} (${registry.length} entries)`);

  if (isRefresh && changes.length > 0) {
    console.log("\n--- Changes since last fetch ---");
    for (const c of changes) console.log(`  ${c}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
