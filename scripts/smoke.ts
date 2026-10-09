/**
 * Opt-in live smoke test script.
 * Not part of CI; requires live network connectivity.
 *
 * Usage:
 *   npm run smoke
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runDetectionPipeline } from '../src/lib/detect/pipeline.ts';

interface GroundTruthItem {
  url: string;
  verifiedDate: string;
  verifiedMethod: string;
  expected: Record<string, string>;
}

async function main() {
  console.log('--- CMSSniff Live Smoke Verification ---');
  const gtPath = join(process.cwd(), 'scripts/ground-truth.json');
  const items: GroundTruthItem[] = JSON.parse(readFileSync(gtPath, 'utf-8'));

  let passCount = 0;
  let failCount = 0;

  for (const item of items) {
    console.log(`\nTesting: ${item.url} (verified: ${item.verifiedDate})`);
    try {
      const res = await runDetectionPipeline(item.url);
      if (!res.ok) {
        console.error(`  FAIL: Scan error: ${res.error.code} - ${res.error.message}`);
        failCount++;
        continue;
      }

      console.log(`  Status: ${res.status}, Coverage duration: ${res.coverage.durationMs}ms`);
      const detectedMap = new Map<string, string>();
      for (const r of res.data.results) {
        detectedMap.set(r.category, r.name);
      }

      let itemPassed = true;
      for (const [cat, expectedName] of Object.entries(item.expected)) {
        const actual = detectedMap.get(cat);
        if (actual && actual.toLowerCase().includes(expectedName.toLowerCase())) {
          console.log(`  PASS: [${cat}] Expected "${expectedName}", Detected "${actual}"`);
        } else {
          console.error(`  FAIL: [${cat}] Expected "${expectedName}", Actual "${actual ?? 'none'}"`);
          itemPassed = false;
        }
      }

      if (itemPassed) passCount++;
      else failCount++;
    } catch (err) {
      console.error(`  ERROR during scan:`, err);
      failCount++;
    }
  }

  console.log(`\n================================`);
  console.log(`Smoke Run Complete: ${passCount} passed, ${failCount} failed`);
  console.log(`================================`);
  if (failCount > 0) process.exit(1);
}

main().catch((err) => {
  console.error('Fatal error in smoke runner:', err);
  process.exit(1);
});
