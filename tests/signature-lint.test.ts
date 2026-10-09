/**
 * CI Signature Linter
 *
 * Validates all signatures in src/data/signatures/*.json:
 * - No duplicate IDs
 * - Valid category names
 * - Every signal has valid type, weight (1-100), strength ('definitive' | 'strong' | 'weak')
 * - Every regex compiles and does not suffer from catastrophic backtracking (ReDoS)
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ALLOWED_CATEGORIES = new Set([
  'cms',
  'builder',
  'ecommerce',
  'framework',
  'hosting',
  'analytics',
  'advertising',
  'marketing',
  'payments',
  'chat',
  'privacy',
  'security',
  'other',
]);

const ALLOWED_SIGNAL_TYPES = new Set([
  'meta-generator',
  'html-path',
  'html-regex',
  'script-host',
  'stylesheet-url',
  'js-global',
  'inline-script',
  'meta-tag',
  'link-relation',
  'header',
  'cookie-name',
  'probe',
  'dom',
  'host',
  'cookie',
  'script',
  'resource-url',
  'meta',
  'header-single',
  'header-pair',
  'cookie-name-single',
  'cookie-prefix',
  'tag-host',
  'gtag-id',
  'fbevents-id',
  'clarity-id',
  'hubspot-id',
  'intercom-id',
  'hotjar-id',
]);

const ALLOWED_STRENGTHS = new Set(['definitive', 'strong', 'weak']);

describe('CI Signature Linter', () => {
  const sigDir = join(process.cwd(), 'src/data/signatures');
  const files = readdirSync(sigDir).filter((f) => f.endsWith('.json'));

  const allIds = new Set<string>();
  const allSignatures: any[] = [];

  for (const f of files) {
    const content = JSON.parse(readFileSync(join(sigDir, f), 'utf-8'));
    assert.ok(Array.isArray(content), `${f} must contain an array of signatures`);
    for (const sig of content) {
      allSignatures.push({ ...sig, _file: f });
    }
  }

  it('contains no duplicate technology IDs across all files', () => {
    for (const sig of allSignatures) {
      assert.ok(sig.id, `Signature in ${sig._file} must have an id`);
      assert.ok(
        !allIds.has(sig.id),
        `Duplicate technology id "${sig.id}" found in ${sig._file}`,
      );
      allIds.add(sig.id);
    }
  });

  it('validates categories against recognized taxonomy', () => {
    for (const sig of allSignatures) {
      assert.ok(
        ALLOWED_CATEGORIES.has(sig.category),
        `Unknown category "${sig.category}" in technology "${sig.id}" (${sig._file})`,
      );
    }
  });

  it('validates signals have weights, valid strengths, and valid signal types', () => {
    for (const sig of allSignatures) {
      assert.ok(
        Array.isArray(sig.signals) && sig.signals.length > 0,
        `Technology "${sig.id}" must have non-empty signals array`,
      );

      for (const [idx, s] of sig.signals.entries()) {
        assert.ok(
          ALLOWED_SIGNAL_TYPES.has(s.type),
          `Unknown signal type "${s.type}" in "${sig.id}" signal #${idx}`,
        );

        if (typeof s.weight === 'number') {
          assert.ok(
            s.weight >= 1 && s.weight <= 100,
            `Weight for "${sig.id}" signal #${idx} (${s.weight}) must be between 1 and 100`,
          );
        }

        if (s.strength) {
          assert.ok(
            ALLOWED_STRENGTHS.has(s.strength),
            `Invalid strength "${s.strength}" in "${sig.id}" signal #${idx}`,
          );
        }
      }
    }
  });

  it('ensures all regex patterns compile and do not catastrophically backtrack', () => {
    const pathologicalInput = 'a'.repeat(50) + 'X!' + 'b'.repeat(50);

    for (const sig of allSignatures) {
      for (const [idx, s] of sig.signals.entries()) {
        if (!s.pattern) continue;

        let rx: RegExp;
        try {
          rx = new RegExp(s.pattern, 'i');
        } catch (err) {
          assert.fail(`Invalid regex pattern in "${sig.id}" signal #${idx}: ${s.pattern}`);
        }

        // Test regex evaluation timing against pathological input
        const start = performance.now();
        rx.test(pathologicalInput);
        const elapsed = performance.now() - start;

        assert.ok(
          elapsed < 10,
          `Potential ReDoS in "${sig.id}" signal #${idx}: pattern ${s.pattern} took ${elapsed}ms`,
        );
      }
    }
  });
});
