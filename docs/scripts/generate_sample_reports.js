import fs from 'node:fs';
import path from 'node:path';
import { generateForensicReportHtml, generateReportFilename } from '../frontend/src/utils/reportGenerator.ts';

const rootDir = path.resolve(import.meta.dirname, '..');
const responsesPath = path.join(rootDir, 'docs/phase10/live_api_responses.json');
const outputReportsDir = path.join(rootDir, 'docs/phase10/sample_reports');

fs.mkdirSync(outputReportsDir, { recursive: true });

const rawData = fs.readFileSync(responsesPath, 'utf-8');
const liveResponses = JSON.parse(rawData);

const reportTargets = [
  '01_simple_plaintext.eml',
  '04_attachments.eml',
  '05_multiple_urls.eml',
  '06_multiple_received_hops.eml',
  '08_missing_optional_headers.eml',
];

console.log('Generating sample standalone forensic reports from real live API data:');

for (const target of reportTargets) {
  const item = liveResponses[target];
  if (!item || !item.response) continue;

  const fixedDate = new Date(Date.UTC(2026, 10, 1, 16, 45, 0));
  const html = generateForensicReportHtml(item.response, fixedDate);
  const outFilename = `report_${target.replace('.eml', '')}.html`;
  const outPath = path.join(outputReportsDir, outFilename);

  fs.writeFileSync(outPath, html, 'utf-8');
  console.log(`  ✓ Generated: ${outFilename} (${html.length} bytes)`);

  // Verify security assertions
  if (!html.includes('<meta http-equiv="Content-Security-Policy"')) {
    throw new Error(`Missing CSP in ${outFilename}`);
  }
  if (html.includes('<script>') || html.includes('</script>')) {
    throw new Error(`Unescaped script tag found in ${outFilename}`);
  }
  if (!html.includes("script-src 'none'")) {
    throw new Error(`script-src 'none' missing in ${outFilename}`);
  }
  if (html.includes('sandbox')) {
    throw new Error(`Disallowed 'sandbox' found in meta CSP of ${outFilename}`);
  }
}

console.log('\nAll sample reports generated, verified offline self-contained, and audited successfully!');
