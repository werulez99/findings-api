#!/bin/bash
# Generate training snippets using Claude API + Supabase CLI for DB
# Usage: ANTHROPIC_API_KEY=sk-... bash scripts/generate_snippets_cli.sh

set -e
export PATH=~/.npm-global/bin:$PATH

ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?Missing ANTHROPIC_API_KEY}"

echo "=== Snippet Generation via CLI ==="

# Get all clusters
CLUSTERS=$(supabase db query --linked -o json "
  SELECT id, name, slug, description, invariant_template, finding_count
  FROM pattern_clusters
  WHERE finding_count >= 20
  ORDER BY finding_count DESC
" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('rows', []):
    print(json.dumps(r))
")

echo "$CLUSTERS" | while IFS= read -r cluster; do
    [ -z "$cluster" ] && continue

    SLUG=$(echo "$cluster" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['slug'])")
    NAME=$(echo "$cluster" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['name'])")
    DESC=$(echo "$cluster" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['description'])")
    INV=$(echo "$cluster" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['invariant_template'])")
    CID=$(echo "$cluster" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['id'])")

    echo ""
    echo "━━━ $NAME ($SLUG) ━━━"

    # Get sample findings
    SAMPLES=$(supabase db query --linked -o json "
      SELECT f.title, f.short_summary, f.severity::text
      FROM findings f
      JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
      WHERE fcm.cluster_id = '$CID'
      ORDER BY f.risk_score DESC NULLS LAST
      LIMIT 6
    " 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('rows', []):
    sev = r.get('severity','')
    title = r.get('title','')[:80]
    summary = (r.get('short_summary','') or '')[:100]
    print(f'- [{sev}] {title}: {summary}')
" 2>/dev/null)

    for DIFFICULTY in beginner intermediate advanced; do
        echo "  Generating $DIFFICULTY snippet..."

        # Call Claude API
        RESULT=$(python3 -c "
import anthropic, json, sys

client = anthropic.Anthropic(api_key='$ANTHROPIC_API_KEY')

system = '''You are a smart contract security educator. Generate a minimal, realistic Solidity code snippet that demonstrates a specific vulnerability pattern. The snippet will be shown to auditors-in-training who must identify the bug.

RULES:
1. 20-50 lines of clean Solidity (pragma solidity ^0.8.0;)
2. Contains EXACTLY ONE vulnerability
3. Realistic variable names and function signatures — looks like real production code
4. NO comments naming the bug. NO \"// vulnerable\" markers.
5. Include necessary imports as comments
6. The vulnerability must be non-trivial but findable

OUTPUT: Return ONLY valid JSON:
{
  \"title\": \"Short title (do NOT reveal the bug)\",
  \"solidity_code\": \"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\n...\",
  \"hints\": [
    {\"line_numbers\": [7], \"text\": \"Hint pointing at the area...\", \"cost\": 0},
    {\"line_numbers\": [7, 15], \"text\": \"More specific hint...\", \"cost\": 1},
    {\"line_numbers\": [7, 15, 22], \"text\": \"Almost gives it away...\", \"cost\": 1}
  ],
  \"annotations\": [
    {\"line_numbers\": [7], \"type\": \"vulnerable\", \"label\": \"VULNERABLE\", \"explanation\": \"What is wrong and why\"},
    {\"line_numbers\": [22], \"type\": \"vulnerable\", \"label\": \"IMPACT\", \"explanation\": \"What the impact is\"}
  ],
  \"invariant\": \"The core invariant that is violated\",
  \"what_breaks\": \"Specific mechanism of the break\",
  \"exploit_path\": \"1. Step one. 2. Step two. 3. Step three. 4. Impact.\",
  \"why_missed\": \"Why auditors miss this\"
}'''

user = '''Generate a $DIFFICULTY-level Solidity training snippet.

PATTERN: $NAME
DESCRIPTION: $DESC
CORE INVARIANT: $INV
DIFFICULTY: $DIFFICULTY

Real findings in this category:
$SAMPLES

Return ONLY the JSON object.'''

try:
    r = client.messages.create(model='claude-sonnet-4-20250514', max_tokens=2000, system=system, messages=[{'role':'user','content':user}])
    text = r.content[0].text.strip()
    if text.startswith('\`\`\`'):
        lines = text.split('\n')
        text = '\n'.join(lines[1:])
        if text.endswith('\`\`\`'): text = text[:-3]
        if text.startswith('json\n'): text = text[5:]
        text = text.strip()
    d = json.loads(text)
    print(json.dumps(d))
except Exception as e:
    print(json.dumps({'error': str(e)}), file=sys.stderr)
    sys.exit(1)
" 2>/dev/null)

        if [ -z "$RESULT" ]; then
            echo "  ✗ Failed to generate"
            continue
        fi

        # Check for error
        HAS_ERROR=$(echo "$RESULT" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print('yes' if 'error' in d else 'no')" 2>/dev/null)
        if [ "$HAS_ERROR" = "yes" ]; then
            echo "  ✗ API error"
            continue
        fi

        # Extract title for logging
        TITLE=$(echo "$RESULT" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('title','?')[:60])" 2>/dev/null)

        # Insert into DB via Supabase CLI
        # Need to escape the JSON for SQL
        ESCAPED=$(python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
def sql_esc(s):
    if s is None: return 'NULL'
    return \"'\" + str(s).replace(\"'\", \"''\") + \"'\"

print(f\"\"\"INSERT INTO training_snippets (id, cluster_id, difficulty, title, solidity_code, hints, annotations, invariant, exploit_path, what_breaks, why_missed, attack_pattern)
VALUES (gen_random_uuid(), '{sys.argv[1]}', '{sys.argv[2]}', {sql_esc(d.get('title'))}, {sql_esc(d.get('solidity_code'))}, {sql_esc(json.dumps(d.get('hints',[])))}, {sql_esc(json.dumps(d.get('annotations',[])))}, {sql_esc(d.get('invariant'))}, {sql_esc(d.get('exploit_path'))}, {sql_esc(d.get('what_breaks'))}, {sql_esc(d.get('why_missed'))}, {sql_esc(d.get('attack_pattern'))});\"\"\")
" "$CID" "$DIFFICULTY" <<< "$RESULT" 2>/dev/null)

        supabase db query --linked "$ESCAPED" 2>/dev/null

        echo "  ✓ $TITLE"

        # Rate limit
        sleep 2
    done
done

# Update snippet counts
echo ""
echo "Updating snippet counts..."
supabase db query --linked "
  UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
  FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
  WHERE pattern_clusters.id = sub.cluster_id;
" 2>/dev/null

echo ""
echo "=== Done ==="
supabase db query --linked "SELECT pc.slug, pc.name, pc.snippet_count FROM pattern_clusters pc WHERE pc.snippet_count > 0 ORDER BY pc.snippet_count DESC;" 2>/dev/null
