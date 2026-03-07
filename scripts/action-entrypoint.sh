#!/usr/bin/env bash
# Nucleus Safe PR Fixer — GitHub Action entrypoint
#
# The agent runs under the safe_pr_fixer profile, which allows:
#   - Read all files, write/edit/test with LowRisk
#   - Commit locally (git_write=LowRisk)
#   - Web fetch for docs lookup (web_fetch=LowRisk)
#
# The agent CANNOT:
#   - Push (git_push=Never)
#   - Create PRs (create_pr=Never)
#   - Web search (web_search=Never)
#
# This script handles the push and PR creation after the agent finishes.

set -euo pipefail

: "${ISSUE_NUMBER:?ISSUE_NUMBER is required}"
: "${LLM_API_TOKEN:?LLM_API_TOKEN is required}"
: "${NUCLEUS_PROFILE:=safe_pr_fixer}"
: "${NUCLEUS_TIMEOUT:=3600}"
: "${LLM_MODEL:=claude-sonnet-4-20250514}"

# Export ANTHROPIC_API_KEY so Claude CLI can authenticate.
# The action input is vendor-agnostic (api-key → LLM_API_TOKEN),
# but the Claude CLI looks for ANTHROPIC_API_KEY in the environment.
export ANTHROPIC_API_KEY="${LLM_API_TOKEN}"

BRANCH="nucleus/fix-issue-${ISSUE_NUMBER}"

echo "::group::Fetch issue details"
ISSUE_TITLE=$(gh issue view "$ISSUE_NUMBER" --json title --jq '.title')
ISSUE_BODY=$(gh issue view "$ISSUE_NUMBER" --json body --jq '.body')
echo "Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}"
echo "::endgroup::"

echo "::group::Create branch"
# Delete remote branch if it exists from a previous run (stale plan-only attempt)
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  echo "Branch $BRANCH exists on remote — deleting stale branch"
  git push origin --delete "$BRANCH" || true
fi
git checkout -b "$BRANCH"
echo "::endgroup::"

echo "::group::Run Nucleus agent"
# Build the prompt from the issue
PROMPT="Fix the following GitHub issue. Read the codebase, understand the problem, implement the fix, and run tests.

Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}

${ISSUE_BODY}

After fixing, commit your changes with a clear commit message referencing issue #${ISSUE_NUMBER}."

# Run under lattice enforcement (local mode — no Firecracker needed in CI)
nucleus run \
  --local \
  --profile "$NUCLEUS_PROFILE" \
  --timeout "$NUCLEUS_TIMEOUT" \
  --model "$LLM_MODEL" \
  --env "LLM_API_TOKEN=${LLM_API_TOKEN}" \
  "$PROMPT"
echo "::endgroup::"

# Check if the agent made any commits
DEFAULT_BRANCH=$(git remote show origin 2>/dev/null | grep 'HEAD branch' | awk '{print $NF}')
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
if git diff --quiet "HEAD" "origin/${DEFAULT_BRANCH}" 2>/dev/null; then
  echo "::warning::Agent made no changes. No PR created."
  exit 0
fi

echo "::group::Push and create PR"
# The TRUSTED CI script pushes — not the agent
git push origin --delete "nucleus/fix-issue-${ISSUE_NUMBER}" 2>/dev/null || true
git push origin "$BRANCH"

# Always output branch — even if PR creation fails
echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"

# PR creation is non-fatal: some orgs block Actions from creating PRs
set +e
PR_URL=$(gh pr create \
  --title "fix: ${ISSUE_TITLE} (nucleus #${ISSUE_NUMBER})" \
  --body "$(cat <<EOF
## Summary

Automated fix for #${ISSUE_NUMBER} by Nucleus safe PR fixer.

## Security

- Profile: \`${NUCLEUS_PROFILE}\`
- The agent could read, write, edit, and commit — but could NOT push or create this PR.
- This PR was created by the trusted CI script, not the agent.
- All agent actions were audit-logged with HMAC signatures.

## Review Checklist

- [ ] Changes are scoped to the reported issue
- [ ] Tests pass
- [ ] No unexpected file modifications
EOF
)" \
  --head "$BRANCH")
PR_EXIT=$?
set -e

if [ $PR_EXIT -eq 0 ]; then
  echo "pr_url=${PR_URL}" >> "$GITHUB_OUTPUT"
  echo "Created PR: ${PR_URL}"
else
  echo "::warning::gh pr create failed (exit $PR_EXIT). Branch '${BRANCH}' was pushed — create the PR manually."
fi
echo "::endgroup::"
