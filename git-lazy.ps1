# 1. Check if inside a git repository
$isGit = git rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Not inside a Git repository." -ForegroundColor Red
    exit 1
}

# 2. Add all changes
Write-Host "Staging all changes (git add .)..." -ForegroundColor Yellow
git add .

# 3. Check if there is anything to commit
$status = git status --porcelain
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host "Working tree clean. Nothing to commit." -ForegroundColor Green
    exit 0
}

# 4. Show the status
Write-Host "The following changes will be committed:" -ForegroundColor Yellow
git status --short
Write-Host ""

# 5. Ask for the commit message
$COMMIT_MSG = Read-Host "Enter commit message (Ctrl+C to cancel)"

# 6. Validate commit message
if ([string]::IsNullOrWhiteSpace($COMMIT_MSG)) {
    Write-Host "Error: Commit message cannot be empty. Aborting." -ForegroundColor Red
    exit 1
}

# 7. Commit
Write-Host "Committing..." -ForegroundColor Yellow
git commit -m "$COMMIT_MSG"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Commit failed." -ForegroundColor Red
    exit 1
}

# 8. Push to the current upstream branch
$CURRENT_BRANCH = git branch --show-current
Write-Host "Pushing to remote branch '$CURRENT_BRANCH'..." -ForegroundColor Yellow

git push
if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed. (Did you forget to run 'git push -u origin $CURRENT_BRANCH' first?)" -ForegroundColor Red
    exit 1
}

Write-Host "Successfully pushed to $CURRENT_BRANCH!" -ForegroundColor Green