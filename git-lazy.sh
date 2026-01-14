#!/bin/bash

# Define colors for pretty output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Check if inside a git repository
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo -e "${RED}Error: Not inside a Git repository.${NC}"
    exit 1
fi

# 2. Add all changes
echo -e "${YELLOW}Staging all changes (git add .)...${NC}"
git add .

# 3. Check if there is anything to commit
if output=$(git status --porcelain) && [ -z "$output" ]; then
  echo -e "${GREEN}Working tree clean. Nothing to commit.${NC}"
  exit 0
fi

# 4. Show the status so the user knows what is happening
echo -e "${YELLOW}The following changes will be committed:${NC}"
git status --short
echo ""

# 5. Ask for the commit message
echo -n "Enter commit message (Ctrl+C to cancel): "
read COMMIT_MSG

# 6. Validate commit message
if [ -z "$COMMIT_MSG" ]; then
    echo -e "${RED}Error: Commit message cannot be empty. Aborting.${NC}"
    exit 1
fi

# 7. Commit
echo -e "${YELLOW}Committing...${NC}"
if git commit -m "$COMMIT_MSG"; then
    echo -e "${GREEN}Commit successful!${NC}"
else
    echo -e "${RED}Commit failed.${NC}"
    exit 1
fi

# 8. Push to the current upstream branch
CURRENT_BRANCH=$(git branch --show-current)
echo -e "${YELLOW}Pushing to remote branch '$CURRENT_BRANCH'...${NC}"

if git push; then
    echo -e "${GREEN}Successfully pushed to $CURRENT_BRANCH!${NC}"
else
    echo -e "${RED}Push failed. (Did you forget to run 'git push -u origin $CURRENT_BRANCH' first?)${NC}"
    exit 1
fi