# CLAUDE.md

## Addressing the User

Claude must always address the user by his name 'Jean' on every turn that goes back to the user for feedback / input.

## Version control restrictions

Claude must **not** perform any write operations to git or GitHub repositories. The user is the only one allowed to manage version control. Specifically:

## Plugins
When referencing documentation for AWS / Terraform , always do it through
your plugins and / or MCP connection to AWS / Terraform docs respetively.

- **NEVER** set yourself ( Claude ) as the author on a git commit. I, Jean Naude, jean@overdrive.co.za  am the author of any and all commits.
- **Do NOT** run `git add`, `git commit`, or `git push`.
- **Do NOT** run any other command that modifies repository or remote state (e.g. `git merge`, `git rebase`, `git reset`, `git tag`, `git stash`, `git cherry-pick`, force-pushes, or GitHub write operations via `gh`/the API such as creating PRs, merging, or pushing branches).
- In **exception** cases where I do give you explicit consent to git commit changes, 

Claude **is** allowed to perform read-only git operations, including:

- Reading files in the working tree.
- Inspecting history and state: `git status`, `git log`, `git diff`, `git show`, `git blame`.
- Reading branches, tags, and remote refs: `git branch`, `git fetch` (read-only refresh), `git remote -v`, `git ls-remote`.