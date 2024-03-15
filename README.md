# push-signed-commits
This composite Github Action uses the createCommitOnBranch GraphQL mutation to allow Github Apps to push 'Verified' commits to Github.

Since this action changes the content of the commits (by deriving authorship information and signing them), the hashes of the commits pushed to the remote will be different from the ones that were created locally. This is expected and is a result of the commit being signed.

The action is intended to be used by Github Actions as a follow-up to a 'commit' step. For example:

```yaml
        # Retrieve an installation token for your Github App
      - name: Generate a token
        id: generate-token
        uses: actions/create-github-app-token@v1
        with:
            app-id: ${{ env.GITHUB_APP_ID }}
            private-key: ${{ env.GITHUB_APP_PRIVATE_KEY }}


      - name: "create a commit"
        id: create-commit
        env:
          GITHUB_TOKEN: ${{ steps.generate-token.outputs.token }}
        run: |
          git config --global user.name "Login will be determined by the Github API based on the creator of the token"
          git config --global user.email ""
          touch "test.txt"
          echo "Hello, world, from the first commit!" >> "test.txt"
          git add "test.txt"
          git commit -m "Once pushed to the remote, this commit will appear as authored by the GitHub App and verified"
    
      - name: "Push commits"
        uses: ./.github/actions/create-signed-remote-commits
        with:
            github-token: ${{ steps.generate-token.outputs.token }}
            local_branch_name: "main"
            remote_name: "origin"
            remote_branch_name: "main"
```

As a final step, the local branch will be reset to match the remote branch using `git reset --hard`