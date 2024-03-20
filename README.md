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
        uses: Asana/push-signed-commits@v1
        with:
            github-token: ${{ steps.generate-token.outputs.token }}
            local_branch_name: "main"
            remote_name: "origin"
            remote_branch_name: "main"
```

As a final step, the local branch will be reset to match the remote branch using `git reset --hard`


## Background and context

Per https://github.com/orgs/community/discussions/50055, historically the only way to create 'signed' commits as a Github App installation was to use the Git database APIs (described at https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-your-git-database?apiVersion=2022-11-28). These APIs are complicated, and it's a challenging multi-step process to implement commit verification with them. 

In 2021, Github released the createCommitOnBranch GraphQL mutation, which makes it easier to add, update, and delete files in a branch of a repository. This new API offers a simpler way to commit changes compared to the existing Git database REST APIs. With the new createCommitOnBranch mutation, you do not need to manually create blobs and trees via separate API calls before creating the commit. This allows you to add, update, or delete multiple files in a single API call.

The push-signed-commits composite action uses the new createCommitOnBranch GraphQL endpoint to create verified commits on a remote branch. This GraphQL API extracts authorship information from the credential used for authentication, and automatically marks commits created using Github App installation credentials as "verified". 

Read more about this new mutation and its conveniences here: https://github.blog/changelog/2021-09-13-a-simpler-api-for-authoring-commits/
