# pyright: strict
import base64
import subprocess
from typing import Literal, Optional, TypedDict
import logging

import requests
import argparse


# exception for when we only manage to push some of the commits to the remote, but fail partway
# through and so don't push all the commits. this is the most serious type of error -- it could
# require operator intervention to resolve and may lead to unexpected results downstream.
class PartialPushFailure(Exception):
    """
    An exception raised when we see a new commit on the remote branch while we're partway through
    pushing new commits to the remote branch. This is unexpected, and it's possible that someone
    else is pushing to the remote branch at the same time as us.

    Important: when this error is raised, the remote branch will be in an unexpected state where
    only some of the commits from the local branch have been pushed to the remote branch. This might
    require manual operator reconciliation.
    """


class GithubAPIError(Exception):
    """
    An exception raised when the GitHub API returns an error.
    """


class RemoteBranchDivergedError(Exception):
    """
    An exception raised when the remote branch has diverged from the local branch - i.e., the remote
    branch has commits that the local branch does not have.
    """


class FileDeletion(TypedDict):
    """
    A type hint for the FileDeletion GraphQL input object, which is an input to the
    FileChanges GraphQL input object.
    https://docs.github.com/en/graphql/reference/input-objects#filedeletion
    """

    path: str


class FileAddition(TypedDict):
    """
    A type hint for the FileAddition GraphQL input object, which is an input to the
    FileChanges GraphQL input object.
    https://docs.github.com/en/graphql/reference/input-objects#fileaddition
    """

    path: str
    contents: str


class FileChanges(TypedDict):
    """
    A type hint for the FileChanges GraphQL input object, which is an input to the
    createCommitOnBranch mutation.
    Read about the mutation here:
    https://docs.github.com/en/graphql/reference/mutations#createcommitonbranch
    And the file changes input object here:
    https://docs.github.com/en/graphql/reference/input-objects#filechanges
    """

    additions: list[FileAddition]
    deletions: list[FileDeletion]


class CommitMessage(TypedDict):
    """
    A type hint for the CommitMessage GraphQL input object, which is an input to the
    createCommitOnBranch mutation.
    Read about the mutation here:
    https://docs.github.com/en/graphql/reference/mutations#createcommitonbranch
    And the commit message input object here:
    https://docs.github.com/en/graphql/reference/input-objects#commitmessage
    """

    body: str
    headline: str


def get_file_changes_from_local_commit_hash(commit_hash: str) -> FileChanges:
    """
    Create a file changes object for a specific commit.

    Args:
        commit_hash (str): The hash of the commit.

    Returns:
        dict: A dictionary representing the FileChanges object.
    """

    # setting config variable advice.detachedHead to false to avoid verbose messages in the logs
    subprocess.run(
        ["git", "config", "advice.detachedHead", "false"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )

    logging.debug("")
    logging.debug("now working on commit hash %s", commit_hash)
    # Get a list of files changed in a specific commit.
    result = subprocess.run(
        ["git", "diff", "--name-status", f"{commit_hash}~1", commit_hash],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    files_changed_by_commit = result.stdout.splitlines()

    logging.debug("files_changed_by_commit:\n %s", files_changed_by_commit)
    file_changes = FileChanges(
        additions=[],
        deletions=[],
    )

    # check out that commit in detached head state, so that we can pull file contents accurately
    subprocess.run(["git", "checkout", commit_hash], check=True)
    logging.debug("output of ls after checking out commit hash:")
    subprocess.run(["ls"], check=True)

    for line in files_changed_by_commit:
        status, *filenames = line.split("\t")
        logging.debug("status: %s", status)
        logging.debug("filenames: %s", filenames)
        if status in ["A", "M"]:
            logging.debug("Added or modified file detected")
            with open(filenames[-1], "rb") as f:
                contents = base64.b64encode(f.read()).decode("utf-8")
            file_changes["additions"].append(
                FileAddition(
                    path=filenames[-1],
                    contents=contents,
                )
            )
        elif "R" in status or status == "R":
            logging.debug("Renamed file detected")
            old_name = filenames[0]
            new_name = filenames[1]
            logging.debug("old_name: %s", old_name)
            logging.debug("new_name: %s", new_name)

            file_changes["deletions"].append({"path": old_name})
            with open(new_name, "rb") as f:
                contents = base64.b64encode(f.read()).decode("utf-8")
            file_changes["additions"].append(
                FileAddition(
                    path=new_name,
                    contents=contents,
                )
            )

        elif status == "D":
            logging.debug("Deleted file detected")
            file_changes["deletions"].append(FileDeletion(path=filenames[0]))

    # go back to the previous ref
    subprocess.run(
        ["git", "checkout", "-"], check=True, stdout=subprocess.PIPE, text=True
    )

    return file_changes


def get_local_commits_not_on_remote(
    local_branch_name: str, remote_name: str, remote_branch_name: str
) -> list[str]:
    """
    Get a list of commit hashes on the local branch that are not on the remote branch,
    chronologically ordered from oldest to newest. This uses the .. operator, and not the ...
    operator, and so it's safe to run this function even if we've fetched updates to the remote.

    Args:
        local_branch_name (str): The name of the local branch.
        remote_branch_name (str): The name of the remote branch.

    Returns:
        list: A list of strings representing the commit hashes.
    """
    result: list[str] = subprocess.run(
        ["git", "rev-list", f"{remote_name}/{remote_branch_name}..{local_branch_name}"],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.splitlines()
    logging.info(
        "Found %s commits on the local branch that are not on the remote branch.",
        len(result),
    )
    logging.debug("Commits to be created on the remote branch:")
    logging.debug("\n".join(result))

    # reverse the list so that the oldest commit is first
    return result[::-1]


def create_commit_on_remote_branch(
    *,
    github_token: str,
    repository_name_with_owner: str,
    remote_branch_name: str,
    expected_head_oid: str,
    file_changes: FileChanges,
    message: CommitMessage,
) -> str:
    """
    Create a commit on a remote branch using the GitHub GraphQL API.

    Args:
        github_token (str): The GitHub personal access github_token.
        repository_name_with_owner (str): The name of the repository with the owner.
        remote_branch_name (str): The name of the branch.
        expected_head_oid (str): The expected git commit oid at the head of the branch prior to the
        commit.
        file_changes (dict): The file changes object.
        message (str): The commit message.

    Returns:
        str: The commit oid of the created commit.
    """
    url = "https://api.github.com/graphql"
    headers = {"Authorization": f"Bearer {github_token}"}

    mutation = """
    mutation ($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) {
        commit {
          oid
        }
      }
    }
    """

    graphql_input = {
        "branch": {
            "repositoryNameWithOwner": repository_name_with_owner,
            "branchName": remote_branch_name,
        },
        "expectedHeadOid": expected_head_oid,
        "fileChanges": file_changes,
        "message": message,
    }

    data = {"query": mutation, "variables": {"input": graphql_input}}
    response = requests.post(url, headers=headers, json=data).json()

    # If there are errors in the response, log the errors and raise an exception
    if "errors" in response:
        logging.error(response)
        if response["errors"][0]["type"] == "STALE_DATA":
            raise PartialPushFailure(
                "The expected head OID for the remote branch is stale. This is likely because "
                "someone else has pushed to the remote branch since we last fetched it. Aborting."
            )
        else:
            raise GithubAPIError(
                f"Error creating commit on branch {repository_name_with_owner}/"
                f"{remote_branch_name}.\n"
                f"Error message: {response['errors']}",
            )

    return response["data"]["createCommitOnBranch"]["commit"]["oid"]


def fetch_remote_branch_and_get_head_oid(
    remote_name: str, remote_branch_name: str
) -> str:
    """
    This function runs a git fetch to get the latest changes to the remote branch. We don't actually
    integrate the changes into the local branch, we just want to get the latest commit OID on the
    remote. We then return the OID of the latest commit on the remote branch.
    """
    # first, fetch the branch to pull in latest changes
    subprocess.run(
        ["git", "fetch", remote_name, remote_branch_name],
        capture_output=True,
        text=True,
        check=True,
    )
    # Get the commit OID of the latest commit on the remote branch
    return subprocess.run(
        ["git", "rev-parse", f"{remote_name}/{remote_branch_name}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def main(
    *,
    github_token: str,
    repository_name_with_owner: str,
    local_branch_name: str,
    remote_name: str,
    remote_branch_name: str,
) -> None:
    """
    Create commits on a remote branch for each commit on the local branch that's not on the remote
    branch.

    Note: This function assumes that the commits created on the remote branch are unlikely to have
    the same commit ID as the local commits. This is intentional - the createCommitOnBranch mutation
    handles commit signing and commit authorship attribution for us, so the commit contents will be
    different than the local commits. As a result, the commit IDs/hashes will be different as well.

    Args:
        github_token (str): The GitHub personal access github_token.
        repository_name_with_owner (str): The name of the repository with the owner.
        local_branch_name (str): The name of the local branch.
        remote_branch_name (str): The name of the remote branch.
    """

    ################################################################################################
    ####### Verification steps - ensure that the script can run safely.                     ########
    ################################################################################################

    # Get the 'expected parent' commit sha of the new commits that we want to push. we do this using
    # git merge-base local_branch_name remote_name/remote_branch_name
    merge_base_commit_oid: str = subprocess.run(
        ["git", "merge-base", local_branch_name, f"{remote_name}/{remote_branch_name}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    # Verify that the remote branch has not diverged from the local branch. If it has, bail
    # immediately.
    if (
        fetch_remote_branch_and_get_head_oid(remote_name, remote_branch_name)
        != merge_base_commit_oid
    ):
        raise RemoteBranchDivergedError(
            f"The remote branch {remote_name}/{remote_branch_name} has diverged from the local "
            f"branch {local_branch_name}. Aborting."
        )

    ################################################################################################
    ####### Get the list of commits on the local branch that are not on the remote branch. #########
    ################################################################################################

    # List of hashes for commit on the local branch that are not on the remote branch
    new_commit_local_hashes: list[str] = get_local_commits_not_on_remote(
        local_branch_name, remote_name, remote_branch_name
    )

    ################################################################################################
    ####### Prepare the FileChanges and CommitMessage objects for each commit to be created. #######
    ################################################################################################

    new_commits_to_create: list[tuple[str, CommitMessage, FileChanges]] = []

    for local_commit_hash in new_commit_local_hashes:
        commit_message = subprocess.run(
            ["git", "log", "--format=%B", "-n", "1", local_commit_hash],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        commit_message_lines = commit_message.split("\n")
        headline = commit_message_lines[0]
        body = "\n".join(commit_message_lines[1:])
        commit_message = CommitMessage(headline=headline, body=body)

        file_changes = get_file_changes_from_local_commit_hash(local_commit_hash)
        new_commits_to_create.append((local_commit_hash, commit_message, file_changes))

    ################################################################################################
    ####### Create the commits on the remote branch using the Github GraphQL endpoint ##############
    ################################################################################################

    # Track the OID for the most recent commit created. This will be used as the parent commit OID
    # for the next commit.
    last_commit_pushed: Optional[str] = None
    remote_commit_hashes_created: list[str] = []

    for local_commit_hash, commit_message, file_changes in new_commits_to_create:

        # Verify that the latest commit on the remote branch is the expected parent of the commit
        # that we're about to create
        if last_commit_pushed and (
            fetch_remote_branch_and_get_head_oid(remote_name, remote_branch_name)
            != last_commit_pushed
        ):
            raise PartialPushFailure(
                "The latest commit on the remote branch is not the last commit created by this "
                "script. This is either because something went wrong during commit creation, or "
                "because someone else is pushing to the remote branch as well. Aborting."
                f"We pushed {len(remote_commit_hashes_created)} commits to the remote branch, "
                f"with hashes, {remote_commit_hashes_created}. The local commits that we didn't "
                f"push were {new_commit_local_hashes[len(remote_commit_hashes_created):]}."
            )

        # Create a commit on the remote branch, and store the OID of the created commit in
        # last_commit_pushed
        last_commit_pushed = create_commit_on_remote_branch(
            github_token=github_token,
            repository_name_with_owner=repository_name_with_owner,
            remote_branch_name=remote_branch_name,
            expected_head_oid=last_commit_pushed or merge_base_commit_oid,
            file_changes=file_changes,
            message=commit_message,
        )
        remote_commit_hashes_created.append(last_commit_pushed)
        logging.info(
            "Created commit %s from commit sha %s on branch %s/%s with message: %s",
            last_commit_pushed,
            local_commit_hash,
            remote_name,
            remote_branch_name,
            commit_message,
        )

    logging.info(
        "Finished creating %s commits on the remote branch %s/%s from the local branch %s.",
        len(new_commit_local_hashes),
        remote_name,
        remote_branch_name,
        local_branch_name,
    )


def validate_branch_name(
    branch_name: str,
    branch_type: Literal["remote", "local"],
    remote_name: str = "origin",
) -> None:
    """
    Validate that the branch name is provided without refs/heads/, and without the remote name. If
    the branch name is invalid, raise a ValueError.
    """

    if branch_name.startswith("origin/"):
        raise ValueError(f"Do not include 'origin/' in the {branch_type} branch name.")
    if branch_name.startswith("refs/heads/"):
        raise ValueError(
            f"Do not include 'refs/heads/' in the {branch_type} branch name."
        )
    if branch_name.startswith(remote_name + "/"):
        raise ValueError(
            f"Do not include the remote name in the {branch_type} branch name."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("github_token", help="GitHub personal access token", type=str)
    parser.add_argument(
        "repository_name_with_owner", help="Repository name with owner", type=str
    )
    parser.add_argument("local_branch_name", help="Local branch name", type=str)
    parser.add_argument("remote_name", help="Remote name")
    parser.add_argument("remote_branch_name", help="Remote branch name")
    args = parser.parse_args()

    # Validate branch names
    validate_branch_name(args.local_branch_name, "local", remote_name=args.remote_name)
    validate_branch_name(
        args.remote_branch_name, "remote", remote_name=args.remote_name
    )

    main(
        github_token=args.github_token,
        repository_name_with_owner=args.repository_name_with_owner,
        local_branch_name=args.local_branch_name,
        remote_name=args.remote_name,
        remote_branch_name=args.remote_branch_name,
    )
