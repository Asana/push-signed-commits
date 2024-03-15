# pyright: strict
import base64
from multiprocessing import Value
import subprocess
import sys
from typing import Literal, Optional, TypedDict
import logging

import requests
import argparse


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
        capture_output=True,
        text=True,
        check=True,
    )

    logging.debug("")
    logging.debug("now working on commit hash %s", commit_hash)
    # Get a list of files changed in a specific commit.
    result = subprocess.run(
        ["git", "diff", "--name-status", f"{commit_hash}~1", commit_hash],
        capture_output=True,
        text=True,
        check=True,
    )
    files_changed_by_commit = result.stdout.splitlines()

    logging.debug("files_changed_by_commit:\n %s", files_changed_by_commit)
    file_changes: FileChanges = {
        "additions": [],
        "deletions": [],
    }

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

        elif status in ["D"]:
            logging.debug("Deleted file detected")
            file_changes["deletions"].append({"path": filenames[0]})

    # go back to the previous ref
    subprocess.run(["git", "checkout", "-"], check=True, capture_output=True, text=True)

    return file_changes


def get_local_commits_not_on_remote(
    local_branch_name: str, remote_name: str, remote_branch_name: str
) -> list[str]:
    """
    Get a list of commit hashes on the local branch that are not on the remote branch,
    chronologically ordered from oldest to newest.

    Args:
        local_branch_name (str): The name of the local branch.
        remote_branch_name (str): The name of the remote branch.

    Returns:
        list: A list of strings representing the commit hashes.
    """
    result = subprocess.run(
        ["git", "rev-list", f"{remote_name}/{remote_branch_name}..{local_branch_name}"],
        capture_output=True,
        text=True,
        check=True,
    )
    logging.info(
        "Found %s commits on the local branch that are not on the remote branch.",
        len(result.stdout.splitlines()),
    )
    logging.debug("Commits to be created on the remote branch:")

    for commit_hash in result.stdout.splitlines():
        logging.debug(commit_hash)

    # reverse the list so that the oldest commit is first
    return result.stdout.splitlines()[::-1]


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
        expected_head_oid (str): The expected git commit oid at the head of the branch prior to the commit.
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
    response = requests.post(url, headers=headers, json=data)

    if "errors" in response.json():
        logging.error(response.json())
        exit(1)

    return response.json()["data"]["createCommitOnBranch"]["commit"]["oid"]


def main(
    *,
    github_token: str,
    repository_name_with_owner: str,
    local_branch_name: str,
    remote_name: str,
    remote_branch_name: str,
) -> None:
    """
    Create commits on a remote branch for each commit on the local branch that's not on the remote branch.

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

    # List of hashes for commit on the local branch that are not on the remote branch
    new_commit_local_hashes: list[str] = get_local_commits_not_on_remote(
        local_branch_name, remote_name, remote_branch_name
    )

    # Track the OID for the most recent commit created. This will be used as the parent commit OID for the next commit.
    last_remote_commit_created_oid: Optional[str] = None

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

        # Get the commit OID of the latest commit on the remote branch
        subprocess.run(
            ["git", "fetch", remote_name, remote_branch_name],
            capture_output=True,
            text=True,
            check=True,
        )
        remote_head_oid = subprocess.run(
            ["git", "rev-parse", f"{remote_name}/{remote_branch_name}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert (
            remote_head_oid == last_remote_commit_created_oid
            or not last_remote_commit_created_oid
        ), "The latest commit on the remote branch is not the last commit created by this script. This is either because something went wrong during commit creation, or because someone else is pushing to the remote branch as well. Aborting."

        # Create a commit on the remote branch, and store the OID of the created commit in
        # last_remote_commit_created_oid
        last_remote_commit_created_oid = create_commit_on_remote_branch(
            github_token=github_token,
            repository_name_with_owner=repository_name_with_owner,
            remote_branch_name=remote_branch_name,
            expected_head_oid=remote_head_oid,
            file_changes=file_changes,
            message=commit_message,
        )

        logging.info(
            "Created commit %s from commit sha %s on branch %s/%s with message: %s",
            last_remote_commit_created_oid,
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
