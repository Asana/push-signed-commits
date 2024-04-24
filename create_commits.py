# pyright: strict
import base64
from email.mime import base
import subprocess
from typing import Literal, Optional, TypedDict
import logging

import requests
import argparse


################################################################################################
####### Define custom exceptions for this script.                                       ########
################################################################################################

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


################################################################################################
####### Define the input objects for the createCommitOnBranch mutation.                  ########
################################################################################################

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


################################################################################################
####### Define functions for interacting with the local git repository.                ########
################################################################################################

def get_file_contents_at_commit(commit_hash: str, filename: str) -> str:
    """
    Get the contents of a file at a specific commit, encoded as a base64 string.

    Args:
        commit_hash (str): The hash of the commit.
        filename (str): The name of the file.

    Returns:
        bytes: The contents of the file, encoded in utf-8
    """
    # get the file contents as utf-8 bytes
    text_contents = subprocess.run(
        ["git", "show", f"{commit_hash}:{filename}"],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.encode("utf-8")

    # encode the file contents as a base64 string and return the string
    return base64.b64encode(text_contents).decode("utf-8")


def get_file_changes_from_local_commit_hash(commit_hash: str) -> FileChanges:
    """
    Create a file changes object for a specific commit.

    Args:
        commit_hash (str): The hash of the commit.

    Returns:
        dict: A dictionary representing the FileChanges object.
    """

    logging.debug(
        "Now retrieving the file changes for local commit hash %s", commit_hash
    )

    # Create a FileChanges object for this commit
    file_changes = FileChanges(
        additions=[],
        deletions=[],
    )

    ################################################################################################
    ####### Get the list of files changed in the commit.                                ###########
    ################################################################################################

    # Get a list of files changed in a specific commit. See
    # https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---name-status for more on the
    # --name-status parameter.
    result = subprocess.run(
        ["git", "diff", "--name-status", f"{commit_hash}^", commit_hash],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    files_changed_by_commit: list[str] = result.stdout.splitlines()

    logging.debug(
        "Output of git diff --name-status:\n %s",
        "\n".join(files_changed_by_commit),
    )

    ################################################################################################
    ####### Create FileAddition and FileDeletion objects for each file changed in the commit. ######
    ################################################################################################
    for file_change_line in files_changed_by_commit:
        # the --name-status parameter in git diff returns lines in the format "status\tfilenames",
        # where status is a single letter representing the change type, and filenames is a
        # tab-separated list of filenames. See
        # https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203
        # for more on what each status code means.

        # Since we're only inspecting full commits (not the
        # contents of the working tree, the index, or the files on disk), we only need to handle the
        # A, M, R, and D status codes.
        status, *filenames = file_change_line.split("\t")

        logging.debug("status: %s", status)
        logging.debug("filenames: %s", filenames)

        ############# Handle Additions and Modifications #############
        if status in ["A", "M"]:
            logging.debug("Added or modified file %s detected", filenames[0])

            # Per Github's docs on modeling file changes:
            # https://docs.github.com/en/graphql/reference/input-objects#modeling-file-changes,
            # new files and modifications to existing files are modeled identically. Each should be
            # specified as an 'addition', with the full file contents provided.

            file_changes["additions"].append(
                FileAddition(
                    path=filenames[-1],
                    contents=get_file_contents_at_commit(commit_hash, filenames[0]),
                )
            )

        ############# Handle Renames #############
        elif (
            # We check for "R" in status because we've seen odd formats for rename status codes,
            # like "R100"
            "R" in status
            or status == "R"
        ):
            old_name = filenames[0]
            new_name = filenames[1]
            logging.debug(
                "Renamed file detected. File was renamed from %s to %s",
                old_name,
                new_name,
            )

            # Per Github's docs on modeling file changes, renames are modeled as a deletion of the
            # old file and an addition of the new file:
            file_changes["deletions"].append(FileDeletion(path=old_name))
            file_changes["additions"].append(
                FileAddition(
                    path=new_name,
                    contents=get_file_contents_at_commit(commit_hash, new_name),
                )
            )

        ############# Handle Deletions #############
        elif status == "D":
            logging.debug("Deleted file %s detected", filenames[0])
            file_changes["deletions"].append(FileDeletion(path=filenames[0]))

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

    if "data" not in response:
        raise GithubAPIError(
            f"Unknown error creating commit on branch {repository_name_with_owner}/"
            f"{remote_branch_name}. The response from the Github API was of an unexpected format.\n"
            f"Response: {response}",
        )

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
        try:
            pushed_commit = create_commit_on_remote_branch(
                github_token=github_token,
                repository_name_with_owner=repository_name_with_owner,
                remote_branch_name=remote_branch_name,
                expected_head_oid=last_commit_pushed or merge_base_commit_oid,
                file_changes=file_changes,
                message=commit_message,
            )
            last_commit_pushed = pushed_commit
        except (RemoteBranchDivergedError, GithubAPIError) as e:
            if not last_commit_pushed:
                # If we haven't pushed any commits yet, then the error is less severe. We'll print
                # an error, but we won't raise an exception - this means the Github Action's status
                # will still be 'success'.
                logging.error(
                    "An error occurred while pushing the first commit to the remote branch. "
                    "This action made no changes to the remote branch. Error message: %s",
                    e,
                )
                return
            else:
                # If we've already pushed some commits, then the error is more severe. We'll raise an
                # exception.
                raise e

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
    parser.add_argument("log_level", default="WARN", help="Log level", type=str)
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)

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
