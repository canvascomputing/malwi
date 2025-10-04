import os
import gzip
import stat
import shutil
import logging
import zipfile
import tarfile
import argparse
import subprocess
import json
from pathlib import Path

from urllib.parse import urlparse


# Load repository URLs from JSON config
def load_repository_urls(language="python"):
    """
    Load repository URLs from JSON configuration file.

    Args:
        language: Programming language to load repos for (default: "python")

    Returns:
        tuple: (benign_urls, malicious_urls)
    """
    config_path = Path(__file__).parent.parent.parent / "util" / "repository_urls.json"

    if not config_path.exists():
        raise FileNotFoundError(f"Repository URLs config not found: {config_path}")

    with open(config_path, "r") as f:
        config = json.load(f)

    # Get repos for the specified language
    benign_repos = config.get("benign_repos", {}).get(language, [])
    malicious_repos = config.get("malicious_repos", {}).get(language, [])

    # Convert to URL format with /tree/HASH for backward compatibility
    benign_urls = []
    for repo in benign_repos:
        url = repo["url"]
        commit = repo.get("commit")
        if commit:
            benign_urls.append(f"{url}/tree/{commit}")
        else:
            benign_urls.append(url)

    malicious_urls = []
    for repo in malicious_repos:
        url = repo["url"]
        commit = repo.get("commit")
        if commit:
            malicious_urls.append(f"{url}/tree/{commit}")
        else:
            malicious_urls.append(url)

    return benign_urls, malicious_urls


# Load URLs from config file
BENIGN_REPO_URLS, MALICIOUS_REPO_URLS = load_repository_urls()

# DataDog malicious repo constant (still used in the code)
DATADOG_MALICIOUS_REPO_URL = (
    "https://github.com/DataDog/malicious-software-packages-dataset.git"
)

ENCRYPTED_ZIP_PASSWORD = b"infected"  # Password for DataDog encrypted zips

REPO_CACHE_DIR = ".repo_cache"
BENIGN_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "benign_repos")
MALICIOUS_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "malicious_repos")

# Global flag to control pinning behavior (uses commits from repository_urls.json)
USE_PINNED_COMMITS = True


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(module)s.%(funcName)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def parse_github_url(url):
    """
    Parse a GitHub URL and extract base repo URL and commit hash.

    Handles URLs like:
    - https://github.com/owner/repo/tree/HASH -> (https://github.com/owner/repo, HASH)
    - https://github.com/owner/repo -> (https://github.com/owner/repo, None)

    Returns:
        tuple: (base_url, commit_hash or None)
    """
    # Check if URL contains /tree/HASH pattern
    if "/tree/" in url:
        parts = url.split("/tree/")
        base_url = parts[0]
        commit_hash = parts[1] if len(parts) > 1 else None
        return (base_url, commit_hash)
    else:
        return (url, None)


def _get_repo_name_from_url_internal(url):
    try:
        # Parse GitHub URL to get base URL without /tree/HASH
        base_url, _ = parse_github_url(url)
        path_part = urlparse(base_url).path
        repo_name = path_part.strip("/").replace(".git", "")
        return os.path.basename(repo_name)
    except Exception:
        return os.path.basename(url).replace(".git", "")


DATADOG_MALICIOUS_REPO_NAME = _get_repo_name_from_url_internal(
    DATADOG_MALICIOUS_REPO_URL
)


def make_writable_recursive(path_to_make_writable):
    logging.debug(f"Making {path_to_make_writable} owner-writable.")
    try:
        if os.path.isdir(path_to_make_writable):
            for root, dirs, files in os.walk(path_to_make_writable, topdown=False):
                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(filepath).st_mode
                        os.chmod(filepath, current_mode | stat.S_IWUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make file {filepath} owner-writable: {e}"
                        )
                for name in dirs:
                    dirpath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(dirpath).st_mode
                        os.chmod(dirpath, current_mode | stat.S_IWUSR | stat.S_IXUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make dir {dirpath} owner-writable: {e}"
                        )
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR | stat.S_IXUSR)
        elif os.path.isfile(path_to_make_writable):
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR)
    except Exception as e:
        logging.warning(
            f"Error in make_writable_recursive for {path_to_make_writable}: {e}"
        )


def make_readonly(path):
    logging.debug(f"Setting group/other read-only permissions for {path}")
    perms_file = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    perms_dir = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
    try:
        if os.path.isdir(path):
            try:
                current_mode = os.stat(path).st_mode
                os.chmod(path, current_mode | stat.S_IWUSR | stat.S_IXUSR)
            except Exception:
                pass
            for root, dirs, files in os.walk(path, topdown=False):
                for f_name in files:
                    try:
                        os.chmod(os.path.join(root, f_name), perms_file)
                    except Exception as e_file:
                        logging.debug(
                            f"Readonly failed for file {os.path.join(root, f_name)}: {e_file}"
                        )
                for d_name in dirs:
                    try:
                        os.chmod(os.path.join(root, d_name), perms_dir)
                    except Exception as e_dir:
                        logging.debug(
                            f"Readonly failed for dir {os.path.join(root, d_name)}: {e_dir}"
                        )
            os.chmod(path, perms_dir)
        elif os.path.isfile(path):
            os.chmod(path, perms_file)
    except Exception as e:
        logging.debug(
            f"Could not set group/other read-only permissions for {path}: {e}"
        )


def get_repo_name_from_url(url):
    return _get_repo_name_from_url_internal(url)


def run_command(command, working_dir=None, repo_name=""):
    logging.debug(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir,
            errors="ignore",
        )
        if result.stderr and not any(
            msg in result.stderr
            for msg in ["Cloning into", "Receiving objects", "Resolving deltas"]
        ):
            logging.debug(f"[{repo_name}] Command stderr: {result.stderr.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(
            f"[{repo_name}] Command failed: {' '.join(command)} (rc={e.returncode})"
        )
        if e.stderr:
            logging.error(f"[{repo_name}] Stderr: {e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"[{repo_name}] Error running command {' '.join(command)}: {e}")
        return False


def get_or_clone_repo(repo_url, target_cache_subdir):
    repo_name = get_repo_name_from_url(repo_url)
    repo_path = os.path.join(target_cache_subdir, repo_name)
    os.makedirs(target_cache_subdir, exist_ok=True)

    # Parse GitHub URL to extract base URL and embedded commit hash
    base_url, url_commit = parse_github_url(repo_url)

    # Use commit from URL (from repository_urls.json) if pinning is enabled
    pinned_commit = url_commit if USE_PINNED_COMMITS else None

    # Create cache directory name that includes commit hash for pinned repos
    if pinned_commit:
        # Include first 8 chars of commit hash in path for clarity
        commit_short = pinned_commit[:8]
        repo_path = os.path.join(target_cache_subdir, f"{repo_name}_{commit_short}")
        cache_info = f"pinned to {commit_short}"
    else:
        cache_info = "latest (non-reproducible)"

    if os.path.exists(repo_path):
        logging.info(
            f"Using cached repository {repo_name} ({cache_info}) from {repo_path}"
        )
    else:
        if pinned_commit:
            logging.info(
                f"Cloning {repo_name} from {base_url} (pinned to {commit_short}) into {repo_path}"
            )
            # Clone the full repository to get the specific commit
            if not run_command(
                ["git", "clone", base_url, repo_path], repo_name=repo_name
            ):
                logging.error(f"Failed to clone {repo_name}.")
                if os.path.exists(repo_path):
                    try:
                        make_writable_recursive(repo_path)
                        shutil.rmtree(repo_path)
                    except Exception as e_rm:
                        logging.warning(
                            f"Could not clean up partial clone {repo_path}: {e_rm}"
                        )
                return None

            # Checkout the specific commit
            if not run_command(
                ["git", "checkout", pinned_commit],
                working_dir=repo_path,
                repo_name=repo_name,
            ):
                logging.error(
                    f"Failed to checkout commit {pinned_commit} for {repo_name}."
                )
                try:
                    make_writable_recursive(repo_path)
                    shutil.rmtree(repo_path)
                except Exception as e_rm:
                    logging.warning(
                        f"Could not clean up failed checkout {repo_path}: {e_rm}"
                    )
                return None
        else:
            logging.info(
                f"Cloning {repo_name} from {base_url} (latest commit) into {repo_path}"
            )
            if not run_command(
                ["git", "clone", "--depth", "1", base_url, repo_path],
                repo_name=repo_name,
            ):
                logging.error(f"Failed to clone {repo_name}.")
                if os.path.exists(repo_path):
                    try:
                        make_writable_recursive(repo_path)
                        shutil.rmtree(repo_path)
                    except Exception as e_rm:
                        logging.warning(
                            f"Could not clean up partial clone {repo_path}: {e_rm}"
                        )
                return None

        make_readonly(repo_path)
    return repo_path


def ensure_writable_for_operation(path_to_check):
    try:
        current_mode = os.stat(path_to_check).st_mode
        if not (current_mode & stat.S_IWUSR):
            new_mode = current_mode | stat.S_IWUSR
            if os.path.isdir(path_to_check) and not (current_mode & stat.S_IXUSR):
                new_mode |= stat.S_IXUSR
            os.chmod(path_to_check, new_mode)
        return True
    except Exception as e:
        logging.debug(f"Could not ensure {path_to_check} owner-writable: {e}")
        if not os.access(
            path_to_check, os.W_OK | (os.X_OK if os.path.isdir(path_to_check) else 0)
        ):
            logging.warning(
                f"Path {path_to_check} not writable/executable & could not be made owner-writable."
            )
            return False
        return True


def unpack_archives_recursively(directory_to_scan, repo_name_being_scanned=None):
    extracted_package_roots = []
    for root, _, files in os.walk(directory_to_scan, topdown=True):
        if not ensure_writable_for_operation(root):
            logging.warning(
                f"Cannot make {root} writable, skipping unpacking in this directory."
            )
            continue

        for filename in list(files):
            filepath = os.path.join(root, filename)
            archive_type = None
            extract_path_name = None
            extraction_succeeded = False  # Flag to track successful extraction

            if filename.endswith(".tar.gz"):
                archive_type = "tar.gz"
                extract_path_name = filename[: -len(".tar.gz")]
            elif filename.endswith(".whl"):
                archive_type = "whl"
                extract_path_name = filename[: -len(".whl")]
            elif filename.endswith(".zip"):
                archive_type = "zip"
                extract_path_name = filename[: -len(".zip")]
                if repo_name_being_scanned == DATADOG_MALICIOUS_REPO_NAME:
                    expected_datadog_zip_path_prefix = os.path.join(
                        directory_to_scan, "samples", "pypi"
                    )
                    if not root.startswith(expected_datadog_zip_path_prefix):
                        logging.debug(
                            f"Skipping zip {filepath} in {repo_name_being_scanned} as it's not under {expected_datadog_zip_path_prefix}"
                        )
                        continue
            elif filename.endswith(".gz") and not filename.endswith(".tar.gz"):
                archive_type = "gz"
                extract_path_name = filename[: -len(".gz")]
            else:
                continue

            logging.debug(f"Attempting to unpack {filepath} (type: {archive_type})")

            if not ensure_writable_for_operation(filepath):
                logging.warning(
                    f"Cannot make archive {filepath} writable for potential deletion, skipping."
                )
                continue

            extract_full_path = os.path.join(root, extract_path_name)

            try:
                if not ensure_writable_for_operation(root):
                    logging.warning(
                        f"Parent directory {root} not writable to create {extract_full_path}, skipping."
                    )
                    continue

                if not os.path.exists(extract_full_path):
                    os.makedirs(extract_full_path, exist_ok=True)
                elif not os.path.isdir(extract_full_path):
                    logging.warning(
                        f"Extraction path {extract_full_path} exists but is not a directory, skipping."
                    )
                    continue

                if not ensure_writable_for_operation(extract_full_path):
                    logging.warning(
                        f"Extraction target {extract_full_path} not writable, skipping."
                    )
                    continue

                if archive_type == "tar.gz":
                    with tarfile.open(filepath, "r:gz") as tar:
                        tar.extractall(path=extract_full_path)
                    logging.debug(
                        f"Successfully unpacked .tar.gz {filepath} to {extract_full_path}"
                    )
                    extraction_succeeded = True
                elif archive_type in ["whl", "zip"]:
                    try:
                        with zipfile.ZipFile(filepath, "r") as zip_ref:
                            zip_ref.extractall(extract_full_path)
                        logging.debug(
                            f"Successfully unpacked .{archive_type} {filepath} to {extract_full_path}"
                        )
                        extraction_succeeded = True
                    except RuntimeError as e_runtime_zip:
                        if (
                            "encrypted" in str(e_runtime_zip).lower()
                            or "password required" in str(e_runtime_zip).lower()
                        ) and repo_name_being_scanned == DATADOG_MALICIOUS_REPO_NAME:
                            logging.info(
                                f"Encrypted zip {filepath} in {DATADOG_MALICIOUS_REPO_NAME}. Attempting extraction with password."
                            )
                            try:
                                with zipfile.ZipFile(filepath, "r") as zip_ref_pwd:
                                    zip_ref_pwd.extractall(
                                        extract_full_path, pwd=ENCRYPTED_ZIP_PASSWORD
                                    )
                                logging.info(
                                    f"Successfully unpacked encrypted .{archive_type} {filepath} with password to {extract_full_path}"
                                )
                                extraction_succeeded = True
                            except RuntimeError as e_pwd_failed:
                                logging.warning(
                                    f"Failed to extract encrypted zip {filepath} with password: {e_pwd_failed}"
                                )
                            except Exception as e_pwd_generic_failed:
                                logging.error(
                                    f"Error extracting encrypted zip {filepath} with password: {e_pwd_generic_failed}"
                                )
                        else:
                            logging.warning(
                                f"Skipping zip file {filepath} due to unhandled RuntimeError: {e_runtime_zip}"
                            )
                    except zipfile.BadZipFile as e_zip_bad:
                        logging.debug(
                            f"Skipping file {filepath} as it's not a valid .whl/.zip file or is corrupted: {e_zip_bad}"
                        )
                elif archive_type == "gz":
                    decompressed_file_path = os.path.join(
                        extract_full_path, os.path.basename(extract_path_name)
                    )
                    with gzip.open(filepath, "rb") as f_in:
                        with open(decompressed_file_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    logging.debug(
                        f"Successfully decompressed .gz {filepath} to {decompressed_file_path}"
                    )
                    extraction_succeeded = True

                if extraction_succeeded:
                    extracted_package_roots.append(extract_full_path)
                    make_readonly(extract_full_path)
                    try:
                        if ensure_writable_for_operation(
                            filepath
                        ):  # Ensure original archive is writable before deleting
                            os.remove(filepath)
                            logging.debug(f"Successfully removed archive {filepath}")
                        else:
                            logging.warning(
                                f"Could not make {filepath} writable to remove it."
                            )
                    except OSError as e_remove:
                        logging.error(
                            f"Failed to remove archive {filepath} after extraction: {e_remove}"
                        )

            except tarfile.ReadError as e_tar:
                logging.debug(
                    f"Skipping file {filepath} as it's not a valid tar.gz file or is corrupted: {e_tar}"
                )
            except gzip.BadGzipFile as e_gzip:
                logging.debug(
                    f"Skipping file {filepath} as it's not a valid .gz file or is corrupted: {e_gzip}"
                )
            except EOFError as e_eof:
                logging.debug(
                    f"Skipping file {filepath} due to EOFError (possibly corrupted): {e_eof}"
                )
            except Exception as e_unpack:  # General catch-all for other issues in this file's processing
                logging.error(f"Failed to unpack or process {filepath}: {e_unpack}")
    return list(set(extracted_package_roots))


def process_benign_repositories(repo_urls):
    logging.info("Processing benign repositories...")
    processed_paths = []
    for repo_url in repo_urls:
        repo_name = get_repo_name_from_url(repo_url)
        try:
            cloned_repo_path = get_or_clone_repo(repo_url, BENIGN_REPOS_CACHE_PATH)
            if not cloned_repo_path:
                continue

            processed_paths.append(cloned_repo_path)
            logging.info(f"Processing benign: {repo_name}")
            # Placeholder for actual processing logic
        except Exception as e:
            logging.error(f"Error processing benign repo {repo_name}: {e}")
    return processed_paths


def process_malicious_repositories(repo_urls_list):
    logging.info("Processing malicious repositories...")
    all_processed_package_paths = []

    for repo_url in repo_urls_list:
        repo_name = get_repo_name_from_url(repo_url)
        current_repo_processed_package_paths = []
        logging.info(f"Processing malicious repository: {repo_name} from {repo_url}")
        try:
            cloned_mal_repo_path = get_or_clone_repo(
                repo_url, MALICIOUS_REPOS_CACHE_PATH
            )
            if not cloned_mal_repo_path:
                continue

            make_writable_recursive(cloned_mal_repo_path)
            logging.info(f"Unpacking archives in malicious repo: {repo_name}")
            extracted_package_paths = unpack_archives_recursively(
                cloned_mal_repo_path, repo_name_being_scanned=repo_name
            )
            make_readonly(cloned_mal_repo_path)

            if not extracted_package_paths:
                logging.warning(
                    f"No applicable packages extracted from {cloned_mal_repo_path}."
                )
            else:
                logging.info(
                    f"Found {len(extracted_package_paths)} malicious packages/extracted directories in {repo_name} for processing."
                )
                for package_path in extracted_package_paths:
                    descriptive_package_name = f"{repo_name}_{os.path.relpath(package_path, cloned_mal_repo_path).replace(os.sep, '_')}"
                    logging.info(
                        f"Processing malicious package content at: {package_path} (derived from {descriptive_package_name})"
                    )
                    current_repo_processed_package_paths.append(package_path)
            all_processed_package_paths.extend(current_repo_processed_package_paths)
        except Exception as e:
            logging.error(f"Error processing malicious repo {repo_name}: {e}")
    return all_processed_package_paths


def main():
    parser = argparse.ArgumentParser(
        description="Clone/use cached repositories and process them."
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["benign", "malicious", "all"],
        default="all",
        help="Type of dataset to process (default: all)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--use-latest",
        action="store_true",
        help="Use latest commits instead of pinned versions (non-reproducible)",
    )
    args, unknown = parser.parse_known_args()
    if unknown:
        logging.debug(f"Ignoring unknown arguments: {unknown}")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.INFO)

    # Handle pinning options
    global USE_PINNED_COMMITS
    if args.use_latest:
        USE_PINNED_COMMITS = False
        logging.info("Using latest commits (non-reproducible mode)")
    else:
        USE_PINNED_COMMITS = True
        logging.info("Using pinned commits for reproducible training")

    logging.info(
        f"Initializing script, using cache directory: {os.path.abspath(REPO_CACHE_DIR)}"
    )
    os.makedirs(BENIGN_REPOS_CACHE_PATH, exist_ok=True)
    os.makedirs(MALICIOUS_REPOS_CACHE_PATH, exist_ok=True)

    if args.type in ["benign", "all"]:
        process_benign_repositories(BENIGN_REPO_URLS)

    if args.type in ["malicious", "all"]:
        process_malicious_repositories(MALICIOUS_REPO_URLS)

    logging.info("Script execution finished.")


if __name__ == "__main__":
    main()
