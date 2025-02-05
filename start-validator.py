#!/usr/bin/env python3

import os
import sys
import time
import signal
import logging
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from git import Repo, GitCommandError
from apscheduler.schedulers.blocking import BlockingScheduler

############## Configuration ##############
BRANCH_NAME = "mainnet"
MAINNET_NETUID = 60

# How often we... (in minutes)
INTERVAL_UPDATE_CODE = 10
INTERVAL_PROCESS_ALIVE = 1

# Paths
WORKING_DIRECTORY = Path(".")   # Current directory
START_SCRIPT = WORKING_DIRECTORY / "scripts/start-validator-once.sh"
PID_FILE = WORKING_DIRECTORY / "validator.pid"

############## Globals ##############
use_testnet = False
stay_on_branch = False

############## Logging ##############
# Set up logging so that it goes to the console (stdout)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout
    # Note: no "filename=" means we're not logging to a file
)

# Suppress APScheduler info messages
logging.getLogger('apscheduler').setLevel(logging.WARNING)


############## Worker Functions ##############
def is_process_alive() -> bool:
    if not PID_FILE.is_file():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except ValueError:
        return False

    # Alt check:
    try:
        if Path(f"/proc/{pid}").exists():
            return True
    except Exception:
        pass
    
    # Standard check:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False # Process not found
    
def start_validator():
    """Start the validator. Output goes to the same screen as this script."""
    global use_testnet
    
    if is_process_alive():
        return
    
    logging.info("Starting validator...")
    
    # Construct the command, including the netuid if not testnet
    cmd = f"bash -c '{START_SCRIPT}"
    if not use_testnet:
        cmd += f" --netuid {MAINNET_NETUID}"
    cmd += "'" # close quote started after `bash -c`

    process = subprocess.Popen(
        cmd,
        cwd=WORKING_DIRECTORY,
        shell=True,
        executable='/bin/bash',
        # Ensure output is properly forwarded
        stdout=sys.stdout,
        stderr=sys.stderr,
        # Required for shell=True
        text=True,
        bufsize=1,
        preexec_fn=os.setsid  # Create new process group
    )
    
    # Write PID to file
    if process.pid:
        PID_FILE.write_text(str(process.pid))

    # Ensure process is properly terminated
    def cleanup_process():
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception as e:
            logging.warning(f"Failed to terminate process: {e}")

    import atexit
    atexit.register(cleanup_process)

def stop_validator():
    """Stops the validator if it's running."""
    if not PID_FILE.is_file():
        return
    
    try:
        pid = int(PID_FILE.read_text().strip())
        logging.info(f"Stopping validator process group with PID={pid}")
        
        # Repeat try to kill for a time
        start_time = time.time()
        killed = False
        while time.time() - start_time < 10:
            try:
                if time.time() - start_time < 4:
                    logging.info("Calling soft quit (SIGTERM)...")
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                else:
                    logging.info("Calling hard quit (-9, SIGKILL)...")
                    os.killpg(os.getpgid(pid), signal.SIGKILL)

                time.sleep(1)
         
                # Check if process exists
                if not is_process_alive():
                    killed = True
                    break
            except ProcessLookupError:
                killed = True
                break
            except OSError:
                killed = True
                break
            
            time.sleep(1)
        
        if not killed:
            logging.error(f"😒😒😒😒😒😒\n" +
                        f"\tFailed to exit validator pid {pid}, after 30 seconds.\n" +
                        f"\tCheck if still running by calling `kill -0 {pid}` -- if you get 'No such process' then you're good.\n" +
                        f"\tOtherwise, you should manually quit by calling `kill -9 {pid}`.\n" +
                        f"\tIf that doesn't work, try restarting your machine.")
            
    except (ValueError, ProcessLookupError):
        pass
    finally:
        # Clean up PID file
        PID_FILE.unlink(missing_ok=True)

def check_for_updates():
    """
    1. Fetch remote changes on BRANCH_NAME.
    2. Compare local vs. remote commits.
    3. If no difference, return early.
    4. If difference, check if repo is dirty; if so, stash. Pull. Then pop if stash was created.
    5. Stop validator & restart with new code
    """
    logging.info("Checking for updates...")

    repo = Repo(str(WORKING_DIRECTORY))
    git_cmd = repo.git

    # 1. Fetch
    try:
        repo.remotes.origin.fetch()
    except GitCommandError as e:
        logging.error(f"Failed to fetch changes: {e}")
        return

    branch = BRANCH_NAME
    # Detect the current branch if staying on the local branch
    if stay_on_branch:
        try:
            repo = Repo(str(WORKING_DIRECTORY))
            branch = repo.active_branch.name
            logging.info(f"Staying on the current branch: {branch}")
        except Exception as e:
            logging.error(f"Failed to detect the current branch: {e}")


    # Check for detached HEAD state and reset
    if repo.head.is_detached:
        logging.warning("HEAD is detached. Resetting to branch head...")
        try:
            git_cmd.reset('--hard', f'origin/{branch}')
            git_cmd.checkout(branch)
        except GitCommandError as e:
            logging.error(f"Failed to reset and checkout branch '{branch}': {e}")
            return

    # 2. Compare local vs. remote commits
    try:
        local_commit = repo.head.commit.hexsha
        remote_commit = repo.remotes.origin.refs[branch].commit.hexsha
        logging.info(f"remote branch: {branch}")
    except (AttributeError, IndexError) as e:
        logging.error(f"Could not find branch '{branch}' or commits: {e}")
        return

    # 3. If no difference, return early
    if local_commit == remote_commit:
        logging.info(f"✅ Code is up to date. ({local_commit})")
        return
    
    logging.info(f"🔄 Pulling new code... ({local_commit} -> {remote_commit})")

    # Log how long ago the newest commit was committed
    try:
        commit_time = repo.head.commit.committed_datetime
        time_since_commit = datetime.now() - commit_time
        # Calculate the total time difference in seconds
        total_seconds = time_since_commit.total_seconds()
        logging.info(f"New version of code was released {total_seconds:.0f} seconds ago.")
    except Exception as e:
        pass

    # 4. Check if we need to stash
    stash_created = False
    if repo.is_dirty(untracked_files=True):
        try:
            stash_result = git_cmd.stash('push', '-u', '-m', 'auto-update-stash')
            if "No local changes to save" not in stash_result:
                stash_created = True
                logging.info("🔖 Local changes saved.")
        except GitCommandError as e:
            logging.warning(f"❌ Error saving local changes: {e}")

    # Switch branch (just to be sure), then pull
    try:
        if not stay_on_branch:
            git_cmd.checkout(branch)
    except GitCommandError as e:
        message = f"❌ Failed to checkout branch '{branch}': {e}.\n\n"
        message += "⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️\n"
        message += f"Try manually updating by running 'git reset --hard HEAD && git clean -fd && git checkout {branch} && git pull && python3 start-validator-autoupdate.py'.\n\n"
        message += "⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️\n"
        logging.error(message)
        if stash_created:
            git_cmd.stash('pop')
        return

    try:
        repo.remotes.origin.pull()
        logging.info("✅ Code updated successfully.")
    except GitCommandError as e:
        logging.error(f"Failed to pull: {e}")
        # Roll back to old commit if needed
        logging.info("Reverting to previous commit...")
        try:
            git_cmd.checkout(local_commit)
        except GitCommandError as e:
            logging.error(f"Failed to checkout previous commit: {e}")

    # Pop stash if we created one
    if stash_created:
        try:
            git_cmd.stash('pop')
            logging.info("🔖 Local changes restored.")
        except GitCommandError as e:
            logging.warning("❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌\n" +
                           f"Conflict restoring local changes: {e}\n" +
                           "❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌")

    # 5. Stop validator & restart with new code
    stop_validator()
    start_validator()

def ensure_validator_is_running():
    """Checks if the validator is alive. If not, starts it."""
    if not is_process_alive():
        logging.warning("Validator is not running. Starting it now...")
        start_validator()

def setup_shutdown_handler():
    """Setup signal handlers to ensure proper shutdown."""
    def shutdown_handler(signum, frame):
        logging.info("Received shutdown signal. Stopping validator...")
        stop_validator()
        logging.info("Validator stopped. Exiting...")
        sys.exit(0)

    # Register the handler for termination signals
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

############## Argument Parsing ##############
def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Start and manage the validator process.")
    parser.add_argument(
        '--testnet',
        action='store_true',
        help='Use testnet instead of mainnet.'
    )
    parser.add_argument(
        '--stay-on-branch',
        action='store_true',
        help='Stay on the current branch instead of switching to BRANCH_NAME.'
    )
    return parser.parse_args()

############## Main: Setup the Scheduler ##############
def main():
    global use_testnet, stay_on_branch
    args = parse_arguments()

    use_testnet = True if args.testnet else False
    stay_on_branch = True if args.stay_on_branch else False

    setup_shutdown_handler()

    # Just to be safe
    stop_validator()

    # Check for updates before starting the scheduler and validator
    try:
        check_for_updates()
    except Exception as e:
        logging.error(f"Failed initial updates check: {e}")

    # use start_validator() instead of adding job to scheduler.
    # If we ran jobs immediately ensure_validator_is_running() 
    # would warn that validator was not running, which would 
    # be confusing! 
    start_validator()

    try:
        scheduler = BlockingScheduler()

        # 1) Check for Git updates
        scheduler.add_job(
            check_for_updates,
            'interval',
            minutes=INTERVAL_UPDATE_CODE,
            id='check_for_updates_job'
        )

        # 2) Ensure the validator is alive
        scheduler.add_job(
            ensure_validator_is_running,
            'interval',
            minutes=INTERVAL_PROCESS_ALIVE,
            id='ensure_validator_running_job'
        )

        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logging.info("Scheduler shutting down. Goodbye.")

if __name__ == "__main__":
    main()
