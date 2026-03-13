# Copyright (C) 2026 DEFION.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

""" Modules to parse directories and subdirectories."""

import subprocess
import os


class DockerComposeError(Exception):
    """Raised when a docker compose command fails."""


class Docker(object):
    """
    Wrapper for managing Docker Compose projects.
    """

    def __init__(self, compose_file: str, project_name: str, timeout: int = 60):
        """
        :param compose_file: Full path to docker-compose.yml
        :param project_name: Docker compose project name
        :param timeout: Command timeout in seconds
        """
        self.compose_file = compose_file
        self.project_name = project_name
        self.timeout = timeout

        if not os.path.exists(self.compose_file):
            raise FileNotFoundError(f"Compose file not found: {self.compose_file}")

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """
        Executes docker compose command safely.
        """
        cmd = ["docker", "compose", "--project-name", self.project_name, "--file", str(self.compose_file), *args]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise DockerComposeError(f"Command timeout after {self.timeout}s: {' '.join(cmd)}") from e

        if check and result.returncode != 0:
            raise DockerComposeError(
                f"Command failed ({result.returncode}):\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

        return result

    def up(self, detach: bool = True, build: bool = False) -> None:
        """
        Start services.
        """
        args = ["up"]
        if detach:
            args.append("-d")
        if build:
            args.append("--build")

        self._run(*args)

    def down(self, volumes: bool = False) -> None:
        """
        Stop and remove services.
        """
        args = ["down"]
        if volumes:
            args.append("-v")

        self._run(*args)

    def stop(self) -> None:
        """
        Stop services without removing them.
        """
        self._run("stop")

    def restart(self) -> None:
        """
        Restart services.
        """
        self._run("restart")

    def status(self) -> str:
        """
        Returns formatted status of the project.
        """
        result = self._run("ps")
        return result.stdout

    def is_running(self) -> bool:
        """
        Returns True if any container in the project is running.
        """
        result = self._run("ps", "-q", check=False)
        return bool(result.stdout.strip())
