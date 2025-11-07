# Unix SMB/CIFS implementation.
# Copyright (C) Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import tarfile
from pathlib import Path
from tarfile import ExtractError, TarFile as UnsafeTarFile


class TarFile(UnsafeTarFile):
    """This TarFile implementation is trying to ameliorate CVE-2007-4559,
    where tarfile.TarFiles can step outside of the target directory
    using '../../'.
    """

    try:
        # New in version 3.11.4 (also has been backported)
        # https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extraction_filter
        # https://peps.python.org/pep-0706/
        extraction_filter = staticmethod(tarfile.tar_filter)
    except AttributeError:
        def extract(self, member, path="", set_attrs=True, *,
                    numeric_owner=False):
            self._safetarfile_check(path)
            super().extract(member, path, set_attrs=set_attrs,
                            numeric_owner=numeric_owner)

        def extractall(self, path, members=None, *, numeric_owner=False):
            self._safetarfile_check(path)
            super().extractall(path, members,
                               numeric_owner=numeric_owner)

        def _safetarfile_check(self, path=""):
            # Resolve the target directory to an absolute path
            target_dir = self._resolve_path(path if path else os.getcwd())
            
            for tarinfo in self.__iter__():
                if self._is_traversal_attempt(tarinfo=tarinfo, target_dir=target_dir):
                    raise ExtractError(
                        "Attempted directory traversal for "
                        f"member: {tarinfo.name}")
                if self._is_unsafe_symlink(tarinfo=tarinfo, target_dir=target_dir):
                    raise ExtractError(
                        "Attempted directory traversal via symlink for "
                        f"member: {tarinfo.linkname}")
                if self._is_unsafe_link(tarinfo=tarinfo, target_dir=target_dir):
                    raise ExtractError(
                        "Attempted directory traversal via link for "
                        f"member: {tarinfo.linkname}")

        def _resolve_path(self, path):
            return os.path.realpath(os.path.abspath(path))

        def _is_path_in_dir(self, path, basedir):
            return self._resolve_path(os.path.join(basedir,
                                      path)).startswith(basedir)

        def _is_traversal_attempt(self, tarinfo, target_dir):
            # Check for obvious traversal patterns
            if (tarinfo.name.startswith(os.sep)
               or ".." + os.sep in tarinfo.name
               or tarinfo.name.startswith("../")):
                return True
            
            # Check if the resolved path would be outside the target directory
            try:
                member_path = os.path.join(target_dir, tarinfo.name)
                resolved_path = self._resolve_path(member_path)
                if not resolved_path.startswith(target_dir + os.sep) and resolved_path != target_dir:
                    return True
            except (OSError, ValueError):
                # If we can't resolve the path, consider it unsafe
                return True
            
            return False

        def _is_unsafe_symlink(self, tarinfo, target_dir):
            if tarinfo.issym():
                # Check if the symlink target would point outside the target directory
                try:
                    # Resolve the symlink target relative to where the symlink will be created
                    symlink_location = os.path.join(target_dir, tarinfo.name)
                    symlink_dir = os.path.dirname(symlink_location)
                    symlink_target = os.path.join(symlink_dir, tarinfo.linkname)
                    resolved_target = self._resolve_path(symlink_target)
                    
                    if not resolved_target.startswith(target_dir + os.sep) and resolved_target != target_dir:
                        return True
                except (OSError, ValueError):
                    # If we can't resolve the symlink, consider it unsafe
                    return True
            return False

        def _is_unsafe_link(self, tarinfo, target_dir):
            if tarinfo.islnk():
                # Check if the hard link target would point outside the target directory
                try:
                    link_target = os.path.join(target_dir, tarinfo.linkname)
                    resolved_target = self._resolve_path(link_target)
                    
                    if not resolved_target.startswith(target_dir + os.sep) and resolved_target != target_dir:
                        return True
                except (OSError, ValueError):
                    # If we can't resolve the link, consider it unsafe
                    return True
            return False


open = TarFile.open
