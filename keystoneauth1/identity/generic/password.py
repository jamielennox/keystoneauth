# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystoneauth1 import _utils as utils
from keystoneauth1 import discover
from keystoneauth1 import exceptions
from keystoneauth1.identity.generic import base
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3

LOG = utils.get_logger(__name__)


class Password(base.BaseGenericPlugin):
    """A common user/password authentication plugin.

    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string password: Password for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.

    """

    @utils.positional()
    def __init__(self, auth_url, username=None, user_id=None, password=None,
                 user_domain_id=None, user_domain_name=None, **kwargs):
        super(Password, self).__init__(auth_url=auth_url, **kwargs)

        self._username = username
        self._user_id = user_id
        self._password = password
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name

    def create_plugin(self, session, version, url, raw_status=None):
        if discover.version_match((2,), version):
            if self._user_domain_id or self._user_domain_name:
                raise exceptions.DiscoveryFailure(
                    'Cannot use v2 authentication with domain scope')

            return v2.Password(auth_url=url,
                               user_id=self._user_id,
                               username=self._username,
                               password=self._password,
                               **self._v2_params)

        elif discover.version_match((3,), version):
            return v3.Password(auth_url=url,
                               user_id=self._user_id,
                               username=self._username,
                               user_domain_id=self._user_domain_id,
                               user_domain_name=self._user_domain_name,
                               password=self._password,
                               **self._v3_params)
