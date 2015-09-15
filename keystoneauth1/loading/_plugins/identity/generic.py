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

import logging

try:
    import dns.resolver as dns_resolver
    import dns.exception as dns_exception
except ImportError:
    dns_exception = dns_resolver = None

from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1.loading._plugins.identity import base

LOG = logging.getLogger(__name__)


class GenericBaseLoader(base.BaseIdentityLoader):

    DNS_NAME = '_openstack_keystone'

    def get_options(self):
        options = super(GenericBaseLoader, self).get_options()

        options.extend([
            loading.Opt('domain-id', help='Domain ID to scope to'),
            loading.Opt('domain-name', help='Domain name to scope to'),
            loading.Opt('project-id', help='Project ID to scope to',
                        deprecated=[loading.Opt('tenant-id')]),
            loading.Opt('project-name', help='Project name to scope to',
                        deprecated=[loading.Opt('tenant-name')]),
            loading.Opt('project-domain-id',
                        help='Domain ID containing project'),
            loading.Opt('project-domain-name',
                        help='Domain name containing project'),
            loading.Opt('trust-id', help='Trust ID'),
        ])

        return options

    def _get_dns_name(self):
        if not (dns_resolver and dns_exception):
            LOG.debug("Skipping DNS lookup as dnspython not installed")
            return None

        try:
            response = dns_resolver.query(self.DNS_NAME,
                                          'TXT',
                                          raise_on_no_answer=True)
        except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN):
            LOG.debug("No authentication URL discovered from DNS")
        except dns_resolver.Timeout:
            LOG.warn("Timed out trying to discover URL from DNS")
        except dns_exception.DNSException as e:
            LOG.warn("Unexpected DNS error: %s", e)
        else:
            urls = [s for answer in response for s in answer.strings]

            if len(urls) > 1:
                LOG.warn("Found multiple options for URL from DNS. "
                         "Ignoring all of them rather than picking one.")
            else:
                LOG.debug("Using auth url from dns: %s", urls[0])
                return urls[0]

    def load_from_options(self, **kwargs):
        if not kwargs.get('auth_url'):
            auth_url = self._get_dns_name()

            if auth_url:
                kwargs['auth_url'] = auth_url

        return super(GenericBaseLoader, self).load_from_options(**kwargs)


class Token(GenericBaseLoader):

    @property
    def plugin_class(self):
        return identity.Token

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            loading.Opt('token', help='Token to authenticate with'),
        ])

        return options


class Password(GenericBaseLoader):

    @property
    def plugin_class(self):
        return identity.Password

    def get_options(cls):
        options = super(Password, cls).get_options()
        options.extend([
            loading.Opt('user-id', help='User id'),
            loading.Opt('user-name',
                        dest='username',
                        help='Username',
                        deprecated=[loading.Opt('username')]),
            loading.Opt('user-domain-id', help="User's domain id"),
            loading.Opt('user-domain-name', help="User's domain name"),
            loading.Opt('password', help="User's password"),
        ])
        return options
