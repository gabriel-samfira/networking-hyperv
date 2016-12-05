# Copyright 2016 Cloudbase Solutions Srl
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


class NetworkingHyperVException(Exception):
    pass


class DataProcessingError(NetworkingHyperVException):

    """Base exception class for data processing related errors."""

    pass


class ServiceException(NetworkingHyperVException):

    """Base exception for all the API interaction related errors."""

    pass


class NotFound(ServiceException):

    """The required resource is not available."""

    pass


class CertificateVerifyFailed(ServiceException):

    """The received certificate is not valid.

    In order to avoid the current exception the validation of the SSL
    certificate should be disabled for the metadata provider. In order
    to do that the `https_allow_insecure` config option should be set.
    """

    pass
