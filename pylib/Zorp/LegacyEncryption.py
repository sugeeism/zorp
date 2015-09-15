############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

from Encryption import *
import types

class LegacyEncryption(object):
    def __init__(self):
        self.client_trusted_certs_directory = ''
        self.server_trusted_certs_directory = ''
        self.client_keypair_generate = FALSE
        self.server_keypair_generate = FALSE
        self.client_certificate_trusted = FALSE
        self.server_certificate_trusted = FALSE
        self.client_handshake={}
        self.server_handshake={}

        self.client_handshake["verify_cert_ext"] = (SSL_HS_POLICY, self.verifyTrustedCertClient)
        self.server_handshake["verify_cert_ext"] = (SSL_HS_POLICY, self.verifyTrustedCertServer)
        pass

    def readPEM(self,filename):
        """<method internal="yes">
        </method>
        """
        log(None, CORE_DEBUG, 6, "Reading PEM file; filename='%s'" % filename)
        f = open(filename, 'r')
        res = f.read()
        f.close()
        return res

    def readHashDir(self, hash, directory):
        """<method internal="yes">
        </method>
        """
        try:
            files = os.listdir(directory)
            i = 0
            for file in files:
                if self.hash_pattern.match(file):
                    try:
                        hash[i] = readPEM(directory + '/' + file)
                    except (TypeError, ValueError), s:
                        log(None, CORE_ERROR, 3, "Error adding CA certificate; reason='%s'" % (s,))
                    i = i+1
        except OSError, e:
            log(None, CORE_ERROR, 3, "Error reading CA or CRL directory; dir='%s', error='%s'", (directory, e.strerror))

    def isEncryptionUsed(self):
        return hasattr(self, "client_connection_security") or hasattr(self, "server_connection_security")

    def getEncryption(self, proxy):
        if self.client_keypair_generate == TRUE and self.server_keypair_generate == TRUE:
            raise ValueError, 'client_keypair_generate and server_keypair_generate are both enabled. '\
                    'Key generation cannot work on both sides at the same time.'

        if not self.isEncryptionUsed():
            return Encryption(client_security=SSL_NONE, server_security=SSL_NONE)

        if not hasattr(self, "client_connection_security"):
            self.client_connection_security = SSL_NONE
        if not hasattr(self, "server_connection_security"):
            self.server_connection_security = SSL_NONE

        client_method = ENCRYPTION_METHOD_SSLV23
        server_method = ENCRYPTION_METHOD_SSLV23
        if hasattr(self, "client_ssl_method"):
            if self.client_ssl_method == SSL_METHOD_SSLV23:
                client_method = ENCRYPTION_METHOD_SSLV23
            elif self.client_ssl_method == SSL_METHOD_SSLV3:
                client_method = ENCRYPTION_METHOD_SSLV3
            elif self.client_ssl_method == SSL_METHOD_TLSV1:
                client_method = ENCRYPTION_METHOD_TLSV1
            elif self.client_ssl_method == SSL_METHOD_ALL:
                client_method = ENCRYPTION_METHOD_SSLV23
            else:
                client_method = 5 #Bad method

        if hasattr(self, "server_ssl_method"):
            if self.server_ssl_method == SSL_METHOD_SSLV23:
                server_method = ENCRYPTION_METHOD_SSLV23
            elif self.server_ssl_method == SSL_METHOD_SSLV3:
                server_method = ENCRYPTION_METHOD_SSLV3
            elif self.server_ssl_method == SSL_METHOD_TLSV1:
                server_method = ENCRYPTION_METHOD_TLSV1
            elif self.server_ssl_method == SSL_METHOD_ALL:
                server_method = ENCRYPTION_METHOD_SSLV23
            else:
                server_method = 5 #Bad method

        encryption = Encryption(client_security=self.client_connection_security, server_security=self.server_connection_security, client_method=client_method, server_method=server_method)

        encryption.settings.client_handshake["verify_cert_ext"] = self.client_handshake["verify_cert_ext"]
        encryption.settings.server_handshake["verify_cert_ext"] = self.server_handshake["verify_cert_ext"]
        if self.client_connection_security > SSL_NONE:
            if hasattr(self, "client_cert") and type(self.client_cert) == types.StringType:
                self.client_cert_file = self.client_cert
            if hasattr(self, "client_key") and type(self.client_key) == types.StringType:
                self.client_key_file = self.client_key

            if hasattr(self, "client_keypair_files"):
                self.client_cert_file = self.client_keypair_files[0]
                self.client_key_file = self.client_keypair_files[1]

            if hasattr(self, "client_cagroup_directories"):
                self.client_ca_directory = self.client_cagroup_directories[0]
                self.client_crl_directory = self.client_cagroup_directories[1]

            if hasattr(self, "client_verify_cagroup_directories"):
                self.client_verify_ca_directory = self.client_verify_cagroup_directories[0]
                self.client_verify_crl_directory = self.client_verify_cagroup_directories[1]

            if hasattr(self, "client_cert_file"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing client_cert_file; value='%s'" % self.client_cert_file)
                proxy.tls.client_local_certificate = self.readPEM(self.client_cert_file)

            if hasattr(self, "client_key_file"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing client_key_file; value='%s'" % self.client_key_file)
                proxy.tls.client_local_privatekey = self.readPEM(self.client_key_file)

            if hasattr(self, "client_ca_directory"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing client_ca_directory; value='%s'" % self.client_ca_directory)
                #self.readHashDir(self.client_local_ca_list, self.client_ca_directory)
                self.readHashDir(encryption.settings.client_local_ca_list, self.client_ca_directory)

            if hasattr(self, "client_crl_directory"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing client_crl_directory; value='%s'" % self.client_crl_directory)
                #self.readHashDir(self.client_local_crl_list, self.client_crl_directory)
                self.readHashDir(encryption.settings.client_local_crl_list, self.client_crl_directory)

            if self.client_keypair_generate:
                if self.handshake_seq != SSL_HSO_SERVER_CLIENT:
                    raise ValueError, "For client-side keypair generation, the handshake order"\
                            " must be SSL_HSO_SERVER_CLIENT."
                else:
                    encryption.settings.client_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyClient)

        if self.server_connection_security > SSL_NONE:
            if hasattr(self, "server_cert") and type(self.server_cert) == types.StringType:
                self.server_cert_file = self.server_cert
            if hasattr(self, "server_key") and type(self.server_key) == types.StringType:
                self.server_key_file = self.server_key

            if hasattr(self, "server_keypair_files"):
                self.server_cert_file = self.server_keypair_files[0]
                self.server_key_file = self.server_keypair_files[1]

            if hasattr(self, "server_cagroup_directories"):
                self.server_ca_directory = self.server_cagroup_directories[0]
                self.server_crl_directory = self.server_cagroup_directories[1]

            if hasattr(self, "server_verify_cagroup_directories"):
                self.server_verify_ca_directory = self.server_verify_cagroup_directories[0]
                self.server_verify_crl_directory = self.server_verify_cagroup_directories[1]

            if hasattr(self, "server_cert_file"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing server_cert_file; value='%s'" % self.server_cert_file)
                proxy.tls.server_local_certificate = self.readPEM(self.server_cert_file)

            if hasattr(self, "server_key_file"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing server_key_file; value='%s'" % self.server_key_file)
                proxy.tls.server_local_privatekey = self.readPEM(self.server_key_file)

            if hasattr(self, "server_ca_directory"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing server_ca_directory; value='%s'" % self.server_ca_directory)
                #self.readHashDir(self.server_local_ca_list, self.server_ca_directory)
                self.readHashDir(encryption.settings.server_local_ca_list, self.server_ca_directory)

            if hasattr(self, "server_crl_directory"):
                log(proxy.session.session_id, SSL_DEBUG, 6, "Compatibility feature, processing server_crl_directory; value='%s'" % self.server_crl_directory)
                #self.readHashDir(self.server_local_crl_list, self.server_crl_directory)
                self.readHashDir(encryption.settings.server_local_crl_list, self.server_crl_directory)

            if self.server_keypair_generate:
                if self.handshake_seq != SSL_HSO_CLIENT_SERVER:
                    raise ValueError, "For server-side keypair generation, the handshake order"\
                            " must be SSL_HSO_CLIENT_SERVER."
                else:
                    encryption.settings.server_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyServer)

        if hasattr(self, "handshake_seq"):
            encryption.settings.handshake_seq = self.handshake_seq
        if hasattr(self, "handshake_timeout"):
            encryption.settings.handshake_timeout = self.handshake_timeout
        if hasattr(self, "permit_invalid_certificates"):
            encryption.settings.client_permit_invalid_certificates = self.permit_invalid_certificates
            encryption.settings.server_permit_invalid_certificates = self.permit_invalid_certificates
        if hasattr(self, "permit_missing_crl"):
            encryption.settings.client_permit_missing_crl = self.permit_missing_crl
            encryption.settings.server_permit_missing_crl = self.permit_missing_crl

        if hasattr(self, "client_verify_type"):
            encryption.settings.client_verify_type = self.client_verify_type
        if hasattr(self, "client_disable_proto_sslv3"):
            encryption.settings.client_disable_proto_sslv3 = self.client_disable_proto_sslv3
        if hasattr(self, "client_disable_proto_tlsv1"):
            encryption.settings.client_disable_proto_tlsv1 = self.client_disable_proto_tlsv1
        if hasattr(self, "client_ssl_cipher"):
            encryption.settings.client_ssl_cipher = self.client_ssl_cipher
        if hasattr(self, "client_verify_ca_directory"):
            encryption.settings.client_verify_ca_directory = self.client_verify_ca_directory
        if hasattr(self, "client_verify_crl_directory"):
            encryption.settings.client_verify_crl_directory = self.client_verify_crl_directory
        if hasattr(self, "client_verify_depth"):
            encryption.settings.client_verify_depth = self.client_verify_depth

        if hasattr(self, "server_verify_type"):
            encryption.settings.server_verify_type = self.server_verify_type
        if hasattr(self, "server_check_subject"):
            encryption.settings.server_check_subject = self.server_check_subject
        if hasattr(self, "server_disable_proto_sslv3"):
            encryption.settings.server_disable_proto_sslv3 = self.server_disable_proto_sslv3
        if hasattr(self, "server_disable_proto_tlsv1"):
            encryption.settings.server_disable_proto_tlsv1 = self.server_disable_proto_tlsv1
        if hasattr(self, "server_ssl_cipher"):
            encryption.settings.server_ssl_cipher = self.server_ssl_cipher
        if hasattr(self, "server_verify_ca_directory"):
            encryption.settings.server_verify_ca_directory = self.server_verify_ca_directory
        if hasattr(self, "server_verify_crl_directory"):
            encryption.settings.server_verify_crl_directory = self.server_verify_crl_directory
        if hasattr(self, "server_verify_depth"):
            encryption.settings.server_verify_depth = self.server_verify_depth

        if not encryption.setup():
            raise Exception, "Encryption.setup() returned error;"

        return encryption

    def verifyTrustedCert(self, side, verify_results, trusted_certs_dir, blob, proxy):
        """<method internal="yes">
        </method>
        """
        if trusted_certs_dir:
            if side == 1:
                f = '%s/%s:%d' % (self.server_trusted_certs_directory, proxy.session.server_address.ip_s, proxy.session.server_address.port)
            elif side == 0:
                f = '%s/%s' % (self.client_trusted_certs_directory, proxy.session.client_address.ip_s)
        else:
            return SSL_HS_ACCEPT

        log(proxy.session.session_id, SSL_DEBUG, 6, "Testing trusted certificates; f='%s'", (f,))
        if blob and os.access(f, os.R_OK):
            if readPEM(f) == blob:
                log(proxy.session.session_id, SSL_INFO, 4, "Trusting peer certificate; stored_cert='%s'", f)
                return SSL_HS_VERIFIED
            else:
                log(proxy.session.session_id, SSL_VIOLATION, 2, "Peer certificate differs from trusted cert; stored_cert='%s'", f)
                return SSL_HS_REJECT

        return SSL_HS_ACCEPT

    def verifyTrustedCertServer(self, side, verify_results, peer_cert, proxy):
        """<method internal="yes">
        </method>"""
        res = self.verifyTrustedCert(side, verify_results, self.server_trusted_certs_directory, peer_cert.blob, proxy)
        if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
            proxy.server_certificate_trusted = TRUE
        return res

    def verifyTrustedCertClient(self, side, verify_results, peer_cert, proxy):
        """<method internal="yes">
        </method>
        """
        res = self.verifyTrustedCert(side, verify_results, self.client_trusted_certs_directory, peer_cert.blob, proxy)
        if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
            proxy.client_certificate_trusted = TRUE
        return res

    def generateKeyClient(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        # client side, we need to look up the server key
        if not peer_cert:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate certificate for the client, no server certificate present, using configured certificate;")
            return SSL_HS_ACCEPT

        if hasattr(self, "key_generator"):
            log(proxy.session.session_id, SSL_DEBUG, 4, "Generating key for the client; trusted='%d'", proxy.server_certificate_trusted)
            if proxy.server_certificate_trusted:
                (proxy.tls.client_local_certificate, proxy.tls.client_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-trusted-key': peer_cert.blob})
            else:
                (proxy.tls.client_local_certificate, proxy.tls.client_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-untrusted-key': peer_cert.blob})
            return SSL_HS_ACCEPT
        else:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate key for the client, no key generator configured;")
            return SSL_HS_REJECT

    def generateKeyServer(self, side, peer_cert, tlsext_server_name, proxy):
        """<method internal="yes">
        </method>
        """
        # server side, we need to look up the client key
        if not peer_cert:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate certificate for the server, no client certificate present, using configured certificate;")
            return SSL_HS_ACCEPT

        if hasattr(self, "key_generator"):
            log(proxy.session.session_id, SSL_DEBUG, 4, "Generating key for the server; trusted='%d'", proxy.client_certificate_trusted)
            if proxy.client_certificate_trusted:
                (proxy.tls.server_local_certificate, proxy.tls.server_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-trusted-key': peer_cert.blob})
            else:
                (proxy.tls.server_local_certificate, proxy.tls.server_local_privatekey) = \
                    self.key_generator.getKeypair(proxy.session.session_id, {'bridge-untrusted-key': peer_cert.blob})
            return SSL_HS_ACCEPT
        else:
            log(proxy.session.session_id, SSL_ERROR, 4, "Unable to generate key for the server, no key generator configured;")
            return SSL_HS_REJECT
