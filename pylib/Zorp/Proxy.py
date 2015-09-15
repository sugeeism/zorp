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

"""
<module maturity="stable">
  <summary>The Proxy module defines the abstract proxy class.</summary>
  <description>
    <para>
      This module encapsulates the ZorpProxy component
      implemented by the Zorp core. The Proxy module provides a common framework for
      protocol-specific proxies, implementing the functions that are used by all proxies.
      Protocol-specific proxy modules are derived from the Proxy module, and are
      described in <xref linkend="chapter_Proxies"/>.
    </para>
  </description>
  <metainfo>
  </metainfo>
</module>
"""

from Zorp import *
from Base import *
from Stream import Stream
from SockAddr import SockAddrInet
from Session import StackedSession, MasterSession
from Stack import getStackingProviderBackend
from Keybridge import *
from Chainer import ConnectChainer
from Exceptions import *
from Detector import *
from LegacyEncryption import *

import string, os, sys, traceback, re, types

def proxyLog(self, type, level, msg, args=None):
    """
    <function maturity="stable">
      <summary>
        Function to send a proxy-specific message to the system log.
      </summary>
      <description>
        <para>
          This function sends a message into the system log. All messages start with the
          <parameter>session_id</parameter> that uniquely identifies the connection.
        </para>
      </description>
      <metainfo>
        <arguments>
          <argument maturity="stable">
            <name>type</name>
            <type>
              <string/>
            </type>
            <description>
              The class of the log message.
            </description>
          </argument>
          <argument maturity="stable">
            <name>level</name>
            <type>
              <integer/>
            </type>
            <description>
              Verbosity level of the log message.
            </description>
          </argument>
          <argument maturity="stable">
            <name>msg</name>
            <type>
              <string/>
            </type>
            <description>
              The text of the log message.
            </description>
          </argument>
        </arguments>
      </metainfo>
    </function>
    """
    ## NOLOG ##
    log(self.session.session_id, type, level, msg, args)

class Proxy(BuiltinProxy):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract Zorp proxy.
      </summary>
      <description>
        <para>
          This class serves as the abstact base class for all proxies implemented
          in Zorp. When an instance of the Proxy class is created, it loads and starts a protocol-specific proxy.
          Proxies operate in their own threads, so this constructor returns immediately.
        </para>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable" internal="yes">
            <name>session</name>
            <type>Session instance</type>
            <description>The session inspected by the proxy.</description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>name</name>
            <type>
              <string/>
            </type>
            <description>The protocol-specific proxy class inspecting the traffic.</description>
          </attribute>
          <attribute maturity="stable" global="yes" internal="yes">
            <name>auth_inband_defer</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
            Set this parameter to <parameter>TRUE</parameter> to enable the protocol-specific proxy to perform
            inband authentication. This has effect only if the <link linkend="python.Auth">AuthenticationPolicy</link> used in
            the service requests InbandAuthentication.
            </description>
          </attribute>
          <attribute>
            <name>language</name>
            <type>
              <string/>
            </type>
            <default>en</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Determines the language used for user-visible error messages.
              Supported languages: <parameter>en</parameter> - English;
              <parameter>de</parameter> - German; <parameter>hu</parameter> - Hungarian.
            </description>
          </attribute>

          <attribute maturity="stable">
            <name>ssl.handshake_timeout</name>
            <type>
              <integer/>
            </type>
            <default>30000</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              SSL handshake timeout in milliseconds.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.permit_invalid_certificates</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Accept any kind of verification failure when UNTRUSTED verify_type is set.
              E.g.: accept expired, self-signed, etc. certificates.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.permit_missing_crl</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              This option has effect only if the CRL directories are set using the <parameter>ssl.client_verify_crl_directory</parameter> or <parameter>ssl.server_verify_crl_directory</parameter> parameters. If Zorp does not find  a CRL in these directories that matches the CAs in the certificate chain and <parameter>ssl.permit_missing_crl</parameter> is set to FALSE, Zorp rejects the certificate. Otherwise, the certificate is accepted even if no matching CRL is found.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.handshake_seq</name>
            <type>
              <link id="enum.ssl.hso"/>
            </type>
            <default>SSL_HSO_CLIENT_SERVER</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Handshake order. SSL_HSO_CLIENT_SERVER performs the client side handshake first, SSL_HSO_SERVER_CLIENT the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_connection_security</name>
            <type>
              <link id="enum.ssl.client_connection_security"/>
            </type>
            <default>SSL_NONE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Enable SSL on the client side of the proxy.
              This requires setting up a client private key and a certificate.
            </description>
          </attribute>
          <attribute internal="yes">
            <name>ssl.client_handshake</name>
            <type>HASH:empty:RW:R</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies policy callbacks for various SSL handshake phases.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_verify_type</name>
            <type>
              <link id="enum.ssl.verify"/>
            </type>
            <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Verification setting of the peer certificate on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_verify_depth</name>
            <type>
              <integer/>
            </type>
            <default>4</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The longest accepted CA verification chain.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_local_privatekey</name>
            <type>
              <certificate key="yes" cert="no"/>
            </type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The private key of the firewall on the client side. Specified as a string in PEM format.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_local_privatekey_passphrase</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Passphrase used to access <parameter>ssl.client_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.client_local_certificate</name>
            <type>X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The certificate associated to <parameter>ssl.client_local_privatekey</parameter> to be used on the client side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.client_peer_certificate</name>
            <type>X509:empty:R:R</type>
            <default>empty</default>
            <conftime>
              <read/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The certificate returned by the peer on the client side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.client_local_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              A hash of trusted certificates. The items in this hash are used to verify client certificates.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.client_local_crl_list</name>
            <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              A hash of Certificate Revocation Lists, associated to CA certificates in <parameter>ssl.client_local_ca_list</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_ssl_method</name>
            <type>
              <link id="enum.ssl.method"/>
            </type>
            <default>SSL_METHOD_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the allowed SSL/TLS protocols on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_disable_proto_sslv2</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_disable_proto_sslv3</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_disable_proto_tlsv1</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_ssl_cipher</name>
            <type>
              <link id="enum.ssl.ciphers"/>
            </type>
            <default>SSL_CIPHERS_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the allowed ciphers on the client side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_connection_security</name>
            <type>
              <link id="enum.ssl.server_connection_security"/>
            </type>
            <default>SSL_NONE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Enable SSL on the server side of the proxy.
              This requires setting up a private key and a certificate on Zorp.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_handshake</name>
            <type>HASH:empty:RW:R</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies policy callbacks for various SSL handshake phases.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_verify_type</name>
            <type>
              <link id="enum.ssl.verify"/>
            </type>
            <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Verification settings of the peer certificate on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_verify_depth</name>
            <type>
              <integer/>
            </type>
            <default>4</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The longest accepted CA verification chain.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_local_privatekey</name>
            <type>
              <certificate key="yes" cert="no"/>
            </type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The private key of the firewall on the server side, specified as a string in PEM format.
              Server side key and certificate are optional.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_local_privatekey_passphrase</name>
            <type>
              <string/>
            </type>
            <default>n/a</default>
            <conftime/>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Passphrase used to access <parameter>ssl.server_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_local_certificate</name>
            <type>X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              The certificate to be used on the server side, associated with <parameter>ssl.server_local_privatekey</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_peer_certificate</name>
            <type>X509:empty:R:R</type>
            <default>empty</default>
            <conftime>
              <read/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              The certificate returned by the peer on the server side.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_local_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of trusted certificates. The items in this hash are used to verify server certificates.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_peer_ca_list</name>
            <type>HASH;INTEGER;X509:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of names of trusted CAs as returned by the server to aid the selection of a local certificate.
            </description>
          </attribute>
          <attribute maturity="stable" internal="yes">
            <name>ssl.server_local_crl_list</name>
            <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
            <default>empty</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
              <write/>
            </runtime>
            <description>
              Hash of Certificate Revocation Lists, associated to CA certificates in <parameter>server_local_ca_list</parameter>.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_ssl_method</name>
            <type>
              <link id="enum.ssl.method"/>
            </type>
            <default>SSL_METHOD_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the SSL/TLS protocols allowed on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_disable_proto_sslv2</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_disable_proto_sslv3</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_disable_proto_tlsv1</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_ssl_cipher</name>
            <type>
              <link id="enum.ssl.ciphers"/>
            </type>
            <default>SSL_CIPHERS_ALL</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies the ciphers allowed on the server side.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_check_subject</name>
            <type>
              <boolean/>
            </type>
            <default>TRUE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Specifies
              whether the Subject of the
              server side certificate is
              checked against application
              layer information
              (e.g.: whether it matches the
              hostname in the URL). See also <xref linkend="certificate_verification"/>.
            </description>
          </attribute>

          <attribute maturity="stable">
            <name>ssl.client_cert_file</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              File containing the client-side certificate.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_key_file</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              File containing the client-side private key.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.client_keypair_files</name>
            <type>
              <certificate cert="yes" key="yes"/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of two file names containing the certificate and
              key files. Using <parameter>ssl.client_keypair_files</parameter> is an alternative to using
              the <parameter>ssl.client_cert_file</parameter> and <parameter>ssl.client_key_file</parameter> attributes.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.client_keypair_generate</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              Enables keybridging towards the clients. (Specifies whether to generate new certificates.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. Note that every certificate
              in this directory is loaded when the proxy is starting up. If
              <parameter>ssl.client_verify_type</parameter> is set to verify
              client certificates, Zorp sends the subject names of CA certificates
              stored in this directory to the client to request a certificate
              from these CAs.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.client_verify_ca_directory</parameter> option instead.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_verify_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. CA certificates are loaded
              on-demand from this directory when verifying the client certificate. Use this
              option instead of <parameter>self.ssl.client_ca_directory</parameter> unless you
              are authenticating the clients based on their certificates.
              Note that when using the <parameter>ssl.client_verify_ca_directory</parameter> option, Zorp
              does not send the list of accepted CAs to the client if the certificate of the client
              is verified.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. Note that every
              CRL in this directory is loaded when the proxy is starting up and this might
              require a huge amount of memory.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.client_verify_crl_directory</parameter> option instead.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.client_verify_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. CRLs are loaded
              on-demand from this directory when verifying the client certificate.
              Unless you are authenticating the clients based on their certificates,
              use this option instead of <parameter>self.ssl.client_crl_directory</parameter>.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.client_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>self.ssl.client_ca_directory</parameter>
              and <parameter>self.ssl.client_crl_directory</parameter>.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.client_verify_cagroup_directories</parameter> option instead.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.client_verify_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>self.ssl.client_verify_ca_directory</parameter>
              and <parameter>self.ssl.client_verify_crl_directory</parameter>.
              Unless you are authenticating the clients based on their certificates,
              use this option instead of <parameter>self.ssl.client_cagroup_directories</parameter>.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.client_trusted_certs_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A directory where trusted IP - certificate assignments are
              stored.  When a specific IP address introduces itself with the
              certificate stored in this directory, it is accepted regardless of
              its expiration or issuer CA. Each file in the directory should
              contain a certificate in PEM format and have the name of the IP
              address.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_cert_file</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              File containing the server-side certificate.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_key_file</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              File containing the server-side private key.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.server_keypair_files</name>
            <type>
              <certificate cert="yes" key="yes"/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of two file names containing the certificate and key
              files. Using <parameter>ssl.server_keypair_files</parameter> is an alternative to using the
              <parameter>ssl.server_cert_file</parameter> and <parameter>ssl.server_key_file</parameter> attributes.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.server_keypair_generate</name>
            <type>
              <boolean/>
            </type>
            <default>FALSE</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              Enables keybridging towards the server. (Specifies whether to generate new certificates.)
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. Please note that all certificates
              in the directory are loaded when the proxy is starting up.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.server_verify_ca_directory</parameter> option instead.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_verify_ca_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the trusted CA certificates are stored. CA certificates are loaded
              on-demand from this directory when verifying the server certificate.
              Unless you are authenticating the clients based on their certificates,
              use this option instead of <parameter>self.ssl.server_ca_directory</parameter>.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with the trusted CAs are stored. Please note that all
              CRLs in the directory are loaded when the proxy is starting up and this might
              require a huge amount of memory.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.server_verify_crl_directory</parameter> option instead.
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ssl.server_verify_crl_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              Directory where the CRLs associated with trusted CAs are stored. CRLs are loaded
              on-demand from this directory when verifying the server certificate.
              Unless you are authenticating the clients based on their certificates,
              use this option instead of <parameter>self.ssl.server_crl_directory</parameter>.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.server_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>self.ssl.server_ca_directory</parameter>
              and <parameter>self.ssl.server_crl_directory</parameter>.
              Unless you are authenticating the clients based on their certificates,
              use the <parameter>self.ssl.server_verify_cagroup_directories</parameter> option instead.
            </description>
          </attribute>
          <attribute>
            <name>ssl.server_verify_cagroup_directories</name>
            <type>
              <cagroup/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A tuple of the trusted CA certificate directory and
              the corresponding CRL directory. This option sets both
              <parameter>self.ssl.server_verify_ca_directory</parameter>
              and <parameter>self.ssl.server_verify_crl_directory</parameter>.
              Unless you are authenticating the clients based on their certificates,
              use this option instead of <parameter>self.ssl.server_cagroup_directories</parameter>.
              <para>Available only in Zorp version 3.4.3 and later.</para>
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.server_trusted_certs_directory</name>
            <type>
              <string/>
            </type>
            <default>""</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime>
              <read/>
            </runtime>
            <description>
              A directory where trusted IP:port - certificate assignments are
              stored. When a specific IP address introduces itself with the
              certificate stored in this directory, it is accepted regardless
              of its expiration or issuer CA. Each file in the directory should
              contain a certificate in PEM format and should be named as
              'IP:PORT'.
            </description>
          </attribute>
          <attribute state="stable">
            <name>ssl.key_generator</name>
            <type>
              <class filter="x509keymanager" instance="yes"/>
            </type>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>
              An instance of a X509KeyManager or derived class to generate keys
              automatically based on the keys on one of the other peers. Use
              X509KeyBridge to generate certificates automatically with a
              firewall hosted local CA.
            </description>
          </attribute>
          <attribute state="stable">
            <name>encryption_policy</name>
            <type>
              <class filter="encryptionpolicy" instance="no" existing="yes"/>
            </type>
            <default>None</default>
            <conftime>
              <read/>
              <write/>
            </conftime>
            <runtime/>
            <description>Name of the Encryption policy instance used to
            encrypt the sessions and verify the certificates used.
            For details, see <xref linkend="python.Encryption"/>.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """
    name = None
    module = None
    auth_inband_defer = FALSE
    auth_inband_supported = FALSE
    auth_server_supported = FALSE

    ssl_deprecation_warning = True
    def __init__(self, session):
        """
        <method internal="yes">
          <summary>
            Constructor to initialize an instance of the Proxy class.
          </summary>
          <description>
            <para>
              This constructor creates a new Proxy instance
              which creates an instance of the protocol-specific proxy class.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>name</name>
                <type></type>
                <description>The protocol-specific proxy class inspecting the traffic.</description>
              </argument>
              <argument maturity="stable">
                <name>session</name>
                <type>SESSION</type>
                <description>The session inspected by the proxy.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        # NOTE: circular reference, it is resolved in the __destroy__ method
        self.session = session
        session.setProxy(self)
        self.server_fd_picked = FALSE
        self.proxy_started = FALSE

        ## LOG ##
        # This message reports that a new proxy instance was started.
        ##
        log(session.session_id, CORE_SESSION, 5, "Proxy starting; class='%s', proxy='%s'", (self.__class__.__name__, self.name))
        if session.owner:
            parent = session.owner.proxy
        else:
            parent = None
        if not self.module:
            self.module = self.name

        super(Proxy, self).__init__(self.name, self.module, session.session_id, session.client_stream, parent)

    def __del__(self):
        """
        <method internal="yes">
          <summary>
            Destructor to deinitialize a Proxy instance.
          </summary>
          <description>
            <para>
              This destructor is called when this object instance is
              freed. It simply sends a message about this event to the
              log.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """

        ## LOG ##
        # This message reports that this proxy instance was ended.
        ##
        log(self.session.session_id, CORE_SESSION, 5, "Proxy ending; class='%s', module='%s'", (self.__class__.__name__, self.name))

    def __pre_startup__(self):
        """
        <method internal="yes">
        </method>
        """
        pass

    def __pre_config__(self):
        """
        <method internal="yes">
          <summary>
            Function called by the proxy core to perform internal proxy initialization.
          </summary>
          <description>
            <para>
              This function is similar to config() to perform initialization
              of internal proxy related data. It is not meant as a user
              interface, currently it is used to perform outband authentication.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if not self.session.auth_user and self.session.service.authentication_policy:
            self.session.service.authentication_policy.performAuthentication(self.session)

        # hack: decrease timeout for UDP sessions
        if (self.session.protocol == ZD_PROTO_UDP) and self.timeout > 60000:
            self.timeout = 60000
        self.language = config.options.language
        self.ssl = LegacyEncryption()
        self.encryption_policy = None

    def __post_config__(self):
        """<method internal="yes">
        </method>
        """
        if Proxy.ssl_deprecation_warning and self.ssl.isEncryptionUsed():
            Proxy.ssl_deprecation_warning = False
            log(None, CORE_DEBUG, 3, "Use of self.ssl properties are deprecated, EncryptionPolicy should be used instead.")

        if self.session.service.encryption_policy and self.ssl.isEncryptionUsed():
            raise ValueError, 'You can only configure encryption through EncryptionPolicy or Proxy settings, not both'
        self.encryption = None
        if self.session.service.encryption_policy:
            self.encryption = self.session.service.encryption_policy.getEncryption()
        elif self.encryption_policy:
            self.encryption = getEncryptionPolicy(self.encryption_policy).getEncryption()
        else:
            self.encryption = self.ssl.getEncryption(self)


    def config(self):
        """
        <method maturity="stable">
          <summary>
            Function called by the proxy core to initialize the proxy instance.
          </summary>
          <description>
            <para>
              This function is called during proxy startup. It sets the attributes of the proxy instance according
               to the configuration of the proxy.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        pass

    def closedByAbort(self):
        """
        <method maturity="stable">
          <summary>
            Function called by the proxy core when an abort has been occured.
          </summary>
          <description>
            <para>
              This function is called when a callback gives abort or no result. It simply sets a flag that
              will be used for logging the reason of the proxy's ending.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if self.session.owner.verdict == ConnectionVerdict(ConnectionVerdict.ACCEPTED):
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.ABORTED_BY_POLICY_ACTION)

    def invalidPolicyCall(self):
        """
        <method maturity="stable">
          <summary>
            Invalid policy function called.
          </summary>
          <description>
            <para>
              This function is called when invalid policy function has been called.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if self.session.owner.verdict == ConnectionVerdict(ConnectionVerdict.ACCEPTED):
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.INVALID_POLICY_CALL)

    def __destroy__(self):
        """
        <method internal="yes">
          <summary>
            Function called by the proxy core when the session is to be freed.
          </summary>
          <description>
            <para>
              This function is called when the proxy module is to be freed. It
              simply sends a message about this event to the log.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        # NOTE: if C proxy was started but the chaining process was
        # not completed then the server side of the connection is
        # still hanging there unpicked. Close it.

        if self.proxy_started and self.session.server_stream and not self.server_fd_picked:
            self.session.server_stream.close()

        # free circular reference between session & proxy
        session = self.session
        del self.session.proxy
        delattr(self.session, self.name)

        ## LOG ##
        # This message reports that this proxy instance was destroyed and freed.
        ##
        log(self.session.session_id, CORE_DEBUG, 6, "Proxy destroy; class='%s', module='%s'", (self.__class__.__name__, self.name))
        # free possible circular references in __dict__ by removing all elements
        self.__dict__.clear()
        self.session = session

    def _stackProxyInSession(self, proxy_class, session):
        """
        <method internal="yes"/>
        """
        try:
            proxy = proxy_class(session)
            if ProxyGroup(1).start(proxy):
                return proxy
            else:
                raise RuntimeError, "Error starting proxy in group"

        except:
            ## LOG ##
            # This message indicates that an error occurred during child proxy stacking.
            # The stacking failed and the subsession is destroyed.
            ##
            proxyLog(self, CORE_ERROR, 2, "Error while stacking child proxy; error='%s', error_desc='%s', " % (sys.exc_info()[0], sys.exc_info()[1]))
            raise

    def stackProxyInSession(self, proxy_class, subsession, stack_info):
        """
        <method internal="yes"/>
        """
        subsession.stack_info = stack_info

        try:
            return self._stackProxyInSession(proxy_class, subsession)
        except:
            subsession.destroy()
            raise

    def stackProxy(self, client_stream, server_stream, proxy_class, stack_info):
        """
        <method internal="yes">
          <summary>
            Function to embed (stack) a proxy into the current proxy instance.
          </summary>
          <description>
            <para>
              This function stacks a new proxy into the current proxy instance. The function receives the
              downstream filedescriptors and the protocol-specific proxy class to embed.
              The way the underlying proxy decides which proxy_class
              to use is proxy specific.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>client_stream</name>
                <type></type>
                <description>The client-side data stream.</description>
              </argument>
              <argument maturity="stable">
                <name>server_stream</name>
                <type></type>
                <description>The server-side data stream.</description>
              </argument>
              <argument maturity="stable">
                <name>proxy_class</name>
                <type></type>
                <description>The protocol-specific proxy class to embed into the current proxy instance.
                </description>
              </argument>
              <argument maturity="stable">
                <name>stack_info</name>
                <type></type>
                <description>Meta-information provided by the parent proxy.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        proxyLog(self, CORE_DEBUG, 7, "Stacking child proxy; client_fd='%d', server_fd='%d', class='%s'", (client_stream.fd, server_stream.fd, proxy_class.__name__))

        # generate session ID for streams by replacing proxy name in the current value
        session_id_parts = string.split(self.session.session_id, '/')
        session_id_parts[-1] = proxy_class.name
        session_id = string.join(session_id_parts, '/')

        subsession = StackedSession(self.session)
        subsession.stack_info = stack_info
        subsession.client_stream = client_stream
        subsession.client_stream.name = "%s/client_upstream" % (session_id)
        subsession.server_stream = server_stream
        subsession.server_stream.name = "%s/server_upstream" % (session_id)

        try:
            return self._stackProxyInSession(proxy_class, subsession)
        except:
            subsession.destroy()
            raise

    def stackCustom(self, args):
        """
        <method maturity="stable" internal="yes">
          <summary>
            Function to perform custom stacking.
          </summary>
          <description>
            <para>
              This function is called by the underlying C proxy to
              stack a Stackin Provider (<parameter>Z_STACK_PROVIDER</parameter>), or to perform a customized
               stacking (<parameter>Z_STACK_CUSTOM</parameter>) stacking.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>args</name>
                <type></type>
                <description>A tuple of custom stacking arguments.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        ## LOG ##
        # This message reports that Zorp is about to stack a new proxy under the current proxy, as a child proxy.
        ##
        proxyLog(self, CORE_DEBUG, 7, "Stacking custom child; args='%s'", (str(args)))
        stack_info = None
        if isinstance(args[0], str):
            # this is a Z_STACK_PROVIDER stacking,
            # args[0] is provider name,
            # args[1] is stack_info argument
            stack_backend = getStackingProviderBackend(args[0])
            stack_info = args[1]
        else:
            # this is a Z_STACK_CUSTOM stacking
            # args[0] is an AbstractStackingBackend instance
            # args[1] is optional stack_info
            stack_backend = args[0]
            stack_info = args[1]
        return stack_backend.stack(stack_info)

    def setServerAddress(self, host, port):
        """
        <method maturity="stable">
          <summary>
            Function called by the proxy instance to set the
            address of the destination server.
          </summary>
          <description>
            <para>
              The proxy instance calls this function to set the
              address of the destination server.
              This function attempts to resolve the hostname of the server using the DNS;
              the result is stored in the <parameter>session.server_address</parameter> parameter.
              The address of the server may be modified later by the router of the service. See
              <xref linkend="python.Router"/> for details.
            </para>
            <note>
            <para>
            The <parameter>setServerAddress</parameter> function has effect
             only when <link linkend="python.Router.InbandRouter">InbandRouter</link>
              is used.
            </para>
            </note>
          </description>
          <metainfo>
            <arguments>
              <argument>
                <name>host</name>
                <type><string/></type>
                <description>The host name of the server.</description>
              </argument>
              <argument>
                <name>port</name>
                <type><integer/></type>
                <description>The Port number of the server.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        return self.session.setTargetAddressByHostname(host, port)

    def _connectServerInternal(self):
        """<method internal="yes"/>"""
        server_stream = None

        try:
            server_stream = self.session.chainer.chainParent(self.session)
        except ZoneException, s:
            ## LOG ##
            # This message indicates that no appropriate zone was found for the server address.
            # @see: Zone
            ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_POLICY)
            proxyLog(self, CORE_POLICY, 1, "Zone not found; info='%s'", (s,))
        except DACException, s:
            ## LOG ##
            # This message indicates that an DAC policy violation occurred.
            # It is likely that the new connection was not permitted as an inbound_service in the given zone.
            # @see: Zone
            ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_POLICY)
            proxyLog(self, CORE_POLICY, 1, "DAC policy violation; info='%s'", (s,))
            self.notifyEvent("core.dac_exception", [])
        except MACException, s:
            ## LOG ##
            # This message indicates that a MAC policy violation occurred.
            ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_POLICY)
            proxyLog(self, CORE_POLICY, 1, "MAC policy violation; info='%s'", (s,))
        except AAException, s:
            ## NOLOG ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_POLICY)
            proxyLog(self.self, CORE_POLICY, 1, "Authentication failure; info='%s'", (s,))
        except LimitException, s:
            ## NOLOG ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_LIMIT)
            proxyLog(self, CORE_POLICY, 1, "Connection over permitted limits; info='%s'", (s,))
        except LicenseException, s:
            ## NOLOG ##
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_LIMIT)
            proxyLog(self, CORE_POLICY, 1, "Attempt to use an unlicensed component, or number of licensed hosts exceeded; info='%s'", (s,))
        except:
            self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_UNKNOWN_FAIL)
            traceback.print_exc()
        else:
            is_silent_io_error = server_stream is None
            if is_silent_io_error:
                self.session.owner.verdict = ConnectionVerdict(ConnectionVerdict.DENIED_BY_CONNECTION_FAIL)

        return server_stream

    def connectServer(self):
        """
        <method maturity="stable">
          <summary>
            Function called by the proxy instance to establish the
            server-side connection.
          </summary>
          <description>
            <para>
              This function is called to establish the server-side connection.
              The function either connects a proxy to the destination server,
              or an embedded proxy to its parent proxy. The proxy may set the
               address of the destination server using the <function>setServerAddress</function>
                function.
            </para>
            <para>
              The <function>connectServer</function> function calls the chainer
              specified in the service definition to connect to the remote server
              using the host name and port parameters.
            </para>
            <para>
              The <function>connectServer</function> function returns the descriptor
               of the server-side data stream.
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        if self.session.chainer == None:

            # we have no chainer, the server side fd
            # should be available by now, used in stacked
            # proxies
            if self.session.server_stream == None:
                raise InternalException, "No chainer and server_stream is None"

            if self.server_fd_picked:
                ## LOG ##
                # This message indicates an internal
                # error condition, more precisely a
                # non-toplevel proxy tried to
                # connect to the server side
                # multiple times, which is not
                # supported. Please report this
                # event to the Zorp QA team (at
                # devel@balabit.com).
                ##
                log(self.session.session_id, CORE_ERROR, 1, "Internal error, stacked proxy reconnected to server multiple times;")
                return None
            self.server_fd_picked = TRUE

        else:
            self.server_fd_picked = TRUE
            self.session.server_stream = self._connectServerInternal()

        return self.session.server_stream

    def userAuthenticated(self, entity,
                          auth_info=''
                          ):
        """
        <method maturity="stable">
          <summary>
            Function called when inband authentication is successful.
          </summary>
          <description>
            <para>
              The proxy instance calls this function to
              indicate that the inband authentication was successfully
              performed. The name of the client is stored in the
              <parameter>entity</parameter> parameter.
            </para>
          </description>
          <metainfo>
          <arguments>
              <argument maturity="stable">
                <name>entity</name>
                <type></type>
                <description>Username of the authenticated client.</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        self.session.auth_user = entity
        self.session.auth_info = auth_info
        ## LOG ##
        # This message reports that the user authentication was successful.
        ##
        proxyLog(self, CORE_AUTH, 3, "User authentication successful; entity='%s', auth_info='%s'", (entity, auth_info))
        update_szig = {'auth_user': entity,
                       'auth_info': auth_info,
                       'auth_groups': str(groups),}

        if auth_info == 'gw-auth':
            update_szig["gateway_user"] = entity
            update_szig["gateway_groups"] = str(groups)
        elif auth_info == 'server':
            update_szig["remote_user"] = entity
            update_szig["remote_groups"] = str(groups)

        self.session.updateSzigConns(Z_SZIG_CONNECTION_PROPS, update_szig);


    def readPEM(self, filename):
        """<method internal="yes">
        </method>
        """
        proxyLog(self, CORE_DEBUG, 6, "Reading PEM file; filename='%s'" % filename)
        f = open(filename, 'r')
        res = f.read()
        f.close()
        return res

    hash_pattern = re.compile("[0-9a-fA-F]*\.(r){0,1}[0-9]")


