var EncryptIdentify = {
    /* 代码参考了 https://github.com/psypanda/hashID/blob/master/hashid.py
    但是显然我能做的比他更好，他并没有考虑到大小写问题
    但是我想了一下，这里是加密/hash，不是编码，似乎所有的加密/hash类型都不需要考虑大小写，只有编码才需要
    但是我又想了一下，他这里并没有统一处理后传进来，所以还是有问题的
    但是我非常fucking的刚才没有保存全关掉了，还好只是一些小工作 */
    // 下面是原始替换表
    /*
    >	_ove_
    ≥	_ove_q_
    <	_und_
    ≤	_und_q_
    =	_eq_
    :	_with_
    $	_dol_
    #	_sharp_
    ()	_to_
    _
    .	_dot_
    +	_add_
    -	_
    /	_or_
    '	_
    */

    /**
     * 通用加密检查，调用以下其他所有检查方法。注意传入的密文应该总是HEX形式的
     * @param  {string} str 要检查的字符串
     * @return {object|boolean}     成功返回对象，失败返回false
     */
    identify: function(str) {
        // 先写个demo，能用就行，后面再慢慢改
        let password = str + '', todo, resTmp, result = [];
        for (let i in this.idGroup) {
            todo = 'this.idGroup[' + i + '](\'' + password + '\')';
            resTmp = eval(todo);
            resTmp && (result = result.concat(resTmp));
        }
        let n = 0, resArr = [];
        for (let i of result) {
            resArr[n++] = eval('this.encryptType.' + i);
        }
        for (let i of resArr) {
            // console.log(i.name);
        }
        return resArr;


        // 注意去除头尾的空白字符并提示
        // 检测非可见字符并提示，以免误判
        // return ...
    },


    /**
     * 加密/HASH类型定义
     * @type {Object}
     */
    encryptType: {
        CRC_16: {
            name: 'CRC-16',
        },
        CRC_16_CCITT: {
            name: 'CRC-16-CCITT',
        },
        FCS_16: {
            name: 'FCS-16',
        },
        ADLER_32: {
            name: 'Adler-32',
        },
        CRC_32B: {
            name: 'CRC-32B',
        },
        FCS_32: {
            name: 'FCS-32',
        },
        GHASH_32_3: {
            name: 'GHash-32-3',
        },
        GHASH_32_5: {
            name: 'GHash-32-5',
        },
        FNV_132: {
            name: 'FNV-132',
        },
        FLETCHER_32: {
            name: 'Fletcher-32',
        },
        JOAAT: {
            name: 'Joaat',
        },
        ELF_32: {
            name: 'ELF-32',
        },
        XOR_32: {
            name: 'XOR-32',
        },
        CRC_24: {
            name: 'CRC-24',
        },
        CRC_32: {
            name: 'CRC-32',
        },
        EGGDROP_IRC_BOT: {
            name: 'Eggdrop IRC Bot',
        },
        DES_TO_UNIX: {
            name: 'DES(Unix)',
        },
        TRADITIONAL_DES: {
            name: 'Traditional DES',
        },
        DESCRYPT: {
            name: 'DEScrypt',
        },
        MYSQL323: {
            name: 'MySQL323',
        },
        DES_TO_ORACLE: {
            name: 'DES(Oracle)',
        },
        HALF_MD5: {
            name: 'Half MD5',
        },
        ORACLE_7_10G: {
            name: 'Oracle 7-10g',
        },
        FNV_164: {
            name: 'FNV-164',
        },
        CRC_64: {
            name: 'CRC-64',
        },
        CISCO_PIX_TO_MD5: {
            name: 'Cisco-PIX(MD5)',
        },
        LOTUS_NOTES_OR_DOMINO_6: {
            name: 'Lotus Notes/Domino 6',
        },
        BSDI_CRYPT: {
            name: 'BSDi Crypt',
        },
        CRC_96_TO_ZIP: {
            name: 'CRC-96(ZIP)',
        },
        CRYPT16: {
            name: 'Crypt16',
        },
        MD2: {
            name: 'MD2',
        },
        MD5: {
            name: 'MD5',
        },
        MD4: {
            name: 'MD4',
        },
        DOUBLE_MD5: {
            name: 'Double MD5',
        },
        LM: {
            name: 'LM',
        },
        RIPEMD_128: {
            name: 'RIPEMD-128',
        },
        HAVAL_128: {
            name: 'Haval-128',
        },
        TIGER_128: {
            name: 'Tiger-128',
        },
        SKEIN_256_TO_128: {
            name: 'Skein-256(128)',
        },
        SKEIN_512_TO_128: {
            name: 'Skein-512(128)',
        },
        LOTUS_NOTES_OR_DOMINO_5: {
            name: 'Lotus Notes/Domino 5',
        },
        SKYPE: {
            name: 'Skype',
        },
        ZIPMONSTER: {
            name: 'ZipMonster',
        },
        PRESTASHOP: {
            name: 'PrestaShop',
        },
        MD5_TO_MD5_TO_MD5_TO_DOL_PASS: {
            name: 'md5(md5(md5($pass)))',
        },
        MD5_TO_STRTOUPPER_TO_MD5_TO_DOL_PASS: {
            name: 'md5(strtoupper(md5($pass)))',
        },
        MD5_TO_SHA1_TO_DOL_PASS: {
            name: 'md5(sha1($pass))',
        },
        MD5_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'md5($pass.$salt)',
        },
        MD5_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'md5($salt.$pass)',
        },
        MD5_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'md5(unicode($pass).$salt)',
        },
        MD5_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS: {
            name: 'md5($salt.unicode($pass))',
        },
        HMAC_MD5_TO_KEY_EQ_DOL_PASS: {
            name: 'HMAC-MD5 (key = $pass)',
        },
        HMAC_MD5_TO_KEY_EQ_DOL_SALT: {
            name: 'HMAC-MD5 (key = $salt)',
        },
        MD5_TO_MD5_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'md5(md5($salt).$pass)',
        },
        MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS: {
            name: 'md5($salt.md5($pass))',
        },
        MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT: {
            name: 'md5($pass.md5($salt))',
        },
        MD5_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT: {
            name: 'md5($salt.$pass.$salt)',
        },
        MD5_TO_MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT: {
            name: 'md5(md5($pass).md5($salt))',
        },
        MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'md5($salt.md5($salt.$pass))',
        },
        MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'md5($salt.md5($pass.$salt))',
        },
        MD5_TO_DOL_USERNAME_DOT_0_DOT_DOL_PASS: {
            name: 'md5($username.0.$pass)',
        },
        SNEFRU_128: {
            name: 'Snefru-128',
        },
        NTLM: {
            name: 'NTLM',
        },
        DOMAIN_CACHED_CREDENTIALS: {
            name: 'Domain Cached Credentials',
        },
        DOMAIN_CACHED_CREDENTIALS_2: {
            name: 'Domain Cached Credentials 2',
        },
        SHA_1_TO_BASE64: {
            name: 'SHA-1(Base64)',
        },
        NETSCAPE_LDAP_SHA: {
            name: 'Netscape LDAP SHA',
        },
        MD5_CRYPT: {
            name: 'MD5 Crypt',
        },
        CISCO_IOS_TO_MD5: {
            name: 'Cisco-IOS(MD5)',
        },
        FREEBSD_MD5: {
            name: 'FreeBSD MD5',
        },
        LINEAGE_II_C4: {
            name: 'Lineage II C4',
        },
        PHPBB_V3_DOT_X: {
            name: 'phpBB v3.x',
        },
        WORDPRESS_V2_DOT_6_DOT_0_OR_2_DOT_6_DOT_1: {
            name: 'Wordpress v2.6.0/2.6.1',
        },
        PHPASS_PORTABLE_HASH: {
            name: 'PHPass\' Portable Hash',
        },
        WORDPRESS_OVE_Q_V2_DOT_6_DOT_2: {
            name: 'Wordpress ≥ v2.6.2',
        },
        JOOMLA_OVE_Q_V2_DOT_5_DOT_18: {
            name: 'Joomla ≥ v2.5.18',
        },
        PHPASS_PORTABLE_HASH: {
            name: 'PHPass\' Portable Hash',
        },
        OSCOMMERCE: {
            name: 'osCommerce',
        },
        XT_WITH_COMMERCE: {
            name: 'xt:Commerce',
        },
        MD5_TO_APR: {
            name: 'MD5(APR)',
        },
        APACHE_MD5: {
            name: 'Apache MD5',
        },
        MD5APR1: {
            name: 'md5apr1',
        },
        AIX_TO_SMD5: {
            name: 'AIX(smd5)',
        },
        WEBEDITION_CMS: {
            name: 'WebEdition CMS',
        },
        IP_DOT_BOARD_OVE_Q_V2_ADD: {
            name: 'IP.Board ≥ v2+',
        },
        MYBB_OVE_Q_V1_DOT_2_ADD: {
            name: 'MyBB ≥ v1.2+',
        },
        CRYPTOCURRENCY_TO_ADRESS: {
            name: 'CryptoCurrency(Adress)',
        },
        SHA_1: {
            name: 'SHA-1',
        },
        DOUBLE_SHA_1: {
            name: 'Double SHA-1',
        },
        RIPEMD_160: {
            name: 'RIPEMD-160',
        },
        HAVAL_160: {
            name: 'Haval-160',
        },
        TIGER_160: {
            name: 'Tiger-160',
        },
        HAS_160: {
            name: 'HAS-160',
        },
        LINKEDIN: {
            name: 'LinkedIn',
        },
        SKEIN_256_TO_160: {
            name: 'Skein-256(160)',
        },
        SKEIN_512_TO_160: {
            name: 'Skein-512(160)',
        },
        MANGOSWEB_ENHANCED_CMS: {
            name: 'MangosWeb Enhanced CMS',
        },
        SHA1_TO_SHA1_TO_SHA1_TO_DOL_PASS: {
            name: 'sha1(sha1(sha1($pass)))',
        },
        SHA1_TO_MD5_TO_DOL_PASS: {
            name: 'sha1(md5($pass))',
        },
        SHA1_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha1($pass.$salt)',
        },
        SHA1_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'sha1($salt.$pass)',
        },
        SHA1_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha1(unicode($pass).$salt)',
        },
        SHA1_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS: {
            name: 'sha1($salt.unicode($pass))',
        },
        HMAC_SHA1_TO_KEY_EQ_DOL_PASS: {
            name: 'HMAC-SHA1 (key = $pass)',
        },
        HMAC_SHA1_TO_KEY_EQ_DOL_SALT: {
            name: 'HMAC-SHA1 (key = $salt)',
        },
        SHA1_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha1($salt.$pass.$salt)',
        },
        MYSQL5_DOT_X: {
            name: 'MySQL5.x',
        },
        MYSQL4_DOT_1: {
            name: 'MySQL4.1',
        },
        CISCO_IOS_TO_SHA_256: {
            name: 'Cisco-IOS(SHA-256)',
        },
        SSHA_1_TO_BASE64: {
            name: 'SSHA-1(Base64)',
        },
        NETSCAPE_LDAP_SSHA: {
            name: 'Netscape LDAP SSHA',
        },
        NSLDAPS: {
            name: 'nsldaps',
        },
        FORTIGATE_TO_FORTIOS: {
            name: 'Fortigate(FortiOS)',
        },
        HAVAL_192: {
            name: 'Haval-192',
        },
        TIGER_192: {
            name: 'Tiger-192',
        },
        SHA_1_TO_ORACLE: {
            name: 'SHA-1(Oracle)',
        },
        OSX_V10_DOT_4: {
            name: 'OSX v10.4',
        },
        OSX_V10_DOT_5: {
            name: 'OSX v10.5',
        },
        OSX_V10_DOT_6: {
            name: 'OSX v10.6',
        },
        PALSHOP_CMS: {
            name: 'Palshop CMS',
        },
        CRYPTOCURRENCY_TO_PRIVATEKEY: {
            name: 'CryptoCurrency(PrivateKey)',
        },
        AIX_TO_SSHA1: {
            name: 'AIX(ssha1)',
        },
        MSSQL_TO_2005: {
            name: 'MSSQL(2005)',
        },
        MSSQL_TO_2008: {
            name: 'MSSQL(2008)',
        },
        SUN_MD5_CRYPT: {
            name: 'Sun MD5 Crypt',
        },
        SHA_224: {
            name: 'SHA-224',
        },
        HAVAL_224: {
            name: 'Haval-224',
        },
        SHA3_224: {
            name: 'SHA3-224',
        },
        SKEIN_256_TO_224: {
            name: 'Skein-256(224)',
        },
        SKEIN_512_TO_224: {
            name: 'Skein-512(224)',
        },
        BLOWFISH_TO_OPENBSD: {
            name: 'Blowfish(OpenBSD)',
        },
        WOLTLAB_BURNING_BOARD_4_DOT_X: {
            name: 'Woltlab Burning Board 4.x',
        },
        BCRYPT: {
            name: 'bcrypt',
        },
        ANDROID_PIN: {
            name: 'Android PIN',
        },
        ORACLE_11G_OR_12C: {
            name: 'Oracle 11g/12c',
        },
        BCRYPT_TO_SHA_256: {
            name: 'bcrypt(SHA-256)',
        },
        VBULLETIN_UND_V3_DOT_8_DOT_5: {
            name: 'vBulletin < v3.8.5',
        },
        VBULLETIN_OVE_Q_V3_DOT_8_DOT_5: {
            name: 'vBulletin ≥ v3.8.5',
        },
        SNEFRU_256: {
            name: 'Snefru-256',
        },
        SHA_256: {
            name: 'SHA-256',
        },
        RIPEMD_256: {
            name: 'RIPEMD-256',
        },
        HAVAL_256: {
            name: 'Haval-256',
        },
        GOST_R_34_DOT_11_94: {
            name: 'GOST R 34.11-94',
        },
        GOST_CRYPTOPRO_S_BOX: {
            name: 'GOST CryptoPro S-Box',
        },
        SHA3_256: {
            name: 'SHA3-256',
        },
        SKEIN_256: {
            name: 'Skein-256',
        },
        SKEIN_512_TO_256: {
            name: 'Skein-512(256)',
        },
        VENTRILO: {
            name: 'Ventrilo',
        },
        SHA256_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha256($pass.$salt)',
        },
        SHA256_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'sha256($salt.$pass)',
        },
        SHA256_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha256(unicode($pass).$salt)',
        },
        SHA256_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS: {
            name: 'sha256($salt.unicode($pass))',
        },
        HMAC_SHA256_TO_KEY_EQ_DOL_PASS: {
            name: 'HMAC-SHA256 (key = $pass)',
        },
        HMAC_SHA256_TO_KEY_EQ_DOL_SALT: {
            name: 'HMAC-SHA256 (key = $salt)',
        },
        JOOMLA_UND_V2_DOT_5_DOT_18: {
            name: 'Joomla < v2.5.18',
        },
        SAM_TO_LM_HASH_WITH_NT_HASH: {
            name: 'SAM(LM_Hash:NT_Hash)',
        },
        MD5_TO_CHAP: {
            name: 'MD5(Chap)',
        },
        ISCSI_CHAP_AUTHENTICATION: {
            name: 'iSCSI CHAP Authentication',
        },
        EPISERVER_6_DOT_X_UND_V4: {
            name: 'EPiServer 6.x < v4',
        },
        AIX_TO_SSHA256: {
            name: 'AIX(ssha256)',
        },
        RIPEMD_320: {
            name: 'RIPEMD-320',
        },
        EPISERVER_6_DOT_X_OVE_Q_V4: {
            name: 'EPiServer 6.x ≥ v4',
        },
        MSSQL_TO_2000: {
            name: 'MSSQL(2000)',
        },
        SHA_384: {
            name: 'SHA-384',
        },
        SHA3_384: {
            name: 'SHA3-384',
        },
        SKEIN_512_TO_384: {
            name: 'Skein-512(384)',
        },
        SKEIN_1024_TO_384: {
            name: 'Skein-1024(384)',
        },
        SSHA_512_TO_BASE64: {
            name: 'SSHA-512(Base64)',
        },
        LDAP_TO_SSHA_512: {
            name: 'LDAP(SSHA-512)',
        },
        AIX_TO_SSHA512: {
            name: 'AIX(ssha512)',
        },
        SHA_512: {
            name: 'SHA-512',
        },
        WHIRLPOOL: {
            name: 'Whirlpool',
        },
        SALSA10: {
            name: 'Salsa10',
        },
        SALSA20: {
            name: 'Salsa20',
        },
        SHA3_512: {
            name: 'SHA3-512',
        },
        SKEIN_512: {
            name: 'Skein-512',
        },
        SKEIN_1024_TO_512: {
            name: 'Skein-1024(512)',
        },
        SHA512_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha512($pass.$salt)',
        },
        SHA512_TO_DOL_SALT_DOT_DOL_PASS: {
            name: 'sha512($salt.$pass)',
        },
        SHA512_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT: {
            name: 'sha512(unicode($pass).$salt)',
        },
        SHA512_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS: {
            name: 'sha512($salt.unicode($pass))',
        },
        HMAC_SHA512_TO_KEY_EQ_DOL_PASS: {
            name: 'HMAC-SHA512 (key = $pass)',
        },
        HMAC_SHA512_TO_KEY_EQ_DOL_SALT: {
            name: 'HMAC-SHA512 (key = $salt)',
        },
        OSX_V10_DOT_7: {
            name: 'OSX v10.7',
        },
        MSSQL_TO_2012: {
            name: 'MSSQL(2012)',
        },
        MSSQL_TO_2014: {
            name: 'MSSQL(2014)',
        },
        OSX_V10_DOT_8: {
            name: 'OSX v10.8',
        },
        OSX_V10_DOT_9: {
            name: 'OSX v10.9',
        },
        SKEIN_1024: {
            name: 'Skein-1024',
        },
        GRUB_2: {
            name: 'GRUB 2',
        },
        DJANGO_TO_SHA_1: {
            name: 'Django(SHA-1)',
        },
        CITRIX_NETSCALER: {
            name: 'Citrix Netscaler',
        },
        DRUPAL_OVE_V7_DOT_X: {
            name: 'Drupal > v7.x',
        },
        SHA_256_CRYPT: {
            name: 'SHA-256 Crypt',
        },
        SYBASE_ASE: {
            name: 'Sybase ASE',
        },
        SHA_512_CRYPT: {
            name: 'SHA-512 Crypt',
        },
        MINECRAFT_TO_AUTHME_RELOADED: {
            name: 'Minecraft(AuthMe Reloaded)',
        },
        DJANGO_TO_SHA_256: {
            name: 'Django(SHA-256)',
        },
        DJANGO_TO_SHA_384: {
            name: 'Django(SHA-384)',
        },
        CLAVISTER_SECURE_GATEWAY: {
            name: 'Clavister Secure Gateway',
        },
        CISCO_VPN_CLIENT_TO_PCF_FILE: {
            name: 'Cisco VPN Client(PCF-File)',
        },
        MICROSOFT_MSTSC_TO_RDP_FILE: {
            name: 'Microsoft MSTSC(RDP-File)',
        },
        NETNTLMV1_VANILLA_OR_NETNTLMV1_ADD_ESS: {
            name: 'NetNTLMv1-VANILLA / NetNTLMv1+ESS',
        },
        NETNTLMV2: {
            name: 'NetNTLMv2',
        },
        KERBEROS_5_AS_REQ_PRE_AUTH: {
            name: 'Kerberos 5 AS-REQ Pre-Auth',
        },
        SCRAM_HASH: {
            name: 'SCRAM Hash',
        },
        REDMINE_PROJECT_MANAGEMENT_WEB_APP: {
            name: 'Redmine Project Management Web App',
        },
        SAP_CODVN_B_TO_BCODE: {
            name: 'SAP CODVN B (BCODE)',
        },
        SAP_CODVN_F_OR_G_TO_PASSCODE: {
            name: 'SAP CODVN F/G (PASSCODE)',
        },
        JUNIPER_NETSCREEN_OR_SSG_TO_SCREENOS: {
            name: 'Juniper Netscreen/SSG(ScreenOS)',
        },
        EPI: {
            name: 'EPi',
        },
        SMF_OVE_Q_V1_DOT_1: {
            name: 'SMF ≥ v1.1',
        },
        WOLTLAB_BURNING_BOARD_3_DOT_X: {
            name: 'Woltlab Burning Board 3.x',
        },
        IPMI2_RAKP_HMAC_SHA1: {
            name: 'IPMI2 RAKP HMAC-SHA1',
        },
        LASTPASS: {
            name: 'Lastpass',
        },
        CISCO_ASA_TO_MD5: {
            name: 'Cisco-ASA(MD5)',
        },
        VNC: {
            name: 'VNC',
        },
        DNSSEC_TO_NSEC3: {
            name: 'DNSSEC(NSEC3)',
        },
        RACF: {
            name: 'RACF',
        },
        NTHASH_TO_FREEBSD_letIANT: {
            name: 'NTHash(FreeBSD letiant)',
        },
        SHA_1_CRYPT: {
            name: 'SHA-1 Crypt',
        },
        HMAILSERVER: {
            name: 'hMailServer',
        },
        MEDIAWIKI: {
            name: 'MediaWiki',
        },
        MINECRAFT_TO_XAUTH: {
            name: 'Minecraft(xAuth)',
        },
        PBKDF2_SHA1_TO_GENERIC: {
            name: 'PBKDF2-SHA1(Generic)',
        },
        PBKDF2_SHA256_TO_GENERIC: {
            name: 'PBKDF2-SHA256(Generic)',
        },
        PBKDF2_SHA512_TO_GENERIC: {
            name: 'PBKDF2-SHA512(Generic)',
        },
        PBKDF2_TO_CRYPTACULAR: {
            name: 'PBKDF2(Cryptacular)',
        },
        PBKDF2_TO_DWAYNE_LITZENBERGER: {
            name: 'PBKDF2(Dwayne Litzenberger)',
        },
        FAIRLY_SECURE_HASHED_PASSWORD: {
            name: 'Fairly Secure Hashed Password',
        },
        PHPS: {
            name: 'PHPS',
        },
        X1PASSWORD_TO_AGILE_KEYCHAIN: {
            name: '1Password(Agile Keychain)',
        },
        X1PASSWORD_TO_CLOUD_KEYCHAIN: {
            name: '1Password(Cloud Keychain)',
        },
        IKE_PSK_MD5: {
            name: 'IKE-PSK MD5',
        },
        IKE_PSK_SHA1: {
            name: 'IKE-PSK SHA1',
        },
        PEOPLESOFT: {
            name: 'PeopleSoft',
        },
        DJANGO_TO_DES_CRYPT_WRAPPER: {
            name: 'Django(DES Crypt Wrapper)',
        },
        DJANGO_TO_PBKDF2_HMAC_SHA256: {
            name: 'Django(PBKDF2-HMAC-SHA256)',
        },
        DJANGO_TO_PBKDF2_HMAC_SHA1: {
            name: 'Django(PBKDF2-HMAC-SHA1)',
        },
        DJANGO_TO_BCRYPT: {
            name: 'Django(bcrypt)',
        },
        DJANGO_TO_MD5: {
            name: 'Django(MD5)',
        },
        PBKDF2_TO_ATLASSIAN: {
            name: 'PBKDF2(Atlassian)',
        },
        POSTGRESQL_MD5: {
            name: 'PostgreSQL MD5',
        },
        LOTUS_NOTES_OR_DOMINO_8: {
            name: 'Lotus Notes/Domino 8',
        },
        SCRYPT: {
            name: 'scrypt',
        },
        CISCO_TYPE_8: {
            name: 'Cisco Type 8',
        },
        CISCO_TYPE_9: {
            name: 'Cisco Type 9',
        },
        MICROSOFT_OFFICE_2007: {
            name: 'Microsoft Office 2007',
        },
        MICROSOFT_OFFICE_2010: {
            name: 'Microsoft Office 2010',
        },
        MICROSOFT_OFFICE_2013: {
            name: 'Microsoft Office 2013',
        },
        ANDROID_FDE_UND_Q_4_DOT_3: {
            name: 'Android FDE ≤ 4.3',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4: {
            name: 'Microsoft Office ≤ 2003 (MD5+RC4)',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_1: {
            name: 'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_2: {
            name: 'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4: {
            name: 'Microsoft Office ≤ 2003 (SHA1+RC4)',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_1: {
            name: 'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1',
        },
        MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_2: {
            name: 'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2',
        },
        RADMIN_V2_DOT_X: {
            name: 'RAdmin v2.x',
        },
        SAP_CODVN_H_TO_PWDSALTEDHASH_ISSHA_1: {
            name: 'SAP CODVN H (PWDSALTEDHASH) iSSHA-1',
        },
        CRAM_MD5: {
            name: 'CRAM-MD5',
        },
        SIPHASH: {
            name: 'SipHash',
        },
        CISCO_TYPE_7: {
            name: 'Cisco Type 7',
        },
        BIGCRYPT: {
            name: 'BigCrypt',
        },
        CISCO_TYPE_4: {
            name: 'Cisco Type 4',
        },
        DJANGO_TO_BCRYPT_SHA256: {
            name: 'Django(bcrypt-SHA256)',
        },
        POSTGRESQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_MD5: {
            name: 'PostgreSQL Challenge-Response Authentication (MD5)',
        },
        SIEMENS_S7: {
            name: 'Siemens-S7',
        },
        MICROSOFT_OUTLOOK_PST: {
            name: 'Microsoft Outlook PST',
        },
        PBKDF2_HMAC_SHA256_TO_PHP: {
            name: 'PBKDF2-HMAC-SHA256(PHP)',
        },
        DAHUA: {
            name: 'Dahua',
        },
        MYSQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_SHA1: {
            name: 'MySQL Challenge-Response Authentication (SHA1)',
        },
        PDF_1_DOT_4_1_DOT_6_TO_ACROBAT_5_8: {
            name: 'PDF 1.4 - 1.6 (Acrobat 5 - 8)',
        },
    },


    /**
     * 下面这些代码先匹配正则后才确定信息，会比根据加密方式来的写法高效，注意传入的参数应保证是string的
     * @param  {string} str 密文
     * @return {obj|bool}     成功返回对象，失败返回false
     */
    idGroup : [
        idGroup1 = function(str) {
            return str.match(/^[a-f0-9]{4}$/) ? [
                'CRC_16',
                'CRC_16_CCITT',
                'FCS_16',
            ] : false;
        },
        idGroup2 = function(str) {
            return str.match(/^[a-f0-9]{8}$/) ? [
                'ADLER_32',
                'CRC_32B',
                'FCS_32',
                'GHASH_32_3',
                'GHASH_32_5',
                'FNV_132',
                'FLETCHER_32',
                'JOAAT',
                'ELF_32',
                'XOR_32',
            ] : false;
        },
        idGroup3 = function(str) {
            return str.match(/^[a-f0-9]{6}$/) ? [
                'CRC_24',
            ] : false;
        },
        idGroup4 = function(str) {
            return str.match(/^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$/) ? [
                'CRC_32',
            ] : false;
        },
        idGroup5 = function(str) {
            return str.match(/^\+[a-z0-9\/.]{12}$/) ? [
                'EGGDROP_IRC_BOT',
            ] : false;
        },
        idGroup6 = function(str) {
            return str.match(/^[a-z0-9\/.]{13}$/) ? [
                'DES_TO_UNIX',
                'TRADITIONAL_DES',
                'DESCRYPT',
            ] : false;
        },
        idGroup7 = function(str) {
            return str.match(/^[a-f0-9]{16}$/) ? [
                'MYSQL323',
                'DES_TO_ORACLE',
                'HALF_MD5',
                'ORACLE_7_10G',
                'FNV_164',
                'CRC_64',
            ] : false;
        },
        idGroup8 = function(str) {
            return str.match(/^[a-z0-9\/.]{16}$/) ? [
                'CISCO_PIX_TO_MD5',
            ] : false;
        },
        idGroup9 = function(str) {
            return str.match(/^\([a-z0-9\/+]{20}\)$/) ? [
                'LOTUS_NOTES_OR_DOMINO_6',
            ] : false;
        },
        idGroup10 = function(str) {
            return str.match(/^_[a-z0-9\/.]{19}$/) ? [
                'BSDI_CRYPT',
            ] : false;
        },
        idGroup11 = function(str) {
            return str.match(/^[a-f0-9]{24}$/) ? [
                'CRC_96_TO_ZIP',
            ] : false;
        },
        idGroup12 = function(str) {
            return str.match(/^[a-z0-9\/.]{24}$/) ? [
                'CRYPT16',
            ] : false;
        },
        idGroup13 = function(str) {
            return str.match(/^(\$md2\$)?[a-f0-9]{32}$/) ? [
                'MD2',
            ] : false;
        },
        idGroup14 = function(str) {
            return str.match(/^[a-f0-9]{32}(:.+)?$/) ? [
                'MD5',
                'MD4',
                'DOUBLE_MD5',
                'LM',
                'RIPEMD_128',
                'HAVAL_128',
                'TIGER_128',
                'SKEIN_256_TO_128',
                'SKEIN_512_TO_128',
                'LOTUS_NOTES_OR_DOMINO_5',
                'SKYPE',
                'ZIPMONSTER',
                'PRESTASHOP',
                'MD5_TO_MD5_TO_MD5_TO_DOL_PASS',
                'MD5_TO_STRTOUPPER_TO_MD5_TO_DOL_PASS',
                'MD5_TO_SHA1_TO_DOL_PASS',
                'MD5_TO_DOL_PASS_DOT_DOL_SALT',
                'MD5_TO_DOL_SALT_DOT_DOL_PASS',
                'MD5_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT',
                'MD5_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS',
                'HMAC_MD5_TO_KEY_EQ_DOL_PASS',
                'HMAC_MD5_TO_KEY_EQ_DOL_SALT',
                'MD5_TO_MD5_TO_DOL_SALT_DOT_DOL_PASS',
                'MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS',
                'MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT',
                'MD5_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT',
                'MD5_TO_MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT',
                'MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_SALT_DOT_DOL_PASS',
                'MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS_DOT_DOL_SALT',
                'MD5_TO_DOL_USERNAME_DOT_0_DOT_DOL_PASS',
            ] : false;
        },
        idGroup15 = function(str) {
            return str.match(/^(\$snefru\$)?[a-f0-9]{32}$/) ? [
                'SNEFRU_128',
            ] : false;
        },
        idGroup16 = function(str) {
            return str.match(/^(\$NT\$)?[a-f0-9]{32}$/) ? [
                'NTLM',
            ] : false;
        },
        idGroup17 = function(str) {
            return str.match(/^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$/) ? [
                'DOMAIN_CACHED_CREDENTIALS',
            ] : false;
        },
        idGroup18 = function(str) {
            return str.match(/^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$/) ? [
                'DOMAIN_CACHED_CREDENTIALS_2',
            ] : false;
        },
        idGroup19 = function(str) {
            return str.match(/^{SHA}[a-z0-9\/+]{27}=$/) ? [
                'SHA_1_TO_BASE64',
                'NETSCAPE_LDAP_SHA',
            ] : false;
        },
        idGroup20 = function(str) {
            return str.match(/^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$/) ? [
                'MD5_CRYPT',
                'CISCO_IOS_TO_MD5',
                'FREEBSD_MD5',
            ] : false;
        },
        idGroup21 = function(str) {
            return str.match(/^0x[a-f0-9]{32}$/) ? [
                'LINEAGE_II_C4',
            ] : false;
        },
        idGroup22 = function(str) {
            return str.match(/^\$H\$[a-z0-9\/.]{31}$/) ? [
                'PHPBB_V3_DOT_X',
                'WORDPRESS_V2_DOT_6_DOT_0_OR_2_DOT_6_DOT_1',
                'PHPASS_PORTABLE_HASH',
            ] : false;
        },
        idGroup23 = function(str) {
            return str.match(/^\$P\$[a-z0-9\/.]{31}$/) ? [
                'WORDPRESS_OVE_Q_V2_DOT_6_DOT_2',
                'JOOMLA_OVE_Q_V2_DOT_5_DOT_18',
                'PHPASS_PORTABLE_HASH',
            ] : false;
        },
        idGroup24 = function(str) {
            return str.match(/^[a-f0-9]{32}:[a-z0-9]{2}$/) ? [
                'OSCOMMERCE',
                'XT_WITH_COMMERCE',
            ] : false;
        },
        idGroup25 = function(str) {
            return str.match(/^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$/) ? [
                'MD5_TO_APR',
                'APACHE_MD5',
                'MD5APR1',
            ] : false;
        },
        idGroup26 = function(str) {
            return str.match(/^{smd5}[a-z0-9$\/.]{31}$/) ? [
                'AIX_TO_SMD5',
            ] : false;
        },
        idGroup27 = function(str) {
            return str.match(/^[a-f0-9]{32}:[a-f0-9]{32}$/) ? [
                'WEBEDITION_CMS',
            ] : false;
        },
        idGroup28 = function(str) {
            return str.match(/^[a-f0-9]{32}:.{5}$/) ? [
                'IP_DOT_BOARD_OVE_Q_V2_ADD',
            ] : false;
        },
        idGroup29 = function(str) {
            return str.match(/^[a-f0-9]{32}:.{8}$/) ? [
                'MYBB_OVE_Q_V1_DOT_2_ADD',
            ] : false;
        },
        idGroup30 = function(str) {
            return str.match(/^[a-z0-9]{34}$/) ? [
                'CRYPTOCURRENCY_TO_ADRESS',
            ] : false;
        },
        idGroup31 = function(str) {
            return str.match(/^[a-f0-9]{40}(:.+)?$/) ? [
                'SHA_1',
                'DOUBLE_SHA_1',
                'RIPEMD_160',
                'HAVAL_160',
                'TIGER_160',
                'HAS_160',
                'LINKEDIN',
                'SKEIN_256_TO_160',
                'SKEIN_512_TO_160',
                'MANGOSWEB_ENHANCED_CMS',
                'SHA1_TO_SHA1_TO_SHA1_TO_DOL_PASS',
                'SHA1_TO_MD5_TO_DOL_PASS',
                'SHA1_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA1_TO_DOL_SALT_DOT_DOL_PASS',
                'SHA1_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA1_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS',
                'HMAC_SHA1_TO_KEY_EQ_DOL_PASS',
                'HMAC_SHA1_TO_KEY_EQ_DOL_SALT',
                'SHA1_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT',
            ] : false;
        },
        idGroup32 = function(str) {
            return str.match(/^\*[a-f0-9]{40}$/) ? [
                'MYSQL5_DOT_X',
                'MYSQL4_DOT_1',
            ] : false;
        },
        idGroup33 = function(str) {
            return str.match(/^[a-z0-9]{43}$/) ? [
                'CISCO_IOS_TO_SHA_256',
            ] : false;
        },
        idGroup34 = function(str) {
            return str.match(/^{SSHA}[a-z0-9\/+]{38}==$/) ? [
                'SSHA_1_TO_BASE64',
                'NETSCAPE_LDAP_SSHA',
                'NSLDAPS',
            ] : false;
        },
        idGroup35 = function(str) {
            return str.match(/^[a-z0-9=]{47}$/) ? [
                'FORTIGATE_TO_FORTIOS',
            ] : false;
        },
        idGroup36 = function(str) {
            return str.match(/^[a-f0-9]{48}$/) ? [
                'HAVAL_192',
                'TIGER_192',
                'SHA_1_TO_ORACLE',
                'OSX_V10_DOT_4',
                'OSX_V10_DOT_5',
                'OSX_V10_DOT_6',
            ] : false;
        },
        idGroup37 = function(str) {
            return str.match(/^[a-f0-9]{51}$/) ? [
                'PALSHOP_CMS',
            ] : false;
        },
        idGroup38 = function(str) {
            return str.match(/^[a-z0-9]{51}$/) ? [
                'CRYPTOCURRENCY_TO_PRIVATEKEY',
            ] : false;
        },
        idGroup39 = function(str) {
            return str.match(/^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$/) ? [
                'AIX_TO_SSHA1',
            ] : false;
        },
        idGroup40 = function(str) {
            return str.match(/^0x0100[a-f0-9]{48}$/) ? [
                'MSSQL_TO_2005',
                'MSSQL_TO_2008',
            ] : false;
        },
        idGroup41 = function(str) {
            return str.match(/^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$/) ? [
                'SUN_MD5_CRYPT',
            ] : false;
        },
        idGroup42 = function(str) {
            return str.match(/^[a-f0-9]{56}$/) ? [
                'SHA_224',
                'HAVAL_224',
                'SHA3_224',
                'SKEIN_256_TO_224',
                'SKEIN_512_TO_224',
            ] : false;
        },
        idGroup43 = function(str) {
            return str.match(/^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
                'BLOWFISH_TO_OPENBSD',
                'WOLTLAB_BURNING_BOARD_4_DOT_X',
                'BCRYPT',
            ] : false;
        },
        idGroup44 = function(str) {
            return str.match(/^[a-f0-9]{40}:[a-f0-9]{16}$/) ? [
                'ANDROID_PIN',
            ] : false;
        },
        idGroup45 = function(str) {
            return str.match(/^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$/) ? [
                'ORACLE_11G_OR_12C',
            ] : false;
        },
        idGroup46 = function(str) {
            return str.match(/^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$/) ? [
                'BCRYPT_TO_SHA_256',
            ] : false;
        },
        idGroup47 = function(str) {
            return str.match(/^[a-f0-9]{32}:.{3}$/) ? [
                'VBULLETIN_UND_V3_DOT_8_DOT_5',
            ] : false;
        },
        idGroup48 = function(str) {
            return str.match(/^[a-f0-9]{32}:.{30}$/) ? [
                'VBULLETIN_OVE_Q_V3_DOT_8_DOT_5',
            ] : false;
        },
        idGroup49 = function(str) {
            return str.match(/^(\$snefru\$)?[a-f0-9]{64}$/) ? [
                'SNEFRU_256',
            ] : false;
        },
        idGroup50 = function(str) {
            return str.match(/^[a-f0-9]{64}(:.+)?$/) ? [
                'SHA_256',
                'RIPEMD_256',
                'HAVAL_256',
                'GOST_R_34_DOT_11_94',
                'GOST_CRYPTOPRO_S_BOX',
                'SHA3_256',
                'SKEIN_256',
                'SKEIN_512_TO_256',
                'VENTRILO',
                'SHA256_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA256_TO_DOL_SALT_DOT_DOL_PASS',
                'SHA256_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA256_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS',
                'HMAC_SHA256_TO_KEY_EQ_DOL_PASS',
                'HMAC_SHA256_TO_KEY_EQ_DOL_SALT',
            ] : false;
        },
        idGroup51 = function(str) {
            return str.match(/^[a-f0-9]{32}:[a-z0-9]{32}$/) ? [
                'JOOMLA_UND_V2_DOT_5_DOT_18',
            ] : false;
        },
        idGroup52 = function(str) {
            return str.match(/^[a-f-0-9]{32}:[a-f-0-9]{32}$/) ? [
                'SAM_TO_LM_HASH_WITH_NT_HASH',
            ] : false;
        },
        idGroup53 = function(str) {
            return str.match(/^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$/) ? [
                'MD5_TO_CHAP',
                'ISCSI_CHAP_AUTHENTICATION',
            ] : false;
        },
        idGroup54 = function(str) {
            return str.match(/^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$/) ? [
                'EPISERVER_6_DOT_X_UND_V4',
            ] : false;
        },
        idGroup55 = function(str) {
            return str.match(/^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$/) ? [
                'AIX_TO_SSHA256',
            ] : false;
        },
        idGroup56 = function(str) {
            return str.match(/^[a-f0-9]{80}$/) ? [
                'RIPEMD_320',
            ] : false;
        },
        idGroup57 = function(str) {
            return str.match(/^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$/) ? [
                'EPISERVER_6_DOT_X_OVE_Q_V4',
            ] : false;
        },
        idGroup58 = function(str) {
            return str.match(/^0x0100[a-f0-9]{88}$/) ? [
                'MSSQL_TO_2000',
            ] : false;
        },
        idGroup59 = function(str) {
            return str.match(/^[a-f0-9]{96}$/) ? [
                'SHA_384',
                'SHA3_384',
                'SKEIN_512_TO_384',
                'SKEIN_1024_TO_384',
            ] : false;
        },
        idGroup60 = function(str) {
            return str.match(/^{SSHA512}[a-z0-9\/+]{96}$/) ? [
                'SSHA_512_TO_BASE64',
                'LDAP_TO_SSHA_512',
            ] : false;
        },
        idGroup61 = function(str) {
            return str.match(/^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$/) ? [
                'AIX_TO_SSHA512',
            ] : false;
        },
        idGroup62 = function(str) {
            return str.match(/^[a-f0-9]{128}(:.+)?$/) ? [
                'SHA_512',
                'WHIRLPOOL',
                'SALSA10',
                'SALSA20',
                'SHA3_512',
                'SKEIN_512',
                'SKEIN_1024_TO_512',
                'SHA512_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA512_TO_DOL_SALT_DOT_DOL_PASS',
                'SHA512_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT',
                'SHA512_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS',
                'HMAC_SHA512_TO_KEY_EQ_DOL_PASS',
                'HMAC_SHA512_TO_KEY_EQ_DOL_SALT',
            ] : false;
        },
        idGroup63 = function(str) {
            return str.match(/^[a-f0-9]{136}$/) ? [
                'OSX_V10_DOT_7',
            ] : false;
        },
        idGroup64 = function(str) {
            return str.match(/^0x0200[a-f0-9]{136}$/) ? [
                'MSSQL_TO_2012',
                'MSSQL_TO_2014',
            ] : false;
        },
        idGroup65 = function(str) {
            return str.match(/^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$/) ? [
                'OSX_V10_DOT_8',
                'OSX_V10_DOT_9',
            ] : false;
        },
        idGroup66 = function(str) {
            return str.match(/^[a-f0-9]{256}$/) ? [
                'SKEIN_1024',
            ] : false;
        },
        idGroup67 = function(str) {
            return str.match(/^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$/) ? [
                'GRUB_2',
            ] : false;
        },
        idGroup68 = function(str) {
            return str.match(/^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/) ? [
                'DJANGO_TO_SHA_1',
            ] : false;
        },
        idGroup69 = function(str) {
            return str.match(/^[a-f0-9]{49}$/) ? [
                'CITRIX_NETSCALER',
            ] : false;
        },
        idGroup70 = function(str) {
            return str.match(/^\$S\$[a-z0-9\/.]{52}$/) ? [
                'DRUPAL_OVE_V7_DOT_X',
            ] : false;
        },
        idGroup71 = function(str) {
            return str.match(/^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$/) ? [
                'SHA_256_CRYPT',
            ] : false;
        },
        idGroup72 = function(str) {
            return str.match(/^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$/) ? [
                'SYBASE_ASE',
            ] : false;
        },
        idGroup73 = function(str) {
            return str.match(/^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$/) ? [
                'SHA_512_CRYPT',
            ] : false;
        },
        idGroup74 = function(str) {
            return str.match(/^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$/) ? [
                'MINECRAFT_TO_AUTHME_RELOADED',
            ] : false;
        },
        idGroup75 = function(str) {
            return str.match(/^sha256\$[a-z0-9]+\$[a-f0-9]{64}$/) ? [
                'DJANGO_TO_SHA_256',
            ] : false;
        },
        idGroup76 = function(str) {
            return str.match(/^sha384\$[a-z0-9]+\$[a-f0-9]{96}$/) ? [
                'DJANGO_TO_SHA_384',
            ] : false;
        },
        idGroup77 = function(str) {
            return str.match(/^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$/) ? [
                'CLAVISTER_SECURE_GATEWAY',
            ] : false;
        },
        idGroup78 = function(str) {
            return str.match(/^[a-f0-9]{112}$/) ? [
                'CISCO_VPN_CLIENT_TO_PCF_FILE',
            ] : false;
        },
        idGroup79 = function(str) {
            return str.match(/^[a-f0-9]{1329}$/) ? [
                'MICROSOFT_MSTSC_TO_RDP_FILE',
            ] : false;
        },
        idGroup80 = function(str) {
            return str.match(/^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/) ? [
                'NETNTLMV1_VANILLA_OR_NETNTLMV1_ADD_ESS',
            ] : false;
        },
        idGroup81 = function(str) {
            return str.match(/^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$/) ? [
                'NETNTLMV2',
            ] : false;
        },
        idGroup82 = function(str) {
            return str.match(/^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$/) ? [
                'KERBEROS_5_AS_REQ_PRE_AUTH',
            ] : false;
        },
        idGroup83 = function(str) {
            return str.match(/^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$/) ? [
                'SCRAM_HASH',
            ] : false;
        },
        idGroup84 = function(str) {
            return str.match(/^[a-f0-9]{40}:[a-f0-9]{0,32}$/) ? [
                'REDMINE_PROJECT_MANAGEMENT_WEB_APP',
            ] : false;
        },
        idGroup85 = function(str) {
            return str.match(/^(.+)?\$[a-f0-9]{16}$/) ? [
                'SAP_CODVN_B_TO_BCODE',
            ] : false;
        },
        idGroup86 = function(str) {
            return str.match(/^(.+)?\$[a-f0-9]{40}$/) ? [
                'SAP_CODVN_F_OR_G_TO_PASSCODE',
            ] : false;
        },
        idGroup87 = function(str) {
            return str.match(/^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$/) ? [
                'JUNIPER_NETSCREEN_OR_SSG_TO_SCREENOS',
            ] : false;
        },
        idGroup88 = function(str) {
            return str.match(/^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$/) ? [
                'EPI',
            ] : false;
        },
        idGroup89 = function(str) {
            return str.match(/^[a-f0-9]{40}:[^*]{1,25}$/) ? [
                'SMF_OVE_Q_V1_DOT_1',
            ] : false;
        },
        idGroup90 = function(str) {
            return str.match(/^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
                'WOLTLAB_BURNING_BOARD_3_DOT_X',
            ] : false;
        },
        idGroup91 = function(str) {
            return str.match(/^[a-f0-9]{130}(:[a-f0-9]{40})?$/) ? [
                'IPMI2_RAKP_HMAC_SHA1',
            ] : false;
        },
        idGroup92 = function(str) {
            return str.match(/^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$/) ? [
                'LASTPASS',
            ] : false;
        },
        idGroup93 = function(str) {
            return str.match(/^[a-z0-9\/.]{16}([:$].{1,})?$/) ? [
                'CISCO_ASA_TO_MD5',
            ] : false;
        },
        idGroup94 = function(str) {
            return str.match(/^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
                'VNC',
            ] : false;
        },
        idGroup95 = function(str) {
            return str.match(/^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$/) ? [
                'DNSSEC_TO_NSEC3',
            ] : false;
        },
        idGroup96 = function(str) {
            return str.match(/^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$/) ? [
                'RACF',
            ] : false;
        },
        idGroup97 = function(str) {
            return str.match(/^\$3\$\$[a-f0-9]{32}$/) ? [
                'NTHASH_TO_FREEBSD_letIANT',
            ] : false;
        },
        idGroup98 = function(str) {
            return str.match(/^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$/) ? [
                'SHA_1_CRYPT',
            ] : false;
        },
        idGroup99 = function(str) {
            return str.match(/^[a-f0-9]{70}$/) ? [
                'HMAILSERVER',
            ] : false;
        },
        idGroup100 = function(str) {
            return str.match(/^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$/) ? [
                'MEDIAWIKI',
            ] : false;
        },
        idGroup101 = function(str) {
            return str.match(/^[a-f0-9]{140}$/) ? [
                'MINECRAFT_TO_XAUTH',
            ] : false;
        },
        idGroup102 = function(str) {
            return str.match(/^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$/) ? [
                'PBKDF2_SHA1_TO_GENERIC',
            ] : false;
        },
        idGroup103 = function(str) {
            return str.match(/^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$/) ? [
                'PBKDF2_SHA256_TO_GENERIC',
            ] : false;
        },
        idGroup104 = function(str) {
            return str.match(/^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$/) ? [
                'PBKDF2_SHA512_TO_GENERIC',
            ] : false;
        },
        idGroup105 = function(str) {
            return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$/) ? [
                'PBKDF2_TO_CRYPTACULAR',
            ] : false;
        },
        idGroup106 = function(str) {
            return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$/) ? [
                'PBKDF2_TO_DWAYNE_LITZENBERGER',
            ] : false;
        },
        idGroup107 = function(str) {
            return str.match(/^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$/) ? [
                'FAIRLY_SECURE_HASHED_PASSWORD',
            ] : false;
        },
        idGroup108 = function(str) {
            return str.match(/^\$PHPS\$.+\$[a-f0-9]{32}$/) ? [
                'PHPS',
            ] : false;
        },
        idGroup109 = function(str) {
            return str.match(/^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$/) ? [
                'X1PASSWORD_TO_AGILE_KEYCHAIN',
            ] : false;
        },
        idGroup110 = function(str) {
            return str.match(/^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$/) ? [
                'X1PASSWORD_TO_CLOUD_KEYCHAIN',
            ] : false;
        },
        idGroup111 = function(str) {
            return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$/) ? [
                'IKE_PSK_MD5',
            ] : false;
        },
        idGroup112 = function(str) {
            return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$/) ? [
                'IKE_PSK_SHA1',
            ] : false;
        },
        idGroup113 = function(str) {
            return str.match(/^[a-z0-9\/+]{27}=$/) ? [
                'PEOPLESOFT',
            ] : false;
        },
        idGroup114 = function(str) {
            return str.match(/^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$/) ? [
                'DJANGO_TO_DES_CRYPT_WRAPPER',
            ] : false;
        },
        idGroup115 = function(str) {
            return str.match(/^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$/) ? [
                'DJANGO_TO_PBKDF2_HMAC_SHA256',
            ] : false;
        },
        idGroup116 = function(str) {
            return str.match(/^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$/) ? [
                'DJANGO_TO_PBKDF2_HMAC_SHA1',
            ] : false;
        },
        idGroup117 = function(str) {
            return str.match(/^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
                'DJANGO_TO_BCRYPT',
            ] : false;
        },
        idGroup118 = function(str) {
            return str.match(/^md5\$[a-f0-9]+\$[a-f0-9]{32}$/) ? [
                'DJANGO_TO_MD5',
            ] : false;
        },
        idGroup119 = function(str) {
            return str.match(/^\{PKCS5S2\}[a-z0-9\/+]{64}$/) ? [
                'PBKDF2_TO_ATLASSIAN',
            ] : false;
        },
        idGroup120 = function(str) {
            return str.match(/^md5[a-f0-9]{32}$/) ? [
                'POSTGRESQL_MD5',
            ] : false;
        },
        idGroup121 = function(str) {
            return str.match(/^\([a-z0-9\/+]{49}\)$/) ? [
                'LOTUS_NOTES_OR_DOMINO_8',
            ] : false;
        },
        idGroup122 = function(str) {
            return str.match(/^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$/) ? [
                'SCRYPT',
            ] : false;
        },
        idGroup123 = function(str) {
            return str.match(/^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
                'CISCO_TYPE_8',
            ] : false;
        },
        idGroup124 = function(str) {
            return str.match(/^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
                'CISCO_TYPE_9',
            ] : false;
        },
        idGroup125 = function(str) {
            return str.match(/^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$/) ? [
                'MICROSOFT_OFFICE_2007',
            ] : false;
        },
        idGroup126 = function(str) {
            return str.match(/^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
                'MICROSOFT_OFFICE_2010',
            ] : false;
        },
        idGroup127 = function(str) {
            return str.match(/^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
                'MICROSOFT_OFFICE_2013',
            ] : false;
        },
        idGroup128 = function(str) {
            return str.match(/^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$/) ? [
                'ANDROID_FDE_UND_Q_4_DOT_3',
            ] : false;
        },
        idGroup129 = function(str) {
            return str.match(/^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
                'MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4',
                'MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_1',
                'MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_2',
            ] : false;
        },
        idGroup130 = function(str) {
            return str.match(/^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$/) ? [
                'MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4',
                'MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_1',
                'MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_2',
            ] : false;
        },
        idGroup131 = function(str) {
            return str.match(/^(\$radmin2\$)?[a-f0-9]{32}$/) ? [
                'RADMIN_V2_DOT_X',
            ] : false;
        },
        idGroup132 = function(str) {
            return str.match(/^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$/) ? [
                'SAP_CODVN_H_TO_PWDSALTEDHASH_ISSHA_1',
            ] : false;
        },
        idGroup133 = function(str) {
            return str.match(/^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$/) ? [
                'CRAM_MD5',
            ] : false;
        },
        idGroup134 = function(str) {
            return str.match(/^[a-f0-9]{16}:2:4:[a-f0-9]{32}$/) ? [
                'SIPHASH',
            ] : false;
        },
        idGroup135 = function(str) {
            return str.match(/^[a-f0-9]{4,}$/) ? [
                'CISCO_TYPE_7',
            ] : false;
        },
        idGroup136 = function(str) {
            return str.match(/^[a-z0-9\/.]{13,}$/) ? [
                'BIGCRYPT',
            ] : false;
        },
        idGroup137 = function(str) {
            return str.match(/^(\$cisco4\$)?[a-z0-9\/.]{43}$/) ? [
                'CISCO_TYPE_4',
            ] : false;
        },
        idGroup138 = function(str) {
            return str.match(/^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$/) ? [
                'DJANGO_TO_BCRYPT_SHA256',
            ] : false;
        },
        idGroup139 = function(str) {
            return str.match(/^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$/) ? [
                'POSTGRESQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_MD5',
            ] : false;
        },
        idGroup140 = function(str) {
            return str.match(/^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$/) ? [
                'SIEMENS_S7',
            ] : false;
        },
        idGroup141 = function(str) {
            return str.match(/^(\$pst\$)?[a-f0-9]{8}$/) ? [
                'MICROSOFT_OUTLOOK_PST',
            ] : false;
        },
        idGroup142 = function(str) {
            return str.match(/^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$/) ? [
                'PBKDF2_HMAC_SHA256_TO_PHP',
            ] : false;
        },
        idGroup143 = function(str) {
            return str.match(/^(\$dahua\$)?[a-z0-9]{8}$/) ? [
                'DAHUA',
            ] : false;
        },
        idGroup144 = function(str) {
            return str.match(/^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
                'MYSQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_SHA1',
            ] : false;
        },
        idGroup145 = function(str) {
            return str.match(/^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$/) ? [
                'PDF_1_DOT_4_1_DOT_6_TO_ACROBAT_5_8',
            ] : false;
        },
    ]
}


/*
let encodeIdentify = function(str){

}

let encryptIdentify = function(str){

}

let md5Identify = function(str){

}
*/