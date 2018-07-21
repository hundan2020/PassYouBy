	idGroup1: function(str) {
		return str.match(/^[a-f0-9]{4}$/) ? [
		this.encryptType.CRC_16,
		this.encryptType.CRC_16_CCITT,
		this.encryptType.FCS_16,
		] : false;
	},
	idGroup2: function(str) {
		return str.match(/^[a-f0-9]{8}$/) ? [
		this.encryptType.ADLER_32,
		this.encryptType.CRC_32B,
		this.encryptType.FCS_32,
		this.encryptType.GHASH_32_3,
		this.encryptType.GHASH_32_5,
		this.encryptType.FNV_132,
		this.encryptType.FLETCHER_32,
		this.encryptType.JOAAT,
		this.encryptType.ELF_32,
		this.encryptType.XOR_32,
		] : false;
	},
	idGroup3: function(str) {
		return str.match(/^[a-f0-9]{6}$/) ? [
		this.encryptType.CRC_24,
		] : false;
	},
	idGroup4: function(str) {
		return str.match(/^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$/) ? [
		this.encryptType.CRC_32,
		] : false;
	},
	idGroup5: function(str) {
		return str.match(/^\+[a-z0-9\/.]{12}$/) ? [
		this.encryptType.EGGDROP_IRC_BOT,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{13}$/) ? [
		this.encryptType.DES_TO_UNIX,
		this.encryptType.TRADITIONAL_DES,
		this.encryptType.DESCRYPT,
		] : false;
	},
	idGroup7: function(str) {
		return str.match(/^[a-f0-9]{16}$/) ? [
		this.encryptType.MYSQL323,
		this.encryptType.DES_TO_ORACLE,
		this.encryptType.HALF_MD5,
		this.encryptType.ORACLE_7_10G,
		this.encryptType.FNV_164,
		this.encryptType.CRC_64,
		] : false;
	},
	idGroup8: function(str) {
		return str.match(/^[a-z0-9\/.]{16}$/) ? [
		this.encryptType.CISCO_PIX_TO_MD5,
		] : false;
	},
	idGroup9: function(str) {
		return str.match(/^\([a-z0-9\/+]{20}\)$/) ? [
		this.encryptType.LOTUS_NOTES_OR_DOMINO_6,
		] : false;
	},
	idGroup10: function(str) {
		return str.match(/^_[a-z0-9\/.]{19}$/) ? [
		this.encryptType.BSDI_CRYPT,
		] : false;
	},
	idGroup11: function(str) {
		return str.match(/^[a-f0-9]{24}$/) ? [
		this.encryptType.CRC_96_TO_ZIP,
		] : false;
	},
	idGroup12: function(str) {
		return str.match(/^[a-z0-9\/.]{24}$/) ? [
		this.encryptType.CRYPT16,
		] : false;
	},
	idGroup13: function(str) {
		return str.match(/^(\$md2\$)?[a-f0-9]{32}$/) ? [
		this.encryptType.MD2,
		] : false;
	},
	idGroup14: function(str) {
		return str.match(/^[a-f0-9]{32}(:.+)?$/) ? [
		this.encryptType.MD5,
		this.encryptType.MD4,
		this.encryptType.DOUBLE_MD5,
		this.encryptType.LM,
		this.encryptType.RIPEMD_128,
		this.encryptType.HAVAL_128,
		this.encryptType.TIGER_128,
		this.encryptType.SKEIN_256_TO_128,
		this.encryptType.SKEIN_512_TO_128,
		this.encryptType.LOTUS_NOTES_OR_DOMINO_5,
		this.encryptType.SKYPE,
		this.encryptType.ZIPMONSTER,
		this.encryptType.PRESTASHOP,
		this.encryptType.MD5_TO_MD5_TO_MD5_TO_DOL_PASS,
		this.encryptType.MD5_TO_STRTOUPPER_TO_MD5_TO_DOL_PASS,
		this.encryptType.MD5_TO_SHA1_TO_DOL_PASS,
		this.encryptType.MD5_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.MD5_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.MD5_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.MD5_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS,
		this.encryptType.HMAC_MD5_TO_KEY_EQ_DOL_PASS,
		this.encryptType.HMAC_MD5_TO_KEY_EQ_DOL_SALT,
		this.encryptType.MD5_TO_MD5_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS,
		this.encryptType.MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT,
		this.encryptType.MD5_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.MD5_TO_MD5_TO_DOL_PASS_DOT_MD5_TO_DOL_SALT,
		this.encryptType.MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.MD5_TO_DOL_SALT_DOT_MD5_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.MD5_TO_DOL_USERNAME_DOT_0_DOT_DOL_PASS,
		] : false;
	},
	idGroup15: function(str) {
		return str.match(/^(\$snefru\$)?[a-f0-9]{32}$/) ? [
		this.encryptType.SNEFRU_128,
		] : false;
	},
	idGroup16: function(str) {
		return str.match(/^(\$NT\$)?[a-f0-9]{32}$/) ? [
		this.encryptType.NTLM,
		] : false;
	},
	idGroup17: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$/) ? [
		this.encryptType.DOMAIN_CACHED_CREDENTIALS,
		] : false;
	},
	idGroup18: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$/) ? [
		this.encryptType.DOMAIN_CACHED_CREDENTIALS_2,
		] : false;
	},
	idGroup19: function(str) {
		return str.match(/^{SHA}[a-z0-9\/+]{27}=$/) ? [
		this.encryptType.SHA_1_TO_BASE64,
		this.encryptType.NETSCAPE_LDAP_SHA,
		] : false;
	},
	idGroup20: function(str) {
		return str.match(/^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$/) ? [
		this.encryptType.MD5_CRYPT,
		this.encryptType.CISCO_IOS_TO_MD5,
		this.encryptType.FREEBSD_MD5,
		] : false;
	},
	idGroup21: function(str) {
		return str.match(/^0x[a-f0-9]{32}$/) ? [
		this.encryptType.LINEAGE_II_C4,
		] : false;
	},
	idGroup22: function(str) {
		return str.match(/^\$H\$[a-z0-9\/.]{31}$/) ? [
		this.encryptType.PHPBB_V3_DOT_X,
		this.encryptType.WORDPRESS_V2_DOT_6_DOT_0_OR_2_DOT_6_DOT_1,
		this.encryptType.PHPASS_PORTABLE_HASH,
		] : false;
	},
	idGroup23: function(str) {
		return str.match(/^\$P\$[a-z0-9\/.]{31}$/) ? [
		this.encryptType.WORDPRESS_OVE_Q_V2_DOT_6_DOT_2,
		this.encryptType.JOOMLA_OVE_Q_V2_DOT_5_DOT_18,
		this.encryptType.PHPASS_PORTABLE_HASH,
		] : false;
	},
	idGroup24: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-z0-9]{2}$/) ? [
		this.encryptType.OSCOMMERCE,
		this.encryptType.XT_WITH_COMMERCE,
		] : false;
	},
	idGroup25: function(str) {
		return str.match(/^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$/) ? [
		this.encryptType.MD5_TO_APR,
		this.encryptType.APACHE_MD5,
		this.encryptType.MD5APR1,
		] : false;
	},
	idGroup26: function(str) {
		return str.match(/^{smd5}[a-z0-9$\/.]{31}$/) ? [
		this.encryptType.AIX_TO_SMD5,
		] : false;
	},
	idGroup27: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-f0-9]{32}$/) ? [
		this.encryptType.WEBEDITION_CMS,
		] : false;
	},
	idGroup28: function(str) {
		return str.match(/^[a-f0-9]{32}:.{5}$/) ? [
		this.encryptType.IP_DOT_BOARD_OVE_Q_V2_ADD,
		] : false;
	},
	idGroup29: function(str) {
		return str.match(/^[a-f0-9]{32}:.{8}$/) ? [
		this.encryptType.MYBB_OVE_Q_V1_DOT_2_ADD,
		] : false;
	},
	idGroup30: function(str) {
		return str.match(/^[a-z0-9]{34}$/) ? [
		this.encryptType.CRYPTOCURRENCY_TO_ADRESS,
		] : false;
	},
	idGroup31: function(str) {
		return str.match(/^[a-f0-9]{40}(:.+)?$/) ? [
		this.encryptType.SHA_1,
		this.encryptType.DOUBLE_SHA_1,
		this.encryptType.RIPEMD_160,
		this.encryptType.HAVAL_160,
		this.encryptType.TIGER_160,
		this.encryptType.HAS_160,
		this.encryptType.LINKEDIN,
		this.encryptType.SKEIN_256_TO_160,
		this.encryptType.SKEIN_512_TO_160,
		this.encryptType.MANGOSWEB_ENHANCED_CMS,
		this.encryptType.SHA1_TO_SHA1_TO_SHA1_TO_DOL_PASS,
		this.encryptType.SHA1_TO_MD5_TO_DOL_PASS,
		this.encryptType.SHA1_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA1_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.SHA1_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA1_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS,
		this.encryptType.HMAC_SHA1_TO_KEY_EQ_DOL_PASS,
		this.encryptType.HMAC_SHA1_TO_KEY_EQ_DOL_SALT,
		this.encryptType.SHA1_TO_DOL_SALT_DOT_DOL_PASS_DOT_DOL_SALT,
		] : false;
	},
	idGroup32: function(str) {
		return str.match(/^\*[a-f0-9]{40}$/) ? [
		this.encryptType.MYSQL5_DOT_X,
		this.encryptType.MYSQL4_DOT_1,
		] : false;
	},
	idGroup33: function(str) {
		return str.match(/^[a-z0-9]{43}$/) ? [
		this.encryptType.CISCO_IOS_TO_SHA_256,
		] : false;
	},
	idGroup34: function(str) {
		return str.match(/^{SSHA}[a-z0-9\/+]{38}==$/) ? [
		this.encryptType.SSHA_1_TO_BASE64,
		this.encryptType.NETSCAPE_LDAP_SSHA,
		this.encryptType.NSLDAPS,
		] : false;
	},
	idGroup35: function(str) {
		return str.match(/^[a-z0-9=]{47}$/) ? [
		this.encryptType.FORTIGATE_TO_FORTIOS,
		] : false;
	},
	idGroup36: function(str) {
		return str.match(/^[a-f0-9]{48}$/) ? [
		this.encryptType.HAVAL_192,
		this.encryptType.TIGER_192,
		this.encryptType.SHA_1_TO_ORACLE,
		this.encryptType.OSX_V10_DOT_4,
		this.encryptType.OSX_V10_DOT_5,
		this.encryptType.OSX_V10_DOT_6,
		] : false;
	},
	idGroup37: function(str) {
		return str.match(/^[a-f0-9]{51}$/) ? [
		this.encryptType.PALSHOP_CMS,
		] : false;
	},
	idGroup38: function(str) {
		return str.match(/^[a-z0-9]{51}$/) ? [
		this.encryptType.CRYPTOCURRENCY_TO_PRIVATEKEY,
		] : false;
	},
	idGroup39: function(str) {
		return str.match(/^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$/) ? [
		this.encryptType.AIX_TO_SSHA1,
		] : false;
	},
	idGroup40: function(str) {
		return str.match(/^0x0100[a-f0-9]{48}$/) ? [
		this.encryptType.MSSQL_TO_2005,
		this.encryptType.MSSQL_TO_2008,
		] : false;
	},
	idGroup41: function(str) {
		return str.match(/^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$/) ? [
		this.encryptType.SUN_MD5_CRYPT,
		] : false;
	},
	idGroup42: function(str) {
		return str.match(/^[a-f0-9]{56}$/) ? [
		this.encryptType.SHA_224,
		this.encryptType.HAVAL_224,
		this.encryptType.SHA3_224,
		this.encryptType.SKEIN_256_TO_224,
		this.encryptType.SKEIN_512_TO_224,
		] : false;
	},
	idGroup43: function(str) {
		return str.match(/^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
		this.encryptType.BLOWFISH_TO_OPENBSD,
		this.encryptType.WOLTLAB_BURNING_BOARD_4_DOT_X,
		this.encryptType.BCRYPT,
		] : false;
	},
	idGroup44: function(str) {
		return str.match(/^[a-f0-9]{40}:[a-f0-9]{16}$/) ? [
		this.encryptType.ANDROID_PIN,
		] : false;
	},
	idGroup45: function(str) {
		return str.match(/^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$/) ? [
		this.encryptType.ORACLE_11G_OR_12C,
		] : false;
	},
	idGroup46: function(str) {
		return str.match(/^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$/) ? [
		this.encryptType.BCRYPT_TO_SHA_256,
		] : false;
	},
	idGroup47: function(str) {
		return str.match(/^[a-f0-9]{32}:.{3}$/) ? [
		this.encryptType.VBULLETIN_UND_V3_DOT_8_DOT_5,
		] : false;
	},
	idGroup48: function(str) {
		return str.match(/^[a-f0-9]{32}:.{30}$/) ? [
		this.encryptType.VBULLETIN_OVE_Q_V3_DOT_8_DOT_5,
		] : false;
	},
	idGroup49: function(str) {
		return str.match(/^(\$snefru\$)?[a-f0-9]{64}$/) ? [
		this.encryptType.SNEFRU_256,
		] : false;
	},
	idGroup50: function(str) {
		return str.match(/^[a-f0-9]{64}(:.+)?$/) ? [
		this.encryptType.SHA_256,
		this.encryptType.RIPEMD_256,
		this.encryptType.HAVAL_256,
		this.encryptType.GOST_R_34_DOT_11_94,
		this.encryptType.GOST_CRYPTOPRO_S_BOX,
		this.encryptType.SHA3_256,
		this.encryptType.SKEIN_256,
		this.encryptType.SKEIN_512_TO_256,
		this.encryptType.VENTRILO,
		this.encryptType.SHA256_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA256_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.SHA256_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA256_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS,
		this.encryptType.HMAC_SHA256_TO_KEY_EQ_DOL_PASS,
		this.encryptType.HMAC_SHA256_TO_KEY_EQ_DOL_SALT,
		] : false;
	},
	idGroup51: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-z0-9]{32}$/) ? [
		this.encryptType.JOOMLA_UND_V2_DOT_5_DOT_18,
		] : false;
	},
	idGroup52: function(str) {
		return str.match(/^[a-f-0-9]{32}:[a-f-0-9]{32}$/) ? [
		this.encryptType.SAM_TO_LM_HASH_WITH_NT_HASH,
		] : false;
	},
	idGroup53: function(str) {
		return str.match(/^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$/) ? [
		this.encryptType.MD5_TO_CHAP,
		this.encryptType.ISCSI_CHAP_AUTHENTICATION,
		] : false;
	},
	idGroup54: function(str) {
		return str.match(/^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$/) ? [
		this.encryptType.EPISERVER_6_DOT_X_UND_V4,
		] : false;
	},
	idGroup55: function(str) {
		return str.match(/^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$/) ? [
		this.encryptType.AIX_TO_SSHA256,
		] : false;
	},
	idGroup56: function(str) {
		return str.match(/^[a-f0-9]{80}$/) ? [
		this.encryptType.RIPEMD_320,
		] : false;
	},
	idGroup57: function(str) {
		return str.match(/^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$/) ? [
		this.encryptType.EPISERVER_6_DOT_X_OVE_Q_V4,
		] : false;
	},
	idGroup58: function(str) {
		return str.match(/^0x0100[a-f0-9]{88}$/) ? [
		this.encryptType.MSSQL_TO_2000,
		] : false;
	},
	idGroup59: function(str) {
		return str.match(/^[a-f0-9]{96}$/) ? [
		this.encryptType.SHA_384,
		this.encryptType.SHA3_384,
		this.encryptType.SKEIN_512_TO_384,
		this.encryptType.SKEIN_1024_TO_384,
		] : false;
	},
	idGroup60: function(str) {
		return str.match(/^{SSHA512}[a-z0-9\/+]{96}$/) ? [
		this.encryptType.SSHA_512_TO_BASE64,
		this.encryptType.LDAP_TO_SSHA_512,
		] : false;
	},
	idGroup61: function(str) {
		return str.match(/^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$/) ? [
		this.encryptType.AIX_TO_SSHA512,
		] : false;
	},
	idGroup62: function(str) {
		return str.match(/^[a-f0-9]{128}(:.+)?$/) ? [
		this.encryptType.SHA_512,
		this.encryptType.WHIRLPOOL,
		this.encryptType.SALSA10,
		this.encryptType.SALSA20,
		this.encryptType.SHA3_512,
		this.encryptType.SKEIN_512,
		this.encryptType.SKEIN_1024_TO_512,
		this.encryptType.SHA512_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA512_TO_DOL_SALT_DOT_DOL_PASS,
		this.encryptType.SHA512_TO_UNICODE_TO_DOL_PASS_DOT_DOL_SALT,
		this.encryptType.SHA512_TO_DOL_SALT_DOT_UNICODE_TO_DOL_PASS,
		this.encryptType.HMAC_SHA512_TO_KEY_EQ_DOL_PASS,
		this.encryptType.HMAC_SHA512_TO_KEY_EQ_DOL_SALT,
		] : false;
	},
	idGroup63: function(str) {
		return str.match(/^[a-f0-9]{136}$/) ? [
		this.encryptType.OSX_V10_DOT_7,
		] : false;
	},
	idGroup64: function(str) {
		return str.match(/^0x0200[a-f0-9]{136}$/) ? [
		this.encryptType.MSSQL_TO_2012,
		this.encryptType.MSSQL_TO_2014,
		] : false;
	},
	idGroup65: function(str) {
		return str.match(/^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$/) ? [
		this.encryptType.OSX_V10_DOT_8,
		this.encryptType.OSX_V10_DOT_9,
		] : false;
	},
	idGroup66: function(str) {
		return str.match(/^[a-f0-9]{256}$/) ? [
		this.encryptType.SKEIN_1024,
		] : false;
	},
	idGroup67: function(str) {
		return str.match(/^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$/) ? [
		this.encryptType.GRUB_2,
		] : false;
	},
	idGroup68: function(str) {
		return str.match(/^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/) ? [
		this.encryptType.DJANGO_TO_SHA_1,
		] : false;
	},
	idGroup69: function(str) {
		return str.match(/^[a-f0-9]{49}$/) ? [
		this.encryptType.CITRIX_NETSCALER,
		] : false;
	},
	idGroup70: function(str) {
		return str.match(/^\$S\$[a-z0-9\/.]{52}$/) ? [
		this.encryptType.DRUPAL_OVE_V7_DOT_X,
		] : false;
	},
	idGroup71: function(str) {
		return str.match(/^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$/) ? [
		this.encryptType.SHA_256_CRYPT,
		] : false;
	},
	idGroup72: function(str) {
		return str.match(/^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$/) ? [
		this.encryptType.SYBASE_ASE,
		] : false;
	},
	idGroup73: function(str) {
		return str.match(/^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$/) ? [
		this.encryptType.SHA_512_CRYPT,
		] : false;
	},
	idGroup74: function(str) {
		return str.match(/^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$/) ? [
		this.encryptType.MINECRAFT_TO_AUTHME_RELOADED,
		] : false;
	},
	idGroup75: function(str) {
		return str.match(/^sha256\$[a-z0-9]+\$[a-f0-9]{64}$/) ? [
		this.encryptType.DJANGO_TO_SHA_256,
		] : false;
	},
	idGroup76: function(str) {
		return str.match(/^sha384\$[a-z0-9]+\$[a-f0-9]{96}$/) ? [
		this.encryptType.DJANGO_TO_SHA_384,
		] : false;
	},
	idGroup77: function(str) {
		return str.match(/^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$/) ? [
		this.encryptType.CLAVISTER_SECURE_GATEWAY,
		] : false;
	},
	idGroup78: function(str) {
		return str.match(/^[a-f0-9]{112}$/) ? [
		this.encryptType.CISCO_VPN_CLIENT_TO_PCF_FILE,
		] : false;
	},
	idGroup79: function(str) {
		return str.match(/^[a-f0-9]{1329}$/) ? [
		this.encryptType.MICROSOFT_MSTSC_TO_RDP_FILE,
		] : false;
	},
	idGroup80: function(str) {
		return str.match(/^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/) ? [
		this.encryptType.NETNTLMV1_VANILLA_OR_NETNTLMV1_ADD_ESS,
		] : false;
	},
	idGroup81: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$/) ? [
		this.encryptType.NETNTLMV2,
		] : false;
	},
	idGroup82: function(str) {
		return str.match(/^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$/) ? [
		this.encryptType.KERBEROS_5_AS_REQ_PRE_AUTH,
		] : false;
	},
	idGroup83: function(str) {
		return str.match(/^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$/) ? [
		this.encryptType.SCRAM_HASH,
		] : false;
	},
	idGroup84: function(str) {
		return str.match(/^[a-f0-9]{40}:[a-f0-9]{0,32}$/) ? [
		this.encryptType.REDMINE_PROJECT_MANAGEMENT_WEB_APP,
		] : false;
	},
	idGroup85: function(str) {
		return str.match(/^(.+)?\$[a-f0-9]{16}$/) ? [
		this.encryptType.SAP_CODVN_B_TO_BCODE,
		] : false;
	},
	idGroup86: function(str) {
		return str.match(/^(.+)?\$[a-f0-9]{40}$/) ? [
		this.encryptType.SAP_CODVN_F_OR_G_TO_PASSCODE,
		] : false;
	},
	idGroup87: function(str) {
		return str.match(/^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$/) ? [
		this.encryptType.JUNIPER_NETSCREEN_OR_SSG_TO_SCREENOS,
		] : false;
	},
	idGroup88: function(str) {
		return str.match(/^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$/) ? [
		this.encryptType.EPI,
		] : false;
	},
	idGroup89: function(str) {
		return str.match(/^[a-f0-9]{40}:[^*]{1,25}$/) ? [
		this.encryptType.SMF_OVE_Q_V1_DOT_1,
		] : false;
	},
	idGroup90: function(str) {
		return str.match(/^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
		this.encryptType.WOLTLAB_BURNING_BOARD_3_DOT_X,
		] : false;
	},
	idGroup91: function(str) {
		return str.match(/^[a-f0-9]{130}(:[a-f0-9]{40})?$/) ? [
		this.encryptType.IPMI2_RAKP_HMAC_SHA1,
		] : false;
	},
	idGroup92: function(str) {
		return str.match(/^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$/) ? [
		this.encryptType.LASTPASS,
		] : false;
	},
	idGroup93: function(str) {
		return str.match(/^[a-z0-9\/.]{16}([:$].{1,})?$/) ? [
		this.encryptType.CISCO_ASA_TO_MD5,
		] : false;
	},
	idGroup94: function(str) {
		return str.match(/^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
		this.encryptType.VNC,
		] : false;
	},
	idGroup95: function(str) {
		return str.match(/^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$/) ? [
		this.encryptType.DNSSEC_TO_NSEC3,
		] : false;
	},
	idGroup96: function(str) {
		return str.match(/^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$/) ? [
		this.encryptType.RACF,
		] : false;
	},
	idGroup97: function(str) {
		return str.match(/^\$3\$\$[a-f0-9]{32}$/) ? [
		this.encryptType.NTHASH_TO_FREEBSD_VARIANT,
		] : false;
	},
	idGroup98: function(str) {
		return str.match(/^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$/) ? [
		this.encryptType.SHA_1_CRYPT,
		] : false;
	},
	idGroup99: function(str) {
		return str.match(/^[a-f0-9]{70}$/) ? [
		this.encryptType.HMAILSERVER,
		] : false;
	},
	idGroup100: function(str) {
		return str.match(/^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$/) ? [
		this.encryptType.MEDIAWIKI,
		] : false;
	},
	idGroup101: function(str) {
		return str.match(/^[a-f0-9]{140}$/) ? [
		this.encryptType.MINECRAFT_TO_XAUTH,
		] : false;
	},
	idGroup102: function(str) {
		return str.match(/^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$/) ? [
		this.encryptType.PBKDF2_SHA1_TO_GENERIC,
		] : false;
	},
	idGroup103: function(str) {
		return str.match(/^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$/) ? [
		this.encryptType.PBKDF2_SHA256_TO_GENERIC,
		] : false;
	},
	idGroup104: function(str) {
		return str.match(/^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$/) ? [
		this.encryptType.PBKDF2_SHA512_TO_GENERIC,
		] : false;
	},
	idGroup105: function(str) {
		return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$/) ? [
		this.encryptType.PBKDF2_TO_CRYPTACULAR,
		] : false;
	},
	idGroup106: function(str) {
		return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$/) ? [
		this.encryptType.PBKDF2_TO_DWAYNE_LITZENBERGER,
		] : false;
	},
	idGroup107: function(str) {
		return str.match(/^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$/) ? [
		this.encryptType.FAIRLY_SECURE_HASHED_PASSWORD,
		] : false;
	},
	idGroup108: function(str) {
		return str.match(/^\$PHPS\$.+\$[a-f0-9]{32}$/) ? [
		this.encryptType.PHPS,
		] : false;
	},
	idGroup109: function(str) {
		return str.match(/^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$/) ? [
		this.encryptType.X1PASSWORD_TO_AGILE_KEYCHAIN,
		] : false;
	},
	idGroup110: function(str) {
		return str.match(/^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$/) ? [
		this.encryptType.X1PASSWORD_TO_CLOUD_KEYCHAIN,
		] : false;
	},
	idGroup111: function(str) {
		return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$/) ? [
		this.encryptType.IKE_PSK_MD5,
		] : false;
	},
	idGroup112: function(str) {
		return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$/) ? [
		this.encryptType.IKE_PSK_SHA1,
		] : false;
	},
	idGroup113: function(str) {
		return str.match(/^[a-z0-9\/+]{27}=$/) ? [
		this.encryptType.PEOPLESOFT,
		] : false;
	},
	idGroup114: function(str) {
		return str.match(/^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$/) ? [
		this.encryptType.DJANGO_TO_DES_CRYPT_WRAPPER,
		] : false;
	},
	idGroup115: function(str) {
		return str.match(/^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$/) ? [
		this.encryptType.DJANGO_TO_PBKDF2_HMAC_SHA256,
		] : false;
	},
	idGroup116: function(str) {
		return str.match(/^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$/) ? [
		this.encryptType.DJANGO_TO_PBKDF2_HMAC_SHA1,
		] : false;
	},
	idGroup117: function(str) {
		return str.match(/^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
		this.encryptType.DJANGO_TO_BCRYPT,
		] : false;
	},
	idGroup118: function(str) {
		return str.match(/^md5\$[a-f0-9]+\$[a-f0-9]{32}$/) ? [
		this.encryptType.DJANGO_TO_MD5,
		] : false;
	},
	idGroup119: function(str) {
		return str.match(/^\{PKCS5S2\}[a-z0-9\/+]{64}$/) ? [
		this.encryptType.PBKDF2_TO_ATLASSIAN,
		] : false;
	},
	idGroup120: function(str) {
		return str.match(/^md5[a-f0-9]{32}$/) ? [
		this.encryptType.POSTGRESQL_MD5,
		] : false;
	},
	idGroup121: function(str) {
		return str.match(/^\([a-z0-9\/+]{49}\)$/) ? [
		this.encryptType.LOTUS_NOTES_OR_DOMINO_8,
		] : false;
	},
	idGroup122: function(str) {
		return str.match(/^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$/) ? [
		this.encryptType.SCRYPT,
		] : false;
	},
	idGroup123: function(str) {
		return str.match(/^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
		this.encryptType.CISCO_TYPE_8,
		] : false;
	},
	idGroup124: function(str) {
		return str.match(/^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
		this.encryptType.CISCO_TYPE_9,
		] : false;
	},
	idGroup125: function(str) {
		return str.match(/^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$/) ? [
		this.encryptType.MICROSOFT_OFFICE_2007,
		] : false;
	},
	idGroup126: function(str) {
		return str.match(/^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
		this.encryptType.MICROSOFT_OFFICE_2010,
		] : false;
	},
	idGroup127: function(str) {
		return str.match(/^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
		this.encryptType.MICROSOFT_OFFICE_2013,
		] : false;
	},
	idGroup128: function(str) {
		return str.match(/^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$/) ? [
		this.encryptType.ANDROID_FDE_UND_Q_4_DOT_3,
		] : false;
	},
	idGroup129: function(str) {
		return str.match(/^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4,
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_1,
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_MD5_ADD_RC4_COLLIDER_MODE_SHARP_2,
		] : false;
	},
	idGroup130: function(str) {
		return str.match(/^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$/) ? [
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4,
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_1,
		this.encryptType.MICROSOFT_OFFICE_UND_Q_2003_TO_SHA1_ADD_RC4_COLLIDER_MODE_SHARP_2,
		] : false;
	},
	idGroup131: function(str) {
		return str.match(/^(\$radmin2\$)?[a-f0-9]{32}$/) ? [
		this.encryptType.RADMIN_V2_DOT_X,
		] : false;
	},
	idGroup132: function(str) {
		return str.match(/^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$/) ? [
		this.encryptType.SAP_CODVN_H_TO_PWDSALTEDHASH_ISSHA_1,
		] : false;
	},
	idGroup133: function(str) {
		return str.match(/^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$/) ? [
		this.encryptType.CRAM_MD5,
		] : false;
	},
	idGroup134: function(str) {
		return str.match(/^[a-f0-9]{16}:2:4:[a-f0-9]{32}$/) ? [
		this.encryptType.SIPHASH,
		] : false;
	},
	idGroup135: function(str) {
		return str.match(/^[a-f0-9]{4,}$/) ? [
		this.encryptType.CISCO_TYPE_7,
		] : false;
	},
	idGroup136: function(str) {
		return str.match(/^[a-z0-9\/.]{13,}$/) ? [
		this.encryptType.BIGCRYPT,
		] : false;
	},
	idGroup137: function(str) {
		return str.match(/^(\$cisco4\$)?[a-z0-9\/.]{43}$/) ? [
		this.encryptType.CISCO_TYPE_4,
		] : false;
	},
	idGroup138: function(str) {
		return str.match(/^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$/) ? [
		this.encryptType.DJANGO_TO_BCRYPT_SHA256,
		] : false;
	},
	idGroup139: function(str) {
		return str.match(/^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$/) ? [
		this.encryptType.POSTGRESQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_MD5,
		] : false;
	},
	idGroup140: function(str) {
		return str.match(/^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$/) ? [
		this.encryptType.SIEMENS_S7,
		] : false;
	},
	idGroup141: function(str) {
		return str.match(/^(\$pst\$)?[a-f0-9]{8}$/) ? [
		this.encryptType.MICROSOFT_OUTLOOK_PST,
		] : false;
	},
	idGroup142: function(str) {
		return str.match(/^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$/) ? [
		this.encryptType.PBKDF2_HMAC_SHA256_TO_PHP,
		] : false;
	},
	idGroup143: function(str) {
		return str.match(/^(\$dahua\$)?[a-z0-9]{8}$/) ? [
		this.encryptType.DAHUA,
		] : false;
	},
	idGroup144: function(str) {
		return str.match(/^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
		this.encryptType.MYSQL_CHALLENGE_RESPONSE_AUTHENTICATION_TO_SHA1,
		] : false;
	},
	idGroup145: function(str) {
		return str.match(/^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$/) ? [
		this.encryptType.PDF_1_DOT_4_1_DOT_6_TO_ACROBAT_5_8,
		] : false;
	},
