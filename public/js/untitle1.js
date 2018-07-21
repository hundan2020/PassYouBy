    Prototype(
        regex=re.compile(r'^[a-f0-9]{4}$/) ? [
			this.encryptType.CRC-16,
            this.encryptType.CRC-16-CCITT,
            this.encryptType.FCS-16,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{8}$/) ? [
			this.encryptType.Adler-32,
            this.encryptType.CRC-32B,
            this.encryptType.FCS-32,
            this.encryptType.GHash-32-3,
            this.encryptType.GHash-32-5,
            this.encryptType.FNV-132,
            this.encryptType.Fletcher-32,
            this.encryptType.Joaat,
            this.encryptType.ELF-32,
            this.encryptType.XOR-32,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{6}$/) ? [
			this.encryptType.CRC-24,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$/) ? [
			this.encryptType.CRC-32,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\+[a-z0-9\/.]{12}$/) ? [
			this.encryptType.Eggdrop IRC Bot,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{13}$/) ? [
			this.encryptType.DES(Unix),
            this.encryptType.Traditional DES,
            this.encryptType.DEScrypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{16}$/) ? [
			this.encryptType.MySQL323,
            this.encryptType.DES(Oracle),
            this.encryptType.Half MD5,
            this.encryptType.Oracle 7-10g,
            this.encryptType.FNV-164,
            this.encryptType.CRC-64,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{16}$/) ? [
			this.encryptType.Cisco-PIX(MD5),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\([a-z0-9\/+]{20}\)$/) ? [
			this.encryptType.Lotus Notes/Domino 6,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^_[a-z0-9\/.]{19}$/) ? [
			this.encryptType.BSDi Crypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{24}$/) ? [
			this.encryptType.CRC-96(ZIP),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{24}$/) ? [
			this.encryptType.Crypt16,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$md2\$)?[a-f0-9]{32}$/) ? [
			this.encryptType.MD2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}(:.+)?$/) ? [
			this.encryptType.MD5,
            this.encryptType.MD4,
            this.encryptType.Double MD5,
            this.encryptType.LM,
            this.encryptType.RIPEMD-128,
            this.encryptType.Haval-128,
            this.encryptType.Tiger-128,
            this.encryptType.Skein-256(128),
            this.encryptType.Skein-512(128),
            this.encryptType.Lotus Notes/Domino 5,
            this.encryptType.Skype,
            this.encryptType.ZipMonster,
            this.encryptType.PrestaShop,
            this.encryptType.md5(md5(md5($pass))),
            this.encryptType.md5(strtoupper(md5($pass))),
            this.encryptType.md5(sha1($pass)),
            this.encryptType.md5($pass.$salt),
            this.encryptType.md5($salt.$pass),
            this.encryptType.md5(unicode($pass).$salt),
            this.encryptType.md5($salt.unicode($pass)),
            this.encryptType.HMAC-MD5 (key = $pass),
            this.encryptType.HMAC-MD5 (key = $salt),
            this.encryptType.md5(md5($salt).$pass),
            this.encryptType.md5($salt.md5($pass)),
            this.encryptType.md5($pass.md5($salt)),
            this.encryptType.md5($salt.$pass.$salt),
            this.encryptType.md5(md5($pass).md5($salt)),
            this.encryptType.md5($salt.md5($salt.$pass)),
            this.encryptType.md5($salt.md5($pass.$salt)),
            this.encryptType.md5($username.0.$pass),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$snefru\$)?[a-f0-9]{32}$/) ? [
			this.encryptType.Snefru-128,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$NT\$)?[a-f0-9]{32}$/) ? [
			this.encryptType.NTLM,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$/) ? [
			this.encryptType.Domain Cached Credentials,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$/) ? [
			this.encryptType.Domain Cached Credentials 2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{SHA}[a-z0-9\/+]{27}=$/) ? [
			this.encryptType.SHA-1(Base64),
            this.encryptType.Netscape LDAP SHA,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$/) ? [
			this.encryptType.MD5 Crypt,
            this.encryptType.Cisco-IOS(MD5),
            this.encryptType.FreeBSD MD5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x[a-f0-9]{32}$/) ? [
			this.encryptType.Lineage II C4,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$H\$[a-z0-9\/.]{31}$/) ? [
			this.encryptType.phpBB v3.x,
            this.encryptType.Wordpress v2.6.0/2.6.1,
            this.encryptType.PHPass' Portable Hash,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$P\$[a-z0-9\/.]{31}$/) ? [
			this.encryptType.Wordpress ≥ v2.6.2,
            this.encryptType.Joomla ≥ v2.5.18,
            this.encryptType.PHPass' Portable Hash,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-z0-9]{2}$/) ? [
			this.encryptType.osCommerce,
            this.encryptType.xt:Commerce,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$/) ? [
			this.encryptType.MD5(APR),
            this.encryptType.Apache MD5,
            this.encryptType.md5apr1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{smd5}[a-z0-9$\/.]{31}$/) ? [
			this.encryptType.AIX(smd5),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-f0-9]{32}$/) ? [
			this.encryptType.WebEdition CMS,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:.{5}$/) ? [
			this.encryptType.IP.Board ≥ v2+,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:.{8}$/) ? [
			this.encryptType.MyBB ≥ v1.2+,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9]{34}$/) ? [
			this.encryptType.CryptoCurrency(Adress),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{40}(:.+)?$/) ? [
			this.encryptType.SHA-1,
            this.encryptType.Double SHA-1,
            this.encryptType.RIPEMD-160,
            this.encryptType.Haval-160,
            this.encryptType.Tiger-160,
            this.encryptType.HAS-160,
            this.encryptType.LinkedIn,
            this.encryptType.Skein-256(160),
            this.encryptType.Skein-512(160),
            this.encryptType.MangosWeb Enhanced CMS,
            this.encryptType.sha1(sha1(sha1($pass))),
            this.encryptType.sha1(md5($pass)),
            this.encryptType.sha1($pass.$salt),
            this.encryptType.sha1($salt.$pass),
            this.encryptType.sha1(unicode($pass).$salt),
            this.encryptType.sha1($salt.unicode($pass)),
            this.encryptType.HMAC-SHA1 (key = $pass),
            this.encryptType.HMAC-SHA1 (key = $salt),
            this.encryptType.sha1($salt.$pass.$salt),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\*[a-f0-9]{40}$/) ? [
			this.encryptType.MySQL5.x,
            this.encryptType.MySQL4.1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9]{43}$/) ? [
			this.encryptType.Cisco-IOS(SHA-256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{SSHA}[a-z0-9\/+]{38}==$/) ? [
			this.encryptType.SSHA-1(Base64),
            this.encryptType.Netscape LDAP SSHA,
            this.encryptType.nsldaps,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9=]{47}$/) ? [
			this.encryptType.Fortigate(FortiOS),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{48}$/) ? [
			this.encryptType.Haval-192,
            this.encryptType.Tiger-192,
            this.encryptType.SHA-1(Oracle),
            this.encryptType.OSX v10.4,
            this.encryptType.OSX v10.5,
            this.encryptType.OSX v10.6,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{51}$/) ? [
			this.encryptType.Palshop CMS,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9]{51}$/) ? [
			this.encryptType.CryptoCurrency(PrivateKey),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$/) ? [
			this.encryptType.AIX(ssha1),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x0100[a-f0-9]{48}$/) ? [
			this.encryptType.MSSQL(2005),
            this.encryptType.MSSQL(2008),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$/) ? [
			this.encryptType.Sun MD5 Crypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{56}$/) ? [
			this.encryptType.SHA-224,
            this.encryptType.Haval-224,
            this.encryptType.SHA3-224,
            this.encryptType.Skein-256(224),
            this.encryptType.Skein-512(224),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
			this.encryptType.Blowfish(OpenBSD),
            this.encryptType.Woltlab Burning Board 4.x,
            this.encryptType.bcrypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{40}:[a-f0-9]{16}$/) ? [
			this.encryptType.Android PIN,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$/) ? [
			this.encryptType.Oracle 11g/12c,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$/) ? [
			this.encryptType.bcrypt(SHA-256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:.{3}$/) ? [
			this.encryptType.vBulletin < v3.8.5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:.{30}$/) ? [
			this.encryptType.vBulletin ≥ v3.8.5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$snefru\$)?[a-f0-9]{64}$/) ? [
			this.encryptType.Snefru-256,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{64}(:.+)?$/) ? [
			this.encryptType.SHA-256,
            this.encryptType.RIPEMD-256,
            this.encryptType.Haval-256,
            this.encryptType.GOST R 34.11-94,
            this.encryptType.GOST CryptoPro S-Box,
            this.encryptType.SHA3-256,
            this.encryptType.Skein-256,
            this.encryptType.Skein-512(256),
            this.encryptType.Ventrilo,
            this.encryptType.sha256($pass.$salt),
            this.encryptType.sha256($salt.$pass),
            this.encryptType.sha256(unicode($pass).$salt),
            this.encryptType.sha256($salt.unicode($pass)),
            this.encryptType.HMAC-SHA256 (key = $pass),
            this.encryptType.HMAC-SHA256 (key = $salt),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:[a-z0-9]{32}$/) ? [
			this.encryptType.Joomla < v2.5.18,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f-0-9]{32}:[a-f-0-9]{32}$/) ? [
			this.encryptType.SAM(LM_Hash:NT_Hash),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$/) ? [
			this.encryptType.MD5(Chap),
            this.encryptType.iSCSI CHAP Authentication,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$/) ? [
			this.encryptType.EPiServer 6.x < v4,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$/) ? [
			this.encryptType.AIX(ssha256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{80}$/) ? [
			this.encryptType.RIPEMD-320,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$/) ? [
			this.encryptType.EPiServer 6.x ≥ v4,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x0100[a-f0-9]{88}$/) ? [
			this.encryptType.MSSQL(2000),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{96}$/) ? [
			this.encryptType.SHA-384,
            this.encryptType.SHA3-384,
            this.encryptType.Skein-512(384),
            this.encryptType.Skein-1024(384),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{SSHA512}[a-z0-9\/+]{96}$/) ? [
			this.encryptType.SSHA-512(Base64),
            this.encryptType.LDAP(SSHA-512),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$/) ? [
			this.encryptType.AIX(ssha512),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{128}(:.+)?$/) ? [
			this.encryptType.SHA-512,
            this.encryptType.Whirlpool,
            this.encryptType.Salsa10,
            this.encryptType.Salsa20,
            this.encryptType.SHA3-512,
            this.encryptType.Skein-512,
            this.encryptType.Skein-1024(512),
            this.encryptType.sha512($pass.$salt),
            this.encryptType.sha512($salt.$pass),
            this.encryptType.sha512(unicode($pass).$salt),
            this.encryptType.sha512($salt.unicode($pass)),
            this.encryptType.HMAC-SHA512 (key = $pass),
            this.encryptType.HMAC-SHA512 (key = $salt),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{136}$/) ? [
			this.encryptType.OSX v10.7,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x0200[a-f0-9]{136}$/) ? [
			this.encryptType.MSSQL(2012),
            this.encryptType.MSSQL(2014),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$/) ? [
			this.encryptType.OSX v10.8,
            this.encryptType.OSX v10.9,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{256}$/) ? [
			this.encryptType.Skein-1024,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$/) ? [
			this.encryptType.GRUB 2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/) ? [
			this.encryptType.Django(SHA-1),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{49}$/) ? [
			this.encryptType.Citrix Netscaler,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$S\$[a-z0-9\/.]{52}$/) ? [
			this.encryptType.Drupal > v7.x,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$/) ? [
			this.encryptType.SHA-256 Crypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$/) ? [
			this.encryptType.Sybase ASE,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$/) ? [
			this.encryptType.SHA-512 Crypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$/) ? [
			this.encryptType.Minecraft(AuthMe Reloaded),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^sha256\$[a-z0-9]+\$[a-f0-9]{64}$/) ? [
			this.encryptType.Django(SHA-256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^sha384\$[a-z0-9]+\$[a-f0-9]{96}$/) ? [
			this.encryptType.Django(SHA-384),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$/) ? [
			this.encryptType.Clavister Secure Gateway,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{112}$/) ? [
			this.encryptType.Cisco VPN Client(PCF-File),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{1329}$/) ? [
			this.encryptType.Microsoft MSTSC(RDP-File),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/) ? [
			this.encryptType.NetNTLMv1-VANILLA / NetNTLMv1+ESS,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$/) ? [
			this.encryptType.NetNTLMv2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$/) ? [
			this.encryptType.Kerberos 5 AS-REQ Pre-Auth,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$/) ? [
			this.encryptType.SCRAM Hash,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{40}:[a-f0-9]{0,32}$/) ? [
			this.encryptType.Redmine Project Management Web App,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(.+)?\$[a-f0-9]{16}$/) ? [
			this.encryptType.SAP CODVN B (BCODE),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(.+)?\$[a-f0-9]{40}$/) ? [
			this.encryptType.SAP CODVN F/G (PASSCODE),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$/) ? [
			this.encryptType.Juniper Netscreen/SSG(ScreenOS),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$/) ? [
			this.encryptType.EPi,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{40}:[^*]{1,25}$/) ? [
			this.encryptType.SMF ≥ v1.1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
			this.encryptType.Woltlab Burning Board 3.x,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{130}(:[a-f0-9]{40})?$/) ? [
			this.encryptType.IPMI2 RAKP HMAC-SHA1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$/) ? [
			this.encryptType.Lastpass,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{16}([:$].{1,})?$/) ? [
			this.encryptType.Cisco-ASA(MD5),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
			this.encryptType.VNC,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$/) ? [
			this.encryptType.DNSSEC(NSEC3),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$/) ? [
			this.encryptType.RACF,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$3\$\$[a-f0-9]{32}$/) ? [
			this.encryptType.NTHash(FreeBSD Variant),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$/) ? [
			this.encryptType.SHA-1 Crypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{70}$/) ? [
			this.encryptType.hMailServer,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$/) ? [
			this.encryptType.MediaWiki,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{140}$/) ? [
			this.encryptType.Minecraft(xAuth),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$/) ? [
			this.encryptType.PBKDF2-SHA1(Generic),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$/) ? [
			this.encryptType.PBKDF2-SHA256(Generic),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$/) ? [
			this.encryptType.PBKDF2-SHA512(Generic),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$/) ? [
			this.encryptType.PBKDF2(Cryptacular),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$/) ? [
			this.encryptType.PBKDF2(Dwayne Litzenberger),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$/) ? [
			this.encryptType.Fairly Secure Hashed Password,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$PHPS\$.+\$[a-f0-9]{32}$/) ? [
			this.encryptType.PHPS,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$/) ? [
			this.encryptType.1Password(Agile Keychain),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$/) ? [
			this.encryptType.1Password(Cloud Keychain),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$/) ? [
			this.encryptType.IKE-PSK MD5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$/) ? [
			this.encryptType.IKE-PSK SHA1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/+]{27}=$/) ? [
			this.encryptType.PeopleSoft,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$/) ? [
			this.encryptType.Django(DES Crypt Wrapper),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$/) ? [
			this.encryptType.Django(PBKDF2-HMAC-SHA256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$/) ? [
			this.encryptType.Django(PBKDF2-HMAC-SHA1),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/) ? [
			this.encryptType.Django(bcrypt),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^md5\$[a-f0-9]+\$[a-f0-9]{32}$/) ? [
			this.encryptType.Django(MD5),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\{PKCS5S2\}[a-z0-9\/+]{64}$/) ? [
			this.encryptType.PBKDF2(Atlassian),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^md5[a-f0-9]{32}$/) ? [
			this.encryptType.PostgreSQL MD5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\([a-z0-9\/+]{49}\)$/) ? [
			this.encryptType.Lotus Notes/Domino 8,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$/) ? [
			this.encryptType.scrypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
			this.encryptType.Cisco Type 8,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/) ? [
			this.encryptType.Cisco Type 9,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$/) ? [
			this.encryptType.Microsoft Office 2007,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
			this.encryptType.Microsoft Office 2010,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/) ? [
			this.encryptType.Microsoft Office 2013,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$/) ? [
			this.encryptType.Android FDE ≤ 4.3,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$/) ? [
			this.encryptType.Microsoft Office ≤ 2003 (MD5+RC4),
            this.encryptType.Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1,
            this.encryptType.Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$/) ? [
			this.encryptType.Microsoft Office ≤ 2003 (SHA1+RC4),
            this.encryptType.Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1,
            this.encryptType.Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$radmin2\$)?[a-f0-9]{32}$/) ? [
			this.encryptType.RAdmin v2.x,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$/) ? [
			this.encryptType.SAP CODVN H (PWDSALTEDHASH) iSSHA-1,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$/) ? [
			this.encryptType.CRAM-MD5,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{16}:2:4:[a-f0-9]{32}$/) ? [
			this.encryptType.SipHash,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-f0-9]{4,}$/) ? [
			this.encryptType.Cisco Type 7,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^[a-z0-9\/.]{13,}$/) ? [
			this.encryptType.BigCrypt,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$cisco4\$)?[a-z0-9\/.]{43}$/) ? [
			this.encryptType.Cisco Type 4,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$/) ? [
			this.encryptType.Django(bcrypt-SHA256),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$/) ? [
			this.encryptType.PostgreSQL Challenge-Response Authentication (MD5),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$/) ? [
			this.encryptType.Siemens-S7,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$pst\$)?[a-f0-9]{8}$/) ? [
			this.encryptType.Microsoft Outlook PST,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$/) ? [
			this.encryptType.PBKDF2-HMAC-SHA256(PHP),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^(\$dahua\$)?[a-z0-9]{8}$/) ? [
			this.encryptType.Dahua,
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$/) ? [
			this.encryptType.MySQL Challenge-Response Authentication (SHA1),
		] : false;
	},
	idGroup6: function(str) {
		return str.match(/^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$/) ? [
			this.encryptType.PDF 1.4 - 1.6 (Acrobat 5 - 8),
