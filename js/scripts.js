
var EncryptIdentify = {
	// 代码参考了 https://github.com/psypanda/hashID/blob/master/hashid.py
	// 但是显然我能做的比他更好，他似乎并没有考虑到大小写问题
	// 但是我想了一下，这里是加密/hash，不是编码，似乎所有的加密/hash类型都不需要考虑大小写，只有编码才需要
	encryptType: {
		MD5_32: 10001,
		MD5_16: 10002,
		CRC_16: 10101,
		CRC_16_CCITT: 10102,
		CRC_24: 10103,
		CRC_32B: 10104,
		FCS_16: 10201,

		FCS_32: 10202,
		ADLER_32: 10301,
		GHash_32_3: 10401,
		GHash_32_5: 10402,
		FNV_132: 10501,
		Fletcher_32: 10601,
		JOAAT: 10701,
		ELF_32: 10801,
		XOR_32: 10901,

	},

	/**
	 * 通用加密检查，调用以下其他所有检查方法。注意传入的密文应该总是HEX形式的
	 * @param  {string} str 要检查的字符串
	 * @return {object|false}     成功返回对象，失败返回false
	 */
	identify: function(str) {
		// code...
		// 注意去除头尾的空白字符并提示
		// 检测非可见字符并提示，以免误判
		// return ...
	},

	/**
	 * 下面这些代码先匹配正则后才确定信息，会比根据加密方式来的写法高效，
	 * @param  {string} str 密文
	 * @return {obj|bool}     成功返回对象，失败返回false
	 */
	idGroup1: function(str) {
		str += '';
		return str.match(/^[0-9a-f]{4}$/) ? [
			this.encryptType.CRC_16,
			this.encryptType.CRC_16_CCITT,
			this.encryptType.FCS_16
		] : false;
	},
	idGroup2: function(str) {
		str += '';
		return str.match(/^[0-9a-f]{8}$/) ? [
			this.encryptType.FCS_32,
			this.encryptType.ADLER_32,
			this.encryptType.GHash_32_3,
			this.encryptType.GHash_32_5,
			this.encryptType.FNV_132,
			this.encryptType.Fletcher_32,
			this.encryptType.JOAAT,
			this.encryptType.ELF_32,
			this.encryptType.XOR_32
		] : false;
	},
	idGroup3: function(str) {
		str += '';
		return str.match(/^[0-9a-f]{6}$/) ? [
			this.encryptType.CRC_24
		] : false;
	},

	// 从这里开始的hash类型，我都暂时不补充到上方字典

	idGroup4: function(str) {
		str += '';
		return str.match(/^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$/) ? [
			this.encryptType.CRC_32
		] : false;
	},
	idGroup5: function(str) {
		str += '';
		return str.match(/^\+[a-z0-9\/.]{12}$/) ? [
			this.encryptType.Eggdrop_IRC_Bot
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-z0-9\/.]{13}$/) ? [
			this.encryptType.DES_In_Unix,
			this.encryptType.Traditional_DES,
			this.encryptType.DEScrypt
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-f0-9]{16}$/) ? [
			this.encryptType.MySQL323,
			this.encryptType.DES_In_Oracle,
			this.encryptType.MD5_16,
			this.encryptType.Oracle_7_To_10g,
			this.encryptType.FNV_164,
			this.encryptType.CRC_64,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-z0-9\/.]{16}$/) ? [
			this.encryptType.Cisco_PIX_In_MD5,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^\([a-z0-9\/+]{20}\)$/) ? [
			this.encryptType.Lotus_Notes_Domino_6,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^_[a-z0-9\/.]{19}$/) ? [
			this.encryptType.BSDi_Crypt,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-f0-9]{24}$/) ? [
			this.encryptType.CRC_96_In_ZIP,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-z0-9\/.]{24}$/) ? [
			this.encryptType.Crypt16,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^(\$md2\$)?[a-f0-9]{32}$/) ? [
			this.encryptType.MD2,
		] : false;
	},
	idGroup6: function(str) {
		str += '';
		return str.match(/^[a-f0-9]{32}(:.+)?$/) ? [
			this.encryptType.MD5,
			this.encryptType.MD4,
			this.encryptType.Double_MD5,
			this.encryptType.LM,
			this.encryptType.RIPEMD_128,
			this.encryptType.Haval_128,
			this.encryptType.Tiger-128,
			this.encryptType.Skein-256(128),
			this.encryptType.Skein-512(128),
			this.encryptType.Lotus Notes/Domino 5,
			this.encryptType.Skype,
			this.encryptType.ZipMonster,
			this.encryptType.PrestaShop,
			this.encryptType.MD5_Variants,
			this.encryptType.HMAC-MD5 (key = $pass),
			this.encryptType.HMAC-MD5 (key = $salt),
		] : false;
	},
  


}



var encodeIdentify = function(str){

}

var encryptIdentify = function(str){

}

var 

var md5Identify = function(str){

}