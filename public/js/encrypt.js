let EncryptIdentify = {
    /**
     * 通用密文串类型检查，包括encode，encrypt，hash
     * 以准确度和精确度来换取hash类型数量
     * @param  {string} str 要检查的字符串
     * @return {object|boolean}     成功返回对象，失败返回false
     */
    identify: function(str, ...param) {
        // 多参数传参还未实现
        let password = str + '', resTmp, result = [];
        Object.keys(EncryptIdentify.encryptType).forEach(function(key){
            resTmp = EncryptIdentify.encryptType[key].checker(password);
            resTmp && (result = result.concat(EncryptIdentify.encryptType[key]));
        });
        return result;

        // 注意去除头尾的空白字符并提示
        // 检测非可见字符并提示，以免误判
        // return ...
    },


    /**
     * 加密/HASH类型定义
     * @type {Object}
     */
    encryptType: {
        /*
            type: 
                1 encode 
                2 encrypt 
                3 hash
                we must use encode / decode for every password string
            minR:
                minimum of required param number
            maxR:
                maximum of required param number
            name:
                the name
            checker:
                the function to check if it is
            solver:
                try to crack/decode/decrypt the string
            gen:
                try to hash/encode/encrypt the string
            ref:
                the extend reference to read
        */
        MD5: {
            type: 3,
            minR: 1,
            maxR: 1,
            name: 'md5',
            checker: function(str) {
                return str.match(/^([0-9a-f]{32}|[0-9A-F]{32})$/) ? true : false;
            },
            solver: function(str) {
                return str;
            },
            gen: function(str) {
                return str;
            }
        },
        MD5_Half: {
            type: 3,
            minR: 1,
            maxR: 1,
            name: 'md5 half',
            checker: function(str) {
                return str.match(/^([0-9a-f]{16}|[0-9A-F]{16})$/) ? true : false;
            },
        },
        base64_MIME: {
            type: 1,
            minR: 1,
            maxR: 3,
            name: 'base64 MIME',
            checker: function(str, t='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789+/', p='=') {
                if (str.length % 4 == 0) { // base64 MIME must be mod by 4
                    return str.match(new RegExp('^[' + t + ']+' + p + '{0,2}$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://zh.wikipedia.org/wiki/Base64'
        },
        base64_UTF7: {
            type: 1,
            minR: 1,
            maxR: 2,
            name: 'base64 UTF7',
            checker: function(str, t='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789+/') {
                return str.match(new RegExp('^[' + t + ']+$')) ? true : false;
            },
            ref: 'https://zh.wikipedia.org/wiki/Base64'
        },
        base64_IRCu: {
            type: 1,
            minR: 1,
            maxR: 3,
            name: 'base64 IRCu',
            checker: function(str, t='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789\\\[\\\]', p='=') {
                if (str.length % 4 == 0) { // standard base64, length  must be mod by 4
                    return str.match(new RegExp('^[' + t + ']+' + p + '{0,2}$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://zh.wikipedia.org/wiki/Base64'
        },
        base58: {
            type: 1,
            minR: 1,
            maxR: 2,
            name: 'base58',
            checker: function(str, t='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz') {
                return str.match(new RegExp('^[' + t + ']+$')) ? true : false;
            },
            ref: 'https://en.wikipedia.org/wiki/Base58'
        },
        base58_short: {
            type: 1,
            minR: 1,
            maxR: 2,
            name: 'base58 short URLs',
            checker: function(str, t='123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ') {
                return str.match(new RegExp('^[' + t + ']+$')) ? true : false;
            },
            ref: 'https://en.wikipedia.org/wiki/Base58'
        },
        base32: {
            type: 1,
            minR: 1,
            maxR: 3,
            name: 'base32',
            checker: function(str, t='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', p='=') {
                if (str.length % 8 == 0) {
                    return str.match(new RegExp('^[' + t + ']+' + p + '{0,6}$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://en.wikipedia.org/wiki/Base32'
        },
        base32_z: {
            type: 1,
            minR: 1,
            maxR: 3,
            name: 'z-base-32',
            checker: function(str, t='ybndrfg8ejkmcpqxot1uwisza345h769', p='=') {
                if (str.length % 8 == 0) {
                    return str.match(new RegExp('^[' + t + ']+' + p + '{0,6}$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://en.wikipedia.org/wiki/Base32'
        },
        base32_Crockford: {
            type: 1,
            minR: 1,
            maxR: 3,
            name: 'Crockford\'s Base32',
            checker: function(str, t='0123456789ABCDEFGHJKMNPQRSTVWXYZ', p='=') {
                if (str.length % 8 == 0) {
                    str = str.replace(/0o/ig, '0').replace(/1il/ig, '1').toUpperCase();
                    return str.match(new RegExp('^[' + t + ']+' + p + '{0,6}$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://en.wikipedia.org/wiki/Base32'
        },
        base16: {
            type: 1,
            minR: 1,
            maxR: 2,
            name: 'base16(hex)',
            checker: function(str, t='0123456789ABCDEF') {
                if (str.length % 2 == 0) { // standard hex length must be multiple of 2, from 00 to ff for each character
                    return str.match(new RegExp('^[' + t + ']+' + '$')) ? true : false;
                }else{
                    return false;
                }
            },
            ref: 'https://en.wikipedia.org/wiki/Base16'
        },
    },


}


/*
let encodeIdentify = function(str){

}

let encryptIdentify = function(str){

}

let md5Identify = function(str){

}
*/