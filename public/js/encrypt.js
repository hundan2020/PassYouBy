let EncryptIdentify = {
    /*
        代码参考了 https://github.com/psypanda/hashID/blob/master/hashid.py
    */

    /**
     * 通用密文串类型检查，包括encode，encrypt，hash
     * 以准确度和精确度来换取hash类型数量
     * @param  {string} str 要检查的字符串
     * @return {object|boolean}     成功返回对象，失败返回false
     */
    identify: function(str) {
        // 先写个demo，能用就行，后面再慢慢改
        let password = str + '', todo, resTmp, result = [];
        let addslashes = function(string){
            return string.replace(/\\/g, '\\\\').replace(/'/g, '\\\'');
        }
        for (let i in this.idGroup) {
            todo = 'this.idGroup[' + i + '](\'' + addslashes(password) + '\')';
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
                }
                return false;
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
            checker: function(str, t='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789[]', p='=') {
                return str.match(new RegExp('^[' + t + ']+' + p + '{0,2}$')) ? true : false;
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
                return str.match(new RegExp('^[' + t + ']+' + p + '{0,2}$')) ? true : false;
            },
            ref: 'https://en.wikipedia.org/wiki/Base32'
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