const monocypher_addon = require('./build/Release/monocypher');
function checkArgs(arg, length) {
    if (Buffer.isBuffer(arg)) {
        if (arg.length === length || length === null) {
            return arg;
        } else {
            return false;
        }
    } else if (Array.isArray(arg)) {
        if (arg.length === length || length === null) {
            return Buffer.from(arg);
        } else {
            return false;
        }
    } else if (typeof arg === "string") {
        let buf = Buffer.from(arg, 'hex')
        if (buf.length === length || length === null) {
            return buf;
        } else {
            return false;
        }
    } else {
        return undefined;
    }
}

module.exports = {
    key_exchange_public_key: function (key) {
        let buff = checkArgs(key, 32);
        if (buff) {
            return monocypher_addon.key_exchange_public_key(buff);
        } else {
            if (buff === undefined) {
                throw new Error("SECRET KEY type not supported");
            } else {
                throw new Error("Invalid SECRET KEY length");
            }
        }
    },

    signature: function (secretKey, pubKey, message) {
        let sk = checkArgs(secretKey, 32);
        if (sk === undefined) {
            throw new Error("SECRET KEY type not supported");
        } else if (!sk) {
            throw new Error("Invalid SECRET KEY length");
        }
        let pk = checkArgs(pubKey, 32);
        if (pk === undefined) {
            throw new Error("PUBLIC KEY type not supported");
        } else if (!pk) {
            throw new Error("Invalid PUBLIC KEY length");
        }
        let sign_message = checkArgs(message, null);
        if (sign_message === undefined) {
            throw new Error("MESSAGE type not supported");
        }

        return monocypher_addon.sign(sk, pk, sign_message);
    },

    key_exchange: function (secretKey, theirPubKey) {
        let sk = checkArgs(secretKey, 32);
        if (sk === undefined) {
            throw new Error("SECRET KEY type not supported");
        } else if (!sk) {
            throw new Error("Invalid SECRET KEY length");
        }
        let pk = checkArgs(theirPubKey, 32);
        if (pk === undefined) {
            throw new Error("THEIR PUBLIC KEY type not supported");
        } else if (!pk) {
            throw new Error("Invalid THEIR PUBLIC KEY length");
        }

        return monocypher_addon.key_exchange(sk, pk);
    },

    get_random_bytes: function (length) {
        if (length > 0) {
            let buffer = Buffer.alloc(length);
            for(let i = 0; i < length; i++){
                buffer[i] = Math.random()*200;
            }
            return buffer;
        } else {
            throw new Error("Invalid length");
        }
    },
};