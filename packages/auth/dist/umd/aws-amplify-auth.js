(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory(require("aws_amplify_core"));
	else if(typeof define === 'function' && define.amd)
		define("aws_amplify_auth", ["aws_amplify_core"], factory);
	else if(typeof exports === 'object')
		exports["aws_amplify_auth"] = factory(require("aws_amplify_core"));
	else
		root["aws_amplify_auth"] = factory(root["aws_amplify_core"]);
})(this, (__WEBPACK_EXTERNAL_MODULE__aws_amplify_core__) => {
return /******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "../../node_modules/@aws-crypto/sha256-js/build/RawSha256.js":
/*!*******************************************************************!*\
  !*** ../../node_modules/@aws-crypto/sha256-js/build/RawSha256.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RawSha256 = void 0;
var constants_1 = __webpack_require__(/*! ./constants */ "../../node_modules/@aws-crypto/sha256-js/build/constants.js");
/**
 * @internal
 */
var RawSha256 = /** @class */ (function () {
    function RawSha256() {
        this.state = Int32Array.from(constants_1.INIT);
        this.temp = new Int32Array(64);
        this.buffer = new Uint8Array(64);
        this.bufferLength = 0;
        this.bytesHashed = 0;
        /**
         * @internal
         */
        this.finished = false;
    }
    RawSha256.prototype.update = function (data) {
        if (this.finished) {
            throw new Error("Attempted to update an already finished hash.");
        }
        var position = 0;
        var byteLength = data.byteLength;
        this.bytesHashed += byteLength;
        if (this.bytesHashed * 8 > constants_1.MAX_HASHABLE_LENGTH) {
            throw new Error("Cannot hash more than 2^53 - 1 bits");
        }
        while (byteLength > 0) {
            this.buffer[this.bufferLength++] = data[position++];
            byteLength--;
            if (this.bufferLength === constants_1.BLOCK_SIZE) {
                this.hashBuffer();
                this.bufferLength = 0;
            }
        }
    };
    RawSha256.prototype.digest = function () {
        if (!this.finished) {
            var bitsHashed = this.bytesHashed * 8;
            var bufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
            var undecoratedLength = this.bufferLength;
            bufferView.setUint8(this.bufferLength++, 0x80);
            // Ensure the final block has enough room for the hashed length
            if (undecoratedLength % constants_1.BLOCK_SIZE >= constants_1.BLOCK_SIZE - 8) {
                for (var i = this.bufferLength; i < constants_1.BLOCK_SIZE; i++) {
                    bufferView.setUint8(i, 0);
                }
                this.hashBuffer();
                this.bufferLength = 0;
            }
            for (var i = this.bufferLength; i < constants_1.BLOCK_SIZE - 8; i++) {
                bufferView.setUint8(i, 0);
            }
            bufferView.setUint32(constants_1.BLOCK_SIZE - 8, Math.floor(bitsHashed / 0x100000000), true);
            bufferView.setUint32(constants_1.BLOCK_SIZE - 4, bitsHashed);
            this.hashBuffer();
            this.finished = true;
        }
        // The value in state is little-endian rather than big-endian, so flip
        // each word into a new Uint8Array
        var out = new Uint8Array(constants_1.DIGEST_LENGTH);
        for (var i = 0; i < 8; i++) {
            out[i * 4] = (this.state[i] >>> 24) & 0xff;
            out[i * 4 + 1] = (this.state[i] >>> 16) & 0xff;
            out[i * 4 + 2] = (this.state[i] >>> 8) & 0xff;
            out[i * 4 + 3] = (this.state[i] >>> 0) & 0xff;
        }
        return out;
    };
    RawSha256.prototype.hashBuffer = function () {
        var _a = this, buffer = _a.buffer, state = _a.state;
        var state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3], state4 = state[4], state5 = state[5], state6 = state[6], state7 = state[7];
        for (var i = 0; i < constants_1.BLOCK_SIZE; i++) {
            if (i < 16) {
                this.temp[i] =
                    ((buffer[i * 4] & 0xff) << 24) |
                        ((buffer[i * 4 + 1] & 0xff) << 16) |
                        ((buffer[i * 4 + 2] & 0xff) << 8) |
                        (buffer[i * 4 + 3] & 0xff);
            }
            else {
                var u = this.temp[i - 2];
                var t1_1 = ((u >>> 17) | (u << 15)) ^ ((u >>> 19) | (u << 13)) ^ (u >>> 10);
                u = this.temp[i - 15];
                var t2_1 = ((u >>> 7) | (u << 25)) ^ ((u >>> 18) | (u << 14)) ^ (u >>> 3);
                this.temp[i] =
                    ((t1_1 + this.temp[i - 7]) | 0) + ((t2_1 + this.temp[i - 16]) | 0);
            }
            var t1 = ((((((state4 >>> 6) | (state4 << 26)) ^
                ((state4 >>> 11) | (state4 << 21)) ^
                ((state4 >>> 25) | (state4 << 7))) +
                ((state4 & state5) ^ (~state4 & state6))) |
                0) +
                ((state7 + ((constants_1.KEY[i] + this.temp[i]) | 0)) | 0)) |
                0;
            var t2 = ((((state0 >>> 2) | (state0 << 30)) ^
                ((state0 >>> 13) | (state0 << 19)) ^
                ((state0 >>> 22) | (state0 << 10))) +
                ((state0 & state1) ^ (state0 & state2) ^ (state1 & state2))) |
                0;
            state7 = state6;
            state6 = state5;
            state5 = state4;
            state4 = (state3 + t1) | 0;
            state3 = state2;
            state2 = state1;
            state1 = state0;
            state0 = (t1 + t2) | 0;
        }
        state[0] += state0;
        state[1] += state1;
        state[2] += state2;
        state[3] += state3;
        state[4] += state4;
        state[5] += state5;
        state[6] += state6;
        state[7] += state7;
    };
    return RawSha256;
}());
exports.RawSha256 = RawSha256;
//# sourceMappingURL=RawSha256.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/sha256-js/build/constants.js":
/*!*******************************************************************!*\
  !*** ../../node_modules/@aws-crypto/sha256-js/build/constants.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MAX_HASHABLE_LENGTH = exports.INIT = exports.KEY = exports.DIGEST_LENGTH = exports.BLOCK_SIZE = void 0;
/**
 * @internal
 */
exports.BLOCK_SIZE = 64;
/**
 * @internal
 */
exports.DIGEST_LENGTH = 32;
/**
 * @internal
 */
exports.KEY = new Uint32Array([
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
]);
/**
 * @internal
 */
exports.INIT = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
];
/**
 * @internal
 */
exports.MAX_HASHABLE_LENGTH = Math.pow(2, 53) - 1;
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/sha256-js/build/index.js":
/*!***************************************************************!*\
  !*** ../../node_modules/@aws-crypto/sha256-js/build/index.js ***!
  \***************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
var tslib_1 = __webpack_require__(/*! tslib */ "../../node_modules/@aws-crypto/sha256-js/node_modules/tslib/tslib.es6.js");
tslib_1.__exportStar(__webpack_require__(/*! ./jsSha256 */ "../../node_modules/@aws-crypto/sha256-js/build/jsSha256.js"), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/sha256-js/build/jsSha256.js":
/*!******************************************************************!*\
  !*** ../../node_modules/@aws-crypto/sha256-js/build/jsSha256.js ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Sha256 = void 0;
var tslib_1 = __webpack_require__(/*! tslib */ "../../node_modules/@aws-crypto/sha256-js/node_modules/tslib/tslib.es6.js");
var constants_1 = __webpack_require__(/*! ./constants */ "../../node_modules/@aws-crypto/sha256-js/build/constants.js");
var RawSha256_1 = __webpack_require__(/*! ./RawSha256 */ "../../node_modules/@aws-crypto/sha256-js/build/RawSha256.js");
var util_1 = __webpack_require__(/*! @aws-crypto/util */ "../../node_modules/@aws-crypto/util/build/index.js");
var Sha256 = /** @class */ (function () {
    function Sha256(secret) {
        this.secret = secret;
        this.hash = new RawSha256_1.RawSha256();
        this.reset();
    }
    Sha256.prototype.update = function (toHash) {
        if ((0, util_1.isEmptyData)(toHash) || this.error) {
            return;
        }
        try {
            this.hash.update((0, util_1.convertToBuffer)(toHash));
        }
        catch (e) {
            this.error = e;
        }
    };
    /* This synchronous method keeps compatibility
     * with the v2 aws-sdk.
     */
    Sha256.prototype.digestSync = function () {
        if (this.error) {
            throw this.error;
        }
        if (this.outer) {
            if (!this.outer.finished) {
                this.outer.update(this.hash.digest());
            }
            return this.outer.digest();
        }
        return this.hash.digest();
    };
    /* The underlying digest method here is synchronous.
     * To keep the same interface with the other hash functions
     * the default is to expose this as an async method.
     * However, it can sometimes be useful to have a sync method.
     */
    Sha256.prototype.digest = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            return tslib_1.__generator(this, function (_a) {
                return [2 /*return*/, this.digestSync()];
            });
        });
    };
    Sha256.prototype.reset = function () {
        this.hash = new RawSha256_1.RawSha256();
        if (this.secret) {
            this.outer = new RawSha256_1.RawSha256();
            var inner = bufferFromSecret(this.secret);
            var outer = new Uint8Array(constants_1.BLOCK_SIZE);
            outer.set(inner);
            for (var i = 0; i < constants_1.BLOCK_SIZE; i++) {
                inner[i] ^= 0x36;
                outer[i] ^= 0x5c;
            }
            this.hash.update(inner);
            this.outer.update(outer);
            // overwrite the copied key in memory
            for (var i = 0; i < inner.byteLength; i++) {
                inner[i] = 0;
            }
        }
    };
    return Sha256;
}());
exports.Sha256 = Sha256;
function bufferFromSecret(secret) {
    var input = (0, util_1.convertToBuffer)(secret);
    if (input.byteLength > constants_1.BLOCK_SIZE) {
        var bufferHash = new RawSha256_1.RawSha256();
        bufferHash.update(input);
        input = bufferHash.digest();
    }
    var buffer = new Uint8Array(constants_1.BLOCK_SIZE);
    buffer.set(input);
    return buffer;
}
//# sourceMappingURL=jsSha256.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/sha256-js/node_modules/tslib/tslib.es6.js":
/*!********************************************************************************!*\
  !*** ../../node_modules/@aws-crypto/sha256-js/node_modules/tslib/tslib.es6.js ***!
  \********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   __assign: () => (/* binding */ __assign),
/* harmony export */   __asyncDelegator: () => (/* binding */ __asyncDelegator),
/* harmony export */   __asyncGenerator: () => (/* binding */ __asyncGenerator),
/* harmony export */   __asyncValues: () => (/* binding */ __asyncValues),
/* harmony export */   __await: () => (/* binding */ __await),
/* harmony export */   __awaiter: () => (/* binding */ __awaiter),
/* harmony export */   __classPrivateFieldGet: () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   __classPrivateFieldSet: () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   __createBinding: () => (/* binding */ __createBinding),
/* harmony export */   __decorate: () => (/* binding */ __decorate),
/* harmony export */   __exportStar: () => (/* binding */ __exportStar),
/* harmony export */   __extends: () => (/* binding */ __extends),
/* harmony export */   __generator: () => (/* binding */ __generator),
/* harmony export */   __importDefault: () => (/* binding */ __importDefault),
/* harmony export */   __importStar: () => (/* binding */ __importStar),
/* harmony export */   __makeTemplateObject: () => (/* binding */ __makeTemplateObject),
/* harmony export */   __metadata: () => (/* binding */ __metadata),
/* harmony export */   __param: () => (/* binding */ __param),
/* harmony export */   __read: () => (/* binding */ __read),
/* harmony export */   __rest: () => (/* binding */ __rest),
/* harmony export */   __spread: () => (/* binding */ __spread),
/* harmony export */   __spreadArrays: () => (/* binding */ __spreadArrays),
/* harmony export */   __values: () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "../../node_modules/@aws-crypto/util/build/convertToBuffer.js":
/*!********************************************************************!*\
  !*** ../../node_modules/@aws-crypto/util/build/convertToBuffer.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.convertToBuffer = void 0;
var util_utf8_browser_1 = __webpack_require__(/*! @aws-sdk/util-utf8-browser */ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/index.js");
// Quick polyfill
var fromUtf8 = typeof Buffer !== "undefined" && Buffer.from
    ? function (input) { return Buffer.from(input, "utf8"); }
    : util_utf8_browser_1.fromUtf8;
function convertToBuffer(data) {
    // Already a Uint8, do nothing
    if (data instanceof Uint8Array)
        return data;
    if (typeof data === "string") {
        return fromUtf8(data);
    }
    if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    }
    return new Uint8Array(data);
}
exports.convertToBuffer = convertToBuffer;
//# sourceMappingURL=convertToBuffer.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/util/build/index.js":
/*!**********************************************************!*\
  !*** ../../node_modules/@aws-crypto/util/build/index.js ***!
  \**********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.uint32ArrayFrom = exports.numToUint8 = exports.isEmptyData = exports.convertToBuffer = void 0;
var convertToBuffer_1 = __webpack_require__(/*! ./convertToBuffer */ "../../node_modules/@aws-crypto/util/build/convertToBuffer.js");
Object.defineProperty(exports, "convertToBuffer", ({ enumerable: true, get: function () { return convertToBuffer_1.convertToBuffer; } }));
var isEmptyData_1 = __webpack_require__(/*! ./isEmptyData */ "../../node_modules/@aws-crypto/util/build/isEmptyData.js");
Object.defineProperty(exports, "isEmptyData", ({ enumerable: true, get: function () { return isEmptyData_1.isEmptyData; } }));
var numToUint8_1 = __webpack_require__(/*! ./numToUint8 */ "../../node_modules/@aws-crypto/util/build/numToUint8.js");
Object.defineProperty(exports, "numToUint8", ({ enumerable: true, get: function () { return numToUint8_1.numToUint8; } }));
var uint32ArrayFrom_1 = __webpack_require__(/*! ./uint32ArrayFrom */ "../../node_modules/@aws-crypto/util/build/uint32ArrayFrom.js");
Object.defineProperty(exports, "uint32ArrayFrom", ({ enumerable: true, get: function () { return uint32ArrayFrom_1.uint32ArrayFrom; } }));
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/util/build/isEmptyData.js":
/*!****************************************************************!*\
  !*** ../../node_modules/@aws-crypto/util/build/isEmptyData.js ***!
  \****************************************************************/
/***/ ((__unused_webpack_module, exports) => {


// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isEmptyData = void 0;
function isEmptyData(data) {
    if (typeof data === "string") {
        return data.length === 0;
    }
    return data.byteLength === 0;
}
exports.isEmptyData = isEmptyData;
//# sourceMappingURL=isEmptyData.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/util/build/numToUint8.js":
/*!***************************************************************!*\
  !*** ../../node_modules/@aws-crypto/util/build/numToUint8.js ***!
  \***************************************************************/
/***/ ((__unused_webpack_module, exports) => {


// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.numToUint8 = void 0;
function numToUint8(num) {
    return new Uint8Array([
        (num & 0xff000000) >> 24,
        (num & 0x00ff0000) >> 16,
        (num & 0x0000ff00) >> 8,
        num & 0x000000ff,
    ]);
}
exports.numToUint8 = numToUint8;
//# sourceMappingURL=numToUint8.js.map

/***/ }),

/***/ "../../node_modules/@aws-crypto/util/build/uint32ArrayFrom.js":
/*!********************************************************************!*\
  !*** ../../node_modules/@aws-crypto/util/build/uint32ArrayFrom.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, exports) => {


// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.uint32ArrayFrom = void 0;
// IE 11 does not support Array.from, so we do it manually
function uint32ArrayFrom(a_lookUpTable) {
    if (!Uint32Array.from) {
        var return_array = new Uint32Array(a_lookUpTable.length);
        var a_index = 0;
        while (a_index < a_lookUpTable.length) {
            return_array[a_index] = a_lookUpTable[a_index];
            a_index += 1;
        }
        return return_array;
    }
    return Uint32Array.from(a_lookUpTable);
}
exports.uint32ArrayFrom = uint32ArrayFrom;
//# sourceMappingURL=uint32ArrayFrom.js.map

/***/ }),

/***/ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/index.js":
/*!**********************************************************************!*\
  !*** ../../node_modules/@aws-sdk/util-utf8-browser/dist-es/index.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fromUtf8: () => (/* binding */ fromUtf8),
/* harmony export */   toUtf8: () => (/* binding */ toUtf8)
/* harmony export */ });
/* harmony import */ var _pureJs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./pureJs */ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/pureJs.js");
/* harmony import */ var _whatwgEncodingApi__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./whatwgEncodingApi */ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/whatwgEncodingApi.js");


const fromUtf8 = (input) => typeof TextEncoder === "function" ? (0,_whatwgEncodingApi__WEBPACK_IMPORTED_MODULE_1__.fromUtf8)(input) : (0,_pureJs__WEBPACK_IMPORTED_MODULE_0__.fromUtf8)(input);
const toUtf8 = (input) => typeof TextDecoder === "function" ? (0,_whatwgEncodingApi__WEBPACK_IMPORTED_MODULE_1__.toUtf8)(input) : (0,_pureJs__WEBPACK_IMPORTED_MODULE_0__.toUtf8)(input);


/***/ }),

/***/ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/pureJs.js":
/*!***********************************************************************!*\
  !*** ../../node_modules/@aws-sdk/util-utf8-browser/dist-es/pureJs.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fromUtf8: () => (/* binding */ fromUtf8),
/* harmony export */   toUtf8: () => (/* binding */ toUtf8)
/* harmony export */ });
const fromUtf8 = (input) => {
    const bytes = [];
    for (let i = 0, len = input.length; i < len; i++) {
        const value = input.charCodeAt(i);
        if (value < 0x80) {
            bytes.push(value);
        }
        else if (value < 0x800) {
            bytes.push((value >> 6) | 0b11000000, (value & 0b111111) | 0b10000000);
        }
        else if (i + 1 < input.length && (value & 0xfc00) === 0xd800 && (input.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
            const surrogatePair = 0x10000 + ((value & 0b1111111111) << 10) + (input.charCodeAt(++i) & 0b1111111111);
            bytes.push((surrogatePair >> 18) | 0b11110000, ((surrogatePair >> 12) & 0b111111) | 0b10000000, ((surrogatePair >> 6) & 0b111111) | 0b10000000, (surrogatePair & 0b111111) | 0b10000000);
        }
        else {
            bytes.push((value >> 12) | 0b11100000, ((value >> 6) & 0b111111) | 0b10000000, (value & 0b111111) | 0b10000000);
        }
    }
    return Uint8Array.from(bytes);
};
const toUtf8 = (input) => {
    let decoded = "";
    for (let i = 0, len = input.length; i < len; i++) {
        const byte = input[i];
        if (byte < 0x80) {
            decoded += String.fromCharCode(byte);
        }
        else if (0b11000000 <= byte && byte < 0b11100000) {
            const nextByte = input[++i];
            decoded += String.fromCharCode(((byte & 0b11111) << 6) | (nextByte & 0b111111));
        }
        else if (0b11110000 <= byte && byte < 0b101101101) {
            const surrogatePair = [byte, input[++i], input[++i], input[++i]];
            const encoded = "%" + surrogatePair.map((byteValue) => byteValue.toString(16)).join("%");
            decoded += decodeURIComponent(encoded);
        }
        else {
            decoded += String.fromCharCode(((byte & 0b1111) << 12) | ((input[++i] & 0b111111) << 6) | (input[++i] & 0b111111));
        }
    }
    return decoded;
};


/***/ }),

/***/ "../../node_modules/@aws-sdk/util-utf8-browser/dist-es/whatwgEncodingApi.js":
/*!**********************************************************************************!*\
  !*** ../../node_modules/@aws-sdk/util-utf8-browser/dist-es/whatwgEncodingApi.js ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fromUtf8: () => (/* binding */ fromUtf8),
/* harmony export */   toUtf8: () => (/* binding */ toUtf8)
/* harmony export */ });
function fromUtf8(input) {
    return new TextEncoder().encode(input);
}
function toUtf8(input) {
    return new TextDecoder("utf-8").decode(input);
}


/***/ }),

/***/ "@aws-amplify/core":
/*!***********************************!*\
  !*** external "aws_amplify_core" ***!
  \***********************************/
/***/ ((module) => {

module.exports = __WEBPACK_EXTERNAL_MODULE__aws_amplify_core__;

/***/ }),

/***/ "./dist/esm/Errors.mjs":
/*!*****************************!*\
  !*** ./dist/esm/Errors.mjs ***!
  \*****************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthError: () => (/* binding */ AuthError),
/* harmony export */   NoUserPoolError: () => (/* binding */ NoUserPoolError),
/* harmony export */   authErrorMessages: () => (/* binding */ authErrorMessages)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./common/AuthErrorStrings.mjs */ "./dist/esm/common/AuthErrorStrings.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const logger = new _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.ConsoleLogger('AuthError');
class AuthError extends Error {
    constructor(type) {
        const { message, log } = authErrorMessages[type];
        super(message);
        // Hack for making the custom error class work when transpiled to es5
        // TODO: Delete the following 2 lines after we change the build target to >= es2015
        this.constructor = AuthError;
        Object.setPrototypeOf(this, AuthError.prototype);
        this.name = 'AuthError';
        this.log = log || message;
        logger.error(this.log);
    }
}
class NoUserPoolError extends AuthError {
    constructor(type) {
        super(type);
        // Hack for making the custom error class work when transpiled to es5
        // TODO: Delete the following 2 lines after we change the build target to >= es2015
        this.constructor = NoUserPoolError;
        Object.setPrototypeOf(this, NoUserPoolError.prototype);
        this.name = 'NoUserPoolError';
    }
}
const authErrorMessages = {
    oauthSignInError: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.OAUTH_ERROR,
        log: 'Make sure Cognito Hosted UI has been configured correctly',
    },
    noConfig: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.DEFAULT_MSG,
        log: `
            Error: Amplify has not been configured correctly.
            This error is typically caused by one of the following scenarios:

            1. Make sure you're passing the awsconfig object to Amplify.configure() in your app's entry point
                See https://aws-amplify.github.io/docs/js/authentication#configure-your-app for more information
            
            2. There might be multiple conflicting versions of amplify packages in your node_modules.
				Refer to our docs site for help upgrading Amplify packages (https://docs.amplify.aws/lib/troubleshooting/upgrading/q/platform/js)
        `,
    },
    missingAuthConfig: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.DEFAULT_MSG,
        log: `
            Error: Amplify has not been configured correctly. 
            The configuration object is missing required auth properties.
            This error is typically caused by one of the following scenarios:

            1. Did you run \`amplify push\` after adding auth via \`amplify add auth\`?
                See https://aws-amplify.github.io/docs/js/authentication#amplify-project-setup for more information

            2. This could also be caused by multiple conflicting versions of amplify packages, see (https://docs.amplify.aws/lib/troubleshooting/upgrading/q/platform/js) for help upgrading Amplify packages.
        `,
    },
    emptyUsername: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.EMPTY_USERNAME,
    },
    // TODO: should include a list of valid sign-in types
    invalidUsername: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.INVALID_USERNAME,
    },
    emptyPassword: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.EMPTY_PASSWORD,
    },
    emptyCode: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.EMPTY_CODE,
    },
    signUpError: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.SIGN_UP_ERROR,
        log: 'The first parameter should either be non-null string or object',
    },
    noMFA: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.NO_MFA,
    },
    invalidMFA: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.INVALID_MFA,
    },
    emptyChallengeResponse: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.EMPTY_CHALLENGE,
    },
    noUserSession: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.NO_USER_SESSION,
    },
    deviceConfig: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.DEVICE_CONFIG,
    },
    networkError: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.NETWORK_ERROR,
    },
    autoSignInError: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.AUTOSIGNIN_ERROR,
    },
    default: {
        message: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorStrings.DEFAULT_MSG,
    },
};


//# sourceMappingURL=Errors.mjs.map


/***/ }),

/***/ "./dist/esm/common/AuthErrorStrings.mjs":
/*!**********************************************!*\
  !*** ./dist/esm/common/AuthErrorStrings.mjs ***!
  \**********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthErrorCodes: () => (/* binding */ AuthErrorCodes),
/* harmony export */   AuthErrorStrings: () => (/* binding */ AuthErrorStrings),
/* harmony export */   validationErrorMap: () => (/* binding */ validationErrorMap)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const validationErrorMap = {
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyChallengeResponse]: {
        message: 'challengeResponse is required to confirmSignIn',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmResetPasswordUsername]: {
        message: 'username is required to confirmResetPassword',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmSignUpCode]: {
        message: 'code is required to confirmSignUp',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmSignUpUsername]: {
        message: 'username is required to confirmSignUp',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmResetPasswordConfirmationCode]: {
        message: 'confirmationCode is required to confirmResetPassword',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmResetPasswordNewPassword]: {
        message: 'newPassword is required to confirmResetPassword',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyResendSignUpCodeUsername]: {
        message: 'username is required to confirmSignUp',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyResetPasswordUsername]: {
        message: 'username is required to resetPassword',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptySignInPassword]: {
        message: 'password is required to signIn',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptySignInUsername]: {
        message: 'username is required to signIn',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptySignUpPassword]: {
        message: 'password is required to signUp',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptySignUpUsername]: {
        message: 'username is required to signUp',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.CustomAuthSignInPassword]: {
        message: 'A password is not needed when signing in with CUSTOM_WITHOUT_SRP',
        recoverySuggestion: 'Do not include a password in your signIn call.',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.IncorrectMFAMethod]: {
        message: 'Incorrect MFA method was chosen. It should be either SMS or TOTP',
        recoverySuggestion: 'Try to pass TOTP or SMS as the challengeResponse',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyVerifyTOTPSetupCode]: {
        message: 'code is required to verifyTotpSetup',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyUpdatePassword]: {
        message: 'oldPassword and newPassword are required to changePassword',
    },
    [_errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthValidationErrorCode.EmptyConfirmUserAttributeCode]: {
        message: 'confirmation code is required to confirmUserAttribute',
    },
};
// TODO: delete this code when the Auth class is removed.
var AuthErrorStrings;
(function (AuthErrorStrings) {
    AuthErrorStrings["DEFAULT_MSG"] = "Authentication Error";
    AuthErrorStrings["EMPTY_EMAIL"] = "Email cannot be empty";
    AuthErrorStrings["EMPTY_PHONE"] = "Phone number cannot be empty";
    AuthErrorStrings["EMPTY_USERNAME"] = "Username cannot be empty";
    AuthErrorStrings["INVALID_USERNAME"] = "The username should either be a string or one of the sign in types";
    AuthErrorStrings["EMPTY_PASSWORD"] = "Password cannot be empty";
    AuthErrorStrings["EMPTY_CODE"] = "Confirmation code cannot be empty";
    AuthErrorStrings["SIGN_UP_ERROR"] = "Error creating account";
    AuthErrorStrings["NO_MFA"] = "No valid MFA method provided";
    AuthErrorStrings["INVALID_MFA"] = "Invalid MFA type";
    AuthErrorStrings["EMPTY_CHALLENGE"] = "Challenge response cannot be empty";
    AuthErrorStrings["NO_USER_SESSION"] = "Failed to get the session because the user is empty";
    AuthErrorStrings["NETWORK_ERROR"] = "Network Error";
    AuthErrorStrings["DEVICE_CONFIG"] = "Device tracking has not been configured in this User Pool";
    AuthErrorStrings["AUTOSIGNIN_ERROR"] = "Please use your credentials to sign in";
    AuthErrorStrings["OAUTH_ERROR"] = "Couldn't finish OAuth flow, check your User Pool HostedUI settings";
})(AuthErrorStrings || (AuthErrorStrings = {}));
var AuthErrorCodes;
(function (AuthErrorCodes) {
    AuthErrorCodes["SignInException"] = "SignInException";
    AuthErrorCodes["OAuthSignInError"] = "OAuthSignInException";
})(AuthErrorCodes || (AuthErrorCodes = {}));


//# sourceMappingURL=AuthErrorStrings.mjs.map


/***/ }),

/***/ "./dist/esm/errors/AuthError.mjs":
/*!***************************************!*\
  !*** ./dist/esm/errors/AuthError.mjs ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthError: () => (/* binding */ AuthError)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/errors/AmplifyError.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
class AuthError extends _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.AmplifyError {
    constructor(params) {
        super(params);
        // Hack for making the custom error class work when transpiled to es5
        // TODO: Delete the following 2 lines after we change the build target to >= es2015
        this.constructor = AuthError;
        Object.setPrototypeOf(this, AuthError.prototype);
    }
}


//# sourceMappingURL=AuthError.mjs.map


/***/ }),

/***/ "./dist/esm/errors/constants.mjs":
/*!***************************************!*\
  !*** ./dist/esm/errors/constants.mjs ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AUTO_SIGN_IN_EXCEPTION: () => (/* binding */ AUTO_SIGN_IN_EXCEPTION),
/* harmony export */   DEVICE_METADATA_NOT_FOUND_EXCEPTION: () => (/* binding */ DEVICE_METADATA_NOT_FOUND_EXCEPTION),
/* harmony export */   INVALID_ORIGIN_EXCEPTION: () => (/* binding */ INVALID_ORIGIN_EXCEPTION),
/* harmony export */   INVALID_REDIRECT_EXCEPTION: () => (/* binding */ INVALID_REDIRECT_EXCEPTION),
/* harmony export */   OAUTH_SIGNOUT_EXCEPTION: () => (/* binding */ OAUTH_SIGNOUT_EXCEPTION),
/* harmony export */   TOKEN_REFRESH_EXCEPTION: () => (/* binding */ TOKEN_REFRESH_EXCEPTION),
/* harmony export */   USER_ALREADY_AUTHENTICATED_EXCEPTION: () => (/* binding */ USER_ALREADY_AUTHENTICATED_EXCEPTION),
/* harmony export */   USER_UNAUTHENTICATED_EXCEPTION: () => (/* binding */ USER_UNAUTHENTICATED_EXCEPTION),
/* harmony export */   invalidOriginException: () => (/* binding */ invalidOriginException),
/* harmony export */   invalidRedirectException: () => (/* binding */ invalidRedirectException)
/* harmony export */ });
/* harmony import */ var _AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const USER_UNAUTHENTICATED_EXCEPTION = 'UserUnAuthenticatedException';
const USER_ALREADY_AUTHENTICATED_EXCEPTION = 'UserAlreadyAuthenticatedException';
const DEVICE_METADATA_NOT_FOUND_EXCEPTION = 'DeviceMetadataNotFoundException';
const AUTO_SIGN_IN_EXCEPTION = 'AutoSignInException';
const INVALID_REDIRECT_EXCEPTION = 'InvalidRedirectException';
const invalidRedirectException = new _AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
    name: INVALID_REDIRECT_EXCEPTION,
    message: 'signInRedirect or signOutRedirect had an invalid format or was not found.',
    recoverySuggestion: 'Please make sure the signIn/Out redirect in your oauth config is valid.',
});
const INVALID_ORIGIN_EXCEPTION = 'InvalidOriginException';
const invalidOriginException = new _AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
    name: INVALID_ORIGIN_EXCEPTION,
    message: 'redirect is coming from a different origin. The oauth flow needs to be initiated from the same origin',
    recoverySuggestion: 'Please call signInWithRedirect from the same origin.',
});
const OAUTH_SIGNOUT_EXCEPTION = 'OAuthSignOutException';
const TOKEN_REFRESH_EXCEPTION = 'TokenRefreshException';


//# sourceMappingURL=constants.mjs.map


/***/ }),

/***/ "./dist/esm/errors/types/validation.mjs":
/*!**********************************************!*\
  !*** ./dist/esm/errors/types/validation.mjs ***!
  \**********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthValidationErrorCode: () => (/* binding */ AuthValidationErrorCode)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var AuthValidationErrorCode;
(function (AuthValidationErrorCode) {
    AuthValidationErrorCode["EmptySignInUsername"] = "EmptySignInUsername";
    AuthValidationErrorCode["EmptySignInPassword"] = "EmptySignInPassword";
    AuthValidationErrorCode["CustomAuthSignInPassword"] = "CustomAuthSignInPassword";
    AuthValidationErrorCode["EmptySignUpUsername"] = "EmptySignUpUsername";
    AuthValidationErrorCode["EmptySignUpPassword"] = "EmptySignUpPassword";
    AuthValidationErrorCode["EmptyConfirmSignUpUsername"] = "EmptyConfirmSignUpUsername";
    AuthValidationErrorCode["EmptyConfirmSignUpCode"] = "EmptyConfirmSignUpCode";
    AuthValidationErrorCode["EmptyResendSignUpCodeUsername"] = "EmptyresendSignUpCodeUsername";
    AuthValidationErrorCode["EmptyChallengeResponse"] = "EmptyChallengeResponse";
    AuthValidationErrorCode["EmptyConfirmResetPasswordUsername"] = "EmptyConfirmResetPasswordUsername";
    AuthValidationErrorCode["EmptyConfirmResetPasswordNewPassword"] = "EmptyConfirmResetPasswordNewPassword";
    AuthValidationErrorCode["EmptyConfirmResetPasswordConfirmationCode"] = "EmptyConfirmResetPasswordConfirmationCode";
    AuthValidationErrorCode["EmptyResetPasswordUsername"] = "EmptyResetPasswordUsername";
    AuthValidationErrorCode["EmptyVerifyTOTPSetupCode"] = "EmptyVerifyTOTPSetupCode";
    AuthValidationErrorCode["EmptyConfirmUserAttributeCode"] = "EmptyConfirmUserAttributeCode";
    AuthValidationErrorCode["IncorrectMFAMethod"] = "IncorrectMFAMethod";
    AuthValidationErrorCode["EmptyUpdatePassword"] = "EmptyUpdatePassword";
})(AuthValidationErrorCode || (AuthValidationErrorCode = {}));


//# sourceMappingURL=validation.mjs.map


/***/ }),

/***/ "./dist/esm/errors/utils/assertServiceError.mjs":
/*!******************************************************!*\
  !*** ./dist/esm/errors/utils/assertServiceError.mjs ***!
  \******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   assertServiceError: () => (/* binding */ assertServiceError)
/* harmony export */ });
/* harmony import */ var _AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/types/errors.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function assertServiceError(error) {
    if (!error ||
        error.name === 'Error' ||
        error instanceof TypeError) {
        throw new _AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyErrorCode.Unknown,
            message: 'An unknown error has occurred.',
            underlyingError: error,
        });
    }
}


//# sourceMappingURL=assertServiceError.mjs.map


/***/ }),

/***/ "./dist/esm/errors/utils/assertValidationError.mjs":
/*!*********************************************************!*\
  !*** ./dist/esm/errors/utils/assertValidationError.mjs ***!
  \*********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   assertValidationError: () => (/* binding */ assertValidationError)
/* harmony export */ });
/* harmony import */ var _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../common/AuthErrorStrings.mjs */ "./dist/esm/common/AuthErrorStrings.mjs");
/* harmony import */ var _AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function assertValidationError(assertion, name) {
    const { message, recoverySuggestion } = _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_0__.validationErrorMap[name];
    if (!assertion) {
        throw new _AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthError({ name, message, recoverySuggestion });
    }
}


//# sourceMappingURL=assertValidationError.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/autoSignIn.mjs":
/*!********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/autoSignIn.mjs ***!
  \********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   autoSignIn: () => (/* binding */ autoSignIn),
/* harmony export */   resetAutoSignIn: () => (/* binding */ resetAutoSignIn),
/* harmony export */   setAutoSignIn: () => (/* binding */ setAutoSignIn)
/* harmony export */ });
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../errors/constants.mjs */ "./dist/esm/errors/constants.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const initialAutoSignIn = async () => {
    throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
        name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.AUTO_SIGN_IN_EXCEPTION,
        message: 'The autoSignIn flow has not started, or has been cancelled/completed.',
        recoverySuggestion: 'Please try to use the signIn API or log out before starting a new autoSignIn flow.',
    });
};
/**
 * Signs a user in automatically after finishing the sign-up process.
 *
 * This API will automatically sign a user in if the autoSignIn flow has been completed in the following cases:
 * - User confirmed their account with a verification code sent to their phone or email (default option).
 * - User confirmed their account with a verification link sent to their phone or email. In order to
 * enable this option you need to go to the Amazon Cognito [console](https://aws.amazon.com/pm/cognito),
 * look for your userpool, then go to the `Messaging` tab and enable `link` mode inside the `Verification message` option.
 * Finally you need to define the `signUpVerificationMethod` in your `Auth` config.
 *
 * @example
 * ```typescript
 *  Amplify.configure({
 *    Auth: {
 *     Cognito: {
 *    ...cognitoConfig,
 *    signUpVerificationMethod: "link" // the default value is "code"
 *   }
 *	}});
 * ```
 *
 * @throws AutoSignInException - Thrown when the autoSignIn flow has not started, or has been cancelled/completed.
 * @returns The signInOutput.
 *
 * @example
 * ```typescript
 *  // handleSignUp.ts
 * async function handleSignUp(
 *   username:string,
 *   password:string
 * ){
 *   try {
 *     const { nextStep } = await signUp({
 *       username,
 *       password,
 *       options: {
 *         userAttributes:{ email:'email@email.com'},
 *         autoSignIn: true // This enables the auto sign-in flow.
 *       },
 *     });
 *
 *     handleSignUpStep(nextStep);
 *
 *   } catch (error) {
 *     console.log(error);
 *   }
 * }
 *
 * // handleConfirmSignUp.ts
 * async function handleConfirmSignUp(username:string, confirmationCode:string) {
 *   try {
 *     const { nextStep } = await confirmSignUp({
 *       username,
 *       confirmationCode,
 *     });
 *
 *     handleSignUpStep(nextStep);
 *   } catch (error) {
 *     console.log(error);
 *   }
 * }
 *
 * // signUpUtils.ts
 * async function handleSignUpStep( step: SignUpOutput["nextStep"]) {
 * switch (step.signUpStep) {
 *   case "CONFIRM_SIGN_UP":
 *
 *    // Redirect end-user to confirm-sign up screen.
 *
 *   case "COMPLETE_AUTO_SIGN_IN":
 *	   const codeDeliveryDetails = step.codeDeliveryDetails;
 *     if (codeDeliveryDetails) {
 *      // Redirect user to confirm-sign-up with link screen.
 *     }
 *     const signInOutput = await autoSignIn();
 *   // handle sign-in steps
 * }
 *
 * ```
 */
let autoSignIn = initialAutoSignIn;
/**
 * Sets the context of autoSignIn at run time.
 * @internal
 */
function setAutoSignIn(callback) {
    autoSignIn = callback;
}
/**
 * Resets the context
 *
 * @internal
 */
function resetAutoSignIn() {
    autoSignIn = initialAutoSignIn;
}


//# sourceMappingURL=autoSignIn.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/confirmResetPassword.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/confirmResetPassword.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   confirmResetPassword: () => (/* binding */ confirmResetPassword)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Confirms the new password and verification code to reset the password.
 *
 * @param input -  The ConfirmResetPasswordInput object.
 * @throws -{@link ConfirmForgotPasswordException }
 * Thrown due to an invalid confirmation code or password.
 * @throws -{@link AuthValidationErrorCode }
 * Thrown due to an empty confirmation code, password or username.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function confirmResetPassword(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { userPoolClientId, userPoolId } = authConfig;
    const { username, newPassword } = input;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmResetPasswordUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!newPassword, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmResetPasswordNewPassword);
    const code = input.confirmationCode;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!code, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmResetPasswordConfirmationCode);
    const metadata = input.options?.clientMetadata;
    const UserContextData = (0,_utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.confirmForgotPassword)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.ConfirmResetPassword),
    }, {
        Username: username,
        ConfirmationCode: code,
        Password: newPassword,
        ClientMetadata: metadata,
        ClientId: authConfig.userPoolClientId,
        UserContextData: UserContextData,
    });
}


//# sourceMappingURL=confirmResetPassword.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/confirmSignIn.mjs":
/*!***********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/confirmSignIn.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   confirmSignIn: () => (/* binding */ confirmSignIn)
/* harmony export */ });
/* harmony import */ var _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../utils/signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../common/AuthErrorStrings.mjs */ "./dist/esm/common/AuthErrorStrings.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");
















// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Continues or completes the sign in process when required by the initial call to `signIn`.
 *
 * @param input -  The ConfirmSignInInput object
 * @returns ConfirmSignInOutput
 * @throws  -{@link VerifySoftwareTokenException }:
 * Thrown due to an invalid MFA token.
 * @throws  -{@link RespondToAuthChallengeException }:
 * Thrown due to an invalid auth challenge response.
 * @throws  -{@link AssociateSoftwareTokenException}:
 * Thrown due to a service error during the MFA setup process.
 * @throws  -{@link AuthValidationErrorCode }:
 * Thrown when `challengeResponse` is not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function confirmSignIn(input) {
    const { challengeResponse, options } = input;
    const { username, challengeName, signInSession, signInDetails } = _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_1__.signInStore.getState();
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertTokenProviderConfig)(authConfig);
    const clientMetaData = options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_3__.assertValidationError)(!!challengeResponse, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_4__.AuthValidationErrorCode.EmptyChallengeResponse);
    if (!username || !challengeName || !signInSession)
        // TODO: remove this error message for production apps
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__.AuthError({
            name: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_6__.AuthErrorCodes.SignInException,
            message: `
			An error occurred during the sign in process. 
			
			This most likely occurred due to:
			1. signIn was not called before confirmSignIn.
			2. signIn threw an exception.
			3. page was refreshed during the sign in flow.
			`,
            recoverySuggestion: 'Make sure a successful call to signIn is made before calling confirmSignIn' +
                'and that the page is not refreshed until the sign in process is done.',
        });
    try {
        const { Session, ChallengeName, AuthenticationResult, ChallengeParameters, } = await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.handleChallengeName)(username, challengeName, signInSession, challengeResponse, authConfig, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_8__.tokenOrchestrator, clientMetaData, options);
        // sets up local state used during the sign-in process
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_1__.setActiveSignInState)({
            signInSession: Session,
            username,
            challengeName: ChallengeName,
            signInDetails,
        });
        if (AuthenticationResult) {
            (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_1__.cleanActiveSignInState)();
            await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_9__.cacheCognitoTokens)({
                username,
                ...AuthenticationResult,
                NewDeviceMetadata: await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.getNewDeviceMetatada)(authConfig.userPoolId, AuthenticationResult.NewDeviceMetadata, AuthenticationResult.AccessToken),
                signInDetails,
            });
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
                event: 'signedIn',
                data: await (0,_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_10__.getCurrentUser)(),
            }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_11__.AMPLIFY_SYMBOL);
            return {
                isSignedIn: true,
                nextStep: { signInStep: 'DONE' },
            };
        }
        return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.getSignInResult)({
            challengeName: ChallengeName,
            challengeParameters: ChallengeParameters,
        });
    }
    catch (error) {
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_12__.assertServiceError)(error);
        const result = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.getSignInResultFromError)(error.name);
        if (result)
            return result;
        throw error;
    }
}


//# sourceMappingURL=confirmSignIn.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/confirmSignUp.mjs":
/*!***********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/confirmSignUp.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   confirmSignUp: () => (/* binding */ confirmSignUp)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../utils/signUpHelpers.mjs */ "./dist/esm/providers/cognito/utils/signUpHelpers.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");










// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Confirms a new user account.
 *
 * @param input -  The ConfirmSignUpInput object.
 * @returns ConfirmSignUpOutput
 * @throws -{@link ConfirmSignUpException }
 * Thrown due to an invalid confirmation code.
 * @throws -{@link AuthValidationErrorCode }
 * Thrown due to an empty confirmation code
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function confirmSignUp(input) {
    const { username, confirmationCode, options } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { userPoolId, userPoolClientId } = authConfig;
    const clientMetadata = options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmSignUpUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!confirmationCode, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmSignUpCode);
    const UserContextData = (0,_utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.confirmSignUp)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.ConfirmSignUp),
    }, {
        Username: username,
        ConfirmationCode: confirmationCode,
        ClientMetadata: clientMetadata,
        ForceAliasCreation: options?.forceAliasCreation,
        ClientId: authConfig.userPoolClientId,
        UserContextData,
    });
    return new Promise((resolve, reject) => {
        try {
            const signUpOut = {
                isSignUpComplete: true,
                nextStep: {
                    signUpStep: 'DONE',
                },
            };
            if (!(0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.isAutoSignInStarted)() ||
                !(0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.isAutoSignInUserUsingConfirmSignUp)(username)) {
                return resolve(signUpOut);
            }
            const stopListener = _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.HubInternal.listen('auth-internal', ({ payload }) => {
                switch (payload.event) {
                    case 'autoSignIn':
                        resolve({
                            isSignUpComplete: true,
                            nextStep: {
                                signUpStep: 'COMPLETE_AUTO_SIGN_IN',
                            },
                        });
                        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.setAutoSignInStarted)(false);
                        stopListener();
                }
            });
            _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.HubInternal.dispatch('auth-internal', {
                event: 'confirmSignUp',
                data: signUpOut,
            });
        }
        catch (error) {
            reject(error);
        }
    });
}


//# sourceMappingURL=confirmSignUp.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/confirmUserAttribute.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/confirmUserAttribute.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   confirmUserAttribute: () => (/* binding */ confirmUserAttribute)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Confirms a user attribute with the confirmation code.
 *
 * @param input -  The ConfirmUserAttributeInput object
 * @throws  -{@link AuthValidationErrorCode } -
 * Thrown when `confirmationCode` is not defined.
 * @throws  -{@link VerifyUserAttributeException } - Thrown due to an invalid confirmation code or attribute.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function confirmUserAttribute(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { confirmationCode, userAttributeKey } = input;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!confirmationCode, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyConfirmUserAttributeCode);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.verifyUserAttribute)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.ConfirmUserAttribute),
    }, {
        AccessToken: tokens.accessToken.toString(),
        AttributeName: userAttributeKey,
        Code: confirmationCode,
    });
}


//# sourceMappingURL=confirmUserAttribute.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/deleteUser.mjs":
/*!********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/deleteUser.mjs ***!
  \********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   deleteUser: () => (/* binding */ deleteUser)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _signOut_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./signOut.mjs */ "./dist/esm/providers/cognito/apis/signOut.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");










// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Deletes a user from the user pool while authenticated.
 *
 * @throws - {@link DeleteUserException}
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function deleteUser() {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)();
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.deleteUser)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.DeleteUser),
    }, {
        AccessToken: tokens.accessToken.toString(),
    });
    await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__.tokenOrchestrator.clearDeviceMetadata();
    await (0,_signOut_mjs__WEBPACK_IMPORTED_MODULE_8__.signOut)();
}


//# sourceMappingURL=deleteUser.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/deleteUserAttributes.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/deleteUserAttributes.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   deleteUserAttributes: () => (/* binding */ deleteUserAttributes)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Deletes user attributes.
 *
 * @param input -  The DeleteUserAttributesInput object
 * @throws  -{@link DeleteUserAttributesException } - Thrown due to invalid attribute.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function deleteUserAttributes(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { userAttributeKeys } = input;
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.deleteUserAttributes)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.DeleteUserAttributes),
    }, {
        AccessToken: tokens.accessToken.toString(),
        UserAttributeNames: userAttributeKeys,
    });
}


//# sourceMappingURL=deleteUserAttributes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/fetchDevices.mjs":
/*!**********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/fetchDevices.mjs ***!
  \**********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchDevices: () => (/* binding */ fetchDevices)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Cognito Documentation for max device
// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListDevices.html#API_ListDevices_RequestSyntax
const MAX_DEVICES = 60;
/**
 * Fetches devices that have been remembered using {@link rememberDevice}
 * for the currently authenticated user.
 *
 * @returns FetchDevicesOutput
 * @throws {@link ListDevicesException}
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function fetchDevices() {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)();
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const response = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.listDevices)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.FetchDevices),
    }, {
        AccessToken: tokens.accessToken.toString(),
        Limit: MAX_DEVICES,
    });
    return parseDevicesResponse(response.Devices ?? []);
}
const parseDevicesResponse = async (devices) => {
    return devices.map(({ DeviceKey: id = '', DeviceAttributes = [], DeviceCreateDate, DeviceLastModifiedDate, DeviceLastAuthenticatedDate, }) => {
        const attributes = DeviceAttributes.reduce((attrs, { Name, Value }) => {
            if (Name && Value) {
                attrs[Name] = Value;
            }
            return attrs;
        }, {});
        return {
            id,
            attributes,
            createDate: DeviceCreateDate
                ? new Date(DeviceCreateDate * 1000)
                : undefined,
            lastModifiedDate: DeviceLastModifiedDate
                ? new Date(DeviceLastModifiedDate * 1000)
                : undefined,
            lastAuthenticatedDate: DeviceLastAuthenticatedDate
                ? new Date(DeviceLastAuthenticatedDate * 1000)
                : undefined,
        };
    });
};


//# sourceMappingURL=fetchDevices.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/fetchMFAPreference.mjs":
/*!****************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/fetchMFAPreference.mjs ***!
  \****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchMFAPreference: () => (/* binding */ fetchMFAPreference)
/* harmony export */ });
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");








// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Fetches the preferred MFA setting and enabled MFA settings for the user.
 *
 * @returns FetchMFAPreferenceOutput
 * @throws  -{@link GetUserException} : error thrown when the service fails to fetch MFA preference
 * and settings.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function fetchMFAPreference() {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const { PreferredMfaSetting, UserMFASettingList } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.getUser)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.FetchMFAPreference),
    }, {
        AccessToken: tokens.accessToken.toString(),
    });
    return {
        preferred: (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.getMFAType)(PreferredMfaSetting),
        enabled: (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.getMFATypes)(UserMFASettingList),
    };
}


//# sourceMappingURL=fetchMFAPreference.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/fetchUserAttributes.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/fetchUserAttributes.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchUserAttributes: () => (/* binding */ fetchUserAttributes)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _internal_fetchUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./internal/fetchUserAttributes.mjs */ "./dist/esm/providers/cognito/apis/internal/fetchUserAttributes.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Fetches the current user attributes while authenticated.
 *
 * @throws - {@link GetUserException} - Cognito service errors thrown when the service is not able to get the user.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
const fetchUserAttributes = () => {
    return (0,_internal_fetchUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_1__.fetchUserAttributes)(_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify);
};


//# sourceMappingURL=fetchUserAttributes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/forgetDevice.mjs":
/*!**********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/forgetDevice.mjs ***!
  \**********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   forgetDevice: () => (/* binding */ forgetDevice)
/* harmony export */ });
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Forget a remembered device while authenticated.
 *
 * @param input - The ForgetDeviceInput object.
 * @throws - {@link ForgetDeviceException} - Cognito service errors thrown when
 * forgetting device with invalid device key
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function forgetDevice(input) {
    const { device: { id: externalDeviceKey } = { id: undefined } } = input ?? {};
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)();
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const deviceMetadata = await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_3__.tokenOrchestrator.getDeviceMetadata();
    const currentDeviceKey = deviceMetadata?.deviceKey;
    if (!externalDeviceKey)
        (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertDeviceMetadata)(deviceMetadata);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__.forgetDevice)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_5__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_6__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__.AuthAction.ForgetDevice),
    }, {
        AccessToken: tokens.accessToken.toString(),
        DeviceKey: externalDeviceKey ?? currentDeviceKey,
    });
    if (!externalDeviceKey || externalDeviceKey === currentDeviceKey)
        await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_3__.tokenOrchestrator.clearDeviceMetadata();
}


//# sourceMappingURL=forgetDevice.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/getCurrentUser.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getCurrentUser: () => (/* binding */ getCurrentUser)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _internal_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./internal/getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/internal/getCurrentUser.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Gets the current user from the idToken.
 *
 * @param input -  The GetCurrentUserInput object.
 * @returns GetCurrentUserOutput
 * @throws - {@link InitiateAuthException} - Thrown when the service fails to refresh the tokens.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
const getCurrentUser = async () => {
    return (0,_internal_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_1__.getCurrentUser)(_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify);
};


//# sourceMappingURL=getCurrentUser.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/internal/fetchUserAttributes.mjs":
/*!**************************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/internal/fetchUserAttributes.mjs ***!
  \**************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchUserAttributes: () => (/* binding */ fetchUserAttributes)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/apis/internal/fetchAuthSession.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../utils/apiHelpers.mjs */ "./dist/esm/providers/cognito/utils/apiHelpers.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const fetchUserAttributes = async (amplify) => {
    const authConfig = amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.fetchAuthSession)(amplify, {
        forceRefresh: false,
    });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const { UserAttributes } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.getUser)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.FetchUserAttributes),
    }, {
        AccessToken: tokens.accessToken.toString(),
    });
    return (0,_utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.toAuthUserAttribute)(UserAttributes);
};


//# sourceMappingURL=fetchUserAttributes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/internal/getCurrentUser.mjs":
/*!*********************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/internal/getCurrentUser.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getCurrentUser: () => (/* binding */ getCurrentUser)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const getCurrentUser = async (amplify) => {
    const authConfig = amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(authConfig);
    const tokens = await amplify.Auth.getTokens({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_1__.assertAuthTokens)(tokens);
    const { 'cognito:username': username, sub } = tokens.idToken?.payload ?? {};
    const authUser = {
        username: username,
        userId: sub,
    };
    const signInDetails = getSignInDetailsFromTokens(tokens);
    if (signInDetails) {
        authUser.signInDetails = signInDetails;
    }
    return authUser;
};
function getSignInDetailsFromTokens(tokens) {
    return tokens?.signInDetails;
}


//# sourceMappingURL=getCurrentUser.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/rememberDevice.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/rememberDevice.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   rememberDevice: () => (/* binding */ rememberDevice)
/* harmony export */ });
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Marks device as remembered while authenticated.
 *
 * @throws - {@link UpdateDeviceStatusException} - Cognito service errors thrown when
 * setting device status to remembered using an invalid device key.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function rememberDevice() {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)();
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const deviceMetadata = await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_3__.tokenOrchestrator?.getDeviceMetadata();
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertDeviceMetadata)(deviceMetadata);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__.updateDeviceStatus)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_5__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_6__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__.AuthAction.RememberDevice),
    }, {
        AccessToken: tokens.accessToken.toString(),
        DeviceKey: deviceMetadata.deviceKey,
        DeviceRememberedStatus: 'remembered',
    });
}


//# sourceMappingURL=rememberDevice.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/resendSignUpCode.mjs":
/*!**************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/resendSignUpCode.mjs ***!
  \**************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   resendSignUpCode: () => (/* binding */ resendSignUpCode)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Resend the confirmation code while signing up
 *
 * @param input -  The ResendSignUpCodeInput object
 * @returns ResendSignUpCodeOutput
 * @throws service: {@link ResendConfirmationException } - Cognito service errors thrown when resending the code.
 * @throws validation: {@link AuthValidationErrorCode } - Validation errors thrown either username are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function resendSignUpCode(input) {
    const username = input.username;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_1__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_2__.AuthValidationErrorCode.EmptySignUpUsername);
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.assertTokenProviderConfig)(authConfig);
    const { userPoolClientId, userPoolId } = authConfig;
    const clientMetadata = input.options?.clientMetadata;
    const UserContextData = (0,_utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const { CodeDeliveryDetails } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.resendConfirmationCode)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.ResendSignUpCode),
    }, {
        Username: username,
        ClientMetadata: clientMetadata,
        ClientId: authConfig.userPoolClientId,
        UserContextData,
    });
    const { DeliveryMedium, AttributeName, Destination } = {
        ...CodeDeliveryDetails,
    };
    return {
        destination: Destination,
        deliveryMedium: DeliveryMedium,
        attributeName: AttributeName
            ? AttributeName
            : undefined,
    };
}


//# sourceMappingURL=resendSignUpCode.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/resetPassword.mjs":
/*!***********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/resetPassword.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   resetPassword: () => (/* binding */ resetPassword)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Resets a user's password.
 *
 * @param input -  The ResetPasswordInput object.
 * @returns ResetPasswordOutput
 * @throws -{@link ForgotPasswordException }
 * Thrown due to an invalid confirmation code or password.
 * @throws -{@link AuthValidationErrorCode }
 * Thrown due to an empty username.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 **/
async function resetPassword(input) {
    const username = input.username;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_1__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_2__.AuthValidationErrorCode.EmptyResetPasswordUsername);
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.assertTokenProviderConfig)(authConfig);
    const { userPoolClientId, userPoolId } = authConfig;
    const clientMetadata = input.options?.clientMetadata;
    const UserContextData = (0,_utils_userContextData_mjs__WEBPACK_IMPORTED_MODULE_4__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const res = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.forgotPassword)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.ResetPassword),
    }, {
        Username: username,
        ClientMetadata: clientMetadata,
        ClientId: authConfig.userPoolClientId,
        UserContextData,
    });
    const codeDeliveryDetails = res.CodeDeliveryDetails;
    return {
        isPasswordReset: false,
        nextStep: {
            resetPasswordStep: 'CONFIRM_RESET_PASSWORD_WITH_CODE',
            codeDeliveryDetails: {
                deliveryMedium: codeDeliveryDetails?.DeliveryMedium,
                destination: codeDeliveryDetails?.Destination,
                attributeName: codeDeliveryDetails?.AttributeName,
            },
        },
    };
}


//# sourceMappingURL=resetPassword.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/sendUserAttributeVerificationCode.mjs":
/*!*******************************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/sendUserAttributeVerificationCode.mjs ***!
  \*******************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   sendUserAttributeVerificationCode: () => (/* binding */ sendUserAttributeVerificationCode)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Resends user's confirmation code when updating attributes while authenticated.
 *
 * @param input - The SendUserAttributeVerificationCodeInput object
 * @returns SendUserAttributeVerificationCodeOutput
 * @throws - {@link GetUserAttributeVerificationException}
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
const sendUserAttributeVerificationCode = async (input) => {
    const { userAttributeKey, options } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const clientMetadata = options?.clientMetadata;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const { CodeDeliveryDetails } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.getUserAttributeVerificationCode)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.SendUserAttributeVerificationCode),
    }, {
        AccessToken: tokens.accessToken.toString(),
        ClientMetadata: clientMetadata,
        AttributeName: userAttributeKey,
    });
    const { DeliveryMedium, AttributeName, Destination } = {
        ...CodeDeliveryDetails,
    };
    return {
        destination: Destination,
        deliveryMedium: DeliveryMedium,
        attributeName: AttributeName,
    };
};


//# sourceMappingURL=sendUserAttributeVerificationCode.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/setUpTOTP.mjs":
/*!*******************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/setUpTOTP.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   setUpTOTP: () => (/* binding */ setUpTOTP)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _types_errors_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../types/errors.mjs */ "./dist/esm/providers/cognito/types/errors.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");










// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Sets up TOTP for the user.
 *
 * @returns SetUpTOTPOutput
 * @throws -{@link AssociateSoftwareTokenException}
 * Thrown if a service occurs while setting up TOTP.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 **/
async function setUpTOTP() {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const username = tokens.idToken?.payload['cognito:username'] ?? '';
    const { SecretCode } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.associateSoftwareToken)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.SetUpTOTP),
    }, {
        AccessToken: tokens.accessToken.toString(),
    });
    if (!SecretCode) {
        // This should never happen.
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_7__.AuthError({
            name: _types_errors_mjs__WEBPACK_IMPORTED_MODULE_8__.SETUP_TOTP_EXCEPTION,
            message: 'Failed to set up TOTP.',
        });
    }
    return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.getTOTPSetupDetails)(SecretCode, JSON.stringify(username));
}


//# sourceMappingURL=setUpTOTP.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signIn.mjs":
/*!****************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signIn.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signIn: () => (/* binding */ signIn)
/* harmony export */ });
/* harmony import */ var _signInWithCustomAuth_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./signInWithCustomAuth.mjs */ "./dist/esm/providers/cognito/apis/signInWithCustomAuth.mjs");
/* harmony import */ var _signInWithCustomSRPAuth_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./signInWithCustomSRPAuth.mjs */ "./dist/esm/providers/cognito/apis/signInWithCustomSRPAuth.mjs");
/* harmony import */ var _signInWithSRP_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./signInWithSRP.mjs */ "./dist/esm/providers/cognito/apis/signInWithSRP.mjs");
/* harmony import */ var _signInWithUserPassword_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./signInWithUserPassword.mjs */ "./dist/esm/providers/cognito/apis/signInWithUserPassword.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");






// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs a user in
 *
 * @param input -  The SignInInput object
 * @returns SignInOutput
 * @throws service: {@link InitiateAuthException }, {@link RespondToAuthChallengeException }
 *  - Cognito service errors thrown during the sign-in process.
 * @throws validation: {@link AuthValidationErrorCode  } - Validation errors thrown when either username or password
 *  are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signIn(input) {
    const authFlowType = input.options?.authFlowType;
    await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.assertUserNotAuthenticated)();
    switch (authFlowType) {
        case 'USER_SRP_AUTH':
            return (0,_signInWithSRP_mjs__WEBPACK_IMPORTED_MODULE_1__.signInWithSRP)(input);
        case 'USER_PASSWORD_AUTH':
            return (0,_signInWithUserPassword_mjs__WEBPACK_IMPORTED_MODULE_2__.signInWithUserPassword)(input);
        case 'CUSTOM_WITHOUT_SRP':
            return (0,_signInWithCustomAuth_mjs__WEBPACK_IMPORTED_MODULE_3__.signInWithCustomAuth)(input);
        case 'CUSTOM_WITH_SRP':
            return (0,_signInWithCustomSRPAuth_mjs__WEBPACK_IMPORTED_MODULE_4__.signInWithCustomSRPAuth)(input);
        default:
            return (0,_signInWithSRP_mjs__WEBPACK_IMPORTED_MODULE_1__.signInWithSRP)(input);
    }
}


//# sourceMappingURL=signIn.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signInWithCustomAuth.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signInWithCustomAuth.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signInWithCustomAuth: () => (/* binding */ signInWithCustomAuth)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");














// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs a user in using a custom authentication flow without password
 *
 * @param input -  The SignInWithCustomAuthInput object
 * @returns AuthSignInResult
 * @throws service: {@link InitiateAuthException } - Cognito service errors thrown during the sign-in process.
 * @throws validation: {@link AuthValidationErrorCode  } - Validation errors thrown when either username or password
 *  are not defined.
 * @throws SignInWithCustomAuthOutput - Thrown when the token provider config is invalid.
 */
async function signInWithCustomAuth(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { username, password, options } = input;
    const signInDetails = {
        loginId: username,
        authFlowType: 'CUSTOM_WITHOUT_SRP',
    };
    const metadata = options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!password, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.CustomAuthSignInPassword);
    try {
        const { ChallengeName, ChallengeParameters, AuthenticationResult, Session, } = await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.retryOnResourceNotFoundException)(_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.handleCustomAuthFlowWithoutSRP, [username, metadata, authConfig, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator], username, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator);
        const activeUsername = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getActiveSignInUsername)(username);
        // sets up local state used during the sign-in process
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.setActiveSignInState)({
            signInSession: Session,
            username: activeUsername,
            challengeName: ChallengeName,
            signInDetails,
        });
        if (AuthenticationResult) {
            (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
            await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__.cacheCognitoTokens)({
                username: activeUsername,
                ...AuthenticationResult,
                NewDeviceMetadata: await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getNewDeviceMetatada)(authConfig.userPoolId, AuthenticationResult.NewDeviceMetadata, AuthenticationResult.AccessToken),
                signInDetails,
            });
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signedIn', data: await (0,_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__.getCurrentUser)() }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__.AMPLIFY_SYMBOL);
            return {
                isSignedIn: true,
                nextStep: { signInStep: 'DONE' },
            };
        }
        return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResult)({
            challengeName: ChallengeName,
            challengeParameters: ChallengeParameters,
        });
    }
    catch (error) {
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__.assertServiceError)(error);
        const result = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResultFromError)(error.name);
        if (result)
            return result;
        throw error;
    }
}


//# sourceMappingURL=signInWithCustomAuth.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signInWithCustomSRPAuth.mjs":
/*!*********************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signInWithCustomSRPAuth.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signInWithCustomSRPAuth: () => (/* binding */ signInWithCustomSRPAuth)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");














// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs a user in using a custom authentication flow with SRP
 *
 * @param input -  The SignInWithCustomSRPAuthInput object
 * @returns SignInWithCustomSRPAuthOutput
 * @throws service: {@link InitiateAuthException }, {@link RespondToAuthChallengeException } - Cognito
 * service errors thrown during the sign-in process.
 * @throws validation: {@link AuthValidationErrorCode  } - Validation errors thrown when either username or password
 *  are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signInWithCustomSRPAuth(input) {
    const { username, password, options } = input;
    const signInDetails = {
        loginId: username,
        authFlowType: 'CUSTOM_WITH_SRP',
    };
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const metadata = options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!password, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInPassword);
    try {
        const { ChallengeName, ChallengeParameters, AuthenticationResult, Session, } = await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.handleCustomSRPAuthFlow)(username, password, metadata, authConfig, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator);
        const activeUsername = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getActiveSignInUsername)(username);
        // sets up local state used during the sign-in process
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.setActiveSignInState)({
            signInSession: Session,
            username: activeUsername,
            challengeName: ChallengeName,
            signInDetails,
        });
        if (AuthenticationResult) {
            await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__.cacheCognitoTokens)({
                username: activeUsername,
                ...AuthenticationResult,
                NewDeviceMetadata: await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getNewDeviceMetatada)(authConfig.userPoolId, AuthenticationResult.NewDeviceMetadata, AuthenticationResult.AccessToken),
                signInDetails,
            });
            (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
                event: 'signedIn',
                data: await (0,_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__.getCurrentUser)(),
            }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__.AMPLIFY_SYMBOL);
            return {
                isSignedIn: true,
                nextStep: { signInStep: 'DONE' },
            };
        }
        return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResult)({
            challengeName: ChallengeName,
            challengeParameters: ChallengeParameters,
        });
    }
    catch (error) {
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__.assertServiceError)(error);
        const result = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResultFromError)(error.name);
        if (result)
            return result;
        throw error;
    }
}


//# sourceMappingURL=signInWithCustomSRPAuth.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signInWithRedirect.mjs":
/*!****************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signInWithRedirect.mjs ***!
  \****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signInWithRedirect: () => (/* binding */ signInWithRedirect)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/urlSafeEncode.mjs");
/* harmony import */ var _utils_oauth_enableOAuthListener_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../utils/oauth/enableOAuthListener.mjs */ "./dist/esm/providers/cognito/utils/oauth/enableOAuthListener.mjs");
/* harmony import */ var _types_models_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../types/models.mjs */ "./dist/esm/providers/cognito/types/models.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _utils_oauth_generateCodeVerifier_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../utils/oauth/generateCodeVerifier.mjs */ "./dist/esm/providers/cognito/utils/oauth/generateCodeVerifier.mjs");
/* harmony import */ var _utils_oauth_generateState_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/oauth/generateState.mjs */ "./dist/esm/providers/cognito/utils/oauth/generateState.mjs");
/* harmony import */ var _utils_oauth_getRedirectUrl_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../utils/oauth/getRedirectUrl.mjs */ "./dist/esm/providers/cognito/utils/oauth/getRedirectUrl.mjs");
/* harmony import */ var _utils_oauth_oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/oauth/oAuthStore.mjs */ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs");

















// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs in a user with OAuth. Redirects the application to an Identity Provider.
 *
 * @param input - The SignInWithRedirectInput object, if empty it will redirect to Cognito HostedUI
 *
 * @throws AuthTokenConfigException - Thrown when the user pool config is invalid.
 * @throws OAuthNotConfigureException - Thrown when the oauth config is invalid.
 */
async function signInWithRedirect(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertTokenProviderConfig)(authConfig);
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertOAuthConfig)(authConfig);
    _utils_oauth_oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_3__.oAuthStore.setAuthConfig(authConfig);
    await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.assertUserNotAuthenticated)();
    let provider = 'COGNITO'; // Default
    if (typeof input?.provider === 'string') {
        provider = _types_models_mjs__WEBPACK_IMPORTED_MODULE_5__.cognitoHostedUIIdentityProviderMap[input.provider];
    }
    else if (input?.provider?.custom) {
        provider = input.provider.custom;
    }
    return oauthSignIn({
        oauthConfig: authConfig.loginWith.oauth,
        clientId: authConfig.userPoolClientId,
        provider,
        customState: input?.customState,
        preferPrivateSession: input?.options?.preferPrivateSession,
    });
}
const oauthSignIn = async ({ oauthConfig, provider, clientId, customState, preferPrivateSession, }) => {
    const { domain, redirectSignIn, responseType, scopes } = oauthConfig;
    const randomState = (0,_utils_oauth_generateState_mjs__WEBPACK_IMPORTED_MODULE_6__.generateState)();
    /* encodeURIComponent is not URL safe, use urlSafeEncode instead. Cognito
    single-encodes/decodes url on first sign in and double-encodes/decodes url
    when user already signed in. Using encodeURIComponent, Base32, Base64 add
    characters % or = which on further encoding becomes unsafe. '=' create issue
    for parsing query params.
    Refer: https://github.com/aws-amplify/amplify-js/issues/5218 */
    const state = customState
        ? `${randomState}-${(0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_7__.urlSafeEncode)(customState)}`
        : randomState;
    const { value, method, toCodeChallenge } = (0,_utils_oauth_generateCodeVerifier_mjs__WEBPACK_IMPORTED_MODULE_8__.generateCodeVerifier)(128);
    const redirectUri = (0,_utils_oauth_getRedirectUrl_mjs__WEBPACK_IMPORTED_MODULE_9__.getRedirectUrl)(oauthConfig.redirectSignIn);
    _utils_oauth_oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_3__.oAuthStore.storeOAuthInFlight(true);
    _utils_oauth_oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_3__.oAuthStore.storeOAuthState(state);
    _utils_oauth_oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_3__.oAuthStore.storePKCE(value);
    const queryString = Object.entries({
        redirect_uri: redirectUri,
        response_type: responseType,
        client_id: clientId,
        identity_provider: provider,
        scope: scopes.join(' '),
        state,
        ...(responseType === 'code' && {
            code_challenge: toCodeChallenge(),
            code_challenge_method: method,
        }),
    })
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');
    // TODO(v6): use URL object instead
    const oAuthUrl = `https://${domain}/oauth2/authorize?${queryString}`;
    return oAuthUrl;
    // // the following is effective only in react-native as openAuthSession resolves only in react-native
    // const { type, error, url } = {}
    // 	(await openAuthSession(oAuthUrl, redirectSignIn, preferPrivateSession)) ??
    // 	{};
    // try {
    // 	if (type === 'error') {
    // 		throw createOAuthError(String(error));
    // 	}
    // 	if (type === 'success' && url) {
    // 		await completeOAuthFlow({
    // 			currentUrl: url,
    // 			clientId,
    // 			domain,
    // 			redirectUri,
    // 			responseType,
    // 			userAgentValue: getAuthUserAgentValue(AuthAction.SignInWithRedirect),
    // 			preferPrivateSession,
    // 		});
    // 	}
    // } catch (error) {
    // 	await handleFailure(error);
    // 	// rethrow the error so it can be caught by `await signInWithRedirect()` in react-native
    // 	throw error;
    // }
};


//# sourceMappingURL=signInWithRedirect.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signInWithSRP.mjs":
/*!***********************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signInWithSRP.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signInWithSRP: () => (/* binding */ signInWithSRP)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");














// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs a user in
 *
 * @param input - The SignInWithSRPInput object
 * @returns SignInWithSRPOutput
 * @throws service: {@link InitiateAuthException }, {@link RespondToAuthChallengeException } - Cognito service errors
 * thrown during the sign-in process.
 * @throws validation: {@link AuthValidationErrorCode  } - Validation errors thrown when either username or password
 *  are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signInWithSRP(input) {
    const { username, password } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const signInDetails = {
        loginId: username,
        authFlowType: 'USER_SRP_AUTH',
    };
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const clientMetaData = input.options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!password, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInPassword);
    try {
        const { ChallengeName, ChallengeParameters, AuthenticationResult, Session, } = await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.handleUserSRPAuthFlow)(username, password, clientMetaData, authConfig, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator);
        const activeUsername = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getActiveSignInUsername)(username);
        // sets up local state used during the sign-in process
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.setActiveSignInState)({
            signInSession: Session,
            username: activeUsername,
            challengeName: ChallengeName,
            signInDetails,
        });
        if (AuthenticationResult) {
            (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
            await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__.cacheCognitoTokens)({
                username: activeUsername,
                ...AuthenticationResult,
                NewDeviceMetadata: await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getNewDeviceMetatada)(authConfig.userPoolId, AuthenticationResult.NewDeviceMetadata, AuthenticationResult.AccessToken),
                signInDetails,
            });
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
                event: 'signedIn',
                data: await (0,_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__.getCurrentUser)(),
            }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__.AMPLIFY_SYMBOL);
            return {
                isSignedIn: true,
                nextStep: { signInStep: 'DONE' },
            };
        }
        return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResult)({
            challengeName: ChallengeName,
            challengeParameters: ChallengeParameters,
        });
    }
    catch (error) {
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__.assertServiceError)(error);
        const result = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResultFromError)(error.name);
        if (result)
            return result;
        throw error;
    }
}


//# sourceMappingURL=signInWithSRP.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signInWithUserPassword.mjs":
/*!********************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signInWithUserPassword.mjs ***!
  \********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signInWithUserPassword: () => (/* binding */ signInWithUserPassword)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signInHelpers.mjs */ "./dist/esm/providers/cognito/utils/signInHelpers.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");














// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Signs a user in using USER_PASSWORD_AUTH AuthFlowType
 *
 * @param input - The SignInWithUserPasswordInput object
 * @returns SignInWithUserPasswordOutput
 * @throws service: {@link InitiateAuthException } - Cognito service error thrown during the sign-in process.
 * @throws validation: {@link AuthValidationErrorCode  } - Validation errors thrown when either username or password
 *  are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signInWithUserPassword(input) {
    const { username, password, options } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const signInDetails = {
        loginId: username,
        authFlowType: 'USER_PASSWORD_AUTH',
    };
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const metadata = options?.clientMetadata;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!password, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignInPassword);
    try {
        const { ChallengeName, ChallengeParameters, AuthenticationResult, Session, } = await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.retryOnResourceNotFoundException)(_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.handleUserPasswordAuthFlow, [username, password, metadata, authConfig, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator], username, _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_5__.tokenOrchestrator);
        const activeUsername = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getActiveSignInUsername)(username);
        // sets up local state used during the sign-in process
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.setActiveSignInState)({
            signInSession: Session,
            username: activeUsername,
            challengeName: ChallengeName,
            signInDetails,
        });
        if (AuthenticationResult) {
            await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_7__.cacheCognitoTokens)({
                ...AuthenticationResult,
                username: activeUsername,
                NewDeviceMetadata: await (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getNewDeviceMetatada)(authConfig.userPoolId, AuthenticationResult.NewDeviceMetadata, AuthenticationResult.AccessToken),
                signInDetails,
            });
            (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
                event: 'signedIn',
                data: await (0,_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_8__.getCurrentUser)(),
            }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__.AMPLIFY_SYMBOL);
            return {
                isSignedIn: true,
                nextStep: { signInStep: 'DONE' },
            };
        }
        return (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResult)({
            challengeName: ChallengeName,
            challengeParameters: ChallengeParameters,
        });
    }
    catch (error) {
        (0,_utils_signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.cleanActiveSignInState)();
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_10__.assertServiceError)(error);
        const result = (0,_utils_signInHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.getSignInResultFromError)(error.name);
        if (result)
            return result;
        throw error;
    }
}


//# sourceMappingURL=signInWithUserPassword.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signOut.mjs":
/*!*****************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signOut.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signOut: () => (/* binding */ signOut)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");
/* harmony import */ var _utils_oauth_handleOAuthSignOut_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/oauth/handleOAuthSignOut.mjs */ "./dist/esm/providers/cognito/utils/oauth/handleOAuthSignOut.mjs");
/* harmony import */ var _utils_signInWithRedirectStore_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/signInWithRedirectStore.mjs */ "./dist/esm/providers/cognito/utils/signInWithRedirectStore.mjs");
/* harmony import */ var _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../errors/constants.mjs */ "./dist/esm/errors/constants.mjs");

















// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const logger = new _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.ConsoleLogger('Auth');
/**
 * Signs a user out
 *
 * @param input - The SignOutInput object
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signOut(input) {
    const cognitoConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertTokenProviderConfig)(cognitoConfig);
    if (input?.global) {
        await globalSignOut(cognitoConfig);
    }
    else {
        await clientSignOut(cognitoConfig);
    }
    let hasOAuthConfig;
    try {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertOAuthConfig)(cognitoConfig);
        hasOAuthConfig = true;
    }
    catch (err) {
        hasOAuthConfig = false;
    }
    if (hasOAuthConfig) {
        const oAuthStore = new _utils_signInWithRedirectStore_mjs__WEBPACK_IMPORTED_MODULE_3__.DefaultOAuthStore(_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.defaultStorage);
        oAuthStore.setAuthConfig(cognitoConfig);
        const { type } = (await (0,_utils_oauth_handleOAuthSignOut_mjs__WEBPACK_IMPORTED_MODULE_4__.handleOAuthSignOut)(cognitoConfig, oAuthStore)) ?? {};
        if (type === 'error') {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__.AuthError({
                name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_6__.OAUTH_SIGNOUT_EXCEPTION,
                message: 'An error occurred when attempting to log out from OAuth provider.',
            });
        }
    }
    else {
        // complete sign out
        _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__.tokenOrchestrator.clearTokens();
        await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.clearCredentials)();
        _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signedOut' }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AMPLIFY_SYMBOL);
    }
}
async function clientSignOut(cognitoConfig) {
    try {
        const authTokens = await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__.tokenOrchestrator.getTokenStore().loadTokens();
        (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_9__.assertAuthTokensWithRefreshToken)(authTokens);
        if (isSessionRevocable(authTokens.accessToken)) {
            await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_10__.revokeToken)({
                region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_11__.getRegion)(cognitoConfig.userPoolId),
                userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_12__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_13__.AuthAction.SignOut),
            }, {
                ClientId: cognitoConfig.userPoolClientId,
                Token: authTokens.refreshToken,
            });
        }
    }
    catch (err) {
        // this shouldn't throw
        logger.debug('Client signOut error caught but will proceed with token removal');
    }
}
async function globalSignOut(cognitoConfig) {
    try {
        const authTokens = await _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_7__.tokenOrchestrator.getTokenStore().loadTokens();
        (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_9__.assertAuthTokens)(authTokens);
        await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_10__.globalSignOut)({
            region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_11__.getRegion)(cognitoConfig.userPoolId),
            userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_12__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_13__.AuthAction.SignOut),
        }, {
            AccessToken: authTokens.accessToken.toString(),
        });
    }
    catch (err) {
        // it should not throw
        logger.debug('Global signOut error caught but will proceed with token removal');
    }
}
const isSessionRevocable = (token) => !!token?.payload?.origin_jti;


//# sourceMappingURL=signOut.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/signUp.mjs":
/*!****************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/signUp.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   signUp: () => (/* binding */ signUp)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../utils/apiHelpers.mjs */ "./dist/esm/providers/cognito/utils/apiHelpers.mjs");
/* harmony import */ var _utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/signUpHelpers.mjs */ "./dist/esm/providers/cognito/utils/signUpHelpers.mjs");
/* harmony import */ var _autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./autoSignIn.mjs */ "./dist/esm/providers/cognito/apis/autoSignIn.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");











// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Creates a user
 *
 * @param input - The SignUpInput object
 * @returns SignUpOutput
 * @throws service: {@link SignUpException } - Cognito service errors thrown during the sign-up process.
 * @throws validation: {@link AuthValidationErrorCode } - Validation errors thrown either username or password
 *  are not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function signUp(input) {
    const { username, password, options } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const signUpVerificationMethod = authConfig?.signUpVerificationMethod ?? 'code';
    const { clientMetadata, validationData, autoSignIn } = input.options ?? {};
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!username, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignUpUsername);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!password, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptySignUpPassword);
    const signInServiceOptions = typeof autoSignIn !== 'boolean' ? autoSignIn : undefined;
    const signInInput = {
        username,
        options: signInServiceOptions,
    };
    // if the authFlowType is 'CUSTOM_WITHOUT_SRP' then we don't include the password
    if (signInServiceOptions?.authFlowType !== 'CUSTOM_WITHOUT_SRP') {
        signInInput['password'] = password;
    }
    if (signInServiceOptions || autoSignIn === true) {
        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.setUsernameUsedForAutoSignIn)(username);
        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.setAutoSignInStarted)(true);
    }
    const clientOutput = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.signUp)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.SignUp),
    }, {
        Username: username,
        Password: password,
        UserAttributes: options?.userAttributes && (0,_utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.toAttributeType)(options?.userAttributes),
        ClientMetadata: clientMetadata,
        ValidationData: validationData && (0,_utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_9__.toAttributeType)(validationData),
        ClientId: authConfig.userPoolClientId,
    });
    const { UserSub, CodeDeliveryDetails } = clientOutput;
    if ((0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isSignUpComplete)(clientOutput) && (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isAutoSignInStarted)()) {
        (0,_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_10__.setAutoSignIn)((0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.autoSignInUserConfirmed)(signInInput));
        return {
            isSignUpComplete: true,
            nextStep: {
                signUpStep: 'COMPLETE_AUTO_SIGN_IN',
            },
        };
    }
    else if ((0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isSignUpComplete)(clientOutput) && !(0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isAutoSignInStarted)()) {
        return {
            isSignUpComplete: true,
            nextStep: {
                signUpStep: 'DONE',
            },
        };
    }
    else if (!(0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isSignUpComplete)(clientOutput) &&
        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isAutoSignInStarted)() &&
        signUpVerificationMethod === 'code') {
        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.handleCodeAutoSignIn)(signInInput);
    }
    else if (!(0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isSignUpComplete)(clientOutput) &&
        (0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.isAutoSignInStarted)() &&
        signUpVerificationMethod === 'link') {
        (0,_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_10__.setAutoSignIn)((0,_utils_signUpHelpers_mjs__WEBPACK_IMPORTED_MODULE_4__.autoSignInWhenUserIsConfirmedWithLink)(signInInput));
        return {
            isSignUpComplete: false,
            nextStep: {
                signUpStep: 'COMPLETE_AUTO_SIGN_IN',
                codeDeliveryDetails: {
                    deliveryMedium: CodeDeliveryDetails?.DeliveryMedium,
                    destination: CodeDeliveryDetails?.Destination,
                    attributeName: CodeDeliveryDetails?.AttributeName,
                },
            },
            userId: UserSub,
        };
    }
    return {
        isSignUpComplete: false,
        nextStep: {
            signUpStep: 'CONFIRM_SIGN_UP',
            codeDeliveryDetails: {
                deliveryMedium: CodeDeliveryDetails?.DeliveryMedium,
                destination: CodeDeliveryDetails?.Destination,
                attributeName: CodeDeliveryDetails?.AttributeName,
            },
        },
        userId: UserSub,
    };
}


//# sourceMappingURL=signUp.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/updateMFAPreference.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/updateMFAPreference.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getMFASettings: () => (/* binding */ getMFASettings),
/* harmony export */   updateMFAPreference: () => (/* binding */ updateMFAPreference)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Updates the MFA preference of the user.
 *
 * @param input - The UpdateMFAPreferenceInput object.
 * @throws -{@link SetUserMFAPreferenceException } - Service error thrown when the MFA preference cannot be updated.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function updateMFAPreference(input) {
    const { sms, totp } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.setUserMFAPreference)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.UpdateMFAPreference),
    }, {
        AccessToken: tokens.accessToken.toString(),
        SMSMfaSettings: getMFASettings(sms),
        SoftwareTokenMfaSettings: getMFASettings(totp),
    });
}
function getMFASettings(mfaPreference) {
    if (mfaPreference === 'DISABLED') {
        return {
            Enabled: false,
        };
    }
    else if (mfaPreference === 'PREFERRED') {
        return {
            Enabled: true,
            PreferredMfa: true,
        };
    }
    else if (mfaPreference === 'ENABLED') {
        return {
            Enabled: true,
        };
    }
    else if (mfaPreference === 'NOT_PREFERRED') {
        return {
            Enabled: true,
            PreferredMfa: false,
        };
    }
}


//# sourceMappingURL=updateMFAPreference.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/updatePassword.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/updatePassword.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   updatePassword: () => (/* binding */ updatePassword)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Updates user's password while authenticated.
 *
 * @param input - The UpdatePasswordInput object.
 * @throws - {@link ChangePasswordException} - Cognito service errors thrown when updating a password.
 * @throws - {@link AuthValidationErrorCode} - Validation errors thrown when oldPassword or newPassword are empty.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function updatePassword(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { oldPassword, newPassword } = input;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!oldPassword, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyUpdatePassword);
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!newPassword, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyUpdatePassword);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.changePassword)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.UpdatePassword),
    }, {
        AccessToken: tokens.accessToken.toString(),
        PreviousPassword: oldPassword,
        ProposedPassword: newPassword,
    });
}


//# sourceMappingURL=updatePassword.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/updateUserAttribute.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/updateUserAttribute.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   updateUserAttribute: () => (/* binding */ updateUserAttribute)
/* harmony export */ });
/* harmony import */ var _updateUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./updateUserAttributes.mjs */ "./dist/esm/providers/cognito/apis/updateUserAttributes.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Updates user's attribute while authenticated.
 *
 * @param input - The UpdateUserAttributeInput object
 * @returns UpdateUserAttributeOutput
 * @throws - {@link UpdateUserAttributesException}
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
const updateUserAttribute = async (input) => {
    const { userAttribute: { attributeKey, value }, options, } = input;
    const output = await (0,_updateUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_0__.updateUserAttributes)({
        userAttributes: { [attributeKey]: value },
        options,
    });
    return Object.values(output)[0];
};


//# sourceMappingURL=updateUserAttribute.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/updateUserAttributes.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/updateUserAttributes.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   updateUserAttributes: () => (/* binding */ updateUserAttributes)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../utils/apiHelpers.mjs */ "./dist/esm/providers/cognito/utils/apiHelpers.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");








// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Updates user's attributes while authenticated.
 *
 * @param input - The UpdateUserAttributesInput object
 * @returns UpdateUserAttributesOutput
 * @throws - {@link UpdateUserAttributesException}
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
const updateUserAttributes = async (input) => {
    const { userAttributes, options } = input;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const clientMetadata = options?.clientMetadata;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokens)(tokens);
    const { CodeDeliveryDetailsList } = await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_3__.updateUserAttributes)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_4__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_5__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_6__.AuthAction.UpdateUserAttributes),
    }, {
        AccessToken: tokens.accessToken.toString(),
        ClientMetadata: clientMetadata,
        UserAttributes: (0,_utils_apiHelpers_mjs__WEBPACK_IMPORTED_MODULE_7__.toAttributeType)(userAttributes),
    });
    return {
        ...getConfirmedAttributes(userAttributes),
        ...getUnConfirmedAttributes(CodeDeliveryDetailsList),
    };
};
function getConfirmedAttributes(attributes) {
    const confirmedAttributes = {};
    Object.keys(attributes)?.forEach(key => {
        confirmedAttributes[key] = {
            isUpdated: true,
            nextStep: {
                updateAttributeStep: 'DONE',
            },
        };
    });
    return confirmedAttributes;
}
function getUnConfirmedAttributes(codeDeliveryDetailsList) {
    const unConfirmedAttributes = {};
    codeDeliveryDetailsList?.forEach(codeDeliveryDetails => {
        const { AttributeName, DeliveryMedium, Destination } = codeDeliveryDetails;
        if (AttributeName)
            unConfirmedAttributes[AttributeName] = {
                isUpdated: false,
                nextStep: {
                    updateAttributeStep: 'CONFIRM_ATTRIBUTE_WITH_CODE',
                    codeDeliveryDetails: {
                        attributeName: AttributeName,
                        deliveryMedium: DeliveryMedium,
                        destination: Destination,
                    },
                },
            };
    });
    return unConfirmedAttributes;
}


//# sourceMappingURL=updateUserAttributes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/apis/verifyTOTPSetup.mjs":
/*!*************************************************************!*\
  !*** ./dist/esm/providers/cognito/apis/verifyTOTPSetup.mjs ***!
  \*************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyTOTPSetup: () => (/* binding */ verifyTOTPSetup)
/* harmony export */ });
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../utils/clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../utils/types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");









// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Verifies an OTP code retrieved from an associated authentication app.
 *
 * @param input - The VerifyTOTPSetupInput
 * @throws  -{@link VerifySoftwareTokenException }:
 * Thrown due to an invalid MFA token.
 * @throws  -{@link AuthValidationErrorCode }:
 * Thrown when `code` is not defined.
 * @throws AuthTokenConfigException - Thrown when the token provider config is invalid.
 */
async function verifyTOTPSetup(input) {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
    const { code, options } = input;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertValidationError)(!!code, _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthValidationErrorCode.EmptyVerifyTOTPSetupCode);
    const { tokens } = await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.fetchAuthSession)({ forceRefresh: false });
    (0,_utils_types_mjs__WEBPACK_IMPORTED_MODULE_4__.assertAuthTokens)(tokens);
    await (0,_utils_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_5__.verifySoftwareToken)({
        region: (0,_utils_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_6__.getRegion)(authConfig.userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.VerifyTOTPSetup),
    }, {
        AccessToken: tokens.accessToken.toString(),
        UserCode: code,
        FriendlyDeviceName: options?.friendlyDeviceName,
    });
}


//# sourceMappingURL=verifyTOTPSetup.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/CognitoUserPoolsTokenProvider.mjs":
/*!************************************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/CognitoUserPoolsTokenProvider.mjs ***!
  \************************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   CognitoUserPoolsTokenProvider: () => (/* binding */ CognitoUserPoolsTokenProvider)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _utils_refreshAuthTokens_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../utils/refreshAuthTokens.mjs */ "./dist/esm/providers/cognito/utils/refreshAuthTokens.mjs");
/* harmony import */ var _TokenStore_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./TokenStore.mjs */ "./dist/esm/providers/cognito/tokenProvider/TokenStore.mjs");
/* harmony import */ var _TokenOrchestrator_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./TokenOrchestrator.mjs */ "./dist/esm/providers/cognito/tokenProvider/TokenOrchestrator.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
class CognitoUserPoolsTokenProvider {
    constructor() {
        this.authTokenStore = new _TokenStore_mjs__WEBPACK_IMPORTED_MODULE_1__.DefaultTokenStore();
        this.authTokenStore.setKeyValueStorage(_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.defaultStorage);
        this.tokenOrchestrator = new _TokenOrchestrator_mjs__WEBPACK_IMPORTED_MODULE_2__.TokenOrchestrator();
        this.tokenOrchestrator.setAuthTokenStore(this.authTokenStore);
        this.tokenOrchestrator.setTokenRefresher(_utils_refreshAuthTokens_mjs__WEBPACK_IMPORTED_MODULE_3__.refreshAuthTokens);
    }
    getTokens({ forceRefresh } = { forceRefresh: false }) {
        return this.tokenOrchestrator.getTokens({ forceRefresh });
    }
    setKeyValueStorage(keyValueStorage) {
        this.authTokenStore.setKeyValueStorage(keyValueStorage);
    }
    setWaitForInflightOAuth(waitForInflightOAuth) {
        this.tokenOrchestrator.setWaitForInflightOAuth(waitForInflightOAuth);
    }
    setAuthConfig(authConfig) {
        this.authTokenStore.setAuthConfig(authConfig);
        this.tokenOrchestrator.setAuthConfig(authConfig);
    }
}


//# sourceMappingURL=CognitoUserPoolsTokenProvider.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/TokenOrchestrator.mjs":
/*!************************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/TokenOrchestrator.mjs ***!
  \************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   TokenOrchestrator: () => (/* binding */ TokenOrchestrator)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
class TokenOrchestrator {
    constructor() {
        this.waitForInflightOAuth = async () => { };
    }
    setAuthConfig(authConfig) {
        this.authConfig = authConfig;
    }
    setTokenRefresher(tokenRefresher) {
        this.tokenRefresher = tokenRefresher;
    }
    setAuthTokenStore(tokenStore) {
        this.tokenStore = tokenStore;
    }
    setWaitForInflightOAuth(waitForInflightOAuth) {
        this.waitForInflightOAuth = waitForInflightOAuth;
    }
    getTokenStore() {
        if (!this.tokenStore) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthError({
                name: 'EmptyTokenStoreException',
                message: 'TokenStore not set',
            });
        }
        return this.tokenStore;
    }
    getTokenRefresher() {
        if (!this.tokenRefresher) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthError({
                name: 'EmptyTokenRefresherException',
                message: 'TokenRefresher not set',
            });
        }
        return this.tokenRefresher;
    }
    async getTokens(options) {
        let tokens;
        try {
            (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.assertTokenProviderConfig)(this.authConfig?.Cognito);
        }
        catch (_err) {
            // Token provider not configured
            return null;
        }
        await this.waitForInflightOAuth();
        tokens = await this.getTokenStore().loadTokens();
        const username = await this.getTokenStore().getLastAuthUser();
        if (tokens === null) {
            return null;
        }
        const idTokenExpired = !!tokens?.idToken &&
            (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.isTokenExpired)({
                expiresAt: (tokens.idToken?.payload?.exp ?? 0) * 1000,
                clockDrift: tokens.clockDrift ?? 0,
            });
        const accessTokenExpired = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.isTokenExpired)({
            expiresAt: (tokens.accessToken?.payload?.exp ?? 0) * 1000,
            clockDrift: tokens.clockDrift ?? 0,
        });
        if (options?.forceRefresh || idTokenExpired || accessTokenExpired) {
            tokens = await this.refreshTokens({
                tokens,
                username,
            });
            if (tokens === null) {
                return null;
            }
        }
        return {
            accessToken: tokens?.accessToken,
            idToken: tokens?.idToken,
            signInDetails: tokens?.signInDetails,
        };
    }
    async refreshTokens({ tokens, username, }) {
        try {
            const newTokens = await this.getTokenRefresher()({
                tokens,
                authConfig: this.authConfig,
                username,
            });
            await this.setTokens({ tokens: newTokens });
            _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'tokenRefresh' }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_4__.AMPLIFY_SYMBOL);
            return newTokens;
        }
        catch (err) {
            return this.handleErrors(err);
        }
    }
    handleErrors(err) {
        (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_5__.assertServiceError)(err);
        if (err.message !== 'Network error') {
            // TODO(v6): Check errors on client
            this.clearTokens();
        }
        _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
            event: 'tokenRefresh_failure',
            data: { error: err },
        }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_4__.AMPLIFY_SYMBOL);
        if (err.name.startsWith('NotAuthorizedException')) {
            return null;
        }
        throw err;
    }
    async setTokens({ tokens }) {
        return this.getTokenStore().storeTokens(tokens);
    }
    async clearTokens() {
        return this.getTokenStore().clearTokens();
    }
    getDeviceMetadata(username) {
        return this.getTokenStore().getDeviceMetadata(username);
    }
    clearDeviceMetadata(username) {
        return this.getTokenStore().clearDeviceMetadata(username);
    }
}


//# sourceMappingURL=TokenOrchestrator.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/TokenStore.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/TokenStore.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   DefaultTokenStore: () => (/* binding */ DefaultTokenStore),
/* harmony export */   createKeysForAuthStorage: () => (/* binding */ createKeysForAuthStorage),
/* harmony export */   getAuthStorageKeys: () => (/* binding */ getAuthStorageKeys)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./types.mjs */ "./dist/esm/providers/cognito/tokenProvider/types.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./errorHelpers.mjs */ "./dist/esm/providers/cognito/tokenProvider/errorHelpers.mjs");





class DefaultTokenStore {
    constructor() {
        this.name = 'CognitoIdentityServiceProvider'; // To be backwards compatible with V5, no migration needed
    }
    getKeyValueStorage() {
        if (!this.keyValueStorage) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
                name: 'KeyValueStorageNotFoundException',
                message: 'KeyValueStorage was not found in TokenStore',
            });
        }
        return this.keyValueStorage;
    }
    setKeyValueStorage(keyValueStorage) {
        this.keyValueStorage = keyValueStorage;
    }
    setAuthConfig(authConfig) {
        this.authConfig = authConfig;
    }
    async loadTokens() {
        // TODO(v6): migration logic should be here
        // Reading V5 tokens old format
        try {
            const authKeys = await this.getAuthKeys();
            const accessTokenString = await this.getKeyValueStorage().getItem(authKeys.accessToken);
            if (!accessTokenString) {
                throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
                    name: 'NoSessionFoundException',
                    message: 'Auth session was not found. Make sure to call signIn.',
                });
            }
            const accessToken = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.decodeJWT)(accessTokenString);
            const itString = await this.getKeyValueStorage().getItem(authKeys.idToken);
            const idToken = itString ? (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.decodeJWT)(itString) : undefined;
            const refreshToken = (await this.getKeyValueStorage().getItem(authKeys.refreshToken)) ??
                undefined;
            const clockDriftString = (await this.getKeyValueStorage().getItem(authKeys.clockDrift)) ?? '0';
            const clockDrift = Number.parseInt(clockDriftString);
            const signInDetails = await this.getKeyValueStorage().getItem(authKeys.signInDetails);
            const tokens = {
                accessToken,
                idToken,
                refreshToken,
                deviceMetadata: (await this.getDeviceMetadata()) ?? undefined,
                clockDrift,
                username: await this.getLastAuthUser(),
            };
            if (signInDetails) {
                tokens.signInDetails = JSON.parse(signInDetails);
            }
            return tokens;
        }
        catch (err) {
            return null;
        }
    }
    async storeTokens(tokens) {
        (0,_errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_2__.assert)(tokens !== undefined, _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_2__.TokenProviderErrorCode.InvalidAuthTokens);
        await this.clearTokens();
        const lastAuthUser = tokens.username;
        await this.getKeyValueStorage().setItem(this.getLastAuthUserKey(), lastAuthUser);
        const authKeys = await this.getAuthKeys();
        await this.getKeyValueStorage().setItem(authKeys.accessToken, tokens.accessToken.toString());
        if (!!tokens.idToken) {
            await this.getKeyValueStorage().setItem(authKeys.idToken, tokens.idToken.toString());
        }
        if (!!tokens.refreshToken) {
            await this.getKeyValueStorage().setItem(authKeys.refreshToken, tokens.refreshToken);
        }
        if (!!tokens.deviceMetadata) {
            if (tokens.deviceMetadata.deviceKey) {
                await this.getKeyValueStorage().setItem(authKeys.deviceKey, tokens.deviceMetadata.deviceKey);
            }
            if (tokens.deviceMetadata.deviceGroupKey) {
                await this.getKeyValueStorage().setItem(authKeys.deviceGroupKey, tokens.deviceMetadata.deviceGroupKey);
            }
            await this.getKeyValueStorage().setItem(authKeys.randomPasswordKey, tokens.deviceMetadata.randomPassword);
        }
        if (!!tokens.signInDetails) {
            await this.getKeyValueStorage().setItem(authKeys.signInDetails, JSON.stringify(tokens.signInDetails));
        }
        await this.getKeyValueStorage().setItem(authKeys.clockDrift, `${tokens.clockDrift}`);
    }
    async clearTokens() {
        const authKeys = await this.getAuthKeys();
        // Not calling clear because it can remove data that is not managed by AuthTokenStore
        await Promise.all([
            this.getKeyValueStorage().removeItem(authKeys.accessToken),
            this.getKeyValueStorage().removeItem(authKeys.idToken),
            this.getKeyValueStorage().removeItem(authKeys.clockDrift),
            this.getKeyValueStorage().removeItem(authKeys.refreshToken),
            this.getKeyValueStorage().removeItem(authKeys.signInDetails),
            this.getKeyValueStorage().removeItem(this.getLastAuthUserKey()),
        ]);
    }
    async getDeviceMetadata(username) {
        const authKeys = await this.getAuthKeys(username);
        const deviceKey = await this.getKeyValueStorage().getItem(authKeys.deviceKey);
        const deviceGroupKey = await this.getKeyValueStorage().getItem(authKeys.deviceGroupKey);
        const randomPassword = await this.getKeyValueStorage().getItem(authKeys.randomPasswordKey);
        return !!randomPassword
            ? {
                deviceKey: deviceKey ?? undefined,
                deviceGroupKey: deviceGroupKey ?? undefined,
                randomPassword,
            }
            : null;
    }
    async clearDeviceMetadata(username) {
        const authKeys = await this.getAuthKeys(username);
        await Promise.all([
            this.getKeyValueStorage().removeItem(authKeys.deviceKey),
            this.getKeyValueStorage().removeItem(authKeys.deviceGroupKey),
            this.getKeyValueStorage().removeItem(authKeys.randomPasswordKey),
        ]);
    }
    async getAuthKeys(username) {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(this.authConfig?.Cognito);
        const lastAuthUser = username ?? (await this.getLastAuthUser());
        return createKeysForAuthStorage(this.name, `${this.authConfig.Cognito.userPoolClientId}.${lastAuthUser}`);
    }
    getLastAuthUserKey() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(this.authConfig?.Cognito);
        const identifier = this.authConfig.Cognito.userPoolClientId;
        return `${this.name}.${identifier}.LastAuthUser`;
    }
    async getLastAuthUser() {
        const lastAuthUser = (await this.getKeyValueStorage().getItem(this.getLastAuthUserKey())) ??
            'username';
        return lastAuthUser;
    }
}
const createKeysForAuthStorage = (provider, identifier) => {
    return getAuthStorageKeys(_types_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthTokenStorageKeys)(`${provider}`, identifier);
};
function getAuthStorageKeys(authKeys) {
    const keys = Object.values({ ...authKeys });
    return (prefix, identifier) => keys.reduce((acc, authKey) => ({
        ...acc,
        [authKey]: `${prefix}.${identifier}.${authKey}`,
    }), {});
}


//# sourceMappingURL=TokenStore.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cacheCognitoTokens: () => (/* binding */ cacheCognitoTokens)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/errors/AmplifyError.mjs");
/* harmony import */ var _tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
async function cacheCognitoTokens(AuthenticationResult) {
    if (AuthenticationResult.AccessToken) {
        const accessToken = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(AuthenticationResult.AccessToken);
        const accessTokenIssuedAtInMillis = (accessToken.payload.iat || 0) * 1000;
        const currentTime = new Date().getTime();
        const clockDrift = accessTokenIssuedAtInMillis > 0
            ? accessTokenIssuedAtInMillis - currentTime
            : 0;
        let idToken;
        let refreshToken;
        let deviceMetadata;
        if (AuthenticationResult.RefreshToken) {
            refreshToken = AuthenticationResult.RefreshToken;
        }
        if (AuthenticationResult.IdToken) {
            idToken = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(AuthenticationResult.IdToken);
        }
        if (AuthenticationResult?.NewDeviceMetadata) {
            deviceMetadata = AuthenticationResult.NewDeviceMetadata;
        }
        const tokens = {
            accessToken,
            idToken,
            refreshToken,
            clockDrift,
            deviceMetadata,
            username: AuthenticationResult.username,
        };
        if (AuthenticationResult?.signInDetails) {
            tokens.signInDetails = AuthenticationResult.signInDetails;
        }
        await _tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_1__.tokenOrchestrator.setTokens({
            tokens,
        });
    }
    else {
        // This would be a service error
        throw new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.AmplifyError({
            message: 'Invalid tokens',
            name: 'InvalidTokens',
            recoverySuggestion: 'Check Cognito UserPool settings',
        });
    }
}


//# sourceMappingURL=cacheTokens.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/errorHelpers.mjs":
/*!*******************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/errorHelpers.mjs ***!
  \*******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   TokenProviderErrorCode: () => (/* binding */ TokenProviderErrorCode),
/* harmony export */   assert: () => (/* binding */ assert)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/errors/createAssertionFunction.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var TokenProviderErrorCode;
(function (TokenProviderErrorCode) {
    TokenProviderErrorCode["InvalidAuthTokens"] = "InvalidAuthTokens";
})(TokenProviderErrorCode || (TokenProviderErrorCode = {}));
const tokenValidationErrorMap = {
    [TokenProviderErrorCode.InvalidAuthTokens]: {
        message: 'Invalid tokens.',
        recoverySuggestion: 'Make sure the tokens are valid.',
    },
};
const assert = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.createAssertionFunction)(tokenValidationErrorMap);


//# sourceMappingURL=errorHelpers.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs":
/*!********************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs ***!
  \********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cognitoUserPoolsTokenProvider: () => (/* binding */ cognitoUserPoolsTokenProvider),
/* harmony export */   tokenOrchestrator: () => (/* binding */ tokenOrchestrator)
/* harmony export */ });
/* harmony import */ var _CognitoUserPoolsTokenProvider_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./CognitoUserPoolsTokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/CognitoUserPoolsTokenProvider.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const cognitoUserPoolsTokenProvider = new _CognitoUserPoolsTokenProvider_mjs__WEBPACK_IMPORTED_MODULE_0__.CognitoUserPoolsTokenProvider();
const tokenOrchestrator = cognitoUserPoolsTokenProvider.tokenOrchestrator;


//# sourceMappingURL=tokenProvider.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/tokenProvider/types.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/tokenProvider/types.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthTokenStorageKeys: () => (/* binding */ AuthTokenStorageKeys)
/* harmony export */ });
const AuthTokenStorageKeys = {
    accessToken: 'accessToken',
    idToken: 'idToken',
    oidcProvider: 'oidcProvider',
    clockDrift: 'clockDrift',
    refreshToken: 'refreshToken',
    deviceKey: 'deviceKey',
    randomPasswordKey: 'randomPasswordKey',
    deviceGroupKey: 'deviceGroupKey',
    signInDetails: 'signInDetails',
};


//# sourceMappingURL=types.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/types/errors.mjs":
/*!*****************************************************!*\
  !*** ./dist/esm/providers/cognito/types/errors.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AssociateSoftwareTokenException: () => (/* binding */ AssociateSoftwareTokenException),
/* harmony export */   ChangePasswordException: () => (/* binding */ ChangePasswordException),
/* harmony export */   ConfirmDeviceException: () => (/* binding */ ConfirmDeviceException),
/* harmony export */   ConfirmForgotPasswordException: () => (/* binding */ ConfirmForgotPasswordException),
/* harmony export */   ConfirmSignUpException: () => (/* binding */ ConfirmSignUpException),
/* harmony export */   DeleteUserAttributesException: () => (/* binding */ DeleteUserAttributesException),
/* harmony export */   DeleteUserException: () => (/* binding */ DeleteUserException),
/* harmony export */   ForgetDeviceException: () => (/* binding */ ForgetDeviceException),
/* harmony export */   ForgotPasswordException: () => (/* binding */ ForgotPasswordException),
/* harmony export */   GetCredentialsForIdentityException: () => (/* binding */ GetCredentialsForIdentityException),
/* harmony export */   GetIdException: () => (/* binding */ GetIdException),
/* harmony export */   GetUserAttributeVerificationException: () => (/* binding */ GetUserAttributeVerificationException),
/* harmony export */   GetUserException: () => (/* binding */ GetUserException),
/* harmony export */   GlobalSignOutException: () => (/* binding */ GlobalSignOutException),
/* harmony export */   InitiateAuthException: () => (/* binding */ InitiateAuthException),
/* harmony export */   ListDevicesException: () => (/* binding */ ListDevicesException),
/* harmony export */   ResendConfirmationException: () => (/* binding */ ResendConfirmationException),
/* harmony export */   RespondToAuthChallengeException: () => (/* binding */ RespondToAuthChallengeException),
/* harmony export */   SETUP_TOTP_EXCEPTION: () => (/* binding */ SETUP_TOTP_EXCEPTION),
/* harmony export */   SetUserMFAPreferenceException: () => (/* binding */ SetUserMFAPreferenceException),
/* harmony export */   SignUpException: () => (/* binding */ SignUpException),
/* harmony export */   UpdateDeviceStatusException: () => (/* binding */ UpdateDeviceStatusException),
/* harmony export */   UpdateUserAttributesException: () => (/* binding */ UpdateUserAttributesException),
/* harmony export */   VerifySoftwareTokenException: () => (/* binding */ VerifySoftwareTokenException),
/* harmony export */   VerifyUserAttributeException: () => (/* binding */ VerifyUserAttributeException)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var AssociateSoftwareTokenException;
(function (AssociateSoftwareTokenException) {
    AssociateSoftwareTokenException["ConcurrentModificationException"] = "ConcurrentModificationException";
    AssociateSoftwareTokenException["ForbiddenException"] = "ForbiddenException";
    AssociateSoftwareTokenException["InternalErrorException"] = "InternalErrorException";
    AssociateSoftwareTokenException["InvalidParameterException"] = "InvalidParameterException";
    AssociateSoftwareTokenException["NotAuthorizedException"] = "NotAuthorizedException";
    AssociateSoftwareTokenException["ResourceNotFoundException"] = "ResourceNotFoundException";
    AssociateSoftwareTokenException["SoftwareTokenMFANotFoundException"] = "SoftwareTokenMFANotFoundException";
})(AssociateSoftwareTokenException || (AssociateSoftwareTokenException = {}));
var ChangePasswordException;
(function (ChangePasswordException) {
    ChangePasswordException["ForbiddenException"] = "ForbiddenException";
    ChangePasswordException["InternalErrorException"] = "InternalErrorException";
    ChangePasswordException["InvalidParameterException"] = "InvalidParameterException";
    ChangePasswordException["InvalidPasswordException"] = "InvalidPasswordException";
    ChangePasswordException["LimitExceededException"] = "LimitExceededException";
    ChangePasswordException["NotAuthorizedException"] = "NotAuthorizedException";
    ChangePasswordException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    ChangePasswordException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ChangePasswordException["TooManyRequestsException"] = "TooManyRequestsException";
    ChangePasswordException["UserNotConfirmedException"] = "UserNotConfirmedException";
    ChangePasswordException["UserNotFoundException"] = "UserNotFoundException";
})(ChangePasswordException || (ChangePasswordException = {}));
var ConfirmDeviceException;
(function (ConfirmDeviceException) {
    ConfirmDeviceException["ForbiddenException"] = "ForbiddenException";
    ConfirmDeviceException["InternalErrorException"] = "InternalErrorException";
    ConfirmDeviceException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    ConfirmDeviceException["InvalidParameterException"] = "InvalidParameterException";
    ConfirmDeviceException["InvalidPasswordException"] = "InvalidPasswordException";
    ConfirmDeviceException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    ConfirmDeviceException["NotAuthorizedException"] = "NotAuthorizedException";
    ConfirmDeviceException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    ConfirmDeviceException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ConfirmDeviceException["TooManyRequestsException"] = "TooManyRequestsException";
    ConfirmDeviceException["UsernameExistsException"] = "UsernameExistsException";
    ConfirmDeviceException["UserNotConfirmedException"] = "UserNotConfirmedException";
    ConfirmDeviceException["UserNotFoundException"] = "UserNotFoundException";
})(ConfirmDeviceException || (ConfirmDeviceException = {}));
var ConfirmForgotPasswordException;
(function (ConfirmForgotPasswordException) {
    ConfirmForgotPasswordException["CodeMismatchException"] = "CodeMismatchException";
    ConfirmForgotPasswordException["ExpiredCodeException"] = "ExpiredCodeException";
    ConfirmForgotPasswordException["ForbiddenException"] = "ForbiddenException";
    ConfirmForgotPasswordException["InternalErrorException"] = "InternalErrorException";
    ConfirmForgotPasswordException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    ConfirmForgotPasswordException["InvalidParameterException"] = "InvalidParameterException";
    ConfirmForgotPasswordException["InvalidPasswordException"] = "InvalidPasswordException";
    ConfirmForgotPasswordException["LimitExceededException"] = "LimitExceededException";
    ConfirmForgotPasswordException["NotAuthorizedException"] = "NotAuthorizedException";
    ConfirmForgotPasswordException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ConfirmForgotPasswordException["TooManyFailedAttemptsException"] = "TooManyFailedAttemptsException";
    ConfirmForgotPasswordException["TooManyRequestsException"] = "TooManyRequestsException";
    ConfirmForgotPasswordException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    ConfirmForgotPasswordException["UserLambdaValidationException"] = "UserLambdaValidationException";
    ConfirmForgotPasswordException["UserNotConfirmedException"] = "UserNotConfirmedException";
    ConfirmForgotPasswordException["UserNotFoundException"] = "UserNotFoundException";
})(ConfirmForgotPasswordException || (ConfirmForgotPasswordException = {}));
var ConfirmSignUpException;
(function (ConfirmSignUpException) {
    ConfirmSignUpException["AliasExistsException"] = "AliasExistsException";
    ConfirmSignUpException["CodeMismatchException"] = "CodeMismatchException";
    ConfirmSignUpException["ExpiredCodeException"] = "ExpiredCodeException";
    ConfirmSignUpException["ForbiddenException"] = "ForbiddenException";
    ConfirmSignUpException["InternalErrorException"] = "InternalErrorException";
    ConfirmSignUpException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    ConfirmSignUpException["InvalidParameterException"] = "InvalidParameterException";
    ConfirmSignUpException["LimitExceededException"] = "LimitExceededException";
    ConfirmSignUpException["NotAuthorizedException"] = "NotAuthorizedException";
    ConfirmSignUpException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ConfirmSignUpException["TooManyFailedAttemptsException"] = "TooManyFailedAttemptsException";
    ConfirmSignUpException["TooManyRequestsException"] = "TooManyRequestsException";
    ConfirmSignUpException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    ConfirmSignUpException["UserLambdaValidationException"] = "UserLambdaValidationException";
    ConfirmSignUpException["UserNotFoundException"] = "UserNotFoundException";
})(ConfirmSignUpException || (ConfirmSignUpException = {}));
var DeleteUserAttributesException;
(function (DeleteUserAttributesException) {
    DeleteUserAttributesException["ForbiddenException"] = "ForbiddenException";
    DeleteUserAttributesException["InternalErrorException"] = "InternalErrorException";
    DeleteUserAttributesException["InvalidParameterException"] = "InvalidParameterException";
    DeleteUserAttributesException["NotAuthorizedException"] = "NotAuthorizedException";
    DeleteUserAttributesException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    DeleteUserAttributesException["ResourceNotFoundException"] = "ResourceNotFoundException";
    DeleteUserAttributesException["TooManyRequestsException"] = "TooManyRequestsException";
    DeleteUserAttributesException["UserNotConfirmedException"] = "UserNotConfirmedException";
    DeleteUserAttributesException["UserNotFoundException"] = "UserNotFoundException";
})(DeleteUserAttributesException || (DeleteUserAttributesException = {}));
var DeleteUserException;
(function (DeleteUserException) {
    DeleteUserException["ForbiddenException"] = "ForbiddenException";
    DeleteUserException["InternalErrorException"] = "InternalErrorException";
    DeleteUserException["InvalidParameterException"] = "InvalidParameterException";
    DeleteUserException["NotAuthorizedException"] = "NotAuthorizedException";
    DeleteUserException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    DeleteUserException["ResourceNotFoundException"] = "ResourceNotFoundException";
    DeleteUserException["TooManyRequestsException"] = "TooManyRequestsException";
    DeleteUserException["UserNotConfirmedException"] = "UserNotConfirmedException";
    DeleteUserException["UserNotFoundException"] = "UserNotFoundException";
})(DeleteUserException || (DeleteUserException = {}));
var ForgetDeviceException;
(function (ForgetDeviceException) {
    ForgetDeviceException["ForbiddenException"] = "ForbiddenException";
    ForgetDeviceException["InternalErrorException"] = "InternalErrorException";
    ForgetDeviceException["InvalidParameterException"] = "InvalidParameterException";
    ForgetDeviceException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    ForgetDeviceException["NotAuthorizedException"] = "NotAuthorizedException";
    ForgetDeviceException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    ForgetDeviceException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ForgetDeviceException["TooManyRequestsException"] = "TooManyRequestsException";
    ForgetDeviceException["UserNotConfirmedException"] = "UserNotConfirmedException";
    ForgetDeviceException["UserNotFoundException"] = "UserNotFoundException";
})(ForgetDeviceException || (ForgetDeviceException = {}));
var ForgotPasswordException;
(function (ForgotPasswordException) {
    ForgotPasswordException["CodeDeliveryFailureException"] = "CodeDeliveryFailureException";
    ForgotPasswordException["ForbiddenException"] = "ForbiddenException";
    ForgotPasswordException["InternalErrorException"] = "InternalErrorException";
    ForgotPasswordException["InvalidEmailRoleAccessPolicyException"] = "InvalidEmailRoleAccessPolicyException";
    ForgotPasswordException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    ForgotPasswordException["InvalidParameterException"] = "InvalidParameterException";
    ForgotPasswordException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    ForgotPasswordException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    ForgotPasswordException["LimitExceededException"] = "LimitExceededException";
    ForgotPasswordException["NotAuthorizedException"] = "NotAuthorizedException";
    ForgotPasswordException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ForgotPasswordException["TooManyRequestsException"] = "TooManyRequestsException";
    ForgotPasswordException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    ForgotPasswordException["UserLambdaValidationException"] = "UserLambdaValidationException";
    ForgotPasswordException["UserNotFoundException"] = "UserNotFoundException";
})(ForgotPasswordException || (ForgotPasswordException = {}));
var GetUserException;
(function (GetUserException) {
    GetUserException["ForbiddenException"] = "ForbiddenException";
    GetUserException["InternalErrorException"] = "InternalErrorException";
    GetUserException["InvalidParameterException"] = "InvalidParameterException";
    GetUserException["NotAuthorizedException"] = "NotAuthorizedException";
    GetUserException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    GetUserException["ResourceNotFoundException"] = "ResourceNotFoundException";
    GetUserException["TooManyRequestsException"] = "TooManyRequestsException";
    GetUserException["UserNotConfirmedException"] = "UserNotConfirmedException";
    GetUserException["UserNotFoundException"] = "UserNotFoundException";
})(GetUserException || (GetUserException = {}));
var GetIdException;
(function (GetIdException) {
    GetIdException["ExternalServiceException"] = "ExternalServiceException";
    GetIdException["InternalErrorException"] = "InternalErrorException";
    GetIdException["InvalidParameterException"] = "InvalidParameterException";
    GetIdException["LimitExceededException"] = "LimitExceededException";
    GetIdException["NotAuthorizedException"] = "NotAuthorizedException";
    GetIdException["ResourceConflictException"] = "ResourceConflictException";
    GetIdException["ResourceNotFoundException"] = "ResourceNotFoundException";
    GetIdException["TooManyRequestsException"] = "TooManyRequestsException";
})(GetIdException || (GetIdException = {}));
var GetCredentialsForIdentityException;
(function (GetCredentialsForIdentityException) {
    GetCredentialsForIdentityException["ExternalServiceException"] = "ExternalServiceException";
    GetCredentialsForIdentityException["InternalErrorException"] = "InternalErrorException";
    GetCredentialsForIdentityException["InvalidIdentityPoolConfigurationException"] = "InvalidIdentityPoolConfigurationException";
    GetCredentialsForIdentityException["InvalidParameterException"] = "InvalidParameterException";
    GetCredentialsForIdentityException["NotAuthorizedException"] = "NotAuthorizedException";
    GetCredentialsForIdentityException["ResourceConflictException"] = "ResourceConflictException";
    GetCredentialsForIdentityException["ResourceNotFoundException"] = "ResourceNotFoundException";
    GetCredentialsForIdentityException["TooManyRequestsException"] = "TooManyRequestsException";
})(GetCredentialsForIdentityException || (GetCredentialsForIdentityException = {}));
var GetUserAttributeVerificationException;
(function (GetUserAttributeVerificationException) {
    GetUserAttributeVerificationException["CodeDeliveryFailureException"] = "CodeDeliveryFailureException";
    GetUserAttributeVerificationException["ForbiddenException"] = "ForbiddenException";
    GetUserAttributeVerificationException["InternalErrorException"] = "InternalErrorException";
    GetUserAttributeVerificationException["InvalidEmailRoleAccessPolicyException"] = "InvalidEmailRoleAccessPolicyException";
    GetUserAttributeVerificationException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    GetUserAttributeVerificationException["InvalidParameterException"] = "InvalidParameterException";
    GetUserAttributeVerificationException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    GetUserAttributeVerificationException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    GetUserAttributeVerificationException["LimitExceededException"] = "LimitExceededException";
    GetUserAttributeVerificationException["NotAuthorizedException"] = "NotAuthorizedException";
    GetUserAttributeVerificationException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    GetUserAttributeVerificationException["ResourceNotFoundException"] = "ResourceNotFoundException";
    GetUserAttributeVerificationException["TooManyRequestsException"] = "TooManyRequestsException";
    GetUserAttributeVerificationException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    GetUserAttributeVerificationException["UserLambdaValidationException"] = "UserLambdaValidationException";
    GetUserAttributeVerificationException["UserNotConfirmedException"] = "UserNotConfirmedException";
    GetUserAttributeVerificationException["UserNotFoundException"] = "UserNotFoundException";
})(GetUserAttributeVerificationException || (GetUserAttributeVerificationException = {}));
var GlobalSignOutException;
(function (GlobalSignOutException) {
    GlobalSignOutException["ForbiddenException"] = "ForbiddenException";
    GlobalSignOutException["InternalErrorException"] = "InternalErrorException";
    GlobalSignOutException["InvalidParameterException"] = "InvalidParameterException";
    GlobalSignOutException["NotAuthorizedException"] = "NotAuthorizedException";
    GlobalSignOutException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    GlobalSignOutException["ResourceNotFoundException"] = "ResourceNotFoundException";
    GlobalSignOutException["TooManyRequestsException"] = "TooManyRequestsException";
    GlobalSignOutException["UserNotConfirmedException"] = "UserNotConfirmedException";
})(GlobalSignOutException || (GlobalSignOutException = {}));
var InitiateAuthException;
(function (InitiateAuthException) {
    InitiateAuthException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    InitiateAuthException["ForbiddenException"] = "ForbiddenException";
    InitiateAuthException["InternalErrorException"] = "InternalErrorException";
    InitiateAuthException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    InitiateAuthException["InvalidParameterException"] = "InvalidParameterException";
    InitiateAuthException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    InitiateAuthException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    InitiateAuthException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    InitiateAuthException["NotAuthorizedException"] = "NotAuthorizedException";
    InitiateAuthException["ResourceNotFoundException"] = "ResourceNotFoundException";
    InitiateAuthException["TooManyRequestsException"] = "TooManyRequestsException";
    InitiateAuthException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    InitiateAuthException["UserLambdaValidationException"] = "UserLambdaValidationException";
    InitiateAuthException["UserNotConfirmedException"] = "UserNotConfirmedException";
    InitiateAuthException["UserNotFoundException"] = "UserNotFoundException";
})(InitiateAuthException || (InitiateAuthException = {}));
var ResendConfirmationException;
(function (ResendConfirmationException) {
    ResendConfirmationException["CodeDeliveryFailureException"] = "CodeDeliveryFailureException";
    ResendConfirmationException["ForbiddenException"] = "ForbiddenException";
    ResendConfirmationException["InternalErrorException"] = "InternalErrorException";
    ResendConfirmationException["InvalidEmailRoleAccessPolicyException"] = "InvalidEmailRoleAccessPolicyException";
    ResendConfirmationException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    ResendConfirmationException["InvalidParameterException"] = "InvalidParameterException";
    ResendConfirmationException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    ResendConfirmationException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    ResendConfirmationException["LimitExceededException"] = "LimitExceededException";
    ResendConfirmationException["NotAuthorizedException"] = "NotAuthorizedException";
    ResendConfirmationException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ResendConfirmationException["TooManyRequestsException"] = "TooManyRequestsException";
    ResendConfirmationException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    ResendConfirmationException["UserLambdaValidationException"] = "UserLambdaValidationException";
    ResendConfirmationException["UserNotFoundException"] = "UserNotFoundException";
})(ResendConfirmationException || (ResendConfirmationException = {}));
var RespondToAuthChallengeException;
(function (RespondToAuthChallengeException) {
    RespondToAuthChallengeException["AliasExistsException"] = "AliasExistsException";
    RespondToAuthChallengeException["CodeMismatchException"] = "CodeMismatchException";
    RespondToAuthChallengeException["ExpiredCodeException"] = "ExpiredCodeException";
    RespondToAuthChallengeException["ForbiddenException"] = "ForbiddenException";
    RespondToAuthChallengeException["InternalErrorException"] = "InternalErrorException";
    RespondToAuthChallengeException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    RespondToAuthChallengeException["InvalidParameterException"] = "InvalidParameterException";
    RespondToAuthChallengeException["InvalidPasswordException"] = "InvalidPasswordException";
    RespondToAuthChallengeException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    RespondToAuthChallengeException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    RespondToAuthChallengeException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    RespondToAuthChallengeException["MFAMethodNotFoundException"] = "MFAMethodNotFoundException";
    RespondToAuthChallengeException["NotAuthorizedException"] = "NotAuthorizedException";
    RespondToAuthChallengeException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    RespondToAuthChallengeException["ResourceNotFoundException"] = "ResourceNotFoundException";
    RespondToAuthChallengeException["SoftwareTokenMFANotFoundException"] = "SoftwareTokenMFANotFoundException";
    RespondToAuthChallengeException["TooManyRequestsException"] = "TooManyRequestsException";
    RespondToAuthChallengeException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    RespondToAuthChallengeException["UserLambdaValidationException"] = "UserLambdaValidationException";
    RespondToAuthChallengeException["UserNotConfirmedException"] = "UserNotConfirmedException";
    RespondToAuthChallengeException["UserNotFoundException"] = "UserNotFoundException";
})(RespondToAuthChallengeException || (RespondToAuthChallengeException = {}));
var SetUserMFAPreferenceException;
(function (SetUserMFAPreferenceException) {
    SetUserMFAPreferenceException["ForbiddenException"] = "ForbiddenException";
    SetUserMFAPreferenceException["InternalErrorException"] = "InternalErrorException";
    SetUserMFAPreferenceException["InvalidParameterException"] = "InvalidParameterException";
    SetUserMFAPreferenceException["NotAuthorizedException"] = "NotAuthorizedException";
    SetUserMFAPreferenceException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    SetUserMFAPreferenceException["ResourceNotFoundException"] = "ResourceNotFoundException";
    SetUserMFAPreferenceException["UserNotConfirmedException"] = "UserNotConfirmedException";
    SetUserMFAPreferenceException["UserNotFoundException"] = "UserNotFoundException";
})(SetUserMFAPreferenceException || (SetUserMFAPreferenceException = {}));
var SignUpException;
(function (SignUpException) {
    SignUpException["CodeDeliveryFailureException"] = "CodeDeliveryFailureException";
    SignUpException["InternalErrorException"] = "InternalErrorException";
    SignUpException["InvalidEmailRoleAccessPolicyException"] = "InvalidEmailRoleAccessPolicyException";
    SignUpException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    SignUpException["InvalidParameterException"] = "InvalidParameterException";
    SignUpException["InvalidPasswordException"] = "InvalidPasswordException";
    SignUpException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    SignUpException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    SignUpException["NotAuthorizedException"] = "NotAuthorizedException";
    SignUpException["ResourceNotFoundException"] = "ResourceNotFoundException";
    SignUpException["TooManyRequestsException"] = "TooManyRequestsException";
    SignUpException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    SignUpException["UserLambdaValidationException"] = "UserLambdaValidationException";
    SignUpException["UsernameExistsException"] = "UsernameExistsException";
})(SignUpException || (SignUpException = {}));
var UpdateUserAttributesException;
(function (UpdateUserAttributesException) {
    UpdateUserAttributesException["AliasExistsException"] = "AliasExistsException";
    UpdateUserAttributesException["CodeDeliveryFailureException"] = "CodeDeliveryFailureException";
    UpdateUserAttributesException["CodeMismatchException"] = "CodeMismatchException";
    UpdateUserAttributesException["ExpiredCodeException"] = "ExpiredCodeException";
    UpdateUserAttributesException["ForbiddenException"] = "ForbiddenException";
    UpdateUserAttributesException["InternalErrorException"] = "InternalErrorException";
    UpdateUserAttributesException["InvalidEmailRoleAccessPolicyException"] = "InvalidEmailRoleAccessPolicyException";
    UpdateUserAttributesException["InvalidLambdaResponseException"] = "InvalidLambdaResponseException";
    UpdateUserAttributesException["InvalidParameterException"] = "InvalidParameterException";
    UpdateUserAttributesException["InvalidSmsRoleAccessPolicyException"] = "InvalidSmsRoleAccessPolicyException";
    UpdateUserAttributesException["InvalidSmsRoleTrustRelationshipException"] = "InvalidSmsRoleTrustRelationshipException";
    UpdateUserAttributesException["NotAuthorizedException"] = "NotAuthorizedException";
    UpdateUserAttributesException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    UpdateUserAttributesException["ResourceNotFoundException"] = "ResourceNotFoundException";
    UpdateUserAttributesException["TooManyRequestsException"] = "TooManyRequestsException";
    UpdateUserAttributesException["UnexpectedLambdaException"] = "UnexpectedLambdaException";
    UpdateUserAttributesException["UserLambdaValidationException"] = "UserLambdaValidationException";
    UpdateUserAttributesException["UserNotConfirmedException"] = "UserNotConfirmedException";
    UpdateUserAttributesException["UserNotFoundException"] = "UserNotFoundException";
})(UpdateUserAttributesException || (UpdateUserAttributesException = {}));
var VerifySoftwareTokenException;
(function (VerifySoftwareTokenException) {
    VerifySoftwareTokenException["CodeMismatchException"] = "CodeMismatchException";
    VerifySoftwareTokenException["EnableSoftwareTokenMFAException"] = "EnableSoftwareTokenMFAException";
    VerifySoftwareTokenException["ForbiddenException"] = "ForbiddenException";
    VerifySoftwareTokenException["InternalErrorException"] = "InternalErrorException";
    VerifySoftwareTokenException["InvalidParameterException"] = "InvalidParameterException";
    VerifySoftwareTokenException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    VerifySoftwareTokenException["NotAuthorizedException"] = "NotAuthorizedException";
    VerifySoftwareTokenException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    VerifySoftwareTokenException["ResourceNotFoundException"] = "ResourceNotFoundException";
    VerifySoftwareTokenException["SoftwareTokenMFANotFoundException"] = "SoftwareTokenMFANotFoundException";
    VerifySoftwareTokenException["TooManyRequestsException"] = "TooManyRequestsException";
    VerifySoftwareTokenException["UserNotConfirmedException"] = "UserNotConfirmedException";
    VerifySoftwareTokenException["UserNotFoundException"] = "UserNotFoundException";
})(VerifySoftwareTokenException || (VerifySoftwareTokenException = {}));
var VerifyUserAttributeException;
(function (VerifyUserAttributeException) {
    VerifyUserAttributeException["AliasExistsException"] = "AliasExistsException";
    VerifyUserAttributeException["CodeMismatchException"] = "CodeMismatchException";
    VerifyUserAttributeException["ExpiredCodeException"] = "ExpiredCodeException";
    VerifyUserAttributeException["ForbiddenException"] = "ForbiddenException";
    VerifyUserAttributeException["InternalErrorException"] = "InternalErrorException";
    VerifyUserAttributeException["InvalidParameterException"] = "InvalidParameterException";
    VerifyUserAttributeException["LimitExceededException"] = "LimitExceededException";
    VerifyUserAttributeException["NotAuthorizedException"] = "NotAuthorizedException";
    VerifyUserAttributeException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    VerifyUserAttributeException["ResourceNotFoundException"] = "ResourceNotFoundException";
    VerifyUserAttributeException["TooManyRequestsException"] = "TooManyRequestsException";
    VerifyUserAttributeException["UserNotConfirmedException"] = "UserNotConfirmedException";
    VerifyUserAttributeException["UserNotFoundException"] = "UserNotFoundException";
})(VerifyUserAttributeException || (VerifyUserAttributeException = {}));
var UpdateDeviceStatusException;
(function (UpdateDeviceStatusException) {
    UpdateDeviceStatusException["ForbiddenException"] = "ForbiddenException";
    UpdateDeviceStatusException["InternalErrorException"] = "InternalErrorException";
    UpdateDeviceStatusException["InvalidParameterException"] = "InvalidParameterException";
    UpdateDeviceStatusException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    UpdateDeviceStatusException["NotAuthorizedException"] = "NotAuthorizedException";
    UpdateDeviceStatusException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    UpdateDeviceStatusException["ResourceNotFoundException"] = "ResourceNotFoundException";
    UpdateDeviceStatusException["TooManyRequestsException"] = "TooManyRequestsException";
    UpdateDeviceStatusException["UserNotConfirmedException"] = "UserNotConfirmedException";
    UpdateDeviceStatusException["UserNotFoundException"] = "UserNotFoundException";
})(UpdateDeviceStatusException || (UpdateDeviceStatusException = {}));
var ListDevicesException;
(function (ListDevicesException) {
    ListDevicesException["ForbiddenException"] = "ForbiddenException";
    ListDevicesException["InternalErrorException"] = "InternalErrorException";
    ListDevicesException["InvalidParameterException"] = "InvalidParameterException";
    ListDevicesException["InvalidUserPoolConfigurationException"] = "InvalidUserPoolConfigurationException";
    ListDevicesException["NotAuthorizedException"] = "NotAuthorizedException";
    ListDevicesException["PasswordResetRequiredException"] = "PasswordResetRequiredException";
    ListDevicesException["ResourceNotFoundException"] = "ResourceNotFoundException";
    ListDevicesException["TooManyRequestsException"] = "TooManyRequestsException";
    ListDevicesException["UserNotConfirmedException"] = "UserNotConfirmedException";
    ListDevicesException["UserNotFoundException"] = "UserNotFoundException";
})(ListDevicesException || (ListDevicesException = {}));
const SETUP_TOTP_EXCEPTION = 'SetUpTOTPException';


//# sourceMappingURL=errors.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/types/models.mjs":
/*!*****************************************************!*\
  !*** ./dist/esm/providers/cognito/types/models.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cognitoHostedUIIdentityProviderMap: () => (/* binding */ cognitoHostedUIIdentityProviderMap)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const cognitoHostedUIIdentityProviderMap = {
    Google: 'Google',
    Facebook: 'Facebook',
    Amazon: 'LoginWithAmazon',
    Apple: 'SignInWithApple',
};


//# sourceMappingURL=models.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/apiHelpers.mjs":
/*!*********************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/apiHelpers.mjs ***!
  \*********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   toAttributeType: () => (/* binding */ toAttributeType),
/* harmony export */   toAuthUserAttribute: () => (/* binding */ toAuthUserAttribute)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Transforms a user attributes object into an array of AttributeType objects.
 * @param attributes user attributes to be mapped to AttributeType objects.
 * @returns an array of AttributeType objects.
 */
function toAttributeType(attributes) {
    return Object.entries(attributes).map(([key, value]) => ({
        Name: key,
        Value: value,
    }));
}
/**
 * Transforms an array of AttributeType objects into a user attributes object.
 *
 * @param attributes - an array of AttributeType objects.
 * @returns AuthUserAttributes object.
 */
function toAuthUserAttribute(attributes) {
    const userAttributes = {};
    attributes?.forEach(attribute => {
        if (attribute.Name)
            userAttributes[attribute.Name] = attribute.Value;
    });
    return userAttributes;
}


//# sourceMappingURL=apiHelpers.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/base.mjs":
/*!***********************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/base.mjs ***!
  \***********************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildHttpRpcRequest: () => (/* binding */ buildHttpRpcRequest),
/* harmony export */   cognitoUserPoolTransferHandler: () => (/* binding */ cognitoUserPoolTransferHandler),
/* harmony export */   defaultConfig: () => (/* binding */ defaultConfig),
/* harmony export */   getSharedHeaders: () => (/* binding */ getSharedHeaders)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/endpoints/getDnsSuffix.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/handlers/unauthenticated.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/middleware/retry/defaultRetryDecider.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/serde/json.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/middleware/retry/jitteredBackoff.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/amplifyUrl/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils/composers */ "../core/dist/esm/clients/internal/composeTransferHandler.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * The service name used to sign requests if the API requires authentication.
 */
const SERVICE_NAME = 'cognito-idp';
/**
 * The endpoint resolver function that returns the endpoint URL for a given region.
 */
const endpointResolver = ({ region }) => {
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    const customURL = authConfig?.userPoolEndpoint;
    const defaultURL = new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyUrl(`https://${SERVICE_NAME}.${region}.${(0,_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_2__.getDnsSuffix)(region)}`);
    return {
        url: customURL ? new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyUrl(customURL) : defaultURL,
    };
};
/**
 * A Cognito Identity-specific middleware that disables caching for all requests.
 */
const disableCacheMiddleware = () => (next, context) => async function disableCacheMiddleware(request) {
    request.headers['cache-control'] = 'no-store';
    return next(request);
};
/**
 * A Cognito Identity-specific transfer handler that does NOT sign requests, and
 * disables caching.
 *
 * @internal
 */
const cognitoUserPoolTransferHandler = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_3__.composeTransferHandler)(_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_4__.unauthenticatedHandler, [disableCacheMiddleware]);
/**
 * @internal
 */
const defaultConfig = {
    service: SERVICE_NAME,
    endpointResolver,
    retryDecider: (0,_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_5__.getRetryDecider)(_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_6__.parseJsonError),
    computeDelay: _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_7__.jitteredBackoff,
    userAgentValue: (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.getAmplifyUserAgent)(),
    cache: 'no-store',
};
/**
 * @internal
 */
const getSharedHeaders = (operation) => ({
    'content-type': 'application/x-amz-json-1.1',
    'x-amz-target': `AWSCognitoIdentityProviderService.${operation}`,
});
/**
 * @internal
 */
const buildHttpRpcRequest = ({ url }, headers, body) => ({
    headers,
    url,
    body,
    method: 'POST',
});


//# sourceMappingURL=base.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs":
/*!************************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs ***!
  \************************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   associateSoftwareToken: () => (/* binding */ associateSoftwareToken),
/* harmony export */   changePassword: () => (/* binding */ changePassword),
/* harmony export */   confirmDevice: () => (/* binding */ confirmDevice),
/* harmony export */   confirmForgotPassword: () => (/* binding */ confirmForgotPassword),
/* harmony export */   confirmSignUp: () => (/* binding */ confirmSignUp),
/* harmony export */   deleteUser: () => (/* binding */ deleteUser),
/* harmony export */   deleteUserAttributes: () => (/* binding */ deleteUserAttributes),
/* harmony export */   forgetDevice: () => (/* binding */ forgetDevice),
/* harmony export */   forgotPassword: () => (/* binding */ forgotPassword),
/* harmony export */   getUser: () => (/* binding */ getUser),
/* harmony export */   getUserAttributeVerificationCode: () => (/* binding */ getUserAttributeVerificationCode),
/* harmony export */   globalSignOut: () => (/* binding */ globalSignOut),
/* harmony export */   initiateAuth: () => (/* binding */ initiateAuth),
/* harmony export */   listDevices: () => (/* binding */ listDevices),
/* harmony export */   resendConfirmationCode: () => (/* binding */ resendConfirmationCode),
/* harmony export */   respondToAuthChallenge: () => (/* binding */ respondToAuthChallenge),
/* harmony export */   revokeToken: () => (/* binding */ revokeToken),
/* harmony export */   setUserMFAPreference: () => (/* binding */ setUserMFAPreference),
/* harmony export */   signUp: () => (/* binding */ signUp),
/* harmony export */   updateDeviceStatus: () => (/* binding */ updateDeviceStatus),
/* harmony export */   updateUserAttributes: () => (/* binding */ updateUserAttributes),
/* harmony export */   verifySoftwareToken: () => (/* binding */ verifySoftwareToken),
/* harmony export */   verifyUserAttribute: () => (/* binding */ verifyUserAttribute)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils/composers */ "../core/dist/esm/clients/internal/composeServiceApi.mjs");
/* harmony import */ var _base_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./base.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/base.mjs");
/* harmony import */ var _aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/aws-client-utils */ "../core/dist/esm/clients/serde/json.mjs");
/* harmony import */ var _errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../../../errors/utils/assertServiceError.mjs */ "./dist/esm/errors/utils/assertServiceError.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");






const buildUserPoolSerializer = (operation) => (input, endpoint) => {
    const headers = (0,_base_mjs__WEBPACK_IMPORTED_MODULE_0__.getSharedHeaders)(operation);
    const body = JSON.stringify(input);
    return (0,_base_mjs__WEBPACK_IMPORTED_MODULE_0__.buildHttpRpcRequest)(endpoint, headers, body);
};
const buildUserPoolDeserializer = () => {
    return async (response) => {
        if (response.statusCode >= 300) {
            const error = await (0,_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_1__.parseJsonError)(response);
            (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertServiceError)(error);
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthError({ name: error.name, message: error.message });
        }
        else {
            const body = await (0,_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_1__.parseJsonBody)(response);
            return body;
        }
    };
};
const handleEmptyResponseDeserializer = () => {
    return async (response) => {
        if (response.statusCode >= 300) {
            const error = await (0,_aws_amplify_core_internals_aws_client_utils__WEBPACK_IMPORTED_MODULE_1__.parseJsonError)(response);
            (0,_errors_utils_assertServiceError_mjs__WEBPACK_IMPORTED_MODULE_2__.assertServiceError)(error);
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_3__.AuthError({ name: error.name, message: error.message });
        }
        else {
            return undefined;
        }
    };
};
const initiateAuth = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('InitiateAuth'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const revokeToken = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('RevokeToken'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const signUp = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('SignUp'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const confirmSignUp = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ConfirmSignUp'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const forgotPassword = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ForgotPassword'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const confirmForgotPassword = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ConfirmForgotPassword'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const respondToAuthChallenge = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('RespondToAuthChallenge'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const resendConfirmationCode = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ResendConfirmationCode'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const verifySoftwareToken = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('VerifySoftwareToken'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const associateSoftwareToken = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('AssociateSoftwareToken'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const setUserMFAPreference = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('SetUserMFAPreference'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const getUser = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('GetUser'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const changePassword = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ChangePassword'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const confirmDevice = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ConfirmDevice'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const forgetDevice = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ForgetDevice'), handleEmptyResponseDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const deleteUser = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('DeleteUser'), handleEmptyResponseDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const getUserAttributeVerificationCode = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('GetUserAttributeVerificationCode'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const globalSignOut = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('GlobalSignOut'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const updateUserAttributes = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('UpdateUserAttributes'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const verifyUserAttribute = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('VerifyUserAttribute'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const updateDeviceStatus = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('UpdateDeviceStatus'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const listDevices = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('ListDevices'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);
const deleteUserAttributes = (0,_aws_amplify_core_internals_aws_client_utils_composers__WEBPACK_IMPORTED_MODULE_4__.composeServiceApi)(_base_mjs__WEBPACK_IMPORTED_MODULE_0__.cognitoUserPoolTransferHandler, buildUserPoolSerializer('DeleteUserAttributes'), buildUserPoolDeserializer(), _base_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultConfig);


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs":
/*!************************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs ***!
  \************************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getRegion: () => (/* binding */ getRegion),
/* harmony export */   getRegionFromIdentityPoolId: () => (/* binding */ getRegionFromIdentityPoolId)
/* harmony export */ });
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function getRegion(userPoolId) {
    const region = userPoolId?.split('_')[0];
    if (!userPoolId ||
        userPoolId.indexOf('_') < 0 ||
        !region ||
        typeof region !== 'string')
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: 'InvalidUserPoolId',
            message: 'Invalid user pool id provided.',
        });
    return region;
}
function getRegionFromIdentityPoolId(identityPoolId) {
    if (!identityPoolId || !identityPoolId.includes(':')) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: 'InvalidIdentityPoolIdException',
            message: 'Invalid identity pool id provided.',
            recoverySuggestion: 'Make sure a valid identityPoolId is given in the config.',
        });
    }
    return identityPoolId.split(':')[0];
}


//# sourceMappingURL=utils.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/attemptCompleteOAuthFlow.mjs":
/*!*****************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/attemptCompleteOAuthFlow.mjs ***!
  \*****************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attemptCompleteOAuthFlow: () => (/* binding */ attemptCompleteOAuthFlow)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./oAuthStore.mjs */ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs");
/* harmony import */ var _completeOAuthFlow_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./completeOAuthFlow.mjs */ "./dist/esm/providers/cognito/utils/oauth/completeOAuthFlow.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _getRedirectUrl_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./getRedirectUrl.mjs */ "./dist/esm/providers/cognito/utils/oauth/getRedirectUrl.mjs");
/* harmony import */ var _handleFailure_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./handleFailure.mjs */ "./dist/esm/providers/cognito/utils/oauth/handleFailure.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");
/* harmony import */ var _inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./inflightPromise.mjs */ "./dist/esm/providers/cognito/utils/oauth/inflightPromise.mjs");













// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const attemptCompleteOAuthFlow = async (authConfig) => {
    try {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertTokenProviderConfig)(authConfig);
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.assertOAuthConfig)(authConfig);
        _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_2__.oAuthStore.setAuthConfig(authConfig);
    }
    catch (_) {
        // no-op
        // This should not happen as Amplify singleton checks the oauth config key
        // unless the oauth config object doesn't contain required properties
        return;
    }
    // No inflight OAuth
    if (!(await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_2__.oAuthStore.loadOAuthInFlight())) {
        return;
    }
    // when there is valid oauth config and there is an inflight oauth flow, try
    // to block async calls that require fetching tokens before the oauth flow completes
    // e.g. getCurrentUser, fetchAuthSession etc.
    const asyncGetSessionBlocker = new Promise((resolve, _) => {
        (0,_inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_3__.addInflightPromise)(resolve);
    });
    _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_4__.cognitoUserPoolsTokenProvider.setWaitForInflightOAuth(() => asyncGetSessionBlocker);
    try {
        const currentUrl = window.location.href;
        const { loginWith, userPoolClientId } = authConfig;
        const { domain, redirectSignIn, responseType } = loginWith.oauth;
        const redirectUri = (0,_getRedirectUrl_mjs__WEBPACK_IMPORTED_MODULE_5__.getRedirectUrl)(redirectSignIn);
        await (0,_completeOAuthFlow_mjs__WEBPACK_IMPORTED_MODULE_6__.completeOAuthFlow)({
            currentUrl,
            clientId: userPoolClientId,
            domain,
            redirectUri,
            responseType,
            userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_7__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_8__.AuthAction.SignInWithRedirect),
        });
    }
    catch (err) {
        await (0,_handleFailure_mjs__WEBPACK_IMPORTED_MODULE_9__.handleFailure)(err);
    }
};


//# sourceMappingURL=attemptCompleteOAuthFlow.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/completeOAuthFlow.mjs":
/*!**********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/completeOAuthFlow.mjs ***!
  \**********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   completeOAuthFlow: () => (/* binding */ completeOAuthFlow)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/amplifyUrl/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/constants.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/urlSafeDecode.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./oAuthStore.mjs */ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _validateState_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./validateState.mjs */ "./dist/esm/providers/cognito/utils/oauth/validateState.mjs");
/* harmony import */ var _inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./inflightPromise.mjs */ "./dist/esm/providers/cognito/utils/oauth/inflightPromise.mjs");
/* harmony import */ var _tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../tokenProvider/cacheTokens.mjs */ "./dist/esm/providers/cognito/tokenProvider/cacheTokens.mjs");
/* harmony import */ var _apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../../apis/getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");
/* harmony import */ var _createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./createOAuthError.mjs */ "./dist/esm/providers/cognito/utils/oauth/createOAuthError.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");













// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const completeOAuthFlow = async ({ currentUrl, userAgentValue, clientId, redirectUri, responseType, domain, preferPrivateSession, }) => {
    const urlParams = new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyUrl(currentUrl);
    const error = urlParams.searchParams.get('error');
    const errorMessage = urlParams.searchParams.get('error_description');
    if (error) {
        throw (0,_createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.createOAuthError)(errorMessage ?? error);
    }
    if (responseType === 'code') {
        return handleCodeFlow({
            currentUrl,
            userAgentValue,
            clientId,
            redirectUri,
            domain,
            preferPrivateSession,
        });
    }
    return handleImplicitFlow({
        currentUrl,
        redirectUri,
        preferPrivateSession,
    });
};
const handleCodeFlow = async ({ currentUrl, userAgentValue, clientId, redirectUri, domain, preferPrivateSession, }) => {
    /* Convert URL into an object with parameters as keys
{ redirect_uri: 'http://localhost:3000/', response_type: 'code', ...} */
    const url = new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyUrl(currentUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    // if `code` or `state` is not presented in the redirect url, most likely
    // that the end user cancelled the inflight oauth flow by:
    // 1. clicking the back button of browser
    // 2. closing the provider hosted UI page and coming back to the app
    if (!code || !state) {
        throw (0,_createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.createOAuthError)('User cancelled OAuth flow.');
    }
    // may throw error is being caught in attemptCompleteOAuthFlow.ts
    const validatedState = await (0,_validateState_mjs__WEBPACK_IMPORTED_MODULE_3__.validateState)(state);
    const oAuthTokenEndpoint = 'https://' + domain + '/oauth2/token';
    // TODO(v6): check hub events
    // dispatchAuthEvent(
    // 	'codeFlow',
    // 	{},
    // 	`Retrieving tokens from ${oAuthTokenEndpoint}`
    // );
    const codeVerifier = await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_4__.oAuthStore.loadPKCE();
    const oAuthTokenBody = {
        grant_type: 'authorization_code',
        code,
        client_id: clientId,
        redirect_uri: redirectUri,
        ...(codeVerifier ? { code_verifier: codeVerifier } : {}),
    };
    const body = Object.entries(oAuthTokenBody)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');
    const { access_token, refresh_token, id_token, error, error_message, token_type, expires_in, } = await (await fetch(oAuthTokenEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            [_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.USER_AGENT_HEADER]: userAgentValue,
        },
        body,
    })).json();
    if (error) {
        // error is being caught in attemptCompleteOAuthFlow.ts
        throw (0,_createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.createOAuthError)(error_message ?? error);
    }
    const username = (access_token && (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(access_token).payload.username) ?? 'username';
    await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_6__.cacheCognitoTokens)({
        username,
        AccessToken: access_token,
        IdToken: id_token,
        RefreshToken: refresh_token,
        TokenType: token_type,
        ExpiresIn: expires_in,
    });
    return completeFlow({
        redirectUri,
        state: validatedState,
        preferPrivateSession,
    });
};
const handleImplicitFlow = async ({ currentUrl, redirectUri, preferPrivateSession, }) => {
    // hash is `null` if `#` doesn't exist on URL
    const url = new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.AmplifyUrl(currentUrl);
    const { id_token, access_token, state, token_type, expires_in, error_description, error, } = (url.hash ?? '#')
        .substring(1) // Remove # from returned code
        .split('&')
        .map(pairings => pairings.split('='))
        .reduce((accum, [k, v]) => ({ ...accum, [k]: v }), {
        id_token: undefined,
        access_token: undefined,
        state: undefined,
        token_type: undefined,
        expires_in: undefined,
        error_description: undefined,
        error: undefined,
    });
    if (error) {
        throw (0,_createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.createOAuthError)(error_description ?? error);
    }
    if (!access_token) {
        // error is being caught in attemptCompleteOAuthFlow.ts
        throw (0,_createOAuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.createOAuthError)('No access token returned from OAuth flow.');
    }
    const validatedState = await (0,_validateState_mjs__WEBPACK_IMPORTED_MODULE_3__.validateState)(state);
    const username = (access_token && (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(access_token).payload.username) ?? 'username';
    await (0,_tokenProvider_cacheTokens_mjs__WEBPACK_IMPORTED_MODULE_6__.cacheCognitoTokens)({
        username,
        AccessToken: access_token,
        IdToken: id_token,
        TokenType: token_type,
        ExpiresIn: expires_in,
    });
    return completeFlow({
        redirectUri,
        state: validatedState,
        preferPrivateSession,
    });
};
const completeFlow = async ({ redirectUri, state, preferPrivateSession, }) => {
    await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_4__.oAuthStore.clearOAuthData();
    await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_4__.oAuthStore.storeOAuthSignIn(true, preferPrivateSession);
    // this should be called before any call that involves `fetchAuthSession`
    // e.g. `getCurrentUser()` below, so it allows every inflight async calls to
    //  `fetchAuthSession` can be resolved
    (0,_inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_7__.resolveAndClearInflightPromises)();
    // when the oauth flow is completed, there should be nothing to block the async calls
    // that involves fetchAuthSession in the `TokenOrchestrator`
    _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_8__.cognitoUserPoolsTokenProvider.setWaitForInflightOAuth(async () => { });
    if (isCustomState(state)) {
        _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', {
            event: 'customOAuthState',
            data: (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_9__.urlSafeDecode)(getCustomState(state)),
        }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.AMPLIFY_SYMBOL);
    }
    _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signInWithRedirect' }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.AMPLIFY_SYMBOL);
    _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signedIn', data: await (0,_apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_11__.getCurrentUser)() }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.AMPLIFY_SYMBOL);
    clearHistory(redirectUri);
};
const isCustomState = (state) => {
    return /-/.test(state);
};
const getCustomState = (state) => {
    return state.split('-').splice(1).join('-');
};
const clearHistory = (redirectUri) => {
    if (typeof window !== 'undefined' && typeof window.history !== 'undefined') {
        window.history.replaceState(window.history.state, '', redirectUri);
    }
};


//# sourceMappingURL=completeOAuthFlow.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/completeOAuthSignOut.mjs":
/*!*************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/completeOAuthSignOut.mjs ***!
  \*************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   completeOAuthSignOut: () => (/* binding */ completeOAuthSignOut)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../tokenProvider/tokenProvider.mjs */ "./dist/esm/providers/cognito/tokenProvider/tokenProvider.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const completeOAuthSignOut = async (store) => {
    await store.clearOAuthData();
    _tokenProvider_tokenProvider_mjs__WEBPACK_IMPORTED_MODULE_1__.tokenOrchestrator.clearTokens();
    await (0,_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.clearCredentials)();
    _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signedOut' }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.AMPLIFY_SYMBOL);
};


//# sourceMappingURL=completeOAuthSignOut.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/createOAuthError.mjs":
/*!*********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/createOAuthError.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   createOAuthError: () => (/* binding */ createOAuthError)
/* harmony export */ });
/* harmony import */ var _Errors_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../../Errors.mjs */ "./dist/esm/Errors.mjs");
/* harmony import */ var _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../../common/AuthErrorStrings.mjs */ "./dist/esm/common/AuthErrorStrings.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const createOAuthError = (message, recoverySuggestion) => new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
    message: message ?? 'An error has occurred during the oauth process.',
    name: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthErrorCodes.OAuthSignInError,
    recoverySuggestion: recoverySuggestion ?? _Errors_mjs__WEBPACK_IMPORTED_MODULE_2__.authErrorMessages.oauthSignInError.log,
});


//# sourceMappingURL=createOAuthError.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/enableOAuthListener.mjs":
/*!************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/enableOAuthListener.mjs ***!
  \************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/isBrowser.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/constants.mjs");
/* harmony import */ var _attemptCompleteOAuthFlow_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./attemptCompleteOAuthFlow.mjs */ "./dist/esm/providers/cognito/utils/oauth/attemptCompleteOAuthFlow.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// attach the side effect for handling the completion of an inflight oauth flow
// this side effect works only on Web
(0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.isBrowser)() &&
    (() => {
        // add the listener to the singleton for triggering
        _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify[_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.ADD_OAUTH_LISTENER](_attemptCompleteOAuthFlow_mjs__WEBPACK_IMPORTED_MODULE_3__.attemptCompleteOAuthFlow);
    })();
//# sourceMappingURL=enableOAuthListener.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/generateCodeVerifier.mjs":
/*!*************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/generateCodeVerifier.mjs ***!
  \*************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   generateCodeVerifier: () => (/* binding */ generateCodeVerifier)
/* harmony export */ });
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/globalHelpers/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/convert/base64/base64Encoder.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const CODE_VERIFIER_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
/**
 *
 * @param length Desired length of the code verifier.
 *
 * **NOTE:** According to the [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1)
 * A code verifier must be with a length >= 43 and <= 128.
 *
 * @returns An object that contains the generated `codeVerifier` and a method
 * `toCodeChallenge` to generate the code challenge from the `codeVerifier`
 * following the spec of [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2).
 */
const generateCodeVerifier = (length) => {
    const randomBytes = new Uint8Array(length);
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.getCrypto)().getRandomValues(randomBytes);
    let value = '';
    let codeChallenge;
    for (let byte of randomBytes) {
        value += CODE_VERIFIER_CHARSET.charAt(byte % CODE_VERIFIER_CHARSET.length);
    }
    return {
        value,
        method: 'S256',
        toCodeChallenge() {
            if (codeChallenge) {
                return codeChallenge;
            }
            codeChallenge = generateCodeChallenge(value);
            return codeChallenge;
        },
    };
};
function generateCodeChallenge(codeVerifier) {
    const awsCryptoHash = new _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__.Sha256();
    awsCryptoHash.update(codeVerifier);
    const codeChallenge = removePaddingChar(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.base64Encoder.convert(awsCryptoHash.digestSync(), { urlSafe: true }));
    return codeChallenge;
}
function removePaddingChar(base64Encoded) {
    return base64Encoded.replace(/=/g, '');
}


//# sourceMappingURL=generateCodeVerifier.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/generateState.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/generateState.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   generateState: () => (/* binding */ generateState)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/generateRandomString.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const generateState = () => {
    return (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.generateRandomString)(32);
};


//# sourceMappingURL=generateState.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/getRedirectUrl.mjs":
/*!*******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/getRedirectUrl.mjs ***!
  \*******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getRedirectUrl: () => (/* binding */ getRedirectUrl)
/* harmony export */ });
/** @internal */
function getRedirectUrl(redirects) {
    return redirects[0];
    // const redirectUrlFromTheSameOrigin =
    // 	redirects?.find(isSameOriginAndPathName) ??
    // 	redirects?.find(isTheSameDomain);
    // const redirectUrlFromDifferentOrigin =
    // 	redirects?.find(isHttps) ?? redirects?.find(isHttp);
    // if (redirectUrlFromTheSameOrigin) {
    // 	return redirectUrlFromTheSameOrigin;
    // } else if (redirectUrlFromDifferentOrigin) {
    // 	throw invalidOriginException;
    // }
    // throw invalidRedirectException;
}


//# sourceMappingURL=getRedirectUrl.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/handleFailure.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/handleFailure.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   handleFailure: () => (/* binding */ handleFailure)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./oAuthStore.mjs */ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs");
/* harmony import */ var _inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./inflightPromise.mjs */ "./dist/esm/providers/cognito/utils/oauth/inflightPromise.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const handleFailure = async (error) => {
    (0,_inflightPromise_mjs__WEBPACK_IMPORTED_MODULE_1__.resolveAndClearInflightPromises)();
    await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_2__.oAuthStore.clearOAuthInflightData();
    _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Hub.dispatch('auth', { event: 'signInWithRedirect_failure', data: { error } }, 'Auth', _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.AMPLIFY_SYMBOL);
};


//# sourceMappingURL=handleFailure.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/handleOAuthSignOut.mjs":
/*!***********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/handleOAuthSignOut.mjs ***!
  \***********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   handleOAuthSignOut: () => (/* binding */ handleOAuthSignOut)
/* harmony export */ });
/* harmony import */ var _completeOAuthSignOut_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./completeOAuthSignOut.mjs */ "./dist/esm/providers/cognito/utils/oauth/completeOAuthSignOut.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const handleOAuthSignOut = async (cognitoConfig, store) => {
    await store.loadOAuthSignIn();
    // Clear everything before attempting to visted logout endpoint since the current application
    // state could be wiped away on redirect
    await (0,_completeOAuthSignOut_mjs__WEBPACK_IMPORTED_MODULE_0__.completeOAuthSignOut)(store);
};


//# sourceMappingURL=handleOAuthSignOut.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/inflightPromise.mjs":
/*!********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/inflightPromise.mjs ***!
  \********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   addInflightPromise: () => (/* binding */ addInflightPromise),
/* harmony export */   resolveAndClearInflightPromises: () => (/* binding */ resolveAndClearInflightPromises)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const inflightPromises = [];
const addInflightPromise = (resolver) => {
    inflightPromises.push(resolver);
};
const resolveAndClearInflightPromises = () => {
    while (inflightPromises.length) {
        inflightPromises.pop()?.();
    }
};


//# sourceMappingURL=inflightPromise.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs":
/*!***************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   oAuthStore: () => (/* binding */ oAuthStore)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _signInWithRedirectStore_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../signInWithRedirectStore.mjs */ "./dist/esm/providers/cognito/utils/signInWithRedirectStore.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const oAuthStore = new _signInWithRedirectStore_mjs__WEBPACK_IMPORTED_MODULE_1__.DefaultOAuthStore(_aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.defaultStorage);


//# sourceMappingURL=oAuthStore.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/oauth/validateState.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/oauth/validateState.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   flowCancelledMessage: () => (/* binding */ flowCancelledMessage),
/* harmony export */   validateState: () => (/* binding */ validateState),
/* harmony export */   validationFailedMessage: () => (/* binding */ validationFailedMessage),
/* harmony export */   validationRecoverySuggestion: () => (/* binding */ validationRecoverySuggestion)
/* harmony export */ });
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _types_Auth_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../../types/Auth.mjs */ "./dist/esm/types/Auth.mjs");
/* harmony import */ var _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./oAuthStore.mjs */ "./dist/esm/providers/cognito/utils/oauth/oAuthStore.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const flowCancelledMessage = '`signInWithRedirect` has been canceled.';
const validationFailedMessage = 'An error occurred while validating the state.';
const validationRecoverySuggestion = 'Try to initiate an OAuth flow from Amplify';
const validateState = async (state) => {
    const savedState = await _oAuthStore_mjs__WEBPACK_IMPORTED_MODULE_0__.oAuthStore.loadOAuthState();
    // This is because savedState only exists if the flow was initiated by Amplify
    const validatedState = state === savedState ? savedState : undefined;
    if (!validatedState) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_1__.AuthError({
            name: _types_Auth_mjs__WEBPACK_IMPORTED_MODULE_2__.AuthErrorTypes.OAuthSignInError,
            message: state === null ? flowCancelledMessage : validationFailedMessage,
            recoverySuggestion: state === null ? undefined : validationRecoverySuggestion,
        });
    }
    return validatedState;
};


//# sourceMappingURL=validateState.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/refreshAuthTokens.mjs":
/*!****************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/refreshAuthTokens.mjs ***!
  \****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   refreshAuthTokens: () => (/* binding */ refreshAuthTokens)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _userContextData_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const refreshAuthTokens = async ({ tokens, authConfig, username, }) => {
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(authConfig?.Cognito);
    const region = (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_1__.getRegion)(authConfig.Cognito.userPoolId);
    (0,_types_mjs__WEBPACK_IMPORTED_MODULE_2__.assertAuthTokensWithRefreshToken)(tokens);
    const refreshTokenString = tokens.refreshToken;
    const AuthParameters = {
        REFRESH_TOKEN: refreshTokenString,
    };
    if (tokens.deviceMetadata?.deviceKey) {
        AuthParameters['DEVICE_KEY'] = tokens.deviceMetadata.deviceKey;
    }
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_3__.getUserContextData)({
        username,
        userPoolId: authConfig.Cognito.userPoolId,
        userPoolClientId: authConfig.Cognito.userPoolClientId,
    });
    const { AuthenticationResult } = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_4__.initiateAuth)({ region }, {
        ClientId: authConfig?.Cognito?.userPoolClientId,
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        AuthParameters,
        UserContextData,
    });
    const accessToken = (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(AuthenticationResult?.AccessToken ?? '');
    const idToken = AuthenticationResult?.IdToken
        ? (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.decodeJWT)(AuthenticationResult.IdToken)
        : undefined;
    const iat = accessToken.payload.iat;
    // This should never happen. If it does, it's a bug from the service.
    if (!iat) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_5__.AuthError({
            name: 'iatNotFoundException',
            message: 'iat not found in access token',
        });
    }
    const clockDrift = iat * 1000 - new Date().getTime();
    return {
        accessToken,
        idToken,
        clockDrift,
        refreshToken: refreshTokenString,
        username,
    };
};


//# sourceMappingURL=refreshAuthTokens.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/signInHelpers.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/signInHelpers.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   assertUserNotAuthenticated: () => (/* binding */ assertUserNotAuthenticated),
/* harmony export */   createAttributes: () => (/* binding */ createAttributes),
/* harmony export */   getActiveSignInUsername: () => (/* binding */ getActiveSignInUsername),
/* harmony export */   getMFAType: () => (/* binding */ getMFAType),
/* harmony export */   getMFATypes: () => (/* binding */ getMFATypes),
/* harmony export */   getNewDeviceMetatada: () => (/* binding */ getNewDeviceMetatada),
/* harmony export */   getSignInResult: () => (/* binding */ getSignInResult),
/* harmony export */   getSignInResultFromError: () => (/* binding */ getSignInResultFromError),
/* harmony export */   getTOTPSetupDetails: () => (/* binding */ getTOTPSetupDetails),
/* harmony export */   handleChallengeName: () => (/* binding */ handleChallengeName),
/* harmony export */   handleCompleteNewPasswordChallenge: () => (/* binding */ handleCompleteNewPasswordChallenge),
/* harmony export */   handleCustomAuthFlowWithoutSRP: () => (/* binding */ handleCustomAuthFlowWithoutSRP),
/* harmony export */   handleCustomChallenge: () => (/* binding */ handleCustomChallenge),
/* harmony export */   handleCustomSRPAuthFlow: () => (/* binding */ handleCustomSRPAuthFlow),
/* harmony export */   handleMFASetupChallenge: () => (/* binding */ handleMFASetupChallenge),
/* harmony export */   handlePasswordVerifierChallenge: () => (/* binding */ handlePasswordVerifierChallenge),
/* harmony export */   handleSMSMFAChallenge: () => (/* binding */ handleSMSMFAChallenge),
/* harmony export */   handleSelectMFATypeChallenge: () => (/* binding */ handleSelectMFATypeChallenge),
/* harmony export */   handleSoftwareTokenMFAChallenge: () => (/* binding */ handleSoftwareTokenMFAChallenge),
/* harmony export */   handleUserPasswordAuthFlow: () => (/* binding */ handleUserPasswordAuthFlow),
/* harmony export */   handleUserSRPAuthFlow: () => (/* binding */ handleUserSRPAuthFlow),
/* harmony export */   isMFATypeEnabled: () => (/* binding */ isMFATypeEnabled),
/* harmony export */   mapMfaType: () => (/* binding */ mapMfaType),
/* harmony export */   parseAttributes: () => (/* binding */ parseAttributes),
/* harmony export */   parseMFATypes: () => (/* binding */ parseMFATypes),
/* harmony export */   retryOnResourceNotFoundException: () => (/* binding */ retryOnResourceNotFoundException),
/* harmony export */   setActiveSignInUsername: () => (/* binding */ setActiveSignInUsername)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_17__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/amplifyUrl/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_21__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/convert/base64/base64Encoder.mjs");
/* harmony import */ var _srp_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ./srp/BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");
/* harmony import */ var _srp_getAuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./srp/getAuthenticationHelper.mjs */ "./dist/esm/providers/cognito/utils/srp/getAuthenticationHelper.mjs");
/* harmony import */ var _srp_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_22__ = __webpack_require__(/*! ./srp/getBytesFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs");
/* harmony import */ var _srp_getNowString_mjs__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ./srp/getNowString.mjs */ "./dist/esm/providers/cognito/utils/srp/getNowString.mjs");
/* harmony import */ var _srp_getSignatureString_mjs__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ./srp/getSignatureString.mjs */ "./dist/esm/providers/cognito/utils/srp/getSignatureString.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _types_errors_mjs__WEBPACK_IMPORTED_MODULE_18__ = __webpack_require__(/*! ../types/errors.mjs */ "./dist/esm/providers/cognito/types/errors.mjs");
/* harmony import */ var _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_16__ = __webpack_require__(/*! ../../../common/AuthErrorStrings.mjs */ "./dist/esm/common/AuthErrorStrings.mjs");
/* harmony import */ var _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../errors/types/validation.mjs */ "./dist/esm/errors/types/validation.mjs");
/* harmony import */ var _errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../errors/utils/assertValidationError.mjs */ "./dist/esm/errors/utils/assertValidationError.mjs");
/* harmony import */ var _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./signInStore.mjs */ "./dist/esm/providers/cognito/utils/signInStore.mjs");
/* harmony import */ var _clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./clients/CognitoIdentityProvider/index.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/index.mjs");
/* harmony import */ var _clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./clients/CognitoIdentityProvider/utils.mjs */ "./dist/esm/providers/cognito/utils/clients/CognitoIdentityProvider/utils.mjs");
/* harmony import */ var _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_20__ = __webpack_require__(/*! ../../../errors/constants.mjs */ "./dist/esm/errors/constants.mjs");
/* harmony import */ var _apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_19__ = __webpack_require__(/*! ../apis/getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ./types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../utils/getAuthUserAgentValue.mjs */ "./dist/esm/utils/getAuthUserAgentValue.mjs");
/* harmony import */ var _userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./userContextData.mjs */ "./dist/esm/providers/cognito/utils/userContextData.mjs");





















// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const USER_ATTRIBUTES = 'userAttributes.';
async function handleCustomChallenge({ challengeResponse, clientMetadata, session, username, config, tokenOrchestrator, }) {
    const { userPoolId, userPoolClientId } = config;
    const challengeResponses = {
        USERNAME: username,
        ANSWER: challengeResponse,
    };
    const deviceMetadata = await tokenOrchestrator?.getDeviceMetadata(username);
    if (deviceMetadata && deviceMetadata.deviceKey) {
        challengeResponses['DEVICE_KEY'] = deviceMetadata.deviceKey;
    }
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        ChallengeName: 'CUSTOM_CHALLENGE',
        ChallengeResponses: challengeResponses,
        Session: session,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const response = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, jsonReq);
    if (response.ChallengeName === 'DEVICE_SRP_AUTH') {
        return handleDeviceSRPAuth({
            username,
            config,
            clientMetadata,
            session: response.Session,
            tokenOrchestrator,
        });
    }
    return response;
}
async function handleMFASetupChallenge({ challengeResponse, username, clientMetadata, session, deviceName, config, }) {
    const { userPoolId, userPoolClientId } = config;
    const challengeResponses = {
        USERNAME: username,
    };
    const { Session } = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.verifySoftwareToken)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, {
        UserCode: challengeResponse,
        Session: session,
        FriendlyDeviceName: deviceName,
    });
    _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.signInStore.dispatch({
        type: 'SET_SIGN_IN_SESSION',
        value: Session,
    });
    const jsonReq = {
        ChallengeName: 'MFA_SETUP',
        ChallengeResponses: challengeResponses,
        Session,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId) }, jsonReq);
}
async function handleSelectMFATypeChallenge({ challengeResponse, username, clientMetadata, session, config, }) {
    const { userPoolId, userPoolClientId } = config;
    (0,_errors_utils_assertValidationError_mjs__WEBPACK_IMPORTED_MODULE_7__.assertValidationError)(challengeResponse === 'TOTP' || challengeResponse === 'SMS', _errors_types_validation_mjs__WEBPACK_IMPORTED_MODULE_8__.AuthValidationErrorCode.IncorrectMFAMethod);
    const challengeResponses = {
        USERNAME: username,
        ANSWER: mapMfaType(challengeResponse),
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        ChallengeName: 'SELECT_MFA_TYPE',
        ChallengeResponses: challengeResponses,
        Session: session,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, jsonReq);
}
async function handleSMSMFAChallenge({ challengeResponse, clientMetadata, session, username, config, }) {
    const { userPoolId, userPoolClientId } = config;
    const challengeResponses = {
        USERNAME: username,
        SMS_MFA_CODE: challengeResponse,
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        ChallengeName: 'SMS_MFA',
        ChallengeResponses: challengeResponses,
        Session: session,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, jsonReq);
}
async function handleSoftwareTokenMFAChallenge({ challengeResponse, clientMetadata, session, username, config, }) {
    const { userPoolId, userPoolClientId } = config;
    const challengeResponses = {
        USERNAME: username,
        SOFTWARE_TOKEN_MFA_CODE: challengeResponse,
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        ChallengeName: 'SOFTWARE_TOKEN_MFA',
        ChallengeResponses: challengeResponses,
        Session: session,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, jsonReq);
}
async function handleCompleteNewPasswordChallenge({ challengeResponse, clientMetadata, session, username, requiredAttributes, config, }) {
    const { userPoolId, userPoolClientId } = config;
    const challengeResponses = {
        ...createAttributes(requiredAttributes),
        NEW_PASSWORD: challengeResponse,
        USERNAME: username,
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        ChallengeName: 'NEW_PASSWORD_REQUIRED',
        ChallengeResponses: challengeResponses,
        ClientMetadata: clientMetadata,
        Session: session,
        ClientId: userPoolClientId,
        UserContextData,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.ConfirmSignIn),
    }, jsonReq);
}
async function handleUserPasswordAuthFlow(username, password, clientMetadata, config, tokenOrchestrator) {
    const { userPoolClientId, userPoolId } = config;
    const authParameters = {
        USERNAME: username,
        PASSWORD: password,
    };
    const deviceMetadata = await tokenOrchestrator.getDeviceMetadata(username);
    if (deviceMetadata && deviceMetadata.deviceKey) {
        authParameters['DEVICE_KEY'] = deviceMetadata.deviceKey;
    }
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        AuthParameters: authParameters,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const response = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.initiateAuth)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.SignIn),
    }, jsonReq);
    const activeUsername = response.ChallengeParameters?.USERNAME ??
        response.ChallengeParameters?.USER_ID_FOR_SRP ??
        username;
    setActiveSignInUsername(activeUsername);
    if (response.ChallengeName === 'DEVICE_SRP_AUTH')
        return handleDeviceSRPAuth({
            username: activeUsername,
            config,
            clientMetadata,
            session: response.Session,
            tokenOrchestrator,
        });
    return response;
}
async function handleUserSRPAuthFlow(username, password, clientMetadata, config, tokenOrchestrator) {
    const { userPoolId, userPoolClientId } = config;
    const userPoolName = userPoolId?.split('_')[1] || '';
    const authenticationHelper = await (0,_srp_getAuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_9__.getAuthenticationHelper)(userPoolName);
    const authParameters = {
        USERNAME: username,
        SRP_A: authenticationHelper.A.toString(16),
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        AuthFlow: 'USER_SRP_AUTH',
        AuthParameters: authParameters,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const resp = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.initiateAuth)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.SignIn),
    }, jsonReq);
    const { ChallengeParameters: challengeParameters, Session: session } = resp;
    const activeUsername = challengeParameters?.USERNAME ?? username;
    setActiveSignInUsername(activeUsername);
    return retryOnResourceNotFoundException(handlePasswordVerifierChallenge, [
        password,
        challengeParameters,
        clientMetadata,
        session,
        authenticationHelper,
        config,
        tokenOrchestrator,
    ], activeUsername, tokenOrchestrator);
}
async function handleCustomAuthFlowWithoutSRP(username, clientMetadata, config, tokenOrchestrator) {
    const { userPoolClientId, userPoolId } = config;
    const authParameters = {
        USERNAME: username,
    };
    const deviceMetadata = await tokenOrchestrator.getDeviceMetadata(username);
    if (deviceMetadata && deviceMetadata.deviceKey) {
        authParameters['DEVICE_KEY'] = deviceMetadata.deviceKey;
    }
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        AuthFlow: 'CUSTOM_AUTH',
        AuthParameters: authParameters,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const response = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.initiateAuth)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.SignIn),
    }, jsonReq);
    const activeUsername = response.ChallengeParameters?.USERNAME ?? username;
    setActiveSignInUsername(activeUsername);
    if (response.ChallengeName === 'DEVICE_SRP_AUTH')
        return handleDeviceSRPAuth({
            username: activeUsername,
            config,
            clientMetadata,
            session: response.Session,
            tokenOrchestrator,
        });
    return response;
}
async function handleCustomSRPAuthFlow(username, password, clientMetadata, config, tokenOrchestrator) {
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.assertTokenProviderConfig)(config);
    const { userPoolId, userPoolClientId } = config;
    const userPoolName = userPoolId?.split('_')[1] || '';
    const authenticationHelper = await (0,_srp_getAuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_9__.getAuthenticationHelper)(userPoolName);
    const authParameters = {
        USERNAME: username,
        SRP_A: authenticationHelper.A.toString(16),
        CHALLENGE_NAME: 'SRP_A',
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReq = {
        AuthFlow: 'CUSTOM_AUTH',
        AuthParameters: authParameters,
        ClientMetadata: clientMetadata,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const { ChallengeParameters: challengeParameters, Session: session } = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.initiateAuth)({
        region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId),
        userAgentValue: (0,_utils_getAuthUserAgentValue_mjs__WEBPACK_IMPORTED_MODULE_4__.getAuthUserAgentValue)(_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_5__.AuthAction.SignIn),
    }, jsonReq);
    const activeUsername = challengeParameters?.USERNAME ?? username;
    setActiveSignInUsername(activeUsername);
    return retryOnResourceNotFoundException(handlePasswordVerifierChallenge, [
        password,
        challengeParameters,
        clientMetadata,
        session,
        authenticationHelper,
        config,
        tokenOrchestrator,
    ], activeUsername, tokenOrchestrator);
}
async function handleDeviceSRPAuth({ username, config, clientMetadata, session, tokenOrchestrator, }) {
    const userPoolId = config.userPoolId;
    const clientId = config.userPoolClientId;
    const deviceMetadata = await tokenOrchestrator?.getDeviceMetadata(username);
    (0,_types_mjs__WEBPACK_IMPORTED_MODULE_11__.assertDeviceMetadata)(deviceMetadata);
    const authenticationHelper = await (0,_srp_getAuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_9__.getAuthenticationHelper)(deviceMetadata.deviceGroupKey);
    const challengeResponses = {
        USERNAME: username,
        SRP_A: authenticationHelper.A.toString(16),
        DEVICE_KEY: deviceMetadata.deviceKey,
    };
    const jsonReqResponseChallenge = {
        ChallengeName: 'DEVICE_SRP_AUTH',
        ClientId: clientId,
        ChallengeResponses: challengeResponses,
        ClientMetadata: clientMetadata,
        Session: session,
    };
    const { ChallengeParameters, Session } = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId) }, jsonReqResponseChallenge);
    return handleDevicePasswordVerifier(username, ChallengeParameters, clientMetadata, Session, authenticationHelper, config, tokenOrchestrator);
}
async function handleDevicePasswordVerifier(username, challengeParameters, clientMetadata, session, authenticationHelper, { userPoolId, userPoolClientId }, tokenOrchestrator) {
    const deviceMetadata = await tokenOrchestrator?.getDeviceMetadata(username);
    (0,_types_mjs__WEBPACK_IMPORTED_MODULE_11__.assertDeviceMetadata)(deviceMetadata);
    const serverBValue = new _srp_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_12__["default"](challengeParameters?.SRP_B, 16);
    const salt = new _srp_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_12__["default"](challengeParameters?.SALT, 16);
    const deviceKey = deviceMetadata.deviceKey;
    const deviceGroupKey = deviceMetadata.deviceGroupKey;
    const hkdf = await authenticationHelper.getPasswordAuthenticationKey({
        username: deviceMetadata.deviceKey,
        password: deviceMetadata.randomPassword,
        serverBValue,
        salt,
    });
    const dateNow = (0,_srp_getNowString_mjs__WEBPACK_IMPORTED_MODULE_13__.getNowString)();
    const challengeResponses = {
        USERNAME: challengeParameters?.USERNAME ?? username,
        PASSWORD_CLAIM_SECRET_BLOCK: challengeParameters?.SECRET_BLOCK,
        TIMESTAMP: dateNow,
        PASSWORD_CLAIM_SIGNATURE: (0,_srp_getSignatureString_mjs__WEBPACK_IMPORTED_MODULE_14__.getSignatureString)({
            username: deviceKey,
            userPoolName: deviceGroupKey,
            challengeParameters,
            dateNow,
            hkdf,
        }),
        DEVICE_KEY: deviceKey,
    };
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReqResponseChallenge = {
        ChallengeName: 'DEVICE_PASSWORD_VERIFIER',
        ClientId: userPoolClientId,
        ChallengeResponses: challengeResponses,
        Session: session,
        ClientMetadata: clientMetadata,
        UserContextData,
    };
    return (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId) }, jsonReqResponseChallenge);
}
async function handlePasswordVerifierChallenge(password, challengeParameters, clientMetadata, session, authenticationHelper, config, tokenOrchestrator) {
    const { userPoolId, userPoolClientId } = config;
    const userPoolName = userPoolId?.split('_')[1] || '';
    const serverBValue = new _srp_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_12__["default"](challengeParameters?.SRP_B, 16);
    const salt = new _srp_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_12__["default"](challengeParameters?.SALT, 16);
    const username = challengeParameters?.USER_ID_FOR_SRP;
    if (!username)
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError({
            name: 'EmptyUserIdForSRPException',
            message: 'USER_ID_FOR_SRP was not found in challengeParameters',
        });
    const hkdf = await authenticationHelper.getPasswordAuthenticationKey({
        username,
        password,
        serverBValue,
        salt,
    });
    const dateNow = (0,_srp_getNowString_mjs__WEBPACK_IMPORTED_MODULE_13__.getNowString)();
    const challengeResponses = {
        USERNAME: username,
        PASSWORD_CLAIM_SECRET_BLOCK: challengeParameters?.SECRET_BLOCK,
        TIMESTAMP: dateNow,
        PASSWORD_CLAIM_SIGNATURE: (0,_srp_getSignatureString_mjs__WEBPACK_IMPORTED_MODULE_14__.getSignatureString)({
            username,
            userPoolName,
            challengeParameters,
            dateNow,
            hkdf,
        }),
    };
    const deviceMetadata = await tokenOrchestrator.getDeviceMetadata(username);
    if (deviceMetadata && deviceMetadata.deviceKey) {
        challengeResponses['DEVICE_KEY'] = deviceMetadata.deviceKey;
    }
    const UserContextData = (0,_userContextData_mjs__WEBPACK_IMPORTED_MODULE_1__.getUserContextData)({
        username,
        userPoolId,
        userPoolClientId,
    });
    const jsonReqResponseChallenge = {
        ChallengeName: 'PASSWORD_VERIFIER',
        ChallengeResponses: challengeResponses,
        ClientMetadata: clientMetadata,
        Session: session,
        ClientId: userPoolClientId,
        UserContextData,
    };
    const response = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.respondToAuthChallenge)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId) }, jsonReqResponseChallenge);
    if (response.ChallengeName === 'DEVICE_SRP_AUTH')
        return handleDeviceSRPAuth({
            username,
            config,
            clientMetadata,
            session: response.Session,
            tokenOrchestrator,
        });
    return response;
}
async function getSignInResult(params) {
    const { challengeName, challengeParameters } = params;
    const authConfig = _aws_amplify_core__WEBPACK_IMPORTED_MODULE_0__.Amplify.getConfig().Auth?.Cognito;
    (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_10__.assertTokenProviderConfig)(authConfig);
    switch (challengeName) {
        case 'CUSTOM_CHALLENGE':
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE',
                    additionalInfo: challengeParameters,
                },
            };
        case 'MFA_SETUP':
            const { signInSession, username } = _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.signInStore.getState();
            if (!isMFATypeEnabled(challengeParameters, 'TOTP'))
                throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError({
                    name: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_16__.AuthErrorCodes.SignInException,
                    message: `Cannot initiate MFA setup from available types: ${getMFATypes(parseMFATypes(challengeParameters.MFAS_CAN_SETUP))}`,
                });
            const { Session, SecretCode: secretCode } = await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.associateSoftwareToken)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(authConfig.userPoolId) }, {
                Session: signInSession,
            });
            _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.signInStore.dispatch({
                type: 'SET_SIGN_IN_SESSION',
                value: Session,
            });
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP',
                    totpSetupDetails: getTOTPSetupDetails(secretCode, username),
                },
            };
        case 'NEW_PASSWORD_REQUIRED':
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED',
                    missingAttributes: parseAttributes(challengeParameters.requiredAttributes),
                },
            };
        case 'SELECT_MFA_TYPE':
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONTINUE_SIGN_IN_WITH_MFA_SELECTION',
                    allowedMFATypes: getMFATypes(parseMFATypes(challengeParameters.MFAS_CAN_CHOOSE)),
                },
            };
        case 'SMS_MFA':
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONFIRM_SIGN_IN_WITH_SMS_CODE',
                    codeDeliveryDetails: {
                        deliveryMedium: challengeParameters.CODE_DELIVERY_DELIVERY_MEDIUM,
                        destination: challengeParameters.CODE_DELIVERY_DESTINATION,
                    },
                },
            };
        case 'SOFTWARE_TOKEN_MFA':
            return {
                isSignedIn: false,
                nextStep: {
                    signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE',
                },
            };
    }
    // TODO: remove this error message for production apps
    throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError({
        name: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_16__.AuthErrorCodes.SignInException,
        message: 'An error occurred during the sign in process. ' +
            `${challengeName} challengeName returned by the underlying service was not addressed.`,
    });
}
function getTOTPSetupDetails(secretCode, username) {
    return {
        sharedSecret: secretCode,
        getSetupUri: (appName, accountName) => {
            const totpUri = `otpauth://totp/${appName}:${accountName ?? username}?secret=${secretCode}&issuer=${appName}`;
            return new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_17__.AmplifyUrl(totpUri);
        },
    };
}
function getSignInResultFromError(errorName) {
    if (errorName === _types_errors_mjs__WEBPACK_IMPORTED_MODULE_18__.InitiateAuthException.PasswordResetRequiredException) {
        return {
            isSignedIn: false,
            nextStep: { signInStep: 'RESET_PASSWORD' },
        };
    }
    else if (errorName === _types_errors_mjs__WEBPACK_IMPORTED_MODULE_18__.InitiateAuthException.UserNotConfirmedException) {
        return {
            isSignedIn: false,
            nextStep: { signInStep: 'CONFIRM_SIGN_UP' },
        };
    }
}
function parseAttributes(attributes) {
    if (!attributes)
        return [];
    const parsedAttributes = JSON.parse(attributes).map(att => att.includes(USER_ATTRIBUTES) ? att.replace(USER_ATTRIBUTES, '') : att);
    return parsedAttributes;
}
function createAttributes(attributes) {
    if (!attributes)
        return {};
    const newAttributes = {};
    Object.entries(attributes).forEach(([key, value]) => {
        if (value)
            newAttributes[`${USER_ATTRIBUTES}${key}`] = value;
    });
    return newAttributes;
}
async function handleChallengeName(username, challengeName, session, challengeResponse, config, tokenOrchestrator, clientMetadata, options) {
    const userAttributes = options?.userAttributes;
    const deviceName = options?.friendlyDeviceName;
    switch (challengeName) {
        case 'SMS_MFA':
            return handleSMSMFAChallenge({
                challengeResponse,
                clientMetadata,
                session,
                username,
                config,
            });
        case 'SELECT_MFA_TYPE':
            return handleSelectMFATypeChallenge({
                challengeResponse,
                clientMetadata,
                session,
                username,
                config,
            });
        case 'MFA_SETUP':
            return handleMFASetupChallenge({
                challengeResponse,
                clientMetadata,
                session,
                username,
                deviceName,
                config,
            });
        case 'NEW_PASSWORD_REQUIRED':
            return handleCompleteNewPasswordChallenge({
                challengeResponse,
                clientMetadata,
                session,
                username,
                requiredAttributes: userAttributes,
                config,
            });
        case 'CUSTOM_CHALLENGE':
            return retryOnResourceNotFoundException(handleCustomChallenge, [
                {
                    challengeResponse,
                    clientMetadata,
                    session,
                    username,
                    config,
                    tokenOrchestrator,
                },
            ], username, tokenOrchestrator);
        case 'SOFTWARE_TOKEN_MFA':
            return handleSoftwareTokenMFAChallenge({
                challengeResponse,
                clientMetadata,
                session,
                username,
                config,
            });
    }
    // TODO: remove this error message for production apps
    throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError({
        name: _common_AuthErrorStrings_mjs__WEBPACK_IMPORTED_MODULE_16__.AuthErrorCodes.SignInException,
        message: `An error occurred during the sign in process. 
		${challengeName} challengeName returned by the underlying service was not addressed.`,
    });
}
function mapMfaType(mfa) {
    let mfaType = 'SMS_MFA';
    if (mfa === 'TOTP')
        mfaType = 'SOFTWARE_TOKEN_MFA';
    return mfaType;
}
function getMFAType(type) {
    if (type === 'SMS_MFA')
        return 'SMS';
    if (type === 'SOFTWARE_TOKEN_MFA')
        return 'TOTP';
    // TODO: log warning for unknown MFA type
}
function getMFATypes(types) {
    if (!types)
        return undefined;
    return types.map(getMFAType).filter(Boolean);
}
function parseMFATypes(mfa) {
    if (!mfa)
        return [];
    return JSON.parse(mfa);
}
function isMFATypeEnabled(challengeParams, mfaType) {
    const { MFAS_CAN_SETUP } = challengeParams;
    const mfaTypes = getMFATypes(parseMFATypes(MFAS_CAN_SETUP));
    if (!mfaTypes)
        return false;
    return mfaTypes.includes(mfaType);
}
async function assertUserNotAuthenticated() {
    let authUser;
    try {
        authUser = await (0,_apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_19__.getCurrentUser)();
    }
    catch (error) { }
    if (authUser && authUser.userId && authUser.username) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError({
            name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_20__.USER_ALREADY_AUTHENTICATED_EXCEPTION,
            message: 'There is already a signed in user.',
            recoverySuggestion: 'Call signOut before calling signIn again.',
        });
    }
}
/**
 * This function is used to kick off the device management flow.
 *
 * If an error is thrown while generating a hash device or calling the `ConfirmDevice`
 * client, then this API will ignore the error and return undefined. Otherwise the authentication
 * flow will not complete and the user won't be able to be signed in.
 *
 * @returns DeviceMetadata | undefined
 */
async function getNewDeviceMetatada(userPoolId, newDeviceMetadata, accessToken) {
    if (!newDeviceMetadata)
        return undefined;
    const userPoolName = userPoolId.split('_')[1] || '';
    const authenticationHelper = await (0,_srp_getAuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_9__.getAuthenticationHelper)(userPoolName);
    const deviceKey = newDeviceMetadata?.DeviceKey;
    const deviceGroupKey = newDeviceMetadata?.DeviceGroupKey;
    try {
        await authenticationHelper.generateHashDevice(deviceGroupKey ?? '', deviceKey ?? '');
    }
    catch (errGenHash) {
        // TODO: log error here
        return undefined;
    }
    const deviceSecretVerifierConfig = {
        Salt: _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_21__.base64Encoder.convert((0,_srp_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_22__.getBytesFromHex)(authenticationHelper.getSaltToHashDevices())),
        PasswordVerifier: _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_21__.base64Encoder.convert((0,_srp_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_22__.getBytesFromHex)(authenticationHelper.getVerifierDevices())),
    };
    const randomPassword = authenticationHelper.getRandomPassword();
    try {
        await (0,_clients_CognitoIdentityProvider_index_mjs__WEBPACK_IMPORTED_MODULE_2__.confirmDevice)({ region: (0,_clients_CognitoIdentityProvider_utils_mjs__WEBPACK_IMPORTED_MODULE_3__.getRegion)(userPoolId) }, {
            AccessToken: accessToken,
            DeviceKey: newDeviceMetadata?.DeviceKey,
            DeviceSecretVerifierConfig: deviceSecretVerifierConfig,
        });
        return {
            deviceKey,
            deviceGroupKey,
            randomPassword,
        };
    }
    catch (error) {
        // TODO: log error here
        return undefined;
    }
}
/**
 * It will retry the function if the error is a `ResourceNotFoundException` and
 * will clean the device keys stored in the storage mechanism.
 *
 */
async function retryOnResourceNotFoundException(func, args, username, tokenOrchestrator) {
    try {
        return await func(...args);
    }
    catch (error) {
        if (error instanceof _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_15__.AuthError &&
            error.name === 'ResourceNotFoundException' &&
            error.message.includes('Device does not exist.')) {
            await tokenOrchestrator.clearDeviceMetadata(username);
            return await func(...args);
        }
        throw error;
    }
}
function setActiveSignInUsername(username) {
    const { dispatch } = _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.signInStore;
    dispatch({ type: 'SET_USERNAME', value: username });
}
function getActiveSignInUsername(username) {
    const state = _signInStore_mjs__WEBPACK_IMPORTED_MODULE_6__.signInStore.getState();
    return state.username ?? username;
}


//# sourceMappingURL=signInHelpers.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/signInStore.mjs":
/*!**********************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/signInStore.mjs ***!
  \**********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cleanActiveSignInState: () => (/* binding */ cleanActiveSignInState),
/* harmony export */   setActiveSignInState: () => (/* binding */ setActiveSignInState),
/* harmony export */   signInStore: () => (/* binding */ signInStore)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const signInReducer = (state, action) => {
    switch (action.type) {
        case 'SET_SIGN_IN_SESSION':
            return {
                ...state,
                signInSession: action.value,
            };
        case 'SET_SIGN_IN_STATE':
            return {
                ...action.value,
            };
        case 'SET_CHALLENGE_NAME':
            return {
                ...state,
                challengeName: action.value,
            };
        case 'SET_USERNAME':
            return {
                ...state,
                username: action.value,
            };
        case 'SET_INITIAL_STATE':
            return defaultState();
        default:
            return state;
    }
};
function defaultState() {
    return {
        username: undefined,
        challengeName: undefined,
        signInSession: undefined,
    };
}
const createStore = reducer => {
    let currentState = reducer(defaultState(), { type: 'SET_INITIAL_STATE' });
    return {
        getState: () => currentState,
        dispatch: action => {
            currentState = reducer(currentState, action);
        },
    };
};
const signInStore = createStore(signInReducer);
function setActiveSignInState(state) {
    signInStore.dispatch({
        type: 'SET_SIGN_IN_STATE',
        value: state,
    });
}
function cleanActiveSignInState() {
    signInStore.dispatch({ type: 'SET_INITIAL_STATE' });
}


//# sourceMappingURL=signInStore.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/signInWithRedirectStore.mjs":
/*!**********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/signInWithRedirectStore.mjs ***!
  \**********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   DefaultOAuthStore: () => (/* binding */ DefaultOAuthStore)
/* harmony export */ });
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./types.mjs */ "./dist/esm/providers/cognito/utils/types.mjs");
/* harmony import */ var _tokenProvider_TokenStore_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../tokenProvider/TokenStore.mjs */ "./dist/esm/providers/cognito/tokenProvider/TokenStore.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/singleton/Auth/utils/index.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const V5_HOSTED_UI_KEY = 'amplify-signin-with-hostedUI';
const name = 'CognitoIdentityServiceProvider';
class DefaultOAuthStore {
    constructor(keyValueStorage) {
        this.keyValueStorage = keyValueStorage;
    }
    async clearOAuthInflightData() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        await Promise.all([
            this.keyValueStorage.removeItem(authKeys.inflightOAuth),
            this.keyValueStorage.removeItem(authKeys.oauthPKCE),
            this.keyValueStorage.removeItem(authKeys.oauthState),
        ]);
    }
    async clearOAuthData() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        await this.clearOAuthInflightData();
        await this.keyValueStorage.removeItem(V5_HOSTED_UI_KEY); // remove in case a customer migrated an App from v5 to v6
        return this.keyValueStorage.removeItem(authKeys.oauthSignIn);
    }
    loadOAuthState() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return this.keyValueStorage.getItem(authKeys.oauthState);
    }
    storeOAuthState(state) {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return this.keyValueStorage.setItem(authKeys.oauthState, state);
    }
    loadPKCE() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return this.keyValueStorage.getItem(authKeys.oauthPKCE);
    }
    storePKCE(pkce) {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return this.keyValueStorage.setItem(authKeys.oauthPKCE, pkce);
    }
    setAuthConfig(authConfigParam) {
        this.cognitoConfig = authConfigParam;
    }
    async loadOAuthInFlight() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return ((await this.keyValueStorage.getItem(authKeys.inflightOAuth)) === 'true');
    }
    async storeOAuthInFlight(inflight) {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return await this.keyValueStorage.setItem(authKeys.inflightOAuth, `${inflight}`);
    }
    async loadOAuthSignIn() {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        const isLegacyHostedUISignIn = await this.keyValueStorage.getItem(V5_HOSTED_UI_KEY);
        const [isOAuthSignIn, preferPrivateSession] = (await this.keyValueStorage.getItem(authKeys.oauthSignIn))?.split(',') ??
            [];
        return {
            isOAuthSignIn: isOAuthSignIn === 'true' || isLegacyHostedUISignIn === 'true',
            preferPrivateSession: preferPrivateSession === 'true',
        };
    }
    async storeOAuthSignIn(oauthSignIn, preferPrivateSession = false) {
        (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.assertTokenProviderConfig)(this.cognitoConfig);
        const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
        return await this.keyValueStorage.setItem(authKeys.oauthSignIn, `${oauthSignIn},${preferPrivateSession}`);
    }
}
const createKeysForAuthStorage = (provider, identifier) => {
    return (0,_tokenProvider_TokenStore_mjs__WEBPACK_IMPORTED_MODULE_1__.getAuthStorageKeys)(_types_mjs__WEBPACK_IMPORTED_MODULE_2__.OAuthStorageKeys)(provider, identifier);
};


//# sourceMappingURL=signInWithRedirectStore.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/signUpHelpers.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/signUpHelpers.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   autoSignInUserConfirmed: () => (/* binding */ autoSignInUserConfirmed),
/* harmony export */   autoSignInWhenUserIsConfirmedWithLink: () => (/* binding */ autoSignInWhenUserIsConfirmedWithLink),
/* harmony export */   handleCodeAutoSignIn: () => (/* binding */ handleCodeAutoSignIn),
/* harmony export */   isAutoSignInStarted: () => (/* binding */ isAutoSignInStarted),
/* harmony export */   isAutoSignInUserUsingConfirmSignUp: () => (/* binding */ isAutoSignInUserUsingConfirmSignUp),
/* harmony export */   isSignUpComplete: () => (/* binding */ isSignUpComplete),
/* harmony export */   setAutoSignInStarted: () => (/* binding */ setAutoSignInStarted),
/* harmony export */   setUsernameUsedForAutoSignIn: () => (/* binding */ setUsernameUsedForAutoSignIn)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Hub/index.mjs");
/* harmony import */ var _apis_signIn_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../apis/signIn.mjs */ "./dist/esm/providers/cognito/apis/signIn.mjs");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../apis/autoSignIn.mjs */ "./dist/esm/providers/cognito/apis/autoSignIn.mjs");
/* harmony import */ var _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../errors/constants.mjs */ "./dist/esm/errors/constants.mjs");






// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const MAX_AUTOSIGNIN_POLLING_MS = 3 * 60 * 1000;
function handleCodeAutoSignIn(signInInput) {
    const stopHubListener = _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.HubInternal.listen('auth-internal', async ({ payload }) => {
        switch (payload.event) {
            case 'confirmSignUp': {
                const response = payload.data;
                if (response?.isSignUpComplete) {
                    _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.HubInternal.dispatch('auth-internal', {
                        event: 'autoSignIn',
                    });
                    (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.setAutoSignIn)(autoSignInWithCode(signInInput));
                    stopHubListener();
                }
            }
        }
    });
    // This will stop the listener if confirmSignUp is not resolved.
    const timeOutId = setTimeout(() => {
        stopHubListener();
        setAutoSignInStarted(false);
        clearTimeout(timeOutId);
        (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
    }, MAX_AUTOSIGNIN_POLLING_MS);
}
function debounce(fun, delay) {
    let timer;
    return function (args) {
        if (!timer) {
            fun(...args);
        }
        clearTimeout(timer);
        timer = setTimeout(() => {
            timer = undefined;
        }, delay);
    };
}
function handleAutoSignInWithLink(signInInput, resolve, reject) {
    const start = Date.now();
    const autoSignInPollingIntervalId = setInterval(async () => {
        const elapsedTime = Date.now() - start;
        const maxTime = MAX_AUTOSIGNIN_POLLING_MS;
        if (elapsedTime > maxTime) {
            clearInterval(autoSignInPollingIntervalId);
            setAutoSignInStarted(false);
            reject(new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_2__.AuthError({
                name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_3__.AUTO_SIGN_IN_EXCEPTION,
                message: 'The account was not confirmed on time.',
                recoverySuggestion: 'Try to verify your account by clicking the link sent your email or phone and then login manually.',
            }));
            (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
            return;
        }
        else {
            try {
                const signInOutput = await (0,_apis_signIn_mjs__WEBPACK_IMPORTED_MODULE_4__.signIn)(signInInput);
                if (signInOutput.nextStep.signInStep !== 'CONFIRM_SIGN_UP') {
                    resolve(signInOutput);
                    clearInterval(autoSignInPollingIntervalId);
                    setAutoSignInStarted(false);
                    (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
                    return;
                }
            }
            catch (error) {
                clearInterval(autoSignInPollingIntervalId);
                setAutoSignInStarted(false);
                reject(error);
                (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
            }
        }
    }, 5000);
}
const debouncedAutoSignInWithLink = debounce(handleAutoSignInWithLink, 300);
const debouncedAutoSignWithCodeOrUserConfirmed = debounce(handleAutoSignInWithCodeOrUserConfirmed, 300);
let autoSignInStarted = false;
let usernameUsedForAutoSignIn;
function setUsernameUsedForAutoSignIn(username) {
    usernameUsedForAutoSignIn = username;
}
function isAutoSignInUserUsingConfirmSignUp(username) {
    return usernameUsedForAutoSignIn === username;
}
function isAutoSignInStarted() {
    return autoSignInStarted;
}
function setAutoSignInStarted(value) {
    if (value === false) {
        setUsernameUsedForAutoSignIn(undefined);
    }
    autoSignInStarted = value;
}
function isSignUpComplete(output) {
    return !!output.UserConfirmed;
}
function autoSignInWhenUserIsConfirmedWithLink(signInInput) {
    return async () => {
        return new Promise(async (resolve, reject) => {
            debouncedAutoSignInWithLink([signInInput, resolve, reject]);
        });
    };
}
async function handleAutoSignInWithCodeOrUserConfirmed(signInInput, resolve, reject) {
    try {
        const output = await (0,_apis_signIn_mjs__WEBPACK_IMPORTED_MODULE_4__.signIn)(signInInput);
        resolve(output);
        (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
    }
    catch (error) {
        reject(error);
        (0,_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_1__.resetAutoSignIn)();
    }
}
function autoSignInWithCode(signInInput) {
    return async () => {
        return new Promise(async (resolve, reject) => {
            debouncedAutoSignWithCodeOrUserConfirmed([signInInput, resolve, reject]);
        });
    };
}
const autoSignInUserConfirmed = autoSignInWithCode;


//# sourceMappingURL=signUpHelpers.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/AuthenticationHelper/AuthenticationHelper.mjs":
/*!********************************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/AuthenticationHelper/AuthenticationHelper.mjs ***!
  \********************************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ AuthenticationHelper)
/* harmony export */ });
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../textEncoder/index.mjs */ "./dist/esm/providers/cognito/utils/textEncoder/index.mjs");
/* harmony import */ var _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");
/* harmony import */ var _calculate_calculateS_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../calculate/calculateS.mjs */ "./dist/esm/providers/cognito/utils/srp/calculate/calculateS.mjs");
/* harmony import */ var _calculate_calculateU_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../calculate/calculateU.mjs */ "./dist/esm/providers/cognito/utils/srp/calculate/calculateU.mjs");
/* harmony import */ var _getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../getBytesFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs");
/* harmony import */ var _getHashFromData_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../getHashFromData.mjs */ "./dist/esm/providers/cognito/utils/srp/getHashFromData.mjs");
/* harmony import */ var _getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../getHashFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getHashFromHex.mjs");
/* harmony import */ var _getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../getHexFromBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getHexFromBytes.mjs");
/* harmony import */ var _getHkdfKey_mjs__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../getHkdfKey.mjs */ "./dist/esm/providers/cognito/utils/srp/getHkdfKey.mjs");
/* harmony import */ var _getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../getPaddedHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getPaddedHex.mjs");
/* harmony import */ var _getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../getRandomBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getRandomBytes.mjs");
/* harmony import */ var _getRandomString_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../getRandomString.mjs */ "./dist/esm/providers/cognito/utils/srp/getRandomString.mjs");














// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/** @class */
class AuthenticationHelper {
    constructor({ userPoolName, a, g, A, N, }) {
        this.encoder = _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_0__.textEncoder;
        this.userPoolName = userPoolName;
        this.a = a;
        this.g = g;
        this.A = A;
        this.N = N;
        this.k = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"]((0,_getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_2__.getHashFromHex)(`${(0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(N)}${(0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(g)}`), 16);
    }
    /**
     * @returns {string} Generated random value included in password hash.
     */
    getRandomPassword() {
        if (!this.randomPassword) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_4__.AuthError({
                name: 'EmptyBigIntegerRandomPassword',
                message: 'random password is empty',
            });
        }
        return this.randomPassword;
    }
    /**
     * @returns {string} Generated random value included in devices hash.
     */
    getSaltToHashDevices() {
        if (!this.saltToHashDevices) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_4__.AuthError({
                name: 'EmptyBigIntegersaltToHashDevices',
                message: 'saltToHashDevices is empty',
            });
        }
        return this.saltToHashDevices;
    }
    /**
     * @returns {string} Value used to verify devices.
     */
    getVerifierDevices() {
        if (!this.verifierDevices) {
            throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_4__.AuthError({
                name: 'EmptyBigIntegerVerifierDevices',
                message: 'verifyDevices is empty',
            });
        }
        return this.verifierDevices;
    }
    /**
     * Generate salts and compute verifier.
     *
     * @param {string} deviceGroupKey Devices to generate verifier for.
     * @param {string} username User to generate verifier for.
     *
     * @returns {Promise<void>}
     */
    async generateHashDevice(deviceGroupKey, username) {
        this.randomPassword = (0,_getRandomString_mjs__WEBPACK_IMPORTED_MODULE_5__.getRandomString)();
        const combinedString = `${deviceGroupKey}${username}:${this.randomPassword}`;
        const hashedString = (0,_getHashFromData_mjs__WEBPACK_IMPORTED_MODULE_6__.getHashFromData)(combinedString);
        const hexRandom = (0,_getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_7__.getHexFromBytes)((0,_getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_8__.getRandomBytes)(16));
        // The random hex will be unambiguously represented as a postive integer
        this.saltToHashDevices = (0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"](hexRandom, 16));
        return new Promise((resolve, reject) => {
            this.g.modPow(new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"]((0,_getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_2__.getHashFromHex)(this.saltToHashDevices + hashedString), 16), this.N, (err, result) => {
                if (err) {
                    reject(err);
                    return;
                }
                this.verifierDevices = (0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(result);
                resolve();
            });
        });
    }
    /**
     * Calculates the final HKDF key based on computed S value, computed U value and the key
     *
     * @param {String} username Username.
     * @param {String} password Password.
     * @param {AuthBigInteger} B Server B value.
     * @param {AuthBigInteger} salt Generated salt.
     */
    async getPasswordAuthenticationKey({ username, password, serverBValue, salt, }) {
        if (serverBValue.mod(this.N).equals(_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"].ZERO)) {
            throw new Error('B cannot be zero.');
        }
        const U = (0,_calculate_calculateU_mjs__WEBPACK_IMPORTED_MODULE_9__.calculateU)({
            A: this.A,
            B: serverBValue,
        });
        const usernamePassword = `${this.userPoolName}${username}:${password}`;
        const usernamePasswordHash = (0,_getHashFromData_mjs__WEBPACK_IMPORTED_MODULE_6__.getHashFromData)(usernamePassword);
        const x = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"]((0,_getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_2__.getHashFromHex)((0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(salt) + usernamePasswordHash), 16);
        const S = await (0,_calculate_calculateS_mjs__WEBPACK_IMPORTED_MODULE_10__.calculateS)({
            a: this.a,
            g: this.g,
            k: this.k,
            x,
            B: serverBValue,
            N: this.N,
            U,
        });
        const context = this.encoder.convert('Caldera Derived Key');
        const spacer = this.encoder.convert(String.fromCharCode(1));
        const info = new Uint8Array(context.byteLength + spacer.byteLength);
        info.set(context, 0);
        info.set(spacer, context.byteLength);
        const hkdfKey = (0,_getHkdfKey_mjs__WEBPACK_IMPORTED_MODULE_11__.getHkdfKey)((0,_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_12__.getBytesFromHex)((0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(S)), (0,_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_12__.getBytesFromHex)((0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_3__.getPaddedHex)(U)), info);
        return hkdfKey;
    }
}


//# sourceMappingURL=AuthenticationHelper.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs":
/*!************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs ***!
  \************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ BigInteger)
/* harmony export */ });
/* tslint:disable */
// @ts-nocheck -> BigInteger is already a vended utility
// A small implementation of BigInteger based on http://www-cs-students.stanford.edu/~tjw/jsbn/
//
// All public methods have been removed except the following:
//   new BigInteger(a, b) (only radix 2, 4, 8, 16 and 32 supported)
//   toString (only radix 2, 4, 8, 16 and 32 supported)
//   negate
//   abs
//   compareTo
//   bitLength
//   mod
//   equals
//   add
//   subtract
//   multiply
//   divide
//   modPow
/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
// (public) Constructor
function BigInteger(a, b) {
    if (a != null)
        this.fromString(a, b);
}
// return new, unset BigInteger
function nbi() {
    return new BigInteger(null, null);
}
// Bits per digit
let dbits;
// JavaScript engine analysis
const canary = 0xdeadbeefcafe;
const j_lm = (canary & 0xffffff) === 0xefcafe;
// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.
// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i, x, w, j, c, n) {
    while (--n >= 0) {
        const v = x * this[i++] + w[j] + c;
        c = Math.floor(v / 0x4000000);
        w[j++] = v & 0x3ffffff;
    }
    return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i, x, w, j, c, n) {
    const xl = x & 0x7fff, xh = x >> 15;
    while (--n >= 0) {
        let l = this[i] & 0x7fff;
        const h = this[i++] >> 15;
        const m = xh * l + h * xl;
        l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
        w[j++] = l & 0x3fffffff;
    }
    return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i, x, w, j, c, n) {
    const xl = x & 0x3fff, xh = x >> 14;
    while (--n >= 0) {
        let l = this[i] & 0x3fff;
        const h = this[i++] >> 14;
        const m = xh * l + h * xl;
        l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
        c = (l >> 28) + (m >> 14) + xh * h;
        w[j++] = l & 0xfffffff;
    }
    return c;
}
const inBrowser = typeof navigator !== 'undefined';
if (inBrowser && j_lm && navigator.appName === 'Microsoft Internet Explorer') {
    BigInteger.prototype.am = am2;
    dbits = 30;
}
else if (inBrowser && j_lm && navigator.appName !== 'Netscape') {
    BigInteger.prototype.am = am1;
    dbits = 26;
}
else {
    // Mozilla/Netscape seems to prefer am3
    BigInteger.prototype.am = am3;
    dbits = 28;
}
BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = (1 << dbits) - 1;
BigInteger.prototype.DV = 1 << dbits;
const BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;
// Digit conversions
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
const BI_RC = new Array();
let rr, vv;
rr = '0'.charCodeAt(0);
for (vv = 0; vv <= 9; ++vv)
    BI_RC[rr++] = vv;
rr = 'a'.charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
    BI_RC[rr++] = vv;
rr = 'A'.charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
    BI_RC[rr++] = vv;
function int2char(n) {
    return BI_RM.charAt(n);
}
function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return c == null ? -1 : c;
}
// (protected) copy this to r
function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i)
        r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
}
// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
    this.t = 1;
    this.s = x < 0 ? -1 : 0;
    if (x > 0)
        this[0] = x;
    else if (x < -1)
        this[0] = x + this.DV;
    else
        this.t = 0;
}
// return bigint initialized to value
function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}
// (protected) set from string and radix
function bnpFromString(s, b) {
    let k;
    if (b === 16)
        k = 4;
    else if (b === 8)
        k = 3;
    else if (b === 2)
        k = 1;
    else if (b === 32)
        k = 5;
    else if (b === 4)
        k = 2;
    else
        throw new Error('Only radix 2, 4, 8, 16, 32 are supported');
    this.t = 0;
    this.s = 0;
    let i = s.length, mi = false, sh = 0;
    while (--i >= 0) {
        const x = intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) === '-')
                mi = true;
            continue;
        }
        mi = false;
        if (sh === 0)
            this[this.t++] = x;
        else if (sh + k > this.DB) {
            this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
            this[this.t++] = x >> (this.DB - sh);
        }
        else
            this[this.t - 1] |= x << sh;
        sh += k;
        if (sh >= this.DB)
            sh -= this.DB;
    }
    this.clamp();
    if (mi)
        BigInteger.ZERO.subTo(this, this);
}
// (protected) clamp off excess high words
function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c)
        --this.t;
}
// (public) return string representation in given radix
function bnToString(b) {
    if (this.s < 0)
        return '-' + this.negate().toString(b);
    var k;
    if (b == 16)
        k = 4;
    else if (b === 8)
        k = 3;
    else if (b === 2)
        k = 1;
    else if (b === 32)
        k = 5;
    else if (b === 4)
        k = 2;
    else
        throw new Error('Only radix 2, 4, 8, 16, 32 are supported');
    let km = (1 << k) - 1, d, m = false, r = '', i = this.t;
    let p = this.DB - ((i * this.DB) % k);
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) > 0) {
            m = true;
            r = int2char(d);
        }
        while (i >= 0) {
            if (p < k) {
                d = (this[i] & ((1 << p) - 1)) << (k - p);
                d |= this[--i] >> (p += this.DB - k);
            }
            else {
                d = (this[i] >> (p -= k)) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if (d > 0)
                m = true;
            if (m)
                r += int2char(d);
        }
    }
    return m ? r : '0';
}
// (public) -this
function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
}
// (public) |this|
function bnAbs() {
    return this.s < 0 ? this.negate() : this;
}
// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0)
        return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0)
        return this.s < 0 ? -r : r;
    while (--i >= 0)
        if ((r = this[i] - a[i]) != 0)
            return r;
    return 0;
}
// returns bit length of the integer x
function nbits(x) {
    var r = 1, t;
    if ((t = x >>> 16) !== 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) !== 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) !== 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) !== 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) !== 0) {
        x = t;
        r += 1;
    }
    return r;
}
// (public) return the number of bits in "this"
function bnBitLength() {
    if (this.t <= 0)
        return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
}
// (protected) r = this << n*DB
function bnpDLShiftTo(n, r) {
    let i;
    for (i = this.t - 1; i >= 0; --i)
        r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i)
        r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
}
// (protected) r = this >> n*DB
function bnpDRShiftTo(n, r) {
    for (let i = n; i < this.t; ++i)
        r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
}
// (protected) r = this << n
function bnpLShiftTo(n, r) {
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << cbs) - 1;
    let ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
    for (i = this.t - 1; i >= 0; --i) {
        r[i + ds + 1] = (this[i] >> cbs) | c;
        c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i)
        r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
}
// (protected) r = this >> n
function bnpRShiftTo(n, r) {
    r.s = this.s;
    const ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
        r.t = 0;
        return;
    }
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (let i = ds + 1; i < this.t; ++i) {
        r[i - ds - 1] |= (this[i] & bm) << cbs;
        r[i - ds] = this[i] >> bs;
    }
    if (bs > 0)
        r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
}
// (protected) r = this - a
function bnpSubTo(a, r) {
    let i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] - a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c -= a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c -= a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c < -1)
        r[i++] = this.DV + c;
    else if (c > 0)
        r[i++] = c;
    r.t = i;
    r.clamp();
}
// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a, r) {
    const x = this.abs(), y = a.abs();
    let i = x.t;
    r.t = i + y.t;
    while (--i >= 0)
        r[i] = 0;
    for (i = 0; i < y.t; ++i)
        r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s !== a.s)
        BigInteger.ZERO.subTo(r, r);
}
// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
    var x = this.abs();
    var i = (r.t = 2 * x.t);
    while (--i >= 0)
        r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
        var c = x.am(i, x[i], r, 2 * i, 0, 1);
        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >=
            x.DV) {
            r[i + x.t] -= x.DV;
            r[i + x.t + 1] = 1;
        }
    }
    if (r.t > 0)
        r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}
// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0)
        return;
    var pt = this.abs();
    if (pt.t < pm.t) {
        if (q != null)
            q.fromInt(0);
        if (r != null)
            this.copyTo(r);
        return;
    }
    if (r === null)
        r = nbi();
    var y = nbi(), ts = this.s, ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]);
    // normalize modulus
    if (nsh > 0) {
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
    }
    else {
        pm.copyTo(y);
        pt.copyTo(r);
    }
    const ys = y.t;
    const y0 = y[ys - 1];
    if (y0 === 0)
        return;
    const yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
    const d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
    let i = r.t, j = i - ys, t = q === null ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
        r[r.t++] = 1;
        r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);
    // "negative" y so we can replace sub with am later
    while (y.t < ys)
        y[y.t++] = 0;
    while (--j >= 0) {
        // Estimate quotient digit
        var qd = r[--i] === y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
            // Try it out
            y.dlShiftTo(j, t);
            r.subTo(t, r);
            while (r[i] < --qd)
                r.subTo(t, r);
        }
    }
    if (q !== null) {
        r.drShiftTo(ys, q);
        if (ts !== ms)
            BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0)
        r.rShiftTo(nsh, r);
    // Denormalize remainder
    if (ts < 0)
        BigInteger.ZERO.subTo(r, r);
}
// (public) this mod a
function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
        a.subTo(r, r);
    return r;
}
// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
    if (this.t < 1)
        return 0;
    var x = this[0];
    if ((x & 1) === 0)
        return 0;
    var y = x & 3;
    // y == 1/x mod 2^2
    y = (y * (2 - (x & 0xf) * y)) & 0xf;
    // y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff;
    // y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
    // y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    y = (y * (2 - ((x * y) % this.DV))) % this.DV;
    // y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return y > 0 ? this.DV - y : -y;
}
function bnEquals(a) {
    return this.compareTo(a) === 0;
}
// (protected) r = this + a
function bnpAddTo(a, r) {
    let i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] + a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c += a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c += a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c > 0)
        r[i++] = c;
    else if (c < -1)
        r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
}
// (public) this + a
function bnAdd(a) {
    var r = nbi();
    this.addTo(a, r);
    return r;
}
// (public) this - a
function bnSubtract(a) {
    var r = nbi();
    this.subTo(a, r);
    return r;
}
// (public) this * a
function bnMultiply(a) {
    var r = nbi();
    this.multiplyTo(a, r);
    return r;
}
// (public) this / a
function bnDivide(a) {
    var r = nbi();
    this.divRemTo(a, r, null);
    return r;
}
// Montgomery reduction
function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
}
// xR mod m
function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
        this.m.subTo(r, r);
    return r;
}
// x/R mod m
function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
}
// x = x/R mod m (HAC 14.32)
function montReduce(x) {
    while (x.t <= this.mt2)
        // pad x so am has enough room later
        x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {
        // faster way of calculating u0 = x[i]*mp mod DV
        var j = x[i] & 0x7fff;
        var u0 = (j * this.mpl +
            (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) &
            x.DM;
        // use am to combine the multiply-shift-add into one call
        j = i + this.m.t;
        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
        // propagate carry
        while (x[j] >= x.DV) {
            x[j] -= x.DV;
            x[++j]++;
        }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0)
        x.subTo(this.m, x);
}
// r = "x^2/R mod m"; x != r
function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}
// r = "xy/R mod m"; x,y != r
function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}
Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;
// (public) this^e % m (HAC 14.85)
function bnModPow(e, m, callback) {
    let i = e.bitLength(), k, r = nbv(1), z = new Montgomery(m);
    if (i <= 0)
        return r;
    else if (i < 18)
        k = 1;
    else if (i < 48)
        k = 3;
    else if (i < 144)
        k = 4;
    else if (i < 768)
        k = 5;
    else
        k = 6;
    // precomputation
    let g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
        const g2 = nbi();
        z.sqrTo(g[1], g2);
        while (n <= km) {
            g[n] = nbi();
            z.mulTo(g2, g[n - 2], g[n]);
            n += 2;
        }
    }
    let j = e.t - 1, w, is1 = true, r2 = nbi(), t;
    i = nbits(e[j]) - 1;
    while (j >= 0) {
        if (i >= k1)
            w = (e[j] >> (i - k1)) & km;
        else {
            w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
            if (j > 0)
                w |= e[j - 1] >> (this.DB + i - k1);
        }
        n = k;
        while ((w & 1) === 0) {
            w >>= 1;
            --n;
        }
        if ((i -= n) < 0) {
            i += this.DB;
            --j;
        }
        if (is1) {
            // ret == 1, don't bother squaring or multiplying it
            g[w].copyTo(r);
            is1 = false;
        }
        else {
            while (n > 1) {
                z.sqrTo(r, r2);
                z.sqrTo(r2, r);
                n -= 2;
            }
            if (n > 0)
                z.sqrTo(r, r2);
            else {
                t = r;
                r = r2;
                r2 = t;
            }
            z.mulTo(r2, g[w], r);
        }
        while (j >= 0 && (e[j] & (1 << i)) === 0) {
            z.sqrTo(r, r2);
            t = r;
            r = r2;
            r2 = t;
            if (--i < 0) {
                i = this.DB - 1;
                --j;
            }
        }
    }
    var result = z.revert(r);
    callback(null, result);
    return result;
}
// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.addTo = bnpAddTo;
// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.modPow = bnModPow;
// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);


//# sourceMappingURL=BigInteger.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/calculate/calculateA.mjs":
/*!***********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/calculate/calculateA.mjs ***!
  \***********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   calculateA: () => (/* binding */ calculateA)
/* harmony export */ });
/* harmony import */ var _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * @internal
 */
const calculateA = async ({ a, g, N, }) => {
    return new Promise((resolve, reject) => {
        g.modPow(a, N, (err, A) => {
            if (err) {
                reject(err);
                return;
            }
            if (A.mod(N).equals(_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"].ZERO)) {
                reject(new Error('Illegal parameter. A mod N cannot be 0.'));
                return;
            }
            resolve(A);
        });
    });
};


//# sourceMappingURL=calculateA.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/calculate/calculateS.mjs":
/*!***********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/calculate/calculateS.mjs ***!
  \***********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   calculateS: () => (/* binding */ calculateS)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * @internal
 */
const calculateS = async ({ a, g, k, x, B, N, U, }) => {
    return new Promise((resolve, reject) => {
        g.modPow(x, N, (outerErr, outerResult) => {
            if (outerErr) {
                reject(outerErr);
                return;
            }
            B.subtract(k.multiply(outerResult)).modPow(a.add(U.multiply(x)), N, (innerErr, innerResult) => {
                if (innerErr) {
                    reject(innerErr);
                    return;
                }
                resolve(innerResult.mod(N));
            });
        });
    });
};


//# sourceMappingURL=calculateS.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/calculate/calculateU.mjs":
/*!***********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/calculate/calculateU.mjs ***!
  \***********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   calculateU: () => (/* binding */ calculateU)
/* harmony export */ });
/* harmony import */ var _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");
/* harmony import */ var _getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../getHashFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getHashFromHex.mjs");
/* harmony import */ var _getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../getPaddedHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getPaddedHex.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * @internal
 */
const calculateU = ({ A, B, }) => {
    const U = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"]((0,_getHashFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__.getHashFromHex)((0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_2__.getPaddedHex)(A) + (0,_getPaddedHex_mjs__WEBPACK_IMPORTED_MODULE_2__.getPaddedHex)(B)), 16);
    if (U.equals(_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"].ZERO)) {
        throw new Error('U cannot be zero.');
    }
    return U;
};


//# sourceMappingURL=calculateU.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/constants.mjs":
/*!************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/constants.mjs ***!
  \************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HEX_TO_SHORT: () => (/* binding */ HEX_TO_SHORT),
/* harmony export */   INIT_N: () => (/* binding */ INIT_N),
/* harmony export */   SHORT_TO_HEX: () => (/* binding */ SHORT_TO_HEX)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const INIT_N = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
const SHORT_TO_HEX = {};
const HEX_TO_SHORT = {};
for (let i = 0; i < 256; i++) {
    let encodedByte = i.toString(16).toLowerCase();
    if (encodedByte.length === 1) {
        encodedByte = `0${encodedByte}`;
    }
    SHORT_TO_HEX[i] = encodedByte;
    HEX_TO_SHORT[encodedByte] = i;
}


//# sourceMappingURL=constants.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getAuthenticationHelper.mjs":
/*!**************************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getAuthenticationHelper.mjs ***!
  \**************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getAuthenticationHelper: () => (/* binding */ getAuthenticationHelper)
/* harmony export */ });
/* harmony import */ var _AuthenticationHelper_AuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./AuthenticationHelper/AuthenticationHelper.mjs */ "./dist/esm/providers/cognito/utils/srp/AuthenticationHelper/AuthenticationHelper.mjs");
/* harmony import */ var _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");
/* harmony import */ var _calculate_calculateA_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./calculate/calculateA.mjs */ "./dist/esm/providers/cognito/utils/srp/calculate/calculateA.mjs");
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./constants.mjs */ "./dist/esm/providers/cognito/utils/srp/constants.mjs");
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");
/* harmony import */ var _getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./getHexFromBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getHexFromBytes.mjs");
/* harmony import */ var _getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./getRandomBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getRandomBytes.mjs");








// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Returns a new {@link AuthenticationHelper} instance with randomly generated BigInteger seed
 *
 * @param userPoolName Cognito user pool name.
 * @returns An {@link AuthenticationHelper} instance.
 *
 * @internal
 */
const getAuthenticationHelper = async (userPoolName) => {
    const N = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"](_constants_mjs__WEBPACK_IMPORTED_MODULE_2__.INIT_N, 16);
    const g = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"]('2', 16);
    const a = generateRandomBigInteger();
    const A = await (0,_calculate_calculateA_mjs__WEBPACK_IMPORTED_MODULE_3__.calculateA)({ a, g, N });
    return new _AuthenticationHelper_AuthenticationHelper_mjs__WEBPACK_IMPORTED_MODULE_4__["default"]({ userPoolName, a, g, A, N });
};
/**
 * Generates a random BigInteger.
 *
 * @returns {BigInteger} a random value.
 */
const generateRandomBigInteger = () => {
    // This will be interpreted as a postive 128-bit integer
    const hexRandom = (0,_getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_5__.getHexFromBytes)((0,_getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_6__.getRandomBytes)(128));
    // There is no need to do randomBigInt.mod(this.N - 1) as N (3072-bit) is > 128 bytes (1024-bit)
    return new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_1__["default"](hexRandom, 16);
};


//# sourceMappingURL=getAuthenticationHelper.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getBytesFromHex: () => (/* binding */ getBytesFromHex)
/* harmony export */ });
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants.mjs */ "./dist/esm/providers/cognito/utils/srp/constants.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Converts a hexadecimal encoded string to a Uint8Array of bytes.
 *
 * @param encoded The hexadecimal encoded string
 */
const getBytesFromHex = (encoded) => {
    if (encoded.length % 2 !== 0) {
        throw new Error('Hex encoded strings must have an even number length');
    }
    const out = new Uint8Array(encoded.length / 2);
    for (let i = 0; i < encoded.length; i += 2) {
        const encodedByte = encoded.slice(i, i + 2).toLowerCase();
        if (encodedByte in _constants_mjs__WEBPACK_IMPORTED_MODULE_0__.HEX_TO_SHORT) {
            out[i / 2] = _constants_mjs__WEBPACK_IMPORTED_MODULE_0__.HEX_TO_SHORT[encodedByte];
        }
        else {
            throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
        }
    }
    return out;
};


//# sourceMappingURL=getBytesFromHex.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getHashFromData.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getHashFromData.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getHashFromData: () => (/* binding */ getHashFromData)
/* harmony export */ });
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");
/* harmony import */ var _getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./getHexFromBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getHexFromBytes.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Calculate a hash from a `SourceData`
 * @param {SourceData} data Value to hash.
 * @returns {string} Hex-encoded hash.
 * @private
 */
const getHashFromData = (data) => {
    const sha256 = new _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__.Sha256();
    sha256.update(data);
    const hashedData = sha256.digestSync();
    const hashHexFromUint8 = (0,_getHexFromBytes_mjs__WEBPACK_IMPORTED_MODULE_1__.getHexFromBytes)(hashedData);
    return new Array(64 - hashHexFromUint8.length).join('0') + hashHexFromUint8;
};


//# sourceMappingURL=getHashFromData.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getHashFromHex.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getHashFromHex.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getHashFromHex: () => (/* binding */ getHashFromHex)
/* harmony export */ });
/* harmony import */ var _getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./getBytesFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs");
/* harmony import */ var _getHashFromData_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./getHashFromData.mjs */ "./dist/esm/providers/cognito/utils/srp/getHashFromData.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Calculate a hash from a hex string
 * @param {string} hexStr Value to hash.
 * @returns {string} Hex-encoded hash.
 * @private
 */
const getHashFromHex = (hexStr) => (0,_getHashFromData_mjs__WEBPACK_IMPORTED_MODULE_0__.getHashFromData)((0,_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__.getBytesFromHex)(hexStr));


//# sourceMappingURL=getHashFromHex.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getHexFromBytes.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getHexFromBytes.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getHexFromBytes: () => (/* binding */ getHexFromBytes)
/* harmony export */ });
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants.mjs */ "./dist/esm/providers/cognito/utils/srp/constants.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Converts a Uint8Array of binary data to a hexadecimal encoded string.
 *
 * @param bytes The binary data to encode
 */
const getHexFromBytes = (bytes) => {
    let out = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        out += _constants_mjs__WEBPACK_IMPORTED_MODULE_0__.SHORT_TO_HEX[bytes[i]];
    }
    return out;
};


//# sourceMappingURL=getHexFromBytes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getHkdfKey.mjs":
/*!*************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getHkdfKey.mjs ***!
  \*************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getHkdfKey: () => (/* binding */ getHkdfKey)
/* harmony export */ });
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Standard HKDF algorithm.
 *
 * @param {Uint8Array} ikm Input key material.
 * @param {Uint8Array} salt Salt value.
 * @param {Uint8Array} info Context and application specific info.
 *
 * @returns {Uint8Array} Strong key material.
 *
 * @internal
 */
const getHkdfKey = (ikm, salt, info) => {
    const awsCryptoHash = new _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__.Sha256(salt);
    awsCryptoHash.update(ikm);
    const resultFromAWSCryptoPrk = awsCryptoHash.digestSync();
    const awsCryptoHashHmac = new _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__.Sha256(resultFromAWSCryptoPrk);
    awsCryptoHashHmac.update(info);
    const resultFromAWSCryptoHmac = awsCryptoHashHmac.digestSync();
    const hashHexFromAWSCrypto = resultFromAWSCryptoHmac;
    return hashHexFromAWSCrypto.slice(0, 16);
};


//# sourceMappingURL=getHkdfKey.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getNowString.mjs":
/*!***************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getNowString.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getNowString: () => (/* binding */ getNowString)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const MONTH_NAMES = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
];
const WEEK_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const getNowString = () => {
    const now = new Date();
    const weekDay = WEEK_NAMES[now.getUTCDay()];
    const month = MONTH_NAMES[now.getUTCMonth()];
    const day = now.getUTCDate();
    let hours = now.getUTCHours();
    if (hours < 10) {
        hours = `0${hours}`;
    }
    let minutes = now.getUTCMinutes();
    if (minutes < 10) {
        minutes = `0${minutes}`;
    }
    let seconds = now.getUTCSeconds();
    if (seconds < 10) {
        seconds = `0${seconds}`;
    }
    const year = now.getUTCFullYear();
    // ddd MMM D HH:mm:ss UTC YYYY
    const dateNow = `${weekDay} ${month} ${day} ${hours}:${minutes}:${seconds} UTC ${year}`;
    return dateNow;
};


//# sourceMappingURL=getNowString.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getPaddedHex.mjs":
/*!***************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getPaddedHex.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getPaddedHex: () => (/* binding */ getPaddedHex)
/* harmony export */ });
/* harmony import */ var _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./BigInteger/BigInteger.mjs */ "./dist/esm/providers/cognito/utils/srp/BigInteger/BigInteger.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Tests if a hex string has it most significant bit set (case-insensitive regex)
 */
const HEX_MSB_REGEX = /^[89a-f]/i;
/**
 * Returns an unambiguous, even-length hex string of the two's complement encoding of an integer.
 *
 * It is compatible with the hex encoding of Java's BigInteger's toByteArray(), wich returns a
 * byte array containing the two's-complement representation of a BigInteger. The array contains
 * the minimum number of bytes required to represent the BigInteger, including at least one sign bit.
 *
 * Examples showing how ambiguity is avoided by left padding with:
 * 	"00" (for positive values where the most-significant-bit is set)
 *  "FF" (for negative values where the most-significant-bit is set)
 *
 * padHex(bigInteger.fromInt(-236))  === "FF14"
 * padHex(bigInteger.fromInt(20))    === "14"
 *
 * padHex(bigInteger.fromInt(-200))  === "FF38"
 * padHex(bigInteger.fromInt(56))    === "38"
 *
 * padHex(bigInteger.fromInt(-20))   === "EC"
 * padHex(bigInteger.fromInt(236))   === "00EC"
 *
 * padHex(bigInteger.fromInt(-56))   === "C8"
 * padHex(bigInteger.fromInt(200))   === "00C8"
 *
 * @param {AuthBigInteger} bigInt Number to encode.
 * @returns {String} even-length hex string of the two's complement encoding.
 */
const getPaddedHex = (bigInt) => {
    if (!(bigInt instanceof _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"])) {
        throw new Error('Not a BigInteger');
    }
    const isNegative = bigInt.compareTo(_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"].ZERO) < 0;
    /* Get a hex string for abs(bigInt) */
    let hexStr = bigInt.abs().toString(16);
    /* Pad hex to even length if needed */
    hexStr = hexStr.length % 2 !== 0 ? `0${hexStr}` : hexStr;
    /* Prepend "00" if the most significant bit is set */
    hexStr = HEX_MSB_REGEX.test(hexStr) ? `00${hexStr}` : hexStr;
    if (isNegative) {
        /* Flip the bits of the representation */
        const invertedNibbles = hexStr
            .split('')
            .map((x) => {
            const invertedNibble = ~parseInt(x, 16) & 0xf;
            return '0123456789ABCDEF'.charAt(invertedNibble);
        })
            .join('');
        /* After flipping the bits, add one to get the 2's complement representation */
        const flippedBitsBI = new _BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"](invertedNibbles, 16).add(_BigInteger_BigInteger_mjs__WEBPACK_IMPORTED_MODULE_0__["default"].ONE);
        hexStr = flippedBitsBI.toString(16);
        /*
        For hex strings starting with 'FF8', 'FF' can be dropped, e.g. 0xFFFF80=0xFF80=0x80=-128

        Any sequence of '1' bits on the left can always be substituted with a single '1' bit
        without changing the represented value.

        This only happens in the case when the input is 80...00
        */
        if (hexStr.toUpperCase().startsWith('FF8')) {
            hexStr = hexStr.substring(2);
        }
    }
    return hexStr;
};


//# sourceMappingURL=getPaddedHex.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getRandomBytes.mjs":
/*!*****************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getRandomBytes.mjs ***!
  \*****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getRandomBytes: () => (/* binding */ getRandomBytes)
/* harmony export */ });
/* harmony import */ var _getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./getBytesFromHex.mjs */ "./dist/esm/providers/cognito/utils/srp/getBytesFromHex.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/WordArray.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Returns a Uint8Array with a sequence of random nBytes
 *
 * @param {number} nBytes
 * @returns {Uint8Array} fixed-length sequence of random bytes
 */
const getRandomBytes = (nBytes) => {
    const str = new _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__["default"]().random(nBytes).toString();
    return (0,_getBytesFromHex_mjs__WEBPACK_IMPORTED_MODULE_1__.getBytesFromHex)(str);
};


//# sourceMappingURL=getRandomBytes.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getRandomString.mjs":
/*!******************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getRandomString.mjs ***!
  \******************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getRandomString: () => (/* binding */ getRandomString)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/convert/base64/base64Encoder.mjs");
/* harmony import */ var _getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./getRandomBytes.mjs */ "./dist/esm/providers/cognito/utils/srp/getRandomBytes.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Helper function to generate a random string
 * @returns {string} a random value.
 *
 * @internal
 */
const getRandomString = () => _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.base64Encoder.convert((0,_getRandomBytes_mjs__WEBPACK_IMPORTED_MODULE_1__.getRandomBytes)(40));


//# sourceMappingURL=getRandomString.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/srp/getSignatureString.mjs":
/*!*********************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/srp/getSignatureString.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getSignatureString: () => (/* binding */ getSignatureString)
/* harmony export */ });
/* harmony import */ var _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-crypto/sha256-js */ "../../node_modules/@aws-crypto/sha256-js/build/index.js");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/convert/base64/base64Encoder.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/utils/convert/base64/base64Decoder.mjs");
/* harmony import */ var _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../textEncoder/index.mjs */ "./dist/esm/providers/cognito/utils/textEncoder/index.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const getSignatureString = ({ userPoolName, username, challengeParameters, dateNow, hkdf, }) => {
    const bufUPIDaToB = _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_1__.textEncoder.convert(userPoolName);
    const bufUNaToB = _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_1__.textEncoder.convert(username);
    const bufSBaToB = urlB64ToUint8Array(challengeParameters.SECRET_BLOCK);
    const bufDNaToB = _textEncoder_index_mjs__WEBPACK_IMPORTED_MODULE_1__.textEncoder.convert(dateNow);
    const bufConcat = new Uint8Array(bufUPIDaToB.byteLength +
        bufUNaToB.byteLength +
        bufSBaToB.byteLength +
        bufDNaToB.byteLength);
    bufConcat.set(bufUPIDaToB, 0);
    bufConcat.set(bufUNaToB, bufUPIDaToB.byteLength);
    bufConcat.set(bufSBaToB, bufUPIDaToB.byteLength + bufUNaToB.byteLength);
    bufConcat.set(bufDNaToB, bufUPIDaToB.byteLength + bufUNaToB.byteLength + bufSBaToB.byteLength);
    const awsCryptoHash = new _aws_crypto_sha256_js__WEBPACK_IMPORTED_MODULE_0__.Sha256(hkdf);
    awsCryptoHash.update(bufConcat);
    const resultFromAWSCrypto = awsCryptoHash.digestSync();
    const signatureString = _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_2__.base64Encoder.convert(resultFromAWSCrypto);
    return signatureString;
};
const urlB64ToUint8Array = (base64String) => {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
    const rawData = _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_3__.base64Decoder.convert(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
};


//# sourceMappingURL=getSignatureString.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/textEncoder/index.mjs":
/*!****************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/textEncoder/index.mjs ***!
  \****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   textEncoder: () => (/* binding */ textEncoder)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const textEncoder = {
    convert(input) {
        return new TextEncoder().encode(input);
    },
};


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/types.mjs":
/*!****************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/types.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   OAuthStorageKeys: () => (/* binding */ OAuthStorageKeys),
/* harmony export */   assertAuthTokens: () => (/* binding */ assertAuthTokens),
/* harmony export */   assertAuthTokensWithRefreshToken: () => (/* binding */ assertAuthTokensWithRefreshToken),
/* harmony export */   assertDeviceMetadata: () => (/* binding */ assertDeviceMetadata),
/* harmony export */   assertIdTokenInAuthTokens: () => (/* binding */ assertIdTokenInAuthTokens),
/* harmony export */   isTypeUserPoolConfig: () => (/* binding */ isTypeUserPoolConfig),
/* harmony export */   oAuthTokenRefreshException: () => (/* binding */ oAuthTokenRefreshException),
/* harmony export */   tokenRefreshException: () => (/* binding */ tokenRefreshException)
/* harmony export */ });
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");
/* harmony import */ var _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../errors/constants.mjs */ "./dist/esm/errors/constants.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function isTypeUserPoolConfig(authConfig) {
    if (authConfig &&
        authConfig.Cognito.userPoolId &&
        authConfig.Cognito.userPoolClientId) {
        return true;
    }
    return false;
}
function assertAuthTokens(tokens) {
    if (!tokens || !tokens.accessToken) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.USER_UNAUTHENTICATED_EXCEPTION,
            message: 'User needs to be authenticated to call this API.',
            recoverySuggestion: 'Sign in before calling this API again.',
        });
    }
}
function assertIdTokenInAuthTokens(tokens) {
    if (!tokens || !tokens.idToken) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.USER_UNAUTHENTICATED_EXCEPTION,
            message: 'User needs to be authenticated to call this API.',
            recoverySuggestion: 'Sign in before calling this API again.',
        });
    }
}
const oAuthTokenRefreshException = new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
    name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.TOKEN_REFRESH_EXCEPTION,
    message: `Token refresh is not supported when authenticated with the 'implicit grant' (token) oauth flow. 
	Please change your oauth configuration to use 'code grant' flow.`,
    recoverySuggestion: `Please logout and change your Amplify configuration to use "code grant" flow. 
	E.g { responseType: 'code' }`,
});
const tokenRefreshException = new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
    name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.USER_UNAUTHENTICATED_EXCEPTION,
    message: 'User needs to be authenticated to call this API.',
    recoverySuggestion: 'Sign in before calling this API again.',
});
function assertAuthTokensWithRefreshToken(tokens) {
    if (isAuthenticatedWithImplicitOauthFlow(tokens)) {
        throw oAuthTokenRefreshException;
    }
    if (!isAuthenticatedWithRefreshToken(tokens)) {
        throw tokenRefreshException;
    }
}
function assertDeviceMetadata(deviceMetadata) {
    if (!deviceMetadata ||
        !deviceMetadata.deviceKey ||
        !deviceMetadata.deviceGroupKey ||
        !deviceMetadata.randomPassword) {
        throw new _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthError({
            name: _errors_constants_mjs__WEBPACK_IMPORTED_MODULE_1__.DEVICE_METADATA_NOT_FOUND_EXCEPTION,
            message: 'Either deviceKey, deviceGroupKey or secretPassword were not found during the sign-in process.',
            recoverySuggestion: 'Make sure to not clear storage after calling the signIn API.',
        });
    }
}
const OAuthStorageKeys = {
    inflightOAuth: 'inflightOAuth',
    oauthSignIn: 'oauthSignIn',
    oauthPKCE: 'oauthPKCE',
    oauthState: 'oauthState',
};
function isAuthenticated(tokens) {
    return tokens?.accessToken || tokens?.idToken;
}
function isAuthenticatedWithRefreshToken(tokens) {
    return isAuthenticated(tokens) && tokens?.refreshToken;
}
function isAuthenticatedWithImplicitOauthFlow(tokens) {
    return isAuthenticated(tokens) && !tokens?.refreshToken;
}


//# sourceMappingURL=types.mjs.map


/***/ }),

/***/ "./dist/esm/providers/cognito/utils/userContextData.mjs":
/*!**************************************************************!*\
  !*** ./dist/esm/providers/cognito/utils/userContextData.mjs ***!
  \**************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getUserContextData: () => (/* binding */ getUserContextData)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function getUserContextData({ username, userPoolId, userPoolClientId, }) {
    if (typeof window === 'undefined') {
        return undefined;
    }
    const amazonCognitoAdvancedSecurityData = window
        .AmazonCognitoAdvancedSecurityData;
    if (typeof amazonCognitoAdvancedSecurityData === 'undefined') {
        return undefined;
    }
    const advancedSecurityData = amazonCognitoAdvancedSecurityData.getData(username, userPoolId, userPoolClientId);
    if (advancedSecurityData) {
        const userContextData = {
            EncodedData: advancedSecurityData,
        };
        return userContextData;
    }
    return {};
}


//# sourceMappingURL=userContextData.mjs.map


/***/ }),

/***/ "./dist/esm/types/Auth.mjs":
/*!*********************************!*\
  !*** ./dist/esm/types/Auth.mjs ***!
  \*********************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthErrorTypes: () => (/* binding */ AuthErrorTypes)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var AuthErrorTypes;
(function (AuthErrorTypes) {
    AuthErrorTypes["NoConfig"] = "noConfig";
    AuthErrorTypes["MissingAuthConfig"] = "missingAuthConfig";
    AuthErrorTypes["EmptyUsername"] = "emptyUsername";
    AuthErrorTypes["InvalidUsername"] = "invalidUsername";
    AuthErrorTypes["EmptyPassword"] = "emptyPassword";
    AuthErrorTypes["EmptyCode"] = "emptyCode";
    AuthErrorTypes["SignUpError"] = "signUpError";
    AuthErrorTypes["NoMFA"] = "noMFA";
    AuthErrorTypes["InvalidMFA"] = "invalidMFA";
    AuthErrorTypes["EmptyChallengeResponse"] = "emptyChallengeResponse";
    AuthErrorTypes["NoUserSession"] = "noUserSession";
    AuthErrorTypes["Default"] = "default";
    AuthErrorTypes["DeviceConfig"] = "deviceConfig";
    AuthErrorTypes["NetworkError"] = "networkError";
    AuthErrorTypes["AutoSignInError"] = "autoSignInError";
    AuthErrorTypes["OAuthSignInError"] = "oauthSignInError";
})(AuthErrorTypes || (AuthErrorTypes = {}));


//# sourceMappingURL=Auth.mjs.map


/***/ }),

/***/ "./dist/esm/utils/getAuthUserAgentValue.mjs":
/*!**************************************************!*\
  !*** ./dist/esm/utils/getAuthUserAgentValue.mjs ***!
  \**************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getAuthUserAgentValue: () => (/* binding */ getAuthUserAgentValue)
/* harmony export */ });
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/index.mjs");
/* harmony import */ var _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @aws-amplify/core/internals/utils */ "../core/dist/esm/Platform/types.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const getAuthUserAgentValue = (action, customUserAgentDetails) => (0,_aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_0__.getAmplifyUserAgent)({
    category: _aws_amplify_core_internals_utils__WEBPACK_IMPORTED_MODULE_1__.Category.Auth,
    action,
    ...customUserAgentDetails,
});


//# sourceMappingURL=getAuthUserAgentValue.mjs.map


/***/ }),

/***/ "../core/dist/esm/Hub/index.mjs":
/*!**************************************!*\
  !*** ../core/dist/esm/Hub/index.mjs ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AMPLIFY_SYMBOL: () => (/* binding */ AMPLIFY_SYMBOL),
/* harmony export */   Hub: () => (/* binding */ Hub),
/* harmony export */   HubClass: () => (/* binding */ HubClass),
/* harmony export */   HubInternal: () => (/* binding */ HubInternal)
/* harmony export */ });
/* harmony import */ var _Logger_ConsoleLogger_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../Logger/ConsoleLogger.mjs */ "../core/dist/esm/Logger/ConsoleLogger.mjs");
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../constants.mjs */ "../core/dist/esm/constants.mjs");
/* harmony import */ var _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../errors/AmplifyError.mjs */ "../core/dist/esm/errors/AmplifyError.mjs");






// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const AMPLIFY_SYMBOL = (typeof Symbol !== 'undefined'
    ? Symbol('amplify_default')
    : '@@amplify_default');
const logger = new _Logger_ConsoleLogger_mjs__WEBPACK_IMPORTED_MODULE_0__.ConsoleLogger('Hub');
class HubClass {
    constructor(name) {
        this.listeners = new Map();
        this.protectedChannels = [
            'core',
            'auth',
            'api',
            'analytics',
            'interactions',
            'pubsub',
            'storage',
            'ui',
            'xr',
        ];
        this.name = name;
    }
    /**
     * Used internally to remove a Hub listener.
     *
     * @remarks
     * This private method is for internal use only. Instead of calling Hub.remove, call the result of Hub.listen.
     */
    _remove(channel, listener) {
        const holder = this.listeners.get(channel);
        if (!holder) {
            logger.warn(`No listeners for ${channel}`);
            return;
        }
        this.listeners.set(channel, [
            ...holder.filter(({ callback }) => callback !== listener),
        ]);
    }
    dispatch(channel, payload, source, ampSymbol) {
        if (typeof channel === 'string' &&
            this.protectedChannels.indexOf(channel) > -1) {
            const hasAccess = ampSymbol === AMPLIFY_SYMBOL;
            if (!hasAccess) {
                logger.warn(`WARNING: ${channel} is protected and dispatching on it can have unintended consequences`);
            }
        }
        const capsule = {
            channel,
            payload: { ...payload },
            source,
            patternInfo: [],
        };
        try {
            this._toListeners(capsule);
        }
        catch (e) {
            logger.error(e);
        }
    }
    listen(channel, callback, listenerName = 'noname') {
        let cb;
        if (typeof callback !== 'function') {
            throw new _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_1__.AmplifyError({
                name: _constants_mjs__WEBPACK_IMPORTED_MODULE_2__.NO_HUBCALLBACK_PROVIDED_EXCEPTION,
                message: 'No callback supplied to Hub',
            });
        }
        else {
            // Needs to be casted as a more generic type
            cb = callback;
        }
        let holder = this.listeners.get(channel);
        if (!holder) {
            holder = [];
            this.listeners.set(channel, holder);
        }
        holder.push({
            name: listenerName,
            callback: cb,
        });
        return () => {
            this._remove(channel, cb);
        };
    }
    _toListeners(capsule) {
        const { channel, payload } = capsule;
        const holder = this.listeners.get(channel);
        if (holder) {
            holder.forEach(listener => {
                logger.debug(`Dispatching to ${channel} with `, payload);
                try {
                    listener.callback(capsule);
                }
                catch (e) {
                    logger.error(e);
                }
            });
        }
    }
}
/*We export a __default__ instance of HubClass to use it as a
pseudo Singleton for the main messaging bus, however you can still create
your own instance of HubClass() for a separate "private bus" of events.*/
const Hub = new HubClass('__default__');
/**
 * @internal
 *
 * Internal hub used for core Amplify functionality. Not intended for use outside of Amplify.
 *
 */
const HubInternal = new HubClass('internal-hub');


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/Logger/ConsoleLogger.mjs":
/*!*************************************************!*\
  !*** ../core/dist/esm/Logger/ConsoleLogger.mjs ***!
  \*************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ConsoleLogger: () => (/* binding */ ConsoleLogger)
/* harmony export */ });
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./types.mjs */ "../core/dist/esm/Logger/types.mjs");
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../constants.mjs */ "../core/dist/esm/constants.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const LOG_LEVELS = {
    VERBOSE: 1,
    DEBUG: 2,
    INFO: 3,
    WARN: 4,
    ERROR: 5,
};
/**
 * Write logs
 * @class Logger
 */
class ConsoleLogger {
    /**
     * @constructor
     * @param {string} name - Name of the logger
     */
    constructor(name, level = _types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.WARN) {
        this.name = name;
        this.level = level;
        this._pluggables = [];
    }
    _padding(n) {
        return n < 10 ? '0' + n : '' + n;
    }
    _ts() {
        const dt = new Date();
        return ([this._padding(dt.getMinutes()), this._padding(dt.getSeconds())].join(':') +
            '.' +
            dt.getMilliseconds());
    }
    configure(config) {
        if (!config)
            return this._config;
        this._config = config;
        return this._config;
    }
    /**
     * Write log
     * @method
     * @memeberof Logger
     * @param {LogType|string} type - log type, default INFO
     * @param {string|object} msg - Logging message or object
     */
    _log(type, ...msg) {
        let logger_level_name = this.level;
        if (ConsoleLogger.LOG_LEVEL) {
            logger_level_name = ConsoleLogger.LOG_LEVEL;
        }
        if (typeof window !== 'undefined' && window.LOG_LEVEL) {
            logger_level_name = window.LOG_LEVEL;
        }
        const logger_level = LOG_LEVELS[logger_level_name];
        const type_level = LOG_LEVELS[type];
        if (!(type_level >= logger_level)) {
            // Do nothing if type is not greater than or equal to logger level (handle undefined)
            return;
        }
        let log = console.log.bind(console);
        if (type === _types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR && console.error) {
            log = console.error.bind(console);
        }
        if (type === _types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.WARN && console.warn) {
            log = console.warn.bind(console);
        }
        const prefix = `[${type}] ${this._ts()} ${this.name}`;
        let message = '';
        if (msg.length === 1 && typeof msg[0] === 'string') {
            message = `${prefix} - ${msg[0]}`;
            log(message);
        }
        else if (msg.length === 1) {
            message = `${prefix} ${msg[0]}`;
            log(prefix, msg[0]);
        }
        else if (typeof msg[0] === 'string') {
            let obj = msg.slice(1);
            if (obj.length === 1) {
                obj = obj[0];
            }
            message = `${prefix} - ${msg[0]} ${obj}`;
            log(`${prefix} - ${msg[0]}`, obj);
        }
        else {
            message = `${prefix} ${msg}`;
            log(prefix, msg);
        }
        for (const plugin of this._pluggables) {
            const logEvent = { message, timestamp: Date.now() };
            plugin.pushLogs([logEvent]);
        }
    }
    /**
     * Write General log. Default to INFO
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    log(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.INFO, ...msg);
    }
    /**
     * Write INFO log
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    info(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.INFO, ...msg);
    }
    /**
     * Write WARN log
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    warn(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.WARN, ...msg);
    }
    /**
     * Write ERROR log
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    error(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR, ...msg);
    }
    /**
     * Write DEBUG log
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    debug(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.DEBUG, ...msg);
    }
    /**
     * Write VERBOSE log
     * @method
     * @memeberof Logger
     * @param {string|object} msg - Logging message or object
     */
    verbose(...msg) {
        this._log(_types_mjs__WEBPACK_IMPORTED_MODULE_0__.LogType.VERBOSE, ...msg);
    }
    addPluggable(pluggable) {
        if (pluggable && pluggable.getCategoryName() === _constants_mjs__WEBPACK_IMPORTED_MODULE_1__.AWS_CLOUDWATCH_CATEGORY) {
            this._pluggables.push(pluggable);
            pluggable.configure(this._config);
        }
    }
    listPluggables() {
        return this._pluggables;
    }
}
ConsoleLogger.LOG_LEVEL = null;


//# sourceMappingURL=ConsoleLogger.mjs.map


/***/ }),

/***/ "../core/dist/esm/Logger/types.mjs":
/*!*****************************************!*\
  !*** ../core/dist/esm/Logger/types.mjs ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogType: () => (/* binding */ LogType)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var LogType;
(function (LogType) {
    LogType["DEBUG"] = "DEBUG";
    LogType["ERROR"] = "ERROR";
    LogType["INFO"] = "INFO";
    LogType["WARN"] = "WARN";
    LogType["VERBOSE"] = "VERBOSE";
})(LogType || (LogType = {}));


//# sourceMappingURL=types.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/customUserAgent.mjs":
/*!*****************************************************!*\
  !*** ../core/dist/esm/Platform/customUserAgent.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getCustomUserAgent: () => (/* binding */ getCustomUserAgent),
/* harmony export */   setCustomUserAgent: () => (/* binding */ setCustomUserAgent)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Maintains custom user-agent state set by external consumers.
const customUserAgentState = {};
/**
 * Sets custom user agent state which will be appended to applicable requests. Returns a function that can be used to
 * clean up any custom state set with this API.
 *
 * @note
 * This API operates globally. Calling this API multiple times will result in the most recently set values for a
 * particular API being used.
 *
 * @note
 * This utility IS NOT compatible with SSR.
 *
 * @param input - SetCustomUserAgentInput that defines custom state to apply to the specified APIs.
 */
const setCustomUserAgent = (input) => {
    // Save custom user-agent state & increment reference counter
    // TODO Remove `any` when we upgrade to TypeScript 5.2, see: https://github.com/microsoft/TypeScript/issues/44373
    customUserAgentState[input.category] = input.apis.reduce((acc, api) => ({
        ...acc,
        [api]: {
            refCount: acc[api]?.refCount ? acc[api].refCount + 1 : 1,
            additionalDetails: input.additionalDetails,
        },
    }), customUserAgentState[input.category] ?? {});
    // Callback that cleans up state for APIs recorded by this call
    let cleanUpCallbackCalled = false;
    const cleanUpCallback = () => {
        // Only allow the cleanup callback to be called once
        if (cleanUpCallbackCalled) {
            return;
        }
        cleanUpCallbackCalled = true;
        input.apis.forEach(api => {
            const apiRefCount = customUserAgentState[input.category][api].refCount;
            if (apiRefCount > 1) {
                customUserAgentState[input.category][api].refCount = apiRefCount - 1;
            }
            else {
                delete customUserAgentState[input.category][api];
                // Clean up category if no more APIs set
                if (!Object.keys(customUserAgentState[input.category]).length) {
                    delete customUserAgentState[input.category];
                }
            }
        });
    };
    return cleanUpCallback;
};
const getCustomUserAgent = (category, api) => customUserAgentState[category]?.[api]?.additionalDetails;


//# sourceMappingURL=customUserAgent.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detectFramework.mjs":
/*!*****************************************************!*\
  !*** ../core/dist/esm/Platform/detectFramework.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   clearCache: () => (/* binding */ clearCache),
/* harmony export */   detectFramework: () => (/* binding */ detectFramework),
/* harmony export */   frameworkChangeObservers: () => (/* binding */ frameworkChangeObservers),
/* harmony export */   observeFrameworkChanges: () => (/* binding */ observeFrameworkChanges)
/* harmony export */ });
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./types.mjs */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _detection_index_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./detection/index.mjs */ "../core/dist/esm/Platform/detection/index.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// We want to cache detection since the framework won't change
let frameworkCache;
const frameworkChangeObservers = [];
// Setup the detection reset tracking / timeout delays
let resetTriggered = false;
const SSR_RESET_TIMEOUT = 10; // ms
const WEB_RESET_TIMEOUT = 10; // ms
const PRIME_FRAMEWORK_DELAY = 1000; // ms
const detectFramework = () => {
    if (!frameworkCache) {
        frameworkCache = (0,_detection_index_mjs__WEBPACK_IMPORTED_MODULE_0__.detect)();
        if (resetTriggered) {
            // The final run of detectFramework:
            // Starting from this point, the `frameworkCache` becomes "final".
            // So we don't need to notify the observers again so the observer
            // can be removed after the final notice.
            while (frameworkChangeObservers.length) {
                frameworkChangeObservers.pop()?.();
            }
        }
        else {
            // The first run of detectFramework:
            // Every time we update the cache, call each observer function
            frameworkChangeObservers.forEach(fcn => fcn());
        }
        // Retry once for either Unknown type after a delay (explained below)
        resetTimeout(_types_mjs__WEBPACK_IMPORTED_MODULE_1__.Framework.ServerSideUnknown, SSR_RESET_TIMEOUT);
        resetTimeout(_types_mjs__WEBPACK_IMPORTED_MODULE_1__.Framework.WebUnknown, WEB_RESET_TIMEOUT);
    }
    return frameworkCache;
};
/**
 * @internal Setup observer callback that will be called everytime the framework changes
 */
const observeFrameworkChanges = (fcn) => {
    // When the `frameworkCache` won't be updated again, we ignore all incoming
    // observers.
    if (resetTriggered) {
        return;
    }
    frameworkChangeObservers.push(fcn);
};
function clearCache() {
    frameworkCache = undefined;
}
// For a framework type and a delay amount, setup the event to re-detect
//   During the runtime boot, it is possible that framework detection will
//   be triggered before the framework has made modifications to the
//   global/window/etc needed for detection. When no framework is detected
//   we will reset and try again to ensure we don't use a cached
//   non-framework detection result for all requests.
function resetTimeout(framework, delay) {
    if (frameworkCache === framework && !resetTriggered) {
        setTimeout(() => {
            clearCache();
            resetTriggered = true;
            setTimeout(detectFramework, PRIME_FRAMEWORK_DELAY);
        }, delay);
    }
}


//# sourceMappingURL=detectFramework.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Angular.mjs":
/*!*******************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Angular.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   angularSSRDetect: () => (/* binding */ angularSSRDetect),
/* harmony export */   angularWebDetect: () => (/* binding */ angularWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with @angular/core 16.0.0
function angularWebDetect() {
    const angularVersionSetInDocument = Boolean((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.documentExists)() && document.querySelector('[ng-version]'));
    const angularContentSetInWindow = Boolean(
    // @ts-ignore
    (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)() && typeof window['ng'] !== 'undefined');
    return angularVersionSetInDocument || angularContentSetInWindow;
}
function angularSSRDetect() {
    return (((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.processExists)() &&
        typeof process.env === 'object' &&
        process.env['npm_lifecycle_script']?.startsWith('ng ')) ||
        false);
}


//# sourceMappingURL=Angular.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Expo.mjs":
/*!****************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Expo.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   expoDetect: () => (/* binding */ expoDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with expo 48 / react-native 0.71.3
function expoDetect() {
    // @ts-ignore
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.globalExists)() && typeof global['expo'] !== 'undefined';
}


//# sourceMappingURL=Expo.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Next.mjs":
/*!****************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Next.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   nextSSRDetect: () => (/* binding */ nextSSRDetect),
/* harmony export */   nextWebDetect: () => (/* binding */ nextWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with next 13.4 / react 18.2
function nextWebDetect() {
    // @ts-ignore
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)() && window['next'] && typeof window['next'] === 'object';
}
function nextSSRDetect() {
    return ((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.globalExists)() &&
        ((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.keyPrefixMatch)(global, '__next') || (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.keyPrefixMatch)(global, '__NEXT')));
}


//# sourceMappingURL=Next.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Nuxt.mjs":
/*!****************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Nuxt.mjs ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   nuxtSSRDetect: () => (/* binding */ nuxtSSRDetect),
/* harmony export */   nuxtWebDetect: () => (/* binding */ nuxtWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with nuxt 2.15 / vue 2.7
function nuxtWebDetect() {
    return ((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)() &&
        // @ts-ignore
        (window['__NUXT__'] !== undefined || window['$nuxt'] !== undefined));
}
function nuxtSSRDetect() {
    // @ts-ignore
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.globalExists)() && typeof global['__NUXT_PATHS__'] !== 'undefined';
}


//# sourceMappingURL=Nuxt.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/React.mjs":
/*!*****************************************************!*\
  !*** ../core/dist/esm/Platform/detection/React.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   reactSSRDetect: () => (/* binding */ reactSSRDetect),
/* harmony export */   reactWebDetect: () => (/* binding */ reactWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with react 18.2 - built using Vite
function reactWebDetect() {
    const elementKeyPrefixedWithReact = (key) => {
        return key.startsWith('_react') || key.startsWith('__react');
    };
    const elementIsReactEnabled = (element) => {
        return Object.keys(element).find(elementKeyPrefixedWithReact);
    };
    const allElementsWithId = () => Array.from(document.querySelectorAll('[id]'));
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.documentExists)() && allElementsWithId().some(elementIsReactEnabled);
}
function reactSSRDetect() {
    return ((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.processExists)() &&
        typeof process.env !== 'undefined' &&
        !!Object.keys(process.env).find(key => key.includes('react')));
}
// use the some


//# sourceMappingURL=React.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/ReactNative.mjs":
/*!***********************************************************!*\
  !*** ../core/dist/esm/Platform/detection/ReactNative.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   reactNativeDetect: () => (/* binding */ reactNativeDetect)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with react-native 0.17.7
function reactNativeDetect() {
    return (typeof navigator !== 'undefined' &&
        typeof navigator.product !== 'undefined' &&
        navigator.product === 'ReactNative');
}


//# sourceMappingURL=ReactNative.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Svelte.mjs":
/*!******************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Svelte.mjs ***!
  \******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   svelteSSRDetect: () => (/* binding */ svelteSSRDetect),
/* harmony export */   svelteWebDetect: () => (/* binding */ svelteWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with svelte 3.59
function svelteWebDetect() {
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)() && (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.keyPrefixMatch)(window, '__SVELTE');
}
function svelteSSRDetect() {
    return ((0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.processExists)() &&
        typeof process.env !== 'undefined' &&
        !!Object.keys(process.env).find(key => key.includes('svelte')));
}


//# sourceMappingURL=Svelte.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Vue.mjs":
/*!***************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Vue.mjs ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   vueSSRDetect: () => (/* binding */ vueSSRDetect),
/* harmony export */   vueWebDetect: () => (/* binding */ vueWebDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Tested with vue 3.3.2
function vueWebDetect() {
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)() && (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.keyPrefixMatch)(window, '__VUE');
}
function vueSSRDetect() {
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.globalExists)() && (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.keyPrefixMatch)(global, '__VUE');
}


//# sourceMappingURL=Vue.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/Web.mjs":
/*!***************************************************!*\
  !*** ../core/dist/esm/Platform/detection/Web.mjs ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   webDetect: () => (/* binding */ webDetect)
/* harmony export */ });
/* harmony import */ var _helpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers.mjs */ "../core/dist/esm/Platform/detection/helpers.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function webDetect() {
    return (0,_helpers_mjs__WEBPACK_IMPORTED_MODULE_0__.windowExists)();
}


//# sourceMappingURL=Web.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/helpers.mjs":
/*!*******************************************************!*\
  !*** ../core/dist/esm/Platform/detection/helpers.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   documentExists: () => (/* binding */ documentExists),
/* harmony export */   globalExists: () => (/* binding */ globalExists),
/* harmony export */   globalThisExists: () => (/* binding */ globalThisExists),
/* harmony export */   keyPrefixMatch: () => (/* binding */ keyPrefixMatch),
/* harmony export */   processExists: () => (/* binding */ processExists),
/* harmony export */   windowExists: () => (/* binding */ windowExists)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const globalExists = () => {
    return typeof global !== 'undefined';
};
const globalThisExists = () => {
    return typeof globalThis !== 'undefined';
};
const windowExists = () => {
    return typeof window !== 'undefined';
};
const documentExists = () => {
    return typeof document !== 'undefined';
};
const processExists = () => {
    return typeof process !== 'undefined';
};
const keyPrefixMatch = (object, prefix) => {
    return !!Object.keys(object).find(key => key.startsWith(prefix));
};


//# sourceMappingURL=helpers.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/detection/index.mjs":
/*!*****************************************************!*\
  !*** ../core/dist/esm/Platform/detection/index.mjs ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   detect: () => (/* binding */ detect)
/* harmony export */ });
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../types.mjs */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _React_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./React.mjs */ "../core/dist/esm/Platform/detection/React.mjs");
/* harmony import */ var _Vue_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./Vue.mjs */ "../core/dist/esm/Platform/detection/Vue.mjs");
/* harmony import */ var _Svelte_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./Svelte.mjs */ "../core/dist/esm/Platform/detection/Svelte.mjs");
/* harmony import */ var _Next_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Next.mjs */ "../core/dist/esm/Platform/detection/Next.mjs");
/* harmony import */ var _Nuxt_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./Nuxt.mjs */ "../core/dist/esm/Platform/detection/Nuxt.mjs");
/* harmony import */ var _Angular_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./Angular.mjs */ "../core/dist/esm/Platform/detection/Angular.mjs");
/* harmony import */ var _ReactNative_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ReactNative.mjs */ "../core/dist/esm/Platform/detection/ReactNative.mjs");
/* harmony import */ var _Expo_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Expo.mjs */ "../core/dist/esm/Platform/detection/Expo.mjs");
/* harmony import */ var _Web_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./Web.mjs */ "../core/dist/esm/Platform/detection/Web.mjs");











// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// These are in the order of detection where when both are detectable, the early Framework will be reported
const detectionMap = [
    // First, detect mobile
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.Expo, detectionMethod: _Expo_mjs__WEBPACK_IMPORTED_MODULE_1__.expoDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.ReactNative, detectionMethod: _ReactNative_mjs__WEBPACK_IMPORTED_MODULE_2__.reactNativeDetect },
    // Next, detect web frameworks
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.NextJs, detectionMethod: _Next_mjs__WEBPACK_IMPORTED_MODULE_3__.nextWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.Nuxt, detectionMethod: _Nuxt_mjs__WEBPACK_IMPORTED_MODULE_4__.nuxtWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.Angular, detectionMethod: _Angular_mjs__WEBPACK_IMPORTED_MODULE_5__.angularWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.React, detectionMethod: _React_mjs__WEBPACK_IMPORTED_MODULE_6__.reactWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.VueJs, detectionMethod: _Vue_mjs__WEBPACK_IMPORTED_MODULE_7__.vueWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.Svelte, detectionMethod: _Svelte_mjs__WEBPACK_IMPORTED_MODULE_8__.svelteWebDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.WebUnknown, detectionMethod: _Web_mjs__WEBPACK_IMPORTED_MODULE_9__.webDetect },
    // Last, detect ssr frameworks
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.NextJsSSR, detectionMethod: _Next_mjs__WEBPACK_IMPORTED_MODULE_3__.nextSSRDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.NuxtSSR, detectionMethod: _Nuxt_mjs__WEBPACK_IMPORTED_MODULE_4__.nuxtSSRDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.ReactSSR, detectionMethod: _React_mjs__WEBPACK_IMPORTED_MODULE_6__.reactSSRDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.VueJsSSR, detectionMethod: _Vue_mjs__WEBPACK_IMPORTED_MODULE_7__.vueSSRDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.AngularSSR, detectionMethod: _Angular_mjs__WEBPACK_IMPORTED_MODULE_5__.angularSSRDetect },
    { platform: _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.SvelteSSR, detectionMethod: _Svelte_mjs__WEBPACK_IMPORTED_MODULE_8__.svelteSSRDetect },
];
function detect() {
    return (detectionMap.find(detectionEntry => detectionEntry.detectionMethod())
        ?.platform || _types_mjs__WEBPACK_IMPORTED_MODULE_0__.Framework.ServerSideUnknown);
}


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/index.mjs":
/*!*******************************************!*\
  !*** ../core/dist/esm/Platform/index.mjs ***!
  \*******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Platform: () => (/* binding */ Platform),
/* harmony export */   getAmplifyUserAgent: () => (/* binding */ getAmplifyUserAgent),
/* harmony export */   getAmplifyUserAgentObject: () => (/* binding */ getAmplifyUserAgentObject)
/* harmony export */ });
/* harmony import */ var _types_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./types.mjs */ "../core/dist/esm/Platform/types.mjs");
/* harmony import */ var _version_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version.mjs */ "../core/dist/esm/Platform/version.mjs");
/* harmony import */ var _detectFramework_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./detectFramework.mjs */ "../core/dist/esm/Platform/detectFramework.mjs");
/* harmony import */ var _customUserAgent_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./customUserAgent.mjs */ "../core/dist/esm/Platform/customUserAgent.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const BASE_USER_AGENT = `aws-amplify`;
class PlatformBuilder {
    constructor() {
        this.userAgent = `${BASE_USER_AGENT}/${_version_mjs__WEBPACK_IMPORTED_MODULE_0__.version}`;
    }
    get framework() {
        return (0,_detectFramework_mjs__WEBPACK_IMPORTED_MODULE_1__.detectFramework)();
    }
    get isReactNative() {
        return (this.framework === _types_mjs__WEBPACK_IMPORTED_MODULE_2__.Framework.ReactNative ||
            this.framework === _types_mjs__WEBPACK_IMPORTED_MODULE_2__.Framework.Expo);
    }
    observeFrameworkChanges(fcn) {
        (0,_detectFramework_mjs__WEBPACK_IMPORTED_MODULE_1__.observeFrameworkChanges)(fcn);
    }
}
const Platform = new PlatformBuilder();
const getAmplifyUserAgentObject = ({ category, action, framework, } = {}) => {
    const userAgent = [[BASE_USER_AGENT, _version_mjs__WEBPACK_IMPORTED_MODULE_0__.version]];
    if (category) {
        userAgent.push([category, action]);
    }
    userAgent.push(['framework', (0,_detectFramework_mjs__WEBPACK_IMPORTED_MODULE_1__.detectFramework)()]);
    if (category && action) {
        const customState = (0,_customUserAgent_mjs__WEBPACK_IMPORTED_MODULE_3__.getCustomUserAgent)(category, action);
        if (customState) {
            customState.forEach(state => {
                userAgent.push(state);
            });
        }
    }
    return userAgent;
};
const getAmplifyUserAgent = (customUserAgentDetails) => {
    const userAgent = getAmplifyUserAgentObject(customUserAgentDetails);
    const userAgentString = userAgent
        .map(([agentKey, agentValue]) => agentKey && agentValue ? `${agentKey}/${agentValue}` : agentKey)
        .join(' ');
    return userAgentString;
};


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/types.mjs":
/*!*******************************************!*\
  !*** ../core/dist/esm/Platform/types.mjs ***!
  \*******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AnalyticsAction: () => (/* binding */ AnalyticsAction),
/* harmony export */   ApiAction: () => (/* binding */ ApiAction),
/* harmony export */   AuthAction: () => (/* binding */ AuthAction),
/* harmony export */   Category: () => (/* binding */ Category),
/* harmony export */   DataStoreAction: () => (/* binding */ DataStoreAction),
/* harmony export */   Framework: () => (/* binding */ Framework),
/* harmony export */   GeoAction: () => (/* binding */ GeoAction),
/* harmony export */   InAppMessagingAction: () => (/* binding */ InAppMessagingAction),
/* harmony export */   InteractionsAction: () => (/* binding */ InteractionsAction),
/* harmony export */   PredictionsAction: () => (/* binding */ PredictionsAction),
/* harmony export */   PubSubAction: () => (/* binding */ PubSubAction),
/* harmony export */   PushNotificationAction: () => (/* binding */ PushNotificationAction),
/* harmony export */   StorageAction: () => (/* binding */ StorageAction)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var Framework;
(function (Framework) {
    // < 100 - Web frameworks
    Framework["WebUnknown"] = "0";
    Framework["React"] = "1";
    Framework["NextJs"] = "2";
    Framework["Angular"] = "3";
    Framework["VueJs"] = "4";
    Framework["Nuxt"] = "5";
    Framework["Svelte"] = "6";
    // 100s - Server side frameworks
    Framework["ServerSideUnknown"] = "100";
    Framework["ReactSSR"] = "101";
    Framework["NextJsSSR"] = "102";
    Framework["AngularSSR"] = "103";
    Framework["VueJsSSR"] = "104";
    Framework["NuxtSSR"] = "105";
    Framework["SvelteSSR"] = "106";
    // 200s - Mobile framework
    Framework["ReactNative"] = "201";
    Framework["Expo"] = "202";
})(Framework || (Framework = {}));
var Category;
(function (Category) {
    Category["API"] = "api";
    Category["Auth"] = "auth";
    Category["Analytics"] = "analytics";
    Category["DataStore"] = "datastore";
    Category["Geo"] = "geo";
    Category["InAppMessaging"] = "inappmessaging";
    Category["Interactions"] = "interactions";
    Category["Predictions"] = "predictions";
    Category["PubSub"] = "pubsub";
    Category["PushNotification"] = "pushnotification";
    Category["Storage"] = "storage";
})(Category || (Category = {}));
var AnalyticsAction;
(function (AnalyticsAction) {
    AnalyticsAction["Record"] = "1";
    AnalyticsAction["IdentifyUser"] = "2";
})(AnalyticsAction || (AnalyticsAction = {}));
var ApiAction;
(function (ApiAction) {
    ApiAction["GraphQl"] = "1";
    ApiAction["Get"] = "2";
    ApiAction["Post"] = "3";
    ApiAction["Put"] = "4";
    ApiAction["Patch"] = "5";
    ApiAction["Del"] = "6";
    ApiAction["Head"] = "7";
})(ApiAction || (ApiAction = {}));
var AuthAction;
(function (AuthAction) {
    AuthAction["SignUp"] = "1";
    AuthAction["ConfirmSignUp"] = "2";
    AuthAction["ResendSignUpCode"] = "3";
    AuthAction["SignIn"] = "4";
    AuthAction["FetchMFAPreference"] = "6";
    AuthAction["UpdateMFAPreference"] = "7";
    AuthAction["SetUpTOTP"] = "10";
    AuthAction["VerifyTOTPSetup"] = "11";
    AuthAction["ConfirmSignIn"] = "12";
    AuthAction["DeleteUserAttributes"] = "15";
    AuthAction["DeleteUser"] = "16";
    AuthAction["UpdateUserAttributes"] = "17";
    AuthAction["FetchUserAttributes"] = "18";
    AuthAction["ConfirmUserAttribute"] = "22";
    AuthAction["SignOut"] = "26";
    AuthAction["UpdatePassword"] = "27";
    AuthAction["ResetPassword"] = "28";
    AuthAction["ConfirmResetPassword"] = "29";
    AuthAction["FederatedSignIn"] = "30";
    AuthAction["RememberDevice"] = "32";
    AuthAction["ForgetDevice"] = "33";
    AuthAction["FetchDevices"] = "34";
    AuthAction["SendUserAttributeVerificationCode"] = "35";
    AuthAction["SignInWithRedirect"] = "36";
})(AuthAction || (AuthAction = {}));
var DataStoreAction;
(function (DataStoreAction) {
    DataStoreAction["Subscribe"] = "1";
    DataStoreAction["GraphQl"] = "2";
})(DataStoreAction || (DataStoreAction = {}));
var GeoAction;
(function (GeoAction) {
    GeoAction["SearchByText"] = "0";
    GeoAction["SearchByCoordinates"] = "1";
    GeoAction["SearchForSuggestions"] = "2";
    GeoAction["SearchByPlaceId"] = "3";
    GeoAction["SaveGeofences"] = "4";
    GeoAction["GetGeofence"] = "5";
    GeoAction["ListGeofences"] = "6";
    GeoAction["DeleteGeofences"] = "7";
})(GeoAction || (GeoAction = {}));
var InAppMessagingAction;
(function (InAppMessagingAction) {
    InAppMessagingAction["SyncMessages"] = "1";
    InAppMessagingAction["IdentifyUser"] = "2";
    InAppMessagingAction["NotifyMessageInteraction"] = "3";
})(InAppMessagingAction || (InAppMessagingAction = {}));
var InteractionsAction;
(function (InteractionsAction) {
    InteractionsAction["None"] = "0";
})(InteractionsAction || (InteractionsAction = {}));
var PredictionsAction;
(function (PredictionsAction) {
    PredictionsAction["Convert"] = "1";
    PredictionsAction["Identify"] = "2";
    PredictionsAction["Interpret"] = "3";
})(PredictionsAction || (PredictionsAction = {}));
var PubSubAction;
(function (PubSubAction) {
    PubSubAction["Subscribe"] = "1";
})(PubSubAction || (PubSubAction = {}));
var PushNotificationAction;
(function (PushNotificationAction) {
    PushNotificationAction["InitializePushNotifications"] = "1";
    PushNotificationAction["IdentifyUser"] = "2";
})(PushNotificationAction || (PushNotificationAction = {}));
var StorageAction;
(function (StorageAction) {
    StorageAction["UploadData"] = "1";
    StorageAction["DownloadData"] = "2";
    StorageAction["List"] = "3";
    StorageAction["Copy"] = "4";
    StorageAction["Remove"] = "5";
    StorageAction["GetProperties"] = "6";
    StorageAction["GetUrl"] = "7";
})(StorageAction || (StorageAction = {}));


//# sourceMappingURL=types.mjs.map


/***/ }),

/***/ "../core/dist/esm/Platform/version.mjs":
/*!*********************************************!*\
  !*** ../core/dist/esm/Platform/version.mjs ***!
  \*********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   version: () => (/* binding */ version)
/* harmony export */ });
// generated by genversion
const version = '6.0.12';


//# sourceMappingURL=version.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/endpoints/getDnsSuffix.mjs":
/*!***********************************************************!*\
  !*** ../core/dist/esm/clients/endpoints/getDnsSuffix.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getDnsSuffix: () => (/* binding */ getDnsSuffix)
/* harmony export */ });
/* harmony import */ var _partitions_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./partitions.mjs */ "../core/dist/esm/clients/endpoints/partitions.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Get the AWS Services endpoint URL's DNS suffix for a given region. A typical AWS regional service endpoint URL will
 * follow this pattern: {endpointPrefix}.{region}.{dnsSuffix}. For example, the endpoint URL for Cognito Identity in
 * us-east-1 will be cognito-identity.us-east-1.amazonaws.com. Here the DnsSuffix is `amazonaws.com`.
 *
 * @param region
 * @returns The DNS suffix
 *
 * @internal
 */
const getDnsSuffix = (region) => {
    const { partitions } = _partitions_mjs__WEBPACK_IMPORTED_MODULE_0__.partitionsInfo;
    for (const { regions, outputs, regionRegex } of partitions) {
        const regex = new RegExp(regionRegex);
        if (regions.includes(region) || regex.test(region)) {
            return outputs.dnsSuffix;
        }
    }
    return _partitions_mjs__WEBPACK_IMPORTED_MODULE_0__.defaultPartition.outputs.dnsSuffix;
};


//# sourceMappingURL=getDnsSuffix.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/endpoints/partitions.mjs":
/*!*********************************************************!*\
  !*** ../core/dist/esm/clients/endpoints/partitions.mjs ***!
  \*********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   defaultPartition: () => (/* binding */ defaultPartition),
/* harmony export */   partitionsInfo: () => (/* binding */ partitionsInfo)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Default partition for AWS services. This is used when the region is not provided or the region is not recognized.
 *
 * @internal
 */
const defaultPartition = {
    id: 'aws',
    outputs: {
        dnsSuffix: 'amazonaws.com',
    },
    regionRegex: '^(us|eu|ap|sa|ca|me|af)\\-\\w+\\-\\d+$',
    regions: ['aws-global'],
};
/**
 * This data is adapted from the partition file from AWS SDK shared utilities but remove some contents for bundle size
 * concern. Information removed are `dualStackDnsSuffix`, `supportDualStack`, `supportFIPS`, restricted partitions, and
 * list of regions for each partition other than global regions.
 *
 * * Ref: https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints
 * * Ref: https://github.com/aws/aws-sdk-js-v3/blob/0201baef03c2379f1f6f7150b9d401d4b230d488/packages/util-endpoints/src/lib/aws/partitions.json#L1
 *
 * @internal
 */
const partitionsInfo = {
    partitions: [
        defaultPartition,
        {
            id: 'aws-cn',
            outputs: {
                dnsSuffix: 'amazonaws.com.cn',
            },
            regionRegex: '^cn\\-\\w+\\-\\d+$',
            regions: ['aws-cn-global'],
        },
    ],
};


//# sourceMappingURL=partitions.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/handlers/fetch.mjs":
/*!***************************************************!*\
  !*** ../core/dist/esm/clients/handlers/fetch.mjs ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchTransferHandler: () => (/* binding */ fetchTransferHandler)
/* harmony export */ });
/* harmony import */ var _utils_memoization_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../utils/memoization.mjs */ "../core/dist/esm/clients/utils/memoization.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const shouldSendBody = (method) => !['HEAD', 'GET', 'DELETE'].includes(method.toUpperCase());
// TODO[AllanZhengYP]: we need to provide isCanceledError utility
const fetchTransferHandler = async ({ url, method, headers, body }, { abortSignal, cache, withCrossDomainCredentials }) => {
    let resp;
    try {
        resp = await fetch(url, {
            method,
            headers,
            body: shouldSendBody(method) ? body : undefined,
            signal: abortSignal,
            cache,
            credentials: withCrossDomainCredentials ? 'include' : 'same-origin',
        });
    }
    catch (e) {
        // TODO: needs to revise error handling in v6
        // For now this is a thin wrapper over original fetch error similar to cognito-identity-js package.
        // Ref: https://github.com/aws-amplify/amplify-js/blob/4fbc8c0a2be7526aab723579b4c95b552195a80b/packages/amazon-cognito-identity-js/src/Client.js#L103-L108
        if (e instanceof TypeError) {
            throw new Error('Network error');
        }
        throw e;
    }
    const responseHeaders = {};
    resp.headers?.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
    });
    const httpResponse = {
        statusCode: resp.status,
        headers: responseHeaders,
        body: null,
    };
    // resp.body is a ReadableStream according to Fetch API spec, but React Native
    // does not implement it.
    const bodyWithMixin = Object.assign(resp.body ?? {}, {
        text: (0,_utils_memoization_mjs__WEBPACK_IMPORTED_MODULE_0__.withMemoization)(() => resp.text()),
        blob: (0,_utils_memoization_mjs__WEBPACK_IMPORTED_MODULE_0__.withMemoization)(() => resp.blob()),
        json: (0,_utils_memoization_mjs__WEBPACK_IMPORTED_MODULE_0__.withMemoization)(() => resp.json()),
    });
    return {
        ...httpResponse,
        body: bodyWithMixin,
    };
};


//# sourceMappingURL=fetch.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/handlers/unauthenticated.mjs":
/*!*************************************************************!*\
  !*** ../core/dist/esm/clients/handlers/unauthenticated.mjs ***!
  \*************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   unauthenticatedHandler: () => (/* binding */ unauthenticatedHandler)
/* harmony export */ });
/* harmony import */ var _middleware_retry_middleware_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../middleware/retry/middleware.mjs */ "../core/dist/esm/clients/middleware/retry/middleware.mjs");
/* harmony import */ var _middleware_userAgent_middleware_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../middleware/userAgent/middleware.mjs */ "../core/dist/esm/clients/middleware/userAgent/middleware.mjs");
/* harmony import */ var _internal_composeTransferHandler_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../internal/composeTransferHandler.mjs */ "../core/dist/esm/clients/internal/composeTransferHandler.mjs");
/* harmony import */ var _fetch_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./fetch.mjs */ "../core/dist/esm/clients/handlers/fetch.mjs");







// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const unauthenticatedHandler = (0,_internal_composeTransferHandler_mjs__WEBPACK_IMPORTED_MODULE_0__.composeTransferHandler)(_fetch_mjs__WEBPACK_IMPORTED_MODULE_1__.fetchTransferHandler, [_middleware_userAgent_middleware_mjs__WEBPACK_IMPORTED_MODULE_2__.userAgentMiddleware, _middleware_retry_middleware_mjs__WEBPACK_IMPORTED_MODULE_3__.retryMiddleware]);


//# sourceMappingURL=unauthenticated.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/internal/composeServiceApi.mjs":
/*!***************************************************************!*\
  !*** ../core/dist/esm/clients/internal/composeServiceApi.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   composeServiceApi: () => (/* binding */ composeServiceApi)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const composeServiceApi = (transferHandler, serializer, deserializer, defaultConfig) => {
    return async (config, input) => {
        const resolvedConfig = {
            ...defaultConfig,
            ...config,
        };
        // We may want to allow different endpoints from given config(other than region) and input.
        // Currently S3 supports additional `useAccelerateEndpoint` option to use accelerate endpoint.
        const endpoint = await resolvedConfig.endpointResolver(resolvedConfig, input);
        // Unlike AWS SDK clients, a serializer should NOT populate the `host` or `content-length` headers.
        // Both of these headers are prohibited per Spec(https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name).
        // They will be populated automatically by browser, or node-fetch polyfill.
        const request = await serializer(input, endpoint);
        const response = await transferHandler(request, {
            ...resolvedConfig,
        });
        return await deserializer(response);
    };
};


//# sourceMappingURL=composeServiceApi.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/internal/composeTransferHandler.mjs":
/*!********************************************************************!*\
  !*** ../core/dist/esm/clients/internal/composeTransferHandler.mjs ***!
  \********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   composeTransferHandler: () => (/* binding */ composeTransferHandler)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Compose a transfer handler with a core transfer handler and a list of middleware.
 * @param coreHandler Core transfer handler
 * @param middleware	List of middleware
 * @returns A transfer handler whose option type is the union of the core
 * 	transfer handler's option type and the middleware's option type.
 * @internal
 */
const composeTransferHandler = (coreHandler, middleware) => (request, options) => {
    const context = {};
    let composedHandler = (request) => coreHandler(request, options);
    for (let i = middleware.length - 1; i >= 0; i--) {
        const m = middleware[i];
        const resolvedMiddleware = m(options);
        composedHandler = resolvedMiddleware(composedHandler, context);
    }
    return composedHandler(request);
};


//# sourceMappingURL=composeTransferHandler.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/middleware/retry/defaultRetryDecider.mjs":
/*!*************************************************************************!*\
  !*** ../core/dist/esm/clients/middleware/retry/defaultRetryDecider.mjs ***!
  \*************************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getRetryDecider: () => (/* binding */ getRetryDecider)
/* harmony export */ });
/* harmony import */ var _isClockSkewError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./isClockSkewError.mjs */ "../core/dist/esm/clients/middleware/retry/isClockSkewError.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Get retry decider function
 * @param errorParser Function to load JavaScript error from HTTP response
 */
const getRetryDecider = (errorParser) => async (response, error) => {
    const parsedError = error ??
        (await errorParser(response)) ??
        undefined;
    const errorCode = parsedError?.['code'];
    const statusCode = response?.statusCode;
    return (isConnectionError(error) ||
        isThrottlingError(statusCode, errorCode) ||
        (0,_isClockSkewError_mjs__WEBPACK_IMPORTED_MODULE_0__.isClockSkewError)(errorCode) ||
        isServerSideError(statusCode, errorCode));
};
// reference: https://github.com/aws/aws-sdk-js-v3/blob/ab0e7be36e7e7f8a0c04834357aaad643c7912c3/packages/service-error-classification/src/constants.ts#L22-L37
const THROTTLING_ERROR_CODES = [
    'BandwidthLimitExceeded',
    'EC2ThrottledException',
    'LimitExceededException',
    'PriorRequestNotComplete',
    'ProvisionedThroughputExceededException',
    'RequestLimitExceeded',
    'RequestThrottled',
    'RequestThrottledException',
    'SlowDown',
    'ThrottledException',
    'Throttling',
    'ThrottlingException',
    'TooManyRequestsException',
];
const TIMEOUT_ERROR_CODES = [
    'TimeoutError',
    'RequestTimeout',
    'RequestTimeoutException',
];
const isThrottlingError = (statusCode, errorCode) => statusCode === 429 ||
    (!!errorCode && THROTTLING_ERROR_CODES.includes(errorCode));
const isConnectionError = (error) => error?.['name'] === 'Network error';
const isServerSideError = (statusCode, errorCode) => (!!statusCode && [500, 502, 503, 504].includes(statusCode)) ||
    (!!errorCode && TIMEOUT_ERROR_CODES.includes(errorCode));


//# sourceMappingURL=defaultRetryDecider.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/middleware/retry/isClockSkewError.mjs":
/*!**********************************************************************!*\
  !*** ../core/dist/esm/clients/middleware/retry/isClockSkewError.mjs ***!
  \**********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   isClockSkewError: () => (/* binding */ isClockSkewError)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// via https://github.com/aws/aws-sdk-js-v3/blob/ab0e7be36e7e7f8a0c04834357aaad643c7912c3/packages/service-error-classification/src/constants.ts#L8
const CLOCK_SKEW_ERROR_CODES = [
    'AuthFailure',
    'InvalidSignatureException',
    'RequestExpired',
    'RequestInTheFuture',
    'RequestTimeTooSkewed',
    'SignatureDoesNotMatch',
    'BadRequestException', // API Gateway
];
/**
 * Given an error code, returns true if it is related to a clock skew error.
 *
 * @param errorCode String representation of some error.
 * @returns True if given error is present in `CLOCK_SKEW_ERROR_CODES`, false otherwise.
 *
 * @internal
 */
const isClockSkewError = (errorCode) => !!errorCode && CLOCK_SKEW_ERROR_CODES.includes(errorCode);


//# sourceMappingURL=isClockSkewError.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/middleware/retry/jitteredBackoff.mjs":
/*!*********************************************************************!*\
  !*** ../core/dist/esm/clients/middleware/retry/jitteredBackoff.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   jitteredBackoff: () => (/* binding */ jitteredBackoff)
/* harmony export */ });
/* harmony import */ var _utils_retry_jitteredBackoff_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../utils/retry/jitteredBackoff.mjs */ "../core/dist/esm/utils/retry/jitteredBackoff.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// TODO: [v6] The separate retry utility is used by Data packages now and will replaced by retry middleware.
const DEFAULT_MAX_DELAY_MS = 5 * 60 * 1000;
const jitteredBackoff = attempt => {
    const delayFunction = (0,_utils_retry_jitteredBackoff_mjs__WEBPACK_IMPORTED_MODULE_0__.jitteredBackoff)(DEFAULT_MAX_DELAY_MS);
    const delay = delayFunction(attempt);
    // The delayFunction returns false when the delay is greater than the max delay(5 mins).
    // In this case, the retry middleware will delay 5 mins instead, as a ceiling of the delay.
    return delay === false ? DEFAULT_MAX_DELAY_MS : delay;
};


//# sourceMappingURL=jitteredBackoff.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/middleware/retry/middleware.mjs":
/*!****************************************************************!*\
  !*** ../core/dist/esm/clients/middleware/retry/middleware.mjs ***!
  \****************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   retryMiddleware: () => (/* binding */ retryMiddleware)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const DEFAULT_RETRY_ATTEMPTS = 3;
/**
 * Retry middleware
 */
const retryMiddleware = ({ maxAttempts = DEFAULT_RETRY_ATTEMPTS, retryDecider, computeDelay, abortSignal, }) => {
    if (maxAttempts < 1) {
        throw new Error('maxAttempts must be greater than 0');
    }
    return (next, context) => async function retryMiddleware(request) {
        let error;
        let attemptsCount = context.attemptsCount ?? 0;
        let response;
        // When retry is not needed or max attempts is reached, either error or response will be set. This function handles either cases.
        const handleTerminalErrorOrResponse = () => {
            if (response) {
                addOrIncrementMetadataAttempts(response, attemptsCount);
                return response;
            }
            else {
                addOrIncrementMetadataAttempts(error, attemptsCount);
                throw error;
            }
        };
        while (!abortSignal?.aborted && attemptsCount < maxAttempts) {
            try {
                response = await next(request);
                error = undefined;
            }
            catch (e) {
                error = e;
                response = undefined;
            }
            // context.attemptsCount may be updated after calling next handler which may retry the request by itself.
            attemptsCount =
                (context.attemptsCount ?? 0) > attemptsCount
                    ? context.attemptsCount ?? 0
                    : attemptsCount + 1;
            context.attemptsCount = attemptsCount;
            if (await retryDecider(response, error)) {
                if (!abortSignal?.aborted && attemptsCount < maxAttempts) {
                    // prevent sleep for last attempt or cancelled request;
                    const delay = computeDelay(attemptsCount);
                    await cancellableSleep(delay, abortSignal);
                }
                continue;
            }
            else {
                return handleTerminalErrorOrResponse();
            }
        }
        if (abortSignal?.aborted) {
            throw new Error('Request aborted.');
        }
        else {
            return handleTerminalErrorOrResponse();
        }
    };
};
const cancellableSleep = (timeoutMs, abortSignal) => {
    if (abortSignal?.aborted) {
        return Promise.resolve();
    }
    let timeoutId;
    let sleepPromiseResolveFn;
    const sleepPromise = new Promise(resolve => {
        sleepPromiseResolveFn = resolve;
        timeoutId = setTimeout(resolve, timeoutMs);
    });
    abortSignal?.addEventListener('abort', function cancelSleep(event) {
        clearTimeout(timeoutId);
        abortSignal?.removeEventListener('abort', cancelSleep);
        sleepPromiseResolveFn();
    });
    return sleepPromise;
};
const addOrIncrementMetadataAttempts = (nextHandlerOutput, attempts) => {
    if (Object.prototype.toString.call(nextHandlerOutput) !== '[object Object]') {
        return;
    }
    nextHandlerOutput['$metadata'] = {
        ...(nextHandlerOutput['$metadata'] ?? {}),
        attempts,
    };
};


//# sourceMappingURL=middleware.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/middleware/userAgent/middleware.mjs":
/*!********************************************************************!*\
  !*** ../core/dist/esm/clients/middleware/userAgent/middleware.mjs ***!
  \********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   userAgentMiddleware: () => (/* binding */ userAgentMiddleware)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Middleware injects user agent string to specified header(default to 'x-amz-user-agent'),
 * if the header is not set already.
 *
 * TODO: incorporate new user agent design
 */
const userAgentMiddleware = ({ userAgentHeader = 'x-amz-user-agent', userAgentValue = '', }) => next => {
    return async function userAgentMiddleware(request) {
        if (userAgentValue.trim().length === 0) {
            const result = await next(request);
            return result;
        }
        else {
            const headerName = userAgentHeader.toLowerCase();
            request.headers[headerName] = request.headers[headerName]
                ? `${request.headers[headerName]} ${userAgentValue}`
                : userAgentValue;
            const response = await next(request);
            return response;
        }
    };
};


//# sourceMappingURL=middleware.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/serde/json.mjs":
/*!***********************************************!*\
  !*** ../core/dist/esm/clients/serde/json.mjs ***!
  \***********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   parseJsonBody: () => (/* binding */ parseJsonBody),
/* harmony export */   parseJsonError: () => (/* binding */ parseJsonError)
/* harmony export */ });
/* harmony import */ var _responseInfo_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./responseInfo.mjs */ "../core/dist/esm/clients/serde/responseInfo.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Utility functions for serializing and deserializing of JSON protocol in general(including: REST-JSON, JSON-RPC, etc.)
 */
/**
 * Error parser for AWS JSON protocol.
 */
const parseJsonError = async (response) => {
    if (!response || response.statusCode < 300) {
        return;
    }
    const body = await parseJsonBody(response);
    const sanitizeErrorCode = (rawValue) => {
        const [cleanValue] = rawValue.toString().split(/[\,\:]+/);
        if (cleanValue.includes('#')) {
            return cleanValue.split('#')[1];
        }
        return cleanValue;
    };
    const code = sanitizeErrorCode(response.headers['x-amzn-errortype'] ??
        body.code ??
        body.__type ??
        'UnknownError');
    const message = body.message ?? body.Message ?? 'Unknown error';
    const error = new Error(message);
    return Object.assign(error, {
        name: code,
        $metadata: (0,_responseInfo_mjs__WEBPACK_IMPORTED_MODULE_0__.parseMetadata)(response),
    });
};
/**
 * Parse JSON response body to JavaScript object.
 */
const parseJsonBody = async (response) => {
    if (!response.body) {
        throw new Error('Missing response payload');
    }
    const output = await response.body.json();
    return Object.assign(output, {
        $metadata: (0,_responseInfo_mjs__WEBPACK_IMPORTED_MODULE_0__.parseMetadata)(response),
    });
};


//# sourceMappingURL=json.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/serde/responseInfo.mjs":
/*!*******************************************************!*\
  !*** ../core/dist/esm/clients/serde/responseInfo.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   parseMetadata: () => (/* binding */ parseMetadata)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const parseMetadata = (response) => {
    const { headers, statusCode } = response;
    return {
        ...(isMetadataBearer(response) ? response.$metadata : {}),
        httpStatusCode: statusCode,
        requestId: headers['x-amzn-requestid'] ??
            headers['x-amzn-request-id'] ??
            headers['x-amz-request-id'],
        extendedRequestId: headers['x-amz-id-2'],
        cfId: headers['x-amz-cf-id'],
    };
};
const isMetadataBearer = (response) => typeof response?.$metadata === 'object';


//# sourceMappingURL=responseInfo.mjs.map


/***/ }),

/***/ "../core/dist/esm/clients/utils/memoization.mjs":
/*!******************************************************!*\
  !*** ../core/dist/esm/clients/utils/memoization.mjs ***!
  \******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   withMemoization: () => (/* binding */ withMemoization)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Cache the payload of a response body. It allows multiple calls to the body,
 * for example, when reading the body in both retry decider and error deserializer.
 * Caching body is allowed here because we call the body accessor(blob(), json(),
 * etc.) when body is small or streaming implementation is not available(RN).
 *
 * @internal
 */
const withMemoization = (payloadAccessor) => {
    let cached;
    return () => {
        if (!cached) {
            // Explicitly not awaiting. Intermediate await would add overhead and
            // introduce a possible race in the event that this wrapper is called
            // again before the first `payloadAccessor` call resolves.
            cached = payloadAccessor();
        }
        return cached;
    };
};


//# sourceMappingURL=memoization.mjs.map


/***/ }),

/***/ "../core/dist/esm/constants.mjs":
/*!**************************************!*\
  !*** ../core/dist/esm/constants.mjs ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AWS_CLOUDWATCH_CATEGORY: () => (/* binding */ AWS_CLOUDWATCH_CATEGORY),
/* harmony export */   NO_HUBCALLBACK_PROVIDED_EXCEPTION: () => (/* binding */ NO_HUBCALLBACK_PROVIDED_EXCEPTION),
/* harmony export */   USER_AGENT_HEADER: () => (/* binding */ USER_AGENT_HEADER)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Logging constants
const AWS_CLOUDWATCH_CATEGORY = 'Logging';
const USER_AGENT_HEADER = 'x-amz-user-agent';
// Error exception code constants
const NO_HUBCALLBACK_PROVIDED_EXCEPTION = 'NoHubcallbackProvidedException';


//# sourceMappingURL=constants.mjs.map


/***/ }),

/***/ "../core/dist/esm/errors/AmplifyError.mjs":
/*!************************************************!*\
  !*** ../core/dist/esm/errors/AmplifyError.mjs ***!
  \************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AmplifyError: () => (/* binding */ AmplifyError)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
class AmplifyError extends Error {
    /**
     *  Constructs an AmplifyError.
     *
     * @param message text that describes the main problem.
     * @param underlyingError the underlying cause of the error.
     * @param recoverySuggestion suggestion to recover from the error.
     *
     */
    constructor({ message, name, recoverySuggestion, underlyingError, }) {
        super(message);
        this.name = name;
        this.underlyingError = underlyingError;
        this.recoverySuggestion = recoverySuggestion;
        // Hack for making the custom error class work when transpiled to es5
        // TODO: Delete the following 2 lines after we change the build target to >= es2015
        this.constructor = AmplifyError;
        Object.setPrototypeOf(this, AmplifyError.prototype);
    }
}


//# sourceMappingURL=AmplifyError.mjs.map


/***/ }),

/***/ "../core/dist/esm/errors/createAssertionFunction.mjs":
/*!***********************************************************!*\
  !*** ../core/dist/esm/errors/createAssertionFunction.mjs ***!
  \***********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   createAssertionFunction: () => (/* binding */ createAssertionFunction)
/* harmony export */ });
/* harmony import */ var _AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./AmplifyError.mjs */ "../core/dist/esm/errors/AmplifyError.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const createAssertionFunction = (errorMap, AssertionError = _AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__.AmplifyError) => (assertion, name, additionalContext) => {
    const { message, recoverySuggestion } = errorMap[name];
    if (!assertion) {
        throw new AssertionError({
            name,
            message: additionalContext
                ? `${message} ${additionalContext}`
                : message,
            recoverySuggestion,
        });
    }
};


//# sourceMappingURL=createAssertionFunction.mjs.map


/***/ }),

/***/ "../core/dist/esm/singleton/Auth/index.mjs":
/*!*************************************************!*\
  !*** ../core/dist/esm/singleton/Auth/index.mjs ***!
  \*************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthClass: () => (/* binding */ AuthClass),
/* harmony export */   isTokenExpired: () => (/* binding */ isTokenExpired)
/* harmony export */ });
function isTokenExpired({ expiresAt, clockDrift, }) {
    const currentTime = Date.now();
    return currentTime + clockDrift > expiresAt;
}
class AuthClass {
    constructor() { }
    /**
     * Configure Auth category
     *
     * @internal
     *
     * @param authResourcesConfig - Resources configurations required by Auth providers.
     * @param authOptions - Client options used by library
     *
     * @returns void
     */
    configure(authResourcesConfig, authOptions) {
        this.authConfig = authResourcesConfig;
        this.authOptions = authOptions;
    }
    async fetchAuthSession(options = {}) {
        let tokens;
        let credentialsAndIdentityId;
        let userSub;
        // Get tokens will throw if session cannot be refreshed (network or service error) or return null if not available
        tokens = await this.getTokens(options);
        if (tokens) {
            userSub = tokens.accessToken?.payload?.sub;
            // getCredentialsAndIdentityId will throw if cannot get credentials (network or service error)
            credentialsAndIdentityId =
                await this.authOptions?.credentialsProvider?.getCredentialsAndIdentityId({
                    authConfig: this.authConfig,
                    tokens,
                    authenticated: true,
                    forceRefresh: options.forceRefresh,
                });
        }
        else {
            // getCredentialsAndIdentityId will throw if cannot get credentials (network or service error)
            credentialsAndIdentityId =
                await this.authOptions?.credentialsProvider?.getCredentialsAndIdentityId({
                    authConfig: this.authConfig,
                    authenticated: false,
                    forceRefresh: options.forceRefresh,
                });
        }
        return {
            tokens,
            credentials: credentialsAndIdentityId?.credentials,
            identityId: credentialsAndIdentityId?.identityId,
            userSub,
        };
    }
    async clearCredentials() {
        if (this.authOptions?.credentialsProvider) {
            return await this.authOptions.credentialsProvider.clearCredentialsAndIdentityId();
        }
    }
    async getTokens(options) {
        return ((await this.authOptions?.tokenProvider?.getTokens(options)) ?? undefined);
    }
}


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/singleton/Auth/utils/errorHelpers.mjs":
/*!**************************************************************!*\
  !*** ../core/dist/esm/singleton/Auth/utils/errorHelpers.mjs ***!
  \**************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthConfigurationErrorCode: () => (/* binding */ AuthConfigurationErrorCode),
/* harmony export */   assert: () => (/* binding */ assert)
/* harmony export */ });
/* harmony import */ var _errors_createAssertionFunction_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../errors/createAssertionFunction.mjs */ "../core/dist/esm/errors/createAssertionFunction.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var AuthConfigurationErrorCode;
(function (AuthConfigurationErrorCode) {
    AuthConfigurationErrorCode["AuthTokenConfigException"] = "AuthTokenConfigException";
    AuthConfigurationErrorCode["AuthUserPoolAndIdentityPoolException"] = "AuthUserPoolAndIdentityPoolException";
    AuthConfigurationErrorCode["AuthUserPoolException"] = "AuthUserPoolException";
    AuthConfigurationErrorCode["InvalidIdentityPoolIdException"] = "InvalidIdentityPoolIdException";
    AuthConfigurationErrorCode["OAuthNotConfigureException"] = "OAuthNotConfigureException";
})(AuthConfigurationErrorCode || (AuthConfigurationErrorCode = {}));
const authConfigurationErrorMap = {
    [AuthConfigurationErrorCode.AuthTokenConfigException]: {
        message: 'Auth Token Provider not configured.',
        recoverySuggestion: 'Make sure to call Amplify.configure in your app.',
    },
    [AuthConfigurationErrorCode.AuthUserPoolAndIdentityPoolException]: {
        message: 'Auth UserPool or IdentityPool not configured.',
        recoverySuggestion: 'Make sure to call Amplify.configure in your app with UserPoolId and IdentityPoolId.',
    },
    [AuthConfigurationErrorCode.AuthUserPoolException]: {
        message: 'Auth UserPool not configured.',
        recoverySuggestion: 'Make sure to call Amplify.configure in your app with userPoolId and userPoolClientId.',
    },
    [AuthConfigurationErrorCode.InvalidIdentityPoolIdException]: {
        message: 'Invalid identity pool id provided.',
        recoverySuggestion: 'Make sure a valid identityPoolId is given in the config.',
    },
    [AuthConfigurationErrorCode.OAuthNotConfigureException]: {
        message: 'oauth param not configured.',
        recoverySuggestion: 'Make sure to call Amplify.configure with oauth parameter in your app.',
    },
};
const assert = (0,_errors_createAssertionFunction_mjs__WEBPACK_IMPORTED_MODULE_0__.createAssertionFunction)(authConfigurationErrorMap);


//# sourceMappingURL=errorHelpers.mjs.map


/***/ }),

/***/ "../core/dist/esm/singleton/Auth/utils/index.mjs":
/*!*******************************************************!*\
  !*** ../core/dist/esm/singleton/Auth/utils/index.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   assertIdentityPoolIdConfig: () => (/* binding */ assertIdentityPoolIdConfig),
/* harmony export */   assertOAuthConfig: () => (/* binding */ assertOAuthConfig),
/* harmony export */   assertTokenProviderConfig: () => (/* binding */ assertTokenProviderConfig),
/* harmony export */   decodeJWT: () => (/* binding */ decodeJWT)
/* harmony export */ });
/* harmony import */ var _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./errorHelpers.mjs */ "../core/dist/esm/singleton/Auth/utils/errorHelpers.mjs");
/* harmony import */ var _utils_convert_base64_base64Decoder_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../utils/convert/base64/base64Decoder.mjs */ "../core/dist/esm/utils/convert/base64/base64Decoder.mjs");





// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function assertTokenProviderConfig(cognitoConfig) {
    let assertionValid = true; // assume valid until otherwise proveed
    if (!cognitoConfig) {
        assertionValid = false;
    }
    else {
        assertionValid =
            !!cognitoConfig.userPoolId && !!cognitoConfig.userPoolClientId;
    }
    return (0,_errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.assert)(assertionValid, _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthConfigurationErrorCode.AuthUserPoolException);
}
function assertOAuthConfig(cognitoConfig) {
    const validOAuthConfig = !!cognitoConfig?.loginWith?.oauth?.domain &&
        !!cognitoConfig?.loginWith?.oauth?.redirectSignOut &&
        !!cognitoConfig?.loginWith?.oauth?.redirectSignIn &&
        !!cognitoConfig?.loginWith?.oauth?.responseType;
    return (0,_errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.assert)(validOAuthConfig, _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthConfigurationErrorCode.OAuthNotConfigureException);
}
function assertIdentityPoolIdConfig(cognitoConfig) {
    const validConfig = !!cognitoConfig?.identityPoolId;
    return (0,_errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.assert)(validConfig, _errorHelpers_mjs__WEBPACK_IMPORTED_MODULE_0__.AuthConfigurationErrorCode.InvalidIdentityPoolIdException);
}
function decodeJWT(token) {
    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) {
        throw new Error('Invalid token');
    }
    try {
        const base64WithUrlSafe = tokenParts[1];
        const base64 = base64WithUrlSafe.replace(/-/g, '+').replace(/_/g, '/');
        const jsonStr = decodeURIComponent(_utils_convert_base64_base64Decoder_mjs__WEBPACK_IMPORTED_MODULE_1__.base64Decoder
            .convert(base64)
            .split('')
            .map(char => `%${`00${char.charCodeAt(0).toString(16)}`.slice(-2)}`)
            .join(''));
        const payload = JSON.parse(jsonStr);
        return {
            toString: () => token,
            payload,
        };
    }
    catch (err) {
        throw new Error('Invalid token payload');
    }
}


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/singleton/apis/internal/fetchAuthSession.mjs":
/*!*********************************************************************!*\
  !*** ../core/dist/esm/singleton/apis/internal/fetchAuthSession.mjs ***!
  \*********************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fetchAuthSession: () => (/* binding */ fetchAuthSession)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const fetchAuthSession = (amplify, options) => {
    return amplify.Auth.fetchAuthSession(options);
};


//# sourceMappingURL=fetchAuthSession.mjs.map


/***/ }),

/***/ "../core/dist/esm/singleton/constants.mjs":
/*!************************************************!*\
  !*** ../core/dist/esm/singleton/constants.mjs ***!
  \************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ADD_OAUTH_LISTENER: () => (/* binding */ ADD_OAUTH_LISTENER)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const ADD_OAUTH_LISTENER = Symbol('oauth-listener');


//# sourceMappingURL=constants.mjs.map


/***/ }),

/***/ "../core/dist/esm/types/errors.mjs":
/*!*****************************************!*\
  !*** ../core/dist/esm/types/errors.mjs ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AmplifyErrorCode: () => (/* binding */ AmplifyErrorCode)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
var AmplifyErrorCode;
(function (AmplifyErrorCode) {
    AmplifyErrorCode["NoEndpointId"] = "NoEndpointId";
    AmplifyErrorCode["PlatformNotSupported"] = "PlatformNotSupported";
    AmplifyErrorCode["Unknown"] = "Unknown";
})(AmplifyErrorCode || (AmplifyErrorCode = {}));


//# sourceMappingURL=errors.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/WordArray.mjs":
/*!********************************************!*\
  !*** ../core/dist/esm/utils/WordArray.mjs ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ WordArray)
/* harmony export */ });
/* harmony import */ var _cryptoSecureRandomInt_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./cryptoSecureRandomInt.mjs */ "../core/dist/esm/utils/cryptoSecureRandomInt.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Hex encoding strategy.
 * Converts a word array to a hex string.
 * @param {WordArray} wordArray The word array.
 * @return {string} The hex string.
 * @static
 */
function hexStringify(wordArray) {
    // Shortcuts
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    // Convert
    const hexChars = [];
    for (let i = 0; i < sigBytes; i++) {
        const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }
    return hexChars.join('');
}
class WordArray {
    constructor(words, sigBytes) {
        this.words = [];
        let Words = words;
        Words = this.words = Words || [];
        if (sigBytes !== undefined) {
            this.sigBytes = sigBytes;
        }
        else {
            this.sigBytes = Words.length * 4;
        }
    }
    random(nBytes) {
        const words = [];
        for (let i = 0; i < nBytes; i += 4) {
            words.push((0,_cryptoSecureRandomInt_mjs__WEBPACK_IMPORTED_MODULE_0__.cryptoSecureRandomInt)());
        }
        return new WordArray(words, nBytes);
    }
    toString() {
        return hexStringify(this);
    }
}


//# sourceMappingURL=WordArray.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/amplifyUrl/index.mjs":
/*!***************************************************!*\
  !*** ../core/dist/esm/utils/amplifyUrl/index.mjs ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AmplifyUrl: () => (/* binding */ AmplifyUrl),
/* harmony export */   AmplifyUrlSearchParams: () => (/* binding */ AmplifyUrlSearchParams)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const AmplifyUrl = URL;
const AmplifyUrlSearchParams = URLSearchParams;


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/convert/base64/base64Decoder.mjs":
/*!***************************************************************!*\
  !*** ../core/dist/esm/utils/convert/base64/base64Decoder.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   base64Decoder: () => (/* binding */ base64Decoder)
/* harmony export */ });
/* harmony import */ var _globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../globalHelpers/index.mjs */ "../core/dist/esm/utils/globalHelpers/index.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const base64Decoder = {
    convert(input) {
        return (0,_globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_0__.getAtob)()(input);
    },
};


//# sourceMappingURL=base64Decoder.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/convert/base64/base64Encoder.mjs":
/*!***************************************************************!*\
  !*** ../core/dist/esm/utils/convert/base64/base64Encoder.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   base64Encoder: () => (/* binding */ base64Encoder)
/* harmony export */ });
/* harmony import */ var _globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../globalHelpers/index.mjs */ "../core/dist/esm/utils/globalHelpers/index.mjs");
/* harmony import */ var _bytesToString_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./bytesToString.mjs */ "../core/dist/esm/utils/convert/base64/bytesToString.mjs");



// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const base64Encoder = {
    convert(input, { urlSafe } = { urlSafe: false }) {
        const inputStr = typeof input === 'string' ? input : (0,_bytesToString_mjs__WEBPACK_IMPORTED_MODULE_0__.bytesToString)(input);
        const encodedStr = (0,_globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_1__.getBtoa)()(inputStr);
        // see details about the char replacing at https://datatracker.ietf.org/doc/html/rfc4648#section-5
        return urlSafe
            ? encodedStr.replace(/\+/g, '-').replace(/\//g, '_')
            : encodedStr;
    },
};


//# sourceMappingURL=base64Encoder.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/convert/base64/bytesToString.mjs":
/*!***************************************************************!*\
  !*** ../core/dist/esm/utils/convert/base64/bytesToString.mjs ***!
  \***************************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   bytesToString: () => (/* binding */ bytesToString)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function bytesToString(input) {
    return Array.from(input, byte => String.fromCodePoint(byte)).join('');
}


//# sourceMappingURL=bytesToString.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/cryptoSecureRandomInt.mjs":
/*!********************************************************!*\
  !*** ../core/dist/esm/utils/cryptoSecureRandomInt.mjs ***!
  \********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cryptoSecureRandomInt: () => (/* binding */ cryptoSecureRandomInt)
/* harmony export */ });
/* harmony import */ var _globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./globalHelpers/index.mjs */ "../core/dist/esm/utils/globalHelpers/index.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/*
 * Cryptographically secure pseudorandom number generator
 * As Math.random() is cryptographically not safe to use
 */
function cryptoSecureRandomInt() {
    const crypto = (0,_globalHelpers_index_mjs__WEBPACK_IMPORTED_MODULE_0__.getCrypto)();
    const randomResult = crypto.getRandomValues(new Uint32Array(1))[0];
    return randomResult;
}


//# sourceMappingURL=cryptoSecureRandomInt.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/generateRandomString.mjs":
/*!*******************************************************!*\
  !*** ../core/dist/esm/utils/generateRandomString.mjs ***!
  \*******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   generateRandomString: () => (/* binding */ generateRandomString)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const generateRandomString = (length) => {
    const STATE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += STATE_CHARSET.charAt(Math.floor(Math.random() * STATE_CHARSET.length));
    }
    return result;
};


//# sourceMappingURL=generateRandomString.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/globalHelpers/index.mjs":
/*!******************************************************!*\
  !*** ../core/dist/esm/utils/globalHelpers/index.mjs ***!
  \******************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getAtob: () => (/* binding */ getAtob),
/* harmony export */   getBtoa: () => (/* binding */ getBtoa),
/* harmony export */   getCrypto: () => (/* binding */ getCrypto)
/* harmony export */ });
/* harmony import */ var _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../errors/AmplifyError.mjs */ "../core/dist/esm/errors/AmplifyError.mjs");




// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const getCrypto = () => {
    if (typeof window === 'object' && typeof window.crypto === 'object') {
        return window.crypto;
    }
    // Next.js global polyfill
    if (typeof crypto === 'object') {
        return crypto;
    }
    throw new _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__.AmplifyError({
        name: 'MissingPolyfill',
        message: 'Cannot resolve the `crypto` function from the environment.',
    });
};
const getBtoa = () => {
    // browser
    if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
        return window.btoa;
    }
    // Next.js global polyfill
    if (typeof btoa === 'function') {
        return btoa;
    }
    throw new _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__.AmplifyError({
        name: 'Base64EncoderError',
        message: 'Cannot resolve the `btoa` function from the environment.',
    });
};
const getAtob = () => {
    // browser
    if (typeof window !== 'undefined' && typeof window.atob === 'function') {
        return window.atob;
    }
    // Next.js global polyfill
    if (typeof atob === 'function') {
        return atob;
    }
    throw new _errors_AmplifyError_mjs__WEBPACK_IMPORTED_MODULE_0__.AmplifyError({
        name: 'Base64EncoderError',
        message: 'Cannot resolve the `atob` function from the environment.',
    });
};


//# sourceMappingURL=index.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/isBrowser.mjs":
/*!********************************************!*\
  !*** ../core/dist/esm/utils/isBrowser.mjs ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   isBrowser: () => (/* binding */ isBrowser)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const isBrowser = () => typeof window !== 'undefined' && typeof window.document !== 'undefined';


//# sourceMappingURL=isBrowser.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/retry/constants.mjs":
/*!**************************************************!*\
  !*** ../core/dist/esm/utils/retry/constants.mjs ***!
  \**************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   MAX_DELAY_MS: () => (/* binding */ MAX_DELAY_MS)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const MAX_DELAY_MS = 5 * 60 * 1000;


//# sourceMappingURL=constants.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/retry/jitteredBackoff.mjs":
/*!********************************************************!*\
  !*** ../core/dist/esm/utils/retry/jitteredBackoff.mjs ***!
  \********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   jitteredBackoff: () => (/* binding */ jitteredBackoff)
/* harmony export */ });
/* harmony import */ var _constants_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants.mjs */ "../core/dist/esm/utils/retry/constants.mjs");


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * @private
 * Internal use of Amplify only
 */
function jitteredBackoff(maxDelayMs = _constants_mjs__WEBPACK_IMPORTED_MODULE_0__.MAX_DELAY_MS) {
    const BASE_TIME_MS = 100;
    const JITTER_FACTOR = 100;
    return attempt => {
        const delay = 2 ** attempt * BASE_TIME_MS + JITTER_FACTOR * Math.random();
        return delay > maxDelayMs ? false : delay;
    };
}


//# sourceMappingURL=jitteredBackoff.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/urlSafeDecode.mjs":
/*!************************************************!*\
  !*** ../core/dist/esm/utils/urlSafeDecode.mjs ***!
  \************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   urlSafeDecode: () => (/* binding */ urlSafeDecode)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function urlSafeDecode(hex) {
    const matchArr = hex.match(/.{2}/g) || [];
    return matchArr.map(char => String.fromCharCode(parseInt(char, 16))).join('');
}


//# sourceMappingURL=urlSafeDecode.mjs.map


/***/ }),

/***/ "../core/dist/esm/utils/urlSafeEncode.mjs":
/*!************************************************!*\
  !*** ../core/dist/esm/utils/urlSafeEncode.mjs ***!
  \************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   urlSafeEncode: () => (/* binding */ urlSafeEncode)
/* harmony export */ });
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
function urlSafeEncode(str) {
    return str
        .split('')
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
}


//# sourceMappingURL=urlSafeEncode.mjs.map


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
/*!****************************!*\
  !*** ./dist/esm/index.mjs ***!
  \****************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthError: () => (/* reexport safe */ _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_27__.AuthError),
/* harmony export */   autoSignIn: () => (/* reexport safe */ _providers_cognito_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_25__.autoSignIn),
/* harmony export */   confirmResetPassword: () => (/* reexport safe */ _providers_cognito_apis_confirmResetPassword_mjs__WEBPACK_IMPORTED_MODULE_2__.confirmResetPassword),
/* harmony export */   confirmSignIn: () => (/* reexport safe */ _providers_cognito_apis_confirmSignIn_mjs__WEBPACK_IMPORTED_MODULE_6__.confirmSignIn),
/* harmony export */   confirmSignUp: () => (/* reexport safe */ _providers_cognito_apis_confirmSignUp_mjs__WEBPACK_IMPORTED_MODULE_5__.confirmSignUp),
/* harmony export */   confirmUserAttribute: () => (/* reexport safe */ _providers_cognito_apis_confirmUserAttribute_mjs__WEBPACK_IMPORTED_MODULE_15__.confirmUserAttribute),
/* harmony export */   decodeJWT: () => (/* reexport safe */ _aws_amplify_core__WEBPACK_IMPORTED_MODULE_26__.decodeJWT),
/* harmony export */   deleteUser: () => (/* reexport safe */ _providers_cognito_apis_deleteUser_mjs__WEBPACK_IMPORTED_MODULE_21__.deleteUser),
/* harmony export */   deleteUserAttributes: () => (/* reexport safe */ _providers_cognito_apis_deleteUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_20__.deleteUserAttributes),
/* harmony export */   fetchAuthSession: () => (/* reexport safe */ _aws_amplify_core__WEBPACK_IMPORTED_MODULE_26__.fetchAuthSession),
/* harmony export */   fetchDevices: () => (/* reexport safe */ _providers_cognito_apis_fetchDevices_mjs__WEBPACK_IMPORTED_MODULE_24__.fetchDevices),
/* harmony export */   fetchMFAPreference: () => (/* reexport safe */ _providers_cognito_apis_fetchMFAPreference_mjs__WEBPACK_IMPORTED_MODULE_8__.fetchMFAPreference),
/* harmony export */   fetchUserAttributes: () => (/* reexport safe */ _providers_cognito_apis_fetchUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_17__.fetchUserAttributes),
/* harmony export */   forgetDevice: () => (/* reexport safe */ _providers_cognito_apis_forgetDevice_mjs__WEBPACK_IMPORTED_MODULE_23__.forgetDevice),
/* harmony export */   getCurrentUser: () => (/* reexport safe */ _providers_cognito_apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_14__.getCurrentUser),
/* harmony export */   rememberDevice: () => (/* reexport safe */ _providers_cognito_apis_rememberDevice_mjs__WEBPACK_IMPORTED_MODULE_22__.rememberDevice),
/* harmony export */   resendSignUpCode: () => (/* reexport safe */ _providers_cognito_apis_resendSignUpCode_mjs__WEBPACK_IMPORTED_MODULE_4__.resendSignUpCode),
/* harmony export */   resetPassword: () => (/* reexport safe */ _providers_cognito_apis_resetPassword_mjs__WEBPACK_IMPORTED_MODULE_1__.resetPassword),
/* harmony export */   sendUserAttributeVerificationCode: () => (/* reexport safe */ _providers_cognito_apis_sendUserAttributeVerificationCode_mjs__WEBPACK_IMPORTED_MODULE_19__.sendUserAttributeVerificationCode),
/* harmony export */   setUpTOTP: () => (/* reexport safe */ _providers_cognito_apis_setUpTOTP_mjs__WEBPACK_IMPORTED_MODULE_11__.setUpTOTP),
/* harmony export */   signIn: () => (/* reexport safe */ _providers_cognito_apis_signIn_mjs__WEBPACK_IMPORTED_MODULE_3__.signIn),
/* harmony export */   signInWithRedirect: () => (/* reexport safe */ _providers_cognito_apis_signInWithRedirect_mjs__WEBPACK_IMPORTED_MODULE_16__.signInWithRedirect),
/* harmony export */   signOut: () => (/* reexport safe */ _providers_cognito_apis_signOut_mjs__WEBPACK_IMPORTED_MODULE_18__.signOut),
/* harmony export */   signUp: () => (/* reexport safe */ _providers_cognito_apis_signUp_mjs__WEBPACK_IMPORTED_MODULE_0__.signUp),
/* harmony export */   updateMFAPreference: () => (/* reexport safe */ _providers_cognito_apis_updateMFAPreference_mjs__WEBPACK_IMPORTED_MODULE_7__.updateMFAPreference),
/* harmony export */   updatePassword: () => (/* reexport safe */ _providers_cognito_apis_updatePassword_mjs__WEBPACK_IMPORTED_MODULE_10__.updatePassword),
/* harmony export */   updateUserAttribute: () => (/* reexport safe */ _providers_cognito_apis_updateUserAttribute_mjs__WEBPACK_IMPORTED_MODULE_13__.updateUserAttribute),
/* harmony export */   updateUserAttributes: () => (/* reexport safe */ _providers_cognito_apis_updateUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_12__.updateUserAttributes),
/* harmony export */   verifyTOTPSetup: () => (/* reexport safe */ _providers_cognito_apis_verifyTOTPSetup_mjs__WEBPACK_IMPORTED_MODULE_9__.verifyTOTPSetup)
/* harmony export */ });
/* harmony import */ var _providers_cognito_apis_signUp_mjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./providers/cognito/apis/signUp.mjs */ "./dist/esm/providers/cognito/apis/signUp.mjs");
/* harmony import */ var _providers_cognito_apis_resetPassword_mjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./providers/cognito/apis/resetPassword.mjs */ "./dist/esm/providers/cognito/apis/resetPassword.mjs");
/* harmony import */ var _providers_cognito_apis_confirmResetPassword_mjs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./providers/cognito/apis/confirmResetPassword.mjs */ "./dist/esm/providers/cognito/apis/confirmResetPassword.mjs");
/* harmony import */ var _providers_cognito_apis_signIn_mjs__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./providers/cognito/apis/signIn.mjs */ "./dist/esm/providers/cognito/apis/signIn.mjs");
/* harmony import */ var _providers_cognito_apis_resendSignUpCode_mjs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./providers/cognito/apis/resendSignUpCode.mjs */ "./dist/esm/providers/cognito/apis/resendSignUpCode.mjs");
/* harmony import */ var _providers_cognito_apis_confirmSignUp_mjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./providers/cognito/apis/confirmSignUp.mjs */ "./dist/esm/providers/cognito/apis/confirmSignUp.mjs");
/* harmony import */ var _providers_cognito_apis_confirmSignIn_mjs__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./providers/cognito/apis/confirmSignIn.mjs */ "./dist/esm/providers/cognito/apis/confirmSignIn.mjs");
/* harmony import */ var _providers_cognito_apis_updateMFAPreference_mjs__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./providers/cognito/apis/updateMFAPreference.mjs */ "./dist/esm/providers/cognito/apis/updateMFAPreference.mjs");
/* harmony import */ var _providers_cognito_apis_fetchMFAPreference_mjs__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./providers/cognito/apis/fetchMFAPreference.mjs */ "./dist/esm/providers/cognito/apis/fetchMFAPreference.mjs");
/* harmony import */ var _providers_cognito_apis_verifyTOTPSetup_mjs__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./providers/cognito/apis/verifyTOTPSetup.mjs */ "./dist/esm/providers/cognito/apis/verifyTOTPSetup.mjs");
/* harmony import */ var _providers_cognito_apis_updatePassword_mjs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./providers/cognito/apis/updatePassword.mjs */ "./dist/esm/providers/cognito/apis/updatePassword.mjs");
/* harmony import */ var _providers_cognito_apis_setUpTOTP_mjs__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ./providers/cognito/apis/setUpTOTP.mjs */ "./dist/esm/providers/cognito/apis/setUpTOTP.mjs");
/* harmony import */ var _providers_cognito_apis_updateUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ./providers/cognito/apis/updateUserAttributes.mjs */ "./dist/esm/providers/cognito/apis/updateUserAttributes.mjs");
/* harmony import */ var _providers_cognito_apis_updateUserAttribute_mjs__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ./providers/cognito/apis/updateUserAttribute.mjs */ "./dist/esm/providers/cognito/apis/updateUserAttribute.mjs");
/* harmony import */ var _providers_cognito_apis_getCurrentUser_mjs__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ./providers/cognito/apis/getCurrentUser.mjs */ "./dist/esm/providers/cognito/apis/getCurrentUser.mjs");
/* harmony import */ var _providers_cognito_apis_confirmUserAttribute_mjs__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(/*! ./providers/cognito/apis/confirmUserAttribute.mjs */ "./dist/esm/providers/cognito/apis/confirmUserAttribute.mjs");
/* harmony import */ var _providers_cognito_apis_signInWithRedirect_mjs__WEBPACK_IMPORTED_MODULE_16__ = __webpack_require__(/*! ./providers/cognito/apis/signInWithRedirect.mjs */ "./dist/esm/providers/cognito/apis/signInWithRedirect.mjs");
/* harmony import */ var _providers_cognito_apis_fetchUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_17__ = __webpack_require__(/*! ./providers/cognito/apis/fetchUserAttributes.mjs */ "./dist/esm/providers/cognito/apis/fetchUserAttributes.mjs");
/* harmony import */ var _providers_cognito_apis_signOut_mjs__WEBPACK_IMPORTED_MODULE_18__ = __webpack_require__(/*! ./providers/cognito/apis/signOut.mjs */ "./dist/esm/providers/cognito/apis/signOut.mjs");
/* harmony import */ var _providers_cognito_apis_sendUserAttributeVerificationCode_mjs__WEBPACK_IMPORTED_MODULE_19__ = __webpack_require__(/*! ./providers/cognito/apis/sendUserAttributeVerificationCode.mjs */ "./dist/esm/providers/cognito/apis/sendUserAttributeVerificationCode.mjs");
/* harmony import */ var _providers_cognito_apis_deleteUserAttributes_mjs__WEBPACK_IMPORTED_MODULE_20__ = __webpack_require__(/*! ./providers/cognito/apis/deleteUserAttributes.mjs */ "./dist/esm/providers/cognito/apis/deleteUserAttributes.mjs");
/* harmony import */ var _providers_cognito_apis_deleteUser_mjs__WEBPACK_IMPORTED_MODULE_21__ = __webpack_require__(/*! ./providers/cognito/apis/deleteUser.mjs */ "./dist/esm/providers/cognito/apis/deleteUser.mjs");
/* harmony import */ var _providers_cognito_apis_rememberDevice_mjs__WEBPACK_IMPORTED_MODULE_22__ = __webpack_require__(/*! ./providers/cognito/apis/rememberDevice.mjs */ "./dist/esm/providers/cognito/apis/rememberDevice.mjs");
/* harmony import */ var _providers_cognito_apis_forgetDevice_mjs__WEBPACK_IMPORTED_MODULE_23__ = __webpack_require__(/*! ./providers/cognito/apis/forgetDevice.mjs */ "./dist/esm/providers/cognito/apis/forgetDevice.mjs");
/* harmony import */ var _providers_cognito_apis_fetchDevices_mjs__WEBPACK_IMPORTED_MODULE_24__ = __webpack_require__(/*! ./providers/cognito/apis/fetchDevices.mjs */ "./dist/esm/providers/cognito/apis/fetchDevices.mjs");
/* harmony import */ var _providers_cognito_apis_autoSignIn_mjs__WEBPACK_IMPORTED_MODULE_25__ = __webpack_require__(/*! ./providers/cognito/apis/autoSignIn.mjs */ "./dist/esm/providers/cognito/apis/autoSignIn.mjs");
/* harmony import */ var _aws_amplify_core__WEBPACK_IMPORTED_MODULE_26__ = __webpack_require__(/*! @aws-amplify/core */ "@aws-amplify/core");
/* harmony import */ var _errors_AuthError_mjs__WEBPACK_IMPORTED_MODULE_27__ = __webpack_require__(/*! ./errors/AuthError.mjs */ "./dist/esm/errors/AuthError.mjs");



































//# sourceMappingURL=index.mjs.map

})();

/******/ 	return __webpack_exports__;
/******/ })()
;
});
//# sourceMappingURL=aws-amplify-auth.js.map