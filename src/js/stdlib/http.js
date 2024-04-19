const core = globalThis[Symbol.for('tjs.internal.core')];
const httpInt = core.http_load_native();

function assertArgString(val, ind) {
    if (typeof val !== 'string') {
        throw new TypeError(`Argument ${ind} must be a string`);
    }
}

function fmtHdrKey(key) {
    assertArgString(key, 'key');

    return key.toLowerCase();
}

export const int = httpInt;

class HttpIncomingRequest {
    #parser;
    #sock;
    constructor(parser, sock) {
        this.#parser = parser;
        this.#sock = sock;
    }

    get method() {
        return this.#parser.data.method;
    }

    get httpVersion() {
        const ver = this.#parser.data.http_version;

        return `${ver.major}.${ver.minor}`;
    }

    get headers() {
        return Object.fromEntries(this.#parser.data.headers);
    }

    get url() {
        return this.#parser.data.url;
    }

    get sock() {
        return this.#sock;
    }

    finish() {
        this.#parser.finish();
    }
}

const statusMessages = {
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    204: 'No Content',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported'
};

const HttpTransStates = {
    STATUS: 0,
    HEADERS: 1,
    BODY: 2,
    FINISHED: 3
};

export class HTTPOutgoingResponse {
    #sock;
    #encoder = { encode: httpInt.text_encode };
    #headers = new Map();
    #status = { code: 200, message: undefined };
    #state = HttpTransStates.STATUS;

    constructor(sock) {
        this.#sock = sock;
    }

    get socket() {
        return this.#sock;
    }

    get statusCode() {
        return this.#status.code;
    }
    set statusCode(code) {
        if (!Number.isInteger(code) || code <= 0) {
            throw new RangeError('statusCode must be a positive integer');
        }

        this.#status.code = code;
    }

    get statusMessage() {
        return this.#status.message;
    }

    set statusMessage(message) {
        assertArgString(message, 'message');

        this.#status.message = message;
    }

    setHeader(key, value) {
        this.#headers.set(fmtHdrKey(key), value);
    }

    getHeader(key) {
        return this.#headers.get(fmtHdrKey(key));
    }

    hasHeader(key) {
        return this.#headers.has(fmtHdrKey(key));
    }

    removeHeader(key) {
        this.#headers.delete(fmtHdrKey(key));
    }

    #buildHeaderBuf() {
        const msg = this.#status.message ?? statusMessages[this.#status.code] ?? 'Unknown';
        let lines = [ `HTTP/1.1 ${this.#status.code} ${msg}` ];

        for (const [ key, value ] of this.#headers) {
            if (Array.isArray(value)) {
                for (const v of value) {
                    lines.push(`${key}: ${String(v)}`);
                }
            } else {
                lines.push(`${key}: ${String(value)}`);
            }
        }

        return this.#encoder.encode(lines.join('\r\n') + '\r\n');
    }

    async flushHeaders() {
        if (this.#state !== HttpTransStates.STATUS) {
            throw new Error('Headers have already been written');
        }

        this.#state = HttpTransStates.HEADERS;
        await this.#sock.write(this.#buildHeaderBuf());
    }

    get transferEncoding() {
        const te = this.getHeader('Transfer-Encoding');

        return te ? String(te).trim().toLowerCase() : undefined;
    }

    get chunked() {
        return this.transferEncoding?.split(',').map(v => v.trim()).includes('chunked');
    }

    #chunkCount = 0;
    async #writeChunk(chunk, last) {
        if (!(chunk instanceof ArrayBuffer)) {
            chunk = this.#encoder.encode(chunk);
        }

        if (this.#state === HttpTransStates.STATUS) {
            if (last) {
                this.setHeader('Content-Length', chunk.byteLength);
            } else {
                this.setHeader('Transfer-Encoding', 'chunked');
            }

            this.flushHeaders();
        }

        if (last) {
            this.#state = HttpTransStates.FINISHED;
        }

        this.#chunkCount++;

        if (this.chunked) {
            this.#sock.write(this.#encoder.encode(chunk.byteLength.toString(16) + '\r\n'));
            await this.#sock.write(chunk);
            await this.#sock.write(this.#encoder.encode('\r\n'));

            if (last) {
                await this.#sock.write(this.#encoder.encode('0\r\n\r\n'));
            }
        } else {
            await this.#sock.write(chunk);
        }

        if (last && !this.chunked && this.hasHeader('Content-Length')) {
            // close connection if no content-length and not chunked
            this.#sock.close();
        }
    }

    #validateTransferEncoding() {
        const te = this.transferEncoding;
        // TODO: Add support for compression

        if (te !== undefined && te !== 'chunked') {
            throw new Error('Unsupported transfer encoding');
        }
    }

    async writeBody(body) {
        if (this.#state === HttpTransStates.FINISHED) {
            throw new Error('Response already finished');
        }

        this.#validateTransferEncoding();

        if (body instanceof ReadableStream) {
            const reader = body.getReader();
            let chunk;

            do {
                chunk = await reader.read();

                if (chunk.done) {
                    await this.#writeChunk(new Uint8Array(0), true);
                } else {
                    await this.#writeChunk(chunk.value, false);
                }
            } while (chunk.done === false);
        } else {
            await this.#writeChunk(body, true);
        }
    }

    finish() {
        this.#sock.close();
        this.#sock = undefined;
    }
}

export class HTTPServer {
    #listener;
    #handler;
    constructor(listener, handler) {
        this.#listener = listener;
        this.#handler = handler;
    }

    async #handleConn(conn) {
        const req = await parseHttp(conn);

        await this.#handler(req, new HTTPOutgoingResponse(conn));
        // TODO: support multipl requests on the same connection
    }

    async start() {
        for await (let conn of this.#listener) {
            this.#handleConn(conn);
        }
    }
}

export async function parseHttp(conn) {
    const parser = httpInt.init_http_request();
    const buf = new Uint8Array(1024);
    let res;
    let len;

    do {
        len = await conn.read(buf);

        if (len !== null) {
            res = parser.update(buf.subarray(0, len));
        }
    } while (res === true && len !== null);

    return new HttpIncomingRequest(parser, conn);
}
