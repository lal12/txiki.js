/*
MIT License

Copyright (c) 2024 lal12

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "private.h"

#include <llhttp.h>

typedef struct {
    llhttp_settings_t settings;
    llhttp_t parser;
    int step;
    JSContext* ctx;
    TJSPromise prom;
	JSValue req;
} tjs_http_parser;

static JSClassID tjs_http_parser_class_id;

static void tjs_http_parser_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    tjs_http_parser *p = JS_GetOpaque(val, tjs_http_parser_class_id);
    if (p) {
        JS_MarkValue(rt, p->req, mark_func);
    }
}

static void tjs_sock_finalizer(JSRuntime *rt, JSValue val) {
    tjs_http_parser *p = JS_GetOpaque(val, tjs_http_parser_class_id);
    if (p) {
		JS_FreeValueRT(rt, p->req);
		TJS_ClearPromise(p->ctx, &p->prom);
        js_free_rt(rt, p);
    }
}


static JSClassDef tjs_http_parser_class = { "HTTPParser", .finalizer = tjs_sock_finalizer, .gc_mark = tjs_http_parser_mark };

static int handle_on_message_complete(llhttp_t* parser) {
	fprintf(stdout, "Message completed!\n");
	return 0;
}

static int on_url(llhttp_t* p, const char *at, size_t length){
	tjs_http_parser* hp = p->data;
	JS_SetPropertyStr(hp->ctx, hp->req, "url", JS_NewStringLen(hp->ctx, at, length));
    return 0;
}

static int on_method_complete(llhttp_t* p){
	tjs_http_parser* hp = p->data;
	JS_SetPropertyStr(hp->ctx, hp->req, "method", JS_NewString(hp->ctx, llhttp_method_name(llhttp_get_method(p))));
    return 0;
}

static int on_version_complete(llhttp_t* p){
	tjs_http_parser* hp = p->data;
	JSValue jsver = JS_NewObject(hp->ctx);
	JS_SetPropertyStr(hp->ctx, jsver, "major", JS_NewInt32(hp->ctx, llhttp_get_http_major(p)));
	JS_SetPropertyStr(hp->ctx, jsver, "minor", JS_NewInt32(hp->ctx, llhttp_get_http_minor(p)));
	JS_SetPropertyStr(hp->ctx, hp->req, "http_version", jsver);
	return 0;
}

static int on_header_field(llhttp_t* p, const char *at, size_t length){
	tjs_http_parser* hp = p->data;
	JS_SetPropertyStr(hp->ctx, hp->req, "_curField", JS_NewStringLen(hp->ctx, at, length));
    return 0;
}

static int on_header_value(llhttp_t* p, const char *at, size_t length){
	tjs_http_parser* hp = p->data;
	JSValue field = JS_GetPropertyStr(hp->ctx, hp->req, "_curField");
	JS_SetPropertyStr(hp->ctx, hp->req, "_curField", JS_UNDEFINED);
	JSValue tuple = JS_NewArray(hp->ctx);
	JS_SetPropertyUint32(hp->ctx, tuple, 0, field);
	JS_SetPropertyUint32(hp->ctx, tuple, 1, JS_NewStringLen(hp->ctx, at, length));
	
	JSValue headers = JS_GetPropertyStr(hp->ctx, hp->req, "headers");
	int arrlen = JS_VALUE_GET_INT(JS_GetPropertyStr(hp->ctx, headers, "length"));
	JS_SetPropertyUint32(hp->ctx, headers, arrlen, tuple);

    return 0;
}

static int on_headers_complete(llhttp_t* parser){
    return HPE_PAUSED; // expect js world to say how to continue
}

static JSValue http_parser_update(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
	tjs_http_parser *p = JS_GetOpaque(this_val, tjs_http_parser_class_id);
	if(!p){
		return JS_EXCEPTION;
	}
	size_t len;
	char* buf = (char*)JS_GetUint8Array(ctx, &len, argv[0]);
    llhttp_errno_t err = llhttp_execute(&p->parser, buf, len);
	if (err != HPE_OK && err != HPE_PAUSED) {
		JS_ThrowInternalError(ctx, "llhttp_execute failed (%d): %s", err, llhttp_errno_name(err));
		return JS_EXCEPTION;
	}
	return JS_NewBool(ctx, err != HPE_PAUSED);
}

static JSValue init_http_request(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    tjs_http_parser* parser = js_mallocz(ctx, sizeof(*parser));
    parser->step = 0; // 0 = headers, 1 = body
    parser->ctx = ctx;
	parser->req = JS_NewObject(ctx);
	JSValue headers = JS_NewArray(ctx);
	JS_SetPropertyStr(ctx, parser->req, "headers", headers);

    llhttp_settings_init(&parser->settings);
    parser->settings.on_message_complete = handle_on_message_complete;
    parser->settings.on_headers_complete = on_headers_complete;
	parser->settings.on_url = on_url;
	parser->settings.on_header_field = on_header_field;
	parser->settings.on_header_value = on_header_value;
	parser->settings.on_method_complete = on_method_complete;
	parser->settings.on_version_complete = on_version_complete;

    llhttp_init(&parser->parser, HTTP_REQUEST, &parser->settings);
	parser->parser.data = parser;

	JSValue parserobj = JS_NewObjectClass(ctx, tjs_http_parser_class_id);
	JS_SetOpaque(parserobj, parser);

    return parserobj;
}

static JSValue tjs_http_parser_data(JSContext *ctx, JSValueConst this_val) {
	tjs_http_parser *p = JS_GetOpaque(this_val, tjs_http_parser_class_id);
	if(!p){
		return JS_EXCEPTION;
	}
	return JS_DupValue(p->ctx, p->req);
}

static JSValue tjs_http_parser_finish(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	tjs_http_parser *p = JS_GetOpaque(this_val, tjs_http_parser_class_id);
	if(!p){
		return JS_EXCEPTION;
	}
	llhttp_errno_t err = llhttp_finish(&p->parser);
	if(err != HPE_OK){
		JSValue jserr = JS_NewError(ctx);
		JS_DefinePropertyValueStr(ctx, jserr, "message", JS_NewString(ctx, llhttp_errno_name(err)), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
		return jserr;
	}
	return JS_UNDEFINED;
}

// helper function until we have a proper fast text encoder
static JSValue tjs_http_parser_text_encode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if(!JS_IsString(argv[0])){
		JS_ThrowTypeError(ctx, "Expected a string");
		return JS_EXCEPTION;
	}
	size_t len;
	const char* str = JS_ToCStringLen(ctx, &len, argv[0]);
	JSValue ret = JS_NewUint8ArrayCopy(ctx, (uint8_t*)str, len);
	JS_FreeCString(ctx, str);
	return ret;
}

static const JSCFunctionListEntry tjs_http_parser_methods[] = {
    TJS_CGETSET_DEF("data", tjs_http_parser_data, NULL),
	TJS_CFUNC_DEF("finish", 0, tjs_http_parser_finish),
	TJS_CFUNC_DEF("update", 1, http_parser_update),
};

static JSValue tjs__mod_http_load_native(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "init_http_request", JS_NewCFunction(ctx, init_http_request, "init_http_request", 0));
	JS_SetPropertyStr(ctx, obj, "text_encode", JS_NewCFunction(ctx, tjs_http_parser_text_encode, "text_encode", 1));

	JSRuntime *rt = JS_GetRuntime(ctx);
	JS_NewClassID(rt, &tjs_http_parser_class_id);
    JS_NewClass(rt, tjs_http_parser_class_id, &tjs_http_parser_class);
    JSValue tjs_sock_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tjs_sock_proto, tjs_http_parser_methods, countof(tjs_http_parser_methods));
    JS_SetClassProto(ctx, tjs_http_parser_class_id, tjs_sock_proto);
    return obj;
}

void tjs__mod_http_init(JSContext *ctx, JSValue ns) {
    JSValue obj = JS_NewCFunction(ctx, tjs__mod_http_load_native, "http_load_native", 0);
    JS_SetPropertyStr(ctx, ns, "http_load_native", obj);
}
