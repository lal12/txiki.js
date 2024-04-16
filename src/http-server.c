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
#include "utils.h"
#include <libwebsockets.h>

typedef union{
    const char* cstring;
    void* ptr;
    JSValue jsval;
} js_alloc_data_u;
typedef struct js_alloc_s{
    struct js_alloc_s* next;
    char type;
    js_alloc_data_u data;
}js_alloc_t;

typedef struct {
    struct lws_context *lws_ctx;
    JSContext* js_ctx;
    js_alloc_t* deps;
} tjs_lws_ctx;

static void free_queue(JSContext* ctx, js_alloc_t** start){
    while(*start){
        js_alloc_t* ptr = *start;
        js_alloc_t* next = ptr->next;
        switch(ptr->type){
            case 's':
                JS_FreeCString(ctx, ptr->data.cstring);
                break;
            case 'p':
                js_free(ctx, ptr->data.ptr);
                break;
            case 'j':
                JS_FreeValue(ctx, ptr->data.jsval);
                break;
        }
        js_free(ctx, ptr);
        *start = next;
    }
}

static void mark_queue(JSRuntime* rt, js_alloc_t** start, JS_MarkFunc* mark_func){
     js_alloc_t* ptr = *start;
    while(ptr){
        js_alloc_t* next = ptr->next;
        if(ptr->type == 'j'){
            JS_MarkValue(rt, ptr->data.jsval, mark_func);
        }
        ptr = next;
    }
}

static js_alloc_t* add_to_queue(JSContext* ctx, js_alloc_t** start, char type, js_alloc_data_u data){
    js_alloc_t* q = js_mallocz(ctx, sizeof(js_alloc_t));
    q->next = *start;
    q->type = type;
    q->data = data;
    *start = q;
    return q;
}

static JSValue* add_jsv_to_queue(JSContext* ctx, js_alloc_t** start, JSValue val){
    js_alloc_data_u u;
    u.jsval = val;
    js_alloc_t* ret = add_to_queue(ctx, start, 'j', u);
    return &ret->data.jsval;
}

static const char* add_cstr_to_queue(JSContext* ctx, js_alloc_t** start, const char* cstr){
    js_alloc_data_u u;
    u.cstring = cstr;
    add_to_queue(ctx, start, 's', u);
    return cstr;
}

static void* add_ptr_to_queue(JSContext* ctx, js_alloc_t** start, void* ptr){
    js_alloc_data_u u;
    u.ptr = ptr;
    add_to_queue(ctx, start, 'p', u);
    return ptr;
}

static JSClassID tjs_lws_ctx_class_id;

static int js_lws_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len){
    printf("called js_lws_callback, reason %d\n", reason);
	switch(reason){
		case LWS_CALLBACK_PROTOCOL_INIT:
			return 0;
	}
	JSValue* cb_js = user;
    tjs_lws_ctx* lws_h = lws_get_opaque_user_data(wsi);
    JSContext* ctx = lws_h->js_ctx;

    JSValueConst args[2];
    args[0] = JS_NewInt32(ctx, reason);
    args[1] = JS_NewArrayBufferCopy(ctx, in, len);
    JSValue ret = JS_Call(ctx, *cb_js, JS_UNDEFINED, 3, args);
    JS_FreeValue(ctx, args[0]);
    JS_FreeValue(ctx, args[1]);
    JS_FreeValue(ctx, ret);
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static JSValue tjs_mod_lws_create_ctx(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_ctx *lws = js_mallocz(ctx, sizeof(tjs_lws_ctx));
    struct lws_context_creation_info info;
    memset( &info, 0, sizeof(info) );
    info.gid = -1;
    info.uid = -1;
    info.user = lws;
    info.options = LWS_SERVER_OPTION_LIBUV | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    void* foreign_loops[1];
    foreign_loops[0] = tjs_get_loop(ctx);
    info.foreign_loops = foreign_loops;
    lws->lws_ctx = lws_create_context(&info);
    if(!lws->lws_ctx){
        js_free(ctx, lws);
        JS_ThrowInternalError(ctx, "Failed to create LWSContext");
        return JS_EXCEPTION;
    }

    JSValue ret = JS_NewObjectClass(ctx, tjs_lws_ctx_class_id);
    JS_SetOpaque(ret, lws);

    return ret;
}

static JSValue tjs_mod_lws_add_vhost(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_ctx *lws = JS_GetOpaque(this_val, tjs_lws_ctx_class_id);
    if (lws == NULL) {
        JS_ThrowTypeError(ctx, "expected this to be LWSContext");
        return JS_EXCEPTION;
    }
    if(!JS_IsObject(argv[0])){
        JS_ThrowTypeError(ctx, "Expected object as arg #1");
        return JS_EXCEPTION;
    }

    js_alloc_t* init_alloc = NULL;

    int port = -1;
    {
        JSValue port_js = JS_GetPropertyStr(ctx, argv[0], "port");
        if(!JS_IsNumber(port_js)){
            JS_ThrowTypeError(ctx, "Expected numeric port property in arg #1");
            return JS_EXCEPTION;
        }
        port = JS_VALUE_GET_INT(port_js);
        JS_FreeValue(ctx, port_js);
        if(port <= 0 || port > 65535){
            JS_ThrowRangeError(ctx, "Invalid port number");
            return JS_EXCEPTION;
        }
    }

    const char* vhost_name;
    {
        JSValue name_js = JS_GetPropertyStr(ctx, argv[0], "vhost_name");
        if(!JS_IsString(name_js)){
            JS_ThrowTypeError(ctx, "Expected string name property in arg #1");
            return JS_EXCEPTION;
        }
        vhost_name = JS_ToCString(ctx, name_js);
        add_cstr_to_queue(ctx, &init_alloc, vhost_name);
        JS_FreeValue(ctx, name_js);
    }

    bool error = false;
    
    const struct lws_protocols** protos = NULL;
    {
        if(!JS_IsArray(ctx, argv[1])){
            JS_ThrowTypeError(ctx, "Expected array as arg #2");
            return JS_EXCEPTION;
        }
        int32_t arrlen = 0;
        JSValue arrlen_js = JS_GetPropertyStr(ctx, argv[1], "length");
        JS_ToInt32(ctx, &arrlen, arrlen_js);
        JS_FreeValue(ctx, arrlen_js);
        if(arrlen == 0){
            JS_ThrowRangeError(ctx, "Expected array in arg #2 to be non-empty");
            return JS_EXCEPTION;
        }
        protos = js_mallocz(ctx, sizeof(struct lws_protocols*) * (arrlen + 1));
        add_ptr_to_queue(ctx, &init_alloc, protos);
        for(unsigned i=0;i<arrlen;i++){
            JSValue proto = JS_GetPropertyUint32(ctx, argv[1], i);
            if(!JS_IsObject(proto)){
                JS_ThrowTypeError(ctx, "Expected object in array in arg #2");
                error = true;
                JS_FreeValue(ctx, proto);
                break;
            }
            JSValue name = JS_GetPropertyStr(ctx, proto, "name");
            JSValue callback = JS_GetPropertyStr(ctx, proto, "callback");
            JS_FreeValue(ctx, proto);
            error = error || !JS_IsString(name);
            if(error){
                JS_ThrowTypeError(ctx, "Expected object with name and callback properties in array in arg #2");
                js_free(ctx, protos);
                JS_FreeValue(ctx, callback);
            }else{
                const char* name_cstr = JS_ToCString(ctx, name);
                add_cstr_to_queue(ctx, &init_alloc, name_cstr);
                struct lws_protocols* lws_proto = js_mallocz(ctx, sizeof(struct lws_protocols));
                add_ptr_to_queue(ctx, &init_alloc, lws_proto);
                protos[i] = lws_proto;
                lws_proto->name = name_cstr;
                if(JS_IsFunction(ctx, callback)){
                    lws_proto->callback = js_lws_callback;
                    lws_proto->user = add_jsv_to_queue(ctx, &lws->deps, callback);
                }else{
                    lws_proto->callback = lws_callback_http_dummy;
                
                }
            }
            JS_FreeValue(ctx, name);
            if(error){
                break;
            }
        }
    }

    const struct lws_http_mount* mountFirst = NULL;
    if(!error){
        if(!JS_IsArray(ctx, argv[2])){
            JS_ThrowTypeError(ctx, "Expected array as arg #3");
            error = true;
            goto end;
        }
        int32_t arrlen = 0;
        JSValue arrlen_js = JS_GetPropertyStr(ctx, argv[2], "length");
        JS_ToInt32(ctx, &arrlen, arrlen_js);
        JS_FreeValue(ctx, arrlen_js);
        if(arrlen == 0){
            JS_ThrowRangeError(ctx, "Expected array in arg #3 to be non-empty");
            error = true;
            goto end;
        }
        struct lws_http_mount* mountLast = NULL;
        for(unsigned i=0;i<arrlen;i++){
            JSValue proto = JS_GetPropertyUint32(ctx, argv[2], i);
            JSValue prop = JS_UNDEFINED;
            if(!JS_IsObject(proto)){
                JS_ThrowTypeError(ctx, "Expected object in array in arg #3");
                error = true;
                goto cleanup;
            }
            struct lws_http_mount* mountNew = js_mallocz(ctx, sizeof(struct lws_http_mount));
            add_ptr_to_queue(ctx, &init_alloc, mountNew);
            if(mountLast){
                mountLast->mount_next = mountNew;
                mountLast = mountNew;
            }else{
                mountFirst = mountNew;
            }
            prop = JS_GetPropertyStr(ctx, proto, "mountpoint");
            if(!JS_IsString(prop)){
                JS_ThrowTypeError(ctx, "Expected string mountpoint property in array in arg #3");
                error = true;
                goto cleanup;
            }
            mountNew->mountpoint = JS_ToCString(ctx, prop);
            add_cstr_to_queue(ctx, &init_alloc, mountNew->mountpoint);
            mountNew->mountpoint_len = strlen(mountNew->mountpoint);
            JS_FreeValue(ctx, prop);

            prop = JS_GetPropertyStr(ctx, proto, "origin");
            if(JS_IsString(prop)){
                mountNew->origin = JS_ToCString(ctx, prop);
                add_cstr_to_queue(ctx, &init_alloc, mountNew->def);
            }
            JS_FreeValue(ctx, prop);

            prop = JS_GetPropertyStr(ctx, proto, "def");
            if(JS_IsString(prop)){
                mountNew->def = JS_ToCString(ctx, prop);
                add_cstr_to_queue(ctx, &init_alloc, mountNew->def);
            }
            JS_FreeValue(ctx, prop);

            prop = JS_GetPropertyStr(ctx, proto, "protocol");
            if(JS_IsString(prop)){
                mountNew->protocol = JS_ToCString(ctx, prop);
                add_cstr_to_queue(ctx, &init_alloc, mountNew->def);
            }
            JS_FreeValue(ctx, prop);

            prop = JS_GetPropertyStr(ctx, proto, "origin_protocol");
            if(!JS_IsNumber(prop)){
                JS_ThrowTypeError(ctx, "Expected numeric origin_protocol property in array in arg #3");
                error = true;
                goto cleanup;
            }
            int origin_protocol = 0;
            JS_ToInt32(ctx, &origin_protocol, prop);
            JS_FreeValue(ctx, prop);
            if(origin_protocol <= 0 || origin_protocol > LWSMPRO_CALLBACK){
                JS_ThrowRangeError(ctx, "Invalid origin_protocol value");
                error = true;
                goto cleanup;
            }
            mountNew->origin_protocol = origin_protocol;
        cleanup:
            JS_FreeValue(ctx, prop);
            JS_FreeValue(ctx, proto);
        }
    }

    if(!error){
        struct lws_context_creation_info info;
        memset( &info, 0, sizeof(info) );
        info.port = port;
        info.vhost_name = vhost_name;
        info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
		info.pcontext = &lws->lws_ctx;
    	info.pprotocols = protos;
        info.mounts = mountFirst;
        //info.vhost_name = "http";
        struct lws_vhost* vh = lws_create_vhost(lws->lws_ctx, &info);
        if(!vh){
            JS_ThrowInternalError(ctx, "Failed to create vhost");
            error = true;
        }
    }

end:

    //free_queue(ctx, &init_alloc);

    printf("end %d\n", error);
    if(error){
        free_queue(ctx, &lws->deps);
        js_free(ctx, lws);
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

static void js_lws_ctx_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    tjs_lws_ctx *u = JS_GetOpaque(val, tjs_lws_ctx_class_id);
    if (u) {
        mark_queue(rt, &u->deps, mark_func);
    }
}

static void js_lws_ctx_finalizer(JSRuntime *rt, JSValue val) {
    tjs_lws_ctx *u = JS_GetOpaque(val, tjs_lws_ctx_class_id);
    if (u) {
        if(u->lws_ctx){
            lws_context_destroy(u->lws_ctx);
			u->lws_ctx = NULL;
        }
        free_queue(u->js_ctx, &u->deps);
        js_free_rt(rt, u);
    }
}

JSClassDef tjs_lws_ctx_class = { "LWSContext", .finalizer = js_lws_ctx_finalizer, .gc_mark = js_lws_ctx_mark };

static const JSCFunctionListEntry tjs_lws_ctx_proto_funcs[] = {
    TJS_CFUNC_DEF("add_vhost", 3, tjs_mod_lws_add_vhost)
};

#define TJS_CONST_STRING_DEF(x) JS_PROP_INT32_DEF(#x, x, JS_PROP_ENUMERABLE)

static const JSCFunctionListEntry tjs_lws_protocol_types[] = {
    JS_PROP_INT32_DEF("HTTP", LWSMPRO_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTPS", LWSMPRO_HTTPS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("FILE", LWSMPRO_FILE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI", LWSMPRO_CGI, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("REDIR_HTTP", LWSMPRO_REDIR_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("REDIR_HTTPS", LWSMPRO_REDIR_HTTPS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CALLBACK", LWSMPRO_CALLBACK, JS_PROP_ENUMERABLE),
};

static JSValue tjs_lws_load_native(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue lwsobj = JS_NewObject(ctx);

    JS_NewClassID(JS_GetRuntime(ctx), &tjs_lws_ctx_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_lws_ctx_class_id, &tjs_lws_ctx_class);
    JSValue tjs_lws_ctx_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tjs_lws_ctx_proto, tjs_lws_ctx_proto_funcs, countof(tjs_lws_ctx_proto_funcs));
    JS_SetClassProto(ctx, tjs_lws_ctx_class_id, tjs_lws_ctx_proto);
    JSValue tjs_lws_ctx_constructor = JS_NewCFunction2(ctx, tjs_mod_lws_create_ctx, tjs_lws_ctx_class.class_name, 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, lwsobj, tjs_lws_ctx_class.class_name, tjs_lws_ctx_constructor, JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE | JS_PROP_ENUMERABLE);

    JSValue protocol_types = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, protocol_types, tjs_lws_protocol_types, countof(tjs_lws_protocol_types));
    JS_SetPropertyStr(ctx, lwsobj, "protocol_types", protocol_types);

    return lwsobj;
}

void tjs__mod_lws_init(JSContext *ctx, JSValue ns) {
    JSValue func = JS_NewCFunction(ctx, tjs_lws_load_native, "lws_load_native", 0);
    JS_SetPropertyStr(ctx, ns, "lws_load_native", func);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_DEBUG, NULL);
}
