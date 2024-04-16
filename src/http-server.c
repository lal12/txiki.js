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
#include <assert.h>
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
        *start = ptr->next;
        js_free(ctx, ptr);
    }
}

static void mark_queue(JSRuntime* rt, js_alloc_t** start, JS_MarkFunc* mark_func){
    js_alloc_t* ptr = *start;
    while(ptr){
        if(ptr->type == 'j'){
            JS_MarkValue(rt, ptr->data.jsval, mark_func);
        }
        ptr = ptr->next;
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
static JSClassID tjs_lws_wsi_class_id;

typedef struct{
    struct lws *wsi;
    JSValue js_wsi;
} tjs_lws_wsi;

static void js_lws_wsi_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    /*
    //TODO Marking self object is probably not necessary?
    tjs_lws_wsi *wsi = JS_GetOpaque(val, tjs_lws_wsi_class_id);
    if (wsi) {
        JS_MarkValue(rt, wsi->js_wsi, mark_func);
    }*/
}

static void js_lws_wsi_finalizer(JSRuntime *rt, JSValue val) {
    tjs_lws_wsi* wsi = JS_GetOpaque(val, tjs_lws_wsi_class_id);
    if (wsi) {
        //TODO cleaning class object itself is probably not necessary
        //JS_FreeValueRT(rt, wsi->js_wsi);
        if(wsi->wsi){
            js_free_rt(rt, wsi->wsi);
        }
    }
}

static JSValue js_lws_wsi_write_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_wsi *wsi = JS_GetOpaque(this_val, tjs_lws_wsi_class_id);
    if (wsi == NULL) {
        JS_ThrowTypeError(ctx, "expected this to be LWSWSI");
        return JS_EXCEPTION;
    }
    if(!JS_IsNumber(argv[0])){
        JS_ThrowTypeError(ctx, "Expected numeric status code");
        return JS_EXCEPTION;
    }
    unsigned statuscode = JS_VALUE_GET_INT(argv[0]);
    if(!JS_IsArray(ctx, argv[1])){
        JS_ThrowTypeError(ctx, "Expected headers to be array");
        return JS_EXCEPTION;
    }
    size_t buf_len = 2048;
    JSValue arrlen_js = JS_GetPropertyStr(ctx, argv[1], "length");
    int arrlen = JS_VALUE_GET_INT(arrlen_js);
    JS_FreeValue(ctx, arrlen_js);
    char* buf = js_malloc(ctx, buf_len);
    char* ptr = buf;
    char* end = buf + buf_len;
    bool err = false;
    int ret = lws_add_http_header_status(wsi->wsi, JS_VALUE_GET_INT(argv[0]), &ptr, end);
    if(!ret){
        for(unsigned i=0;i<arrlen;i++){
            JSValue header = JS_GetPropertyUint32(ctx, argv[1], i);
            if(JS_IsArray(ctx, header)){
                arrlen_js = JS_GetPropertyStr(ctx, header, "length");
                int header_arr_len = JS_VALUE_GET_INT(arrlen_js);
                JS_FreeValue(ctx, arrlen_js);
                if(header_arr_len == 2){
                    JSValue name = JS_GetPropertyUint32(ctx, header, 0);
                    JSValue value = JS_GetPropertyUint32(ctx, header, 1);
                    if(JS_IsString(name) && JS_IsString(value)){
                        size_t name_len, value_len;
                        const char* name_cstr = JS_ToCStringLen2(ctx, &name_len, name, 0);
                        const char* value_cstr = JS_ToCStringLen2(ctx, &value_len, name, 0);
                        //TODO increase buffer size if needed
                        int ret = lws_add_http_header_by_name(wsi->wsi, name_cstr, value_cstr, value_cstr, &ptr, end);
                        if(ret){
                            JS_ThrowInternalError(ctx, "Failed to add header");
                            err = true;
                        }
                        JS_FreeCString(ctx, name_cstr);
                        JS_FreeCString(ctx, value_cstr);
                    }else{
                        err = true;
                        JS_ThrowTypeError(ctx, "Expected strings as header name and value");
                    }
                    JS_FreeValue(ctx, name);
                    JS_FreeValue(ctx, value);
                }else{
                    err = true;
                    JS_ThrowTypeError(ctx, "Expected array of length 2 as header");
                }
            }else{
                JS_ThrowTypeError(ctx, "Expected arrray of arrays as headers");
                err = true;
            }
            JS_FreeValue(ctx, header);
            if(err){
                break;
            }
        }
    }else{
        JS_ThrowInternalError(ctx, "Failed to set status code");
        err = true;
    }
    if(!err){
        ret = lws_finalize_write_http_header(wsi->wsi, buf, &ptr, end);
        if(ret){
            JS_ThrowInternalError(ctx, "Failed to finalize header");
            err = true;
        }
    }
    js_free(ctx, buf);
    if(err){
        return JS_EXCEPTION;
    }
    return JS_UNDEFINED;
}

static JSValue js_lws_wsi_info(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_wsi *wsi = JS_GetOpaque(this_val, tjs_lws_wsi_class_id);
    char* uri;
    int len;
    int method = lws_http_get_uri_and_method(wsi->wsi, &uri, &len);
    if(method < 0){
        JS_ThrowInternalError(ctx, "could not get uri");
        return JS_EXCEPTION;
    }
    JSValue uri_js = JS_NewStringLen(ctx, uri, len);
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "uri", uri_js);
    JSValue method_js = JS_UNDEFINED;
    switch(method){
        case WSI_TOKEN_GET_URI:
            method_js = JS_NewString(ctx, "GET");
        break;
        case WSI_TOKEN_POST_URI:
            method_js = JS_NewString(ctx, "POST");
        case WSI_TOKEN_OPTIONS_URI:
            method_js = JS_NewString(ctx, "OPTIONS");
        break;
        case WSI_TOKEN_PUT_URI:
            method_js = JS_NewString(ctx, "PUT");
        break;
        case WSI_TOKEN_PATCH_URI:
            method_js = JS_NewString(ctx, "PATCH");
        break;
        case WSI_TOKEN_DELETE_URI:
            method_js = JS_NewString(ctx, "DELETE");
        break;
        case WSI_TOKEN_CONNECT:
            method_js = JS_NewString(ctx, "CONNECT");
        break;
        case WSI_TOKEN_HEAD_URI:
            method_js = JS_NewString(ctx, "HEAD");
        break;
    }
    if(!JS_IsUndefined(method_js)){
        JS_SetPropertyStr(ctx, obj, "method", method_js);
    }
    return obj;
}

static JSValue js_lws_wsi_wait_writable(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_wsi *wsi = JS_GetOpaque(this_val, tjs_lws_wsi_class_id);
    if (wsi == NULL) {
        JS_ThrowTypeError(ctx, "expected this to be LWSWSI");
        return JS_EXCEPTION;
    }
    int ret = lws_callback_on_writable(wsi->wsi);
    if(ret){
        JS_ThrowInternalError(ctx, "Failed to enable writable callback");
        return JS_EXCEPTION;
    }
    return JS_UNDEFINED;
}

static JSValue js_lws_wsi_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_wsi *wsi = JS_GetOpaque(this_val, tjs_lws_wsi_class_id);
    if (wsi == NULL) {
        JS_ThrowTypeError(ctx, "expected this to be LWSWSI");
        return JS_EXCEPTION;
    }
    unsigned proto;
    if(!JS_IsNumber(argv[1])){
        JS_ThrowTypeError(ctx, "Expected numeric protocol");
        return JS_EXCEPTION;
    }
    proto = JS_VALUE_GET_INT(argv[1]);
    if(JS_IsString(argv[0])){
        size_t len;
        const char* buf = JS_ToCStringLen(ctx, &len, argv[0]);
        int ret = lws_write(wsi->wsi, (uint8_t*)buf, len, proto);
        JS_FreeCString(ctx, buf);
        if(ret != len){
            JS_ThrowInternalError(ctx, "Failed to write");
            return JS_EXCEPTION;
        }
    }else if(JS_IsArrayBuffer(argv[0])){
        size_t len;
        uint8_t* buf = JS_GetArrayBuffer(ctx, &len, argv[0]);
        int ret = lws_write(wsi->wsi, buf, len, proto);
        if(ret != len){
            JS_ThrowInternalError(ctx, "Failed to write");
            return JS_EXCEPTION;
        }
    }else{
        JS_ThrowTypeError(ctx, "Expected string or array buffer as arg #1");
        return JS_EXCEPTION;
    }
    return JS_UNDEFINED;
}

static JSValue js_lws_wsi_complete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_wsi *wsi = JS_GetOpaque(this_val, tjs_lws_wsi_class_id);
    if (wsi == NULL) {
        JS_ThrowTypeError(ctx, "expected this to be LWSWSI");
        return JS_EXCEPTION;
    }
    wsi->http.did_stream_close = 1;
    int ret = lws_http_transaction_completed(wsi);
    if(ret){
        JS_ThrowInternalError(ctx, "Failed to complete transaction");
        return JS_EXCEPTION;
    }
    return JS_UNDEFINED;
}

static int js_lws_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len){
    switch(reason){
        case LWS_CALLBACK_PROTOCOL_INIT:
        case LWS_CALLBACK_PROTOCOL_DESTROY:
        case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
        case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
        case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
            return 0;
        default:
            break;
    }

    JSValue* cb_js = lws_get_protocol(wsi)->user;
    assert(cb_js > 0);
    tjs_lws_ctx* lws_h = lws_context_user(lws_get_context(wsi));
    assert(lws_h > 0);
    JSContext* js_ctx = lws_h->js_ctx;
    assert(js_ctx > 0);

    switch(reason){
        case LWS_CALLBACK_WSI_CREATE:{
            tjs_lws_wsi* wsi_data = js_mallocz(js_ctx, sizeof(tjs_lws_wsi));
            lws_set_opaque_parent_data(wsi, wsi_data);
            wsi_data->wsi = wsi;
            wsi_data->js_wsi = JS_NewObjectClass(js_ctx, tjs_lws_wsi_class_id);
            JS_SetOpaque(wsi_data->js_wsi, wsi_data);
            return 0;
        }
        case LWS_CALLBACK_WSI_DESTROY:{
            tjs_lws_wsi* wsi_data = lws_get_opaque_parent_data(wsi);
            if(wsi_data && wsi_data->wsi){ // seems to be called twice sometimes, so check if data is already freed
                wsi_data->wsi = NULL; // notice to js side that this wsi is no longer valid
                JS_FreeValue(js_ctx, wsi_data->js_wsi);
            }
            return 0;
        }
        // following requests are handled by js side
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
        case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
        case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
        case LWS_CALLBACK_HTTP:
        case LWS_CALLBACK_HTTP_WRITEABLE:
        case LWS_CALLBACK_CLOSED_HTTP:
            break;
    }

    tjs_lws_wsi* wsi_data = lws_get_opaque_parent_data(wsi);

    JSValueConst args[3];
    args[0] = JS_NewInt32(js_ctx, reason);
    args[1] = len > 0 ? JS_NewArrayBufferCopy(js_ctx, in, len) : JS_UNDEFINED;
    args[2] = wsi_data ? wsi_data->js_wsi : JS_UNDEFINED;
    JSValue ret = JS_Call(js_ctx, *cb_js, JS_UNDEFINED, 3, args);
    JS_FreeValue(js_ctx, args[0]);
    JS_FreeValue(js_ctx, args[1]);
    int retcode = 1;
    if(JS_IsNumber(ret)){
        retcode = JS_VALUE_GET_INT(ret);
    }
    JS_FreeValue(js_ctx, ret);
    return retcode;
}

static JSValue tjs_mod_lws_create_ctx(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    tjs_lws_ctx *lws = js_mallocz(ctx, sizeof(tjs_lws_ctx));
    struct lws_context_creation_info info;
    memset( &info, 0, sizeof(info) );
    info.gid = -1;
    info.uid = -1;
    info.user = lws;
    info.options = LWS_SERVER_OPTION_LIBUV | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    void* foreign_loops[2] = {0};
    foreign_loops[0] = tjs_get_loop(ctx);
    info.foreign_loops = foreign_loops;
    lws->lws_ctx = lws_create_context(&info);
    lws->js_ctx = ctx;
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
        struct lws_vhost* vh = lws_create_vhost(lws->lws_ctx, &info);
        if(!vh){
            JS_ThrowInternalError(ctx, "Failed to create vhost");
            error = true;
        }
    }

end:

    free_queue(ctx, &init_alloc);

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
        printf("Destroying LWSContext\n");
        if(u->lws_ctx){
            lws_context_destroy(u->lws_ctx);
            u->lws_ctx = NULL;
        }
        printf("Freeing deps\n");
        free_queue(u->js_ctx, &u->deps);
        printf("Freeing tjs_lws_ctx\n");
        js_free_rt(rt, u);
    }
}

JSClassDef tjs_lws_wsi_class = { "LWSWSI", .finalizer = js_lws_wsi_finalizer, .gc_mark = js_lws_wsi_mark };
static const JSCFunctionListEntry tjs_lws_wsi_methods[] = {
    TJS_CFUNC_DEF("write_header", 2, js_lws_wsi_write_header),
    TJS_CFUNC_DEF("info", 0, js_lws_wsi_info),
    TJS_CFUNC_DEF("wait_writable", 0, js_lws_wsi_wait_writable),
    TJS_CFUNC_DEF("write", 2, js_lws_wsi_write),
    TJS_CFUNC_DEF("complete", 0, js_lws_wsi_complete),
};

JSClassDef tjs_lws_ctx_class = { "LWSContext", .finalizer = js_lws_ctx_finalizer, .gc_mark = js_lws_ctx_mark };
static const JSCFunctionListEntry tjs_lws_ctx_methods[] = {
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

static const JSCFunctionListEntry tjs_lws_reasons[] = {
    JS_PROP_INT32_DEF("PROTOCOL_INIT",LWS_CALLBACK_PROTOCOL_INIT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("PROTOCOL_DESTROY",LWS_CALLBACK_PROTOCOL_DESTROY, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WSI_CREATE",LWS_CALLBACK_WSI_CREATE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WSI_DESTROY",LWS_CALLBACK_WSI_DESTROY, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WSI_TX_CREDIT_GET",LWS_CALLBACK_WSI_TX_CREDIT_GET, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS",LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS",LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION",LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("SSL_INFO",LWS_CALLBACK_SSL_INFO, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("OPENSSL_PERFORM_SERVER_CERT_VERIFICATION",LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("SERVER_NEW_CLIENT_INSTANTIATED",LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP",LWS_CALLBACK_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_BODY",LWS_CALLBACK_HTTP_BODY, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_BODY_COMPLETION",LWS_CALLBACK_HTTP_BODY_COMPLETION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_FILE_COMPLETION",LWS_CALLBACK_HTTP_FILE_COMPLETION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_WRITEABLE",LWS_CALLBACK_HTTP_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLOSED_HTTP",LWS_CALLBACK_CLOSED_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("FILTER_HTTP_CONNECTION",LWS_CALLBACK_FILTER_HTTP_CONNECTION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("ADD_HEADERS",LWS_CALLBACK_ADD_HEADERS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("VERIFY_BASIC_AUTHORIZATION",LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CHECK_ACCESS_RIGHTS",LWS_CALLBACK_CHECK_ACCESS_RIGHTS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("PROCESS_HTML",LWS_CALLBACK_PROCESS_HTML, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_BIND_PROTOCOL",LWS_CALLBACK_HTTP_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_DROP_PROTOCOL",LWS_CALLBACK_HTTP_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_CONFIRM_UPGRADE",LWS_CALLBACK_HTTP_CONFIRM_UPGRADE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("ESTABLISHED_CLIENT_HTTP",LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLOSED_CLIENT_HTTP",LWS_CALLBACK_CLOSED_CLIENT_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RECEIVE_CLIENT_HTTP_READ",LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RECEIVE_CLIENT_HTTP",LWS_CALLBACK_RECEIVE_CLIENT_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("COMPLETED_CLIENT_HTTP",LWS_CALLBACK_COMPLETED_CLIENT_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_HTTP_WRITEABLE",LWS_CALLBACK_CLIENT_HTTP_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_HTTP_REDIRECT",LWS_CALLBACK_CLIENT_HTTP_REDIRECT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_HTTP_BIND_PROTOCOL",LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_HTTP_DROP_PROTOCOL",LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("ESTABLISHED",LWS_CALLBACK_ESTABLISHED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLOSED",LWS_CALLBACK_CLOSED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("SERVER_WRITEABLE",LWS_CALLBACK_SERVER_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RECEIVE",LWS_CALLBACK_RECEIVE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RECEIVE_PONG",LWS_CALLBACK_RECEIVE_PONG, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_PEER_INITIATED_CLOSE",LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("FILTER_PROTOCOL_CONNECTION",LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CONFIRM_EXTENSION_OKAY",LWS_CALLBACK_CONFIRM_EXTENSION_OKAY, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_SERVER_BIND_PROTOCOL",LWS_CALLBACK_WS_SERVER_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_SERVER_DROP_PROTOCOL",LWS_CALLBACK_WS_SERVER_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_CONNECTION_ERROR",LWS_CALLBACK_CLIENT_CONNECTION_ERROR, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_FILTER_PRE_ESTABLISH",LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_ESTABLISHED",LWS_CALLBACK_CLIENT_ESTABLISHED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_CLOSED",LWS_CALLBACK_CLIENT_CLOSED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_APPEND_HANDSHAKE_HEADER",LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_RECEIVE",LWS_CALLBACK_CLIENT_RECEIVE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_RECEIVE_PONG",LWS_CALLBACK_CLIENT_RECEIVE_PONG, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_WRITEABLE",LWS_CALLBACK_CLIENT_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_CONFIRM_EXTENSION_SUPPORTED",LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_EXT_DEFAULTS",LWS_CALLBACK_WS_EXT_DEFAULTS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("FILTER_NETWORK_CONNECTION",LWS_CALLBACK_FILTER_NETWORK_CONNECTION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_CLIENT_BIND_PROTOCOL",LWS_CALLBACK_WS_CLIENT_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("WS_CLIENT_DROP_PROTOCOL",LWS_CALLBACK_WS_CLIENT_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("GET_THREAD_ID",LWS_CALLBACK_GET_THREAD_ID, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("ADD_POLL_FD",LWS_CALLBACK_ADD_POLL_FD, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("DEL_POLL_FD",LWS_CALLBACK_DEL_POLL_FD, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CHANGE_MODE_POLL_FD",LWS_CALLBACK_CHANGE_MODE_POLL_FD, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("LOCK_POLL",LWS_CALLBACK_LOCK_POLL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("UNLOCK_POLL",LWS_CALLBACK_UNLOCK_POLL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI",LWS_CALLBACK_CGI, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI_TERMINATED",LWS_CALLBACK_CGI_TERMINATED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI_STDIN_DATA",LWS_CALLBACK_CGI_STDIN_DATA, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI_STDIN_COMPLETED",LWS_CALLBACK_CGI_STDIN_COMPLETED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CGI_PROCESS_ATTACH",LWS_CALLBACK_CGI_PROCESS_ATTACH, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("SESSION_INFO",LWS_CALLBACK_SESSION_INFO, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("GS_EVENT",LWS_CALLBACK_GS_EVENT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_PMO",LWS_CALLBACK_HTTP_PMO, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_RX",LWS_CALLBACK_RAW_PROXY_CLI_RX, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_RX",LWS_CALLBACK_RAW_PROXY_SRV_RX, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_CLOSE",LWS_CALLBACK_RAW_PROXY_CLI_CLOSE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_CLOSE",LWS_CALLBACK_RAW_PROXY_SRV_CLOSE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_WRITEABLE",LWS_CALLBACK_RAW_PROXY_CLI_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_WRITEABLE",LWS_CALLBACK_RAW_PROXY_SRV_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_ADOPT",LWS_CALLBACK_RAW_PROXY_CLI_ADOPT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_ADOPT",LWS_CALLBACK_RAW_PROXY_SRV_ADOPT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_BIND_PROTOCOL",LWS_CALLBACK_RAW_PROXY_CLI_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_BIND_PROTOCOL",LWS_CALLBACK_RAW_PROXY_SRV_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_CLI_DROP_PROTOCOL",LWS_CALLBACK_RAW_PROXY_CLI_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_PROXY_SRV_DROP_PROTOCOL",LWS_CALLBACK_RAW_PROXY_SRV_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_RX",LWS_CALLBACK_RAW_RX, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_CLOSE",LWS_CALLBACK_RAW_CLOSE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_WRITEABLE",LWS_CALLBACK_RAW_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_ADOPT",LWS_CALLBACK_RAW_ADOPT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_CONNECTED",LWS_CALLBACK_RAW_CONNECTED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_SKT_BIND_PROTOCOL",LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_SKT_DROP_PROTOCOL",LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_ADOPT_FILE",LWS_CALLBACK_RAW_ADOPT_FILE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_RX_FILE",LWS_CALLBACK_RAW_RX_FILE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_WRITEABLE_FILE",LWS_CALLBACK_RAW_WRITEABLE_FILE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_CLOSE_FILE",LWS_CALLBACK_RAW_CLOSE_FILE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_FILE_BIND_PROTOCOL",LWS_CALLBACK_RAW_FILE_BIND_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("RAW_FILE_DROP_PROTOCOL",LWS_CALLBACK_RAW_FILE_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("TIMER",LWS_CALLBACK_TIMER, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("EVENT_WAIT_CANCELLED",LWS_CALLBACK_EVENT_WAIT_CANCELLED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CHILD_CLOSING",LWS_CALLBACK_CHILD_CLOSING, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CONNECTING",LWS_CALLBACK_CONNECTING, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("VHOST_CERT_AGING",LWS_CALLBACK_VHOST_CERT_AGING, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("VHOST_CERT_UPDATE",LWS_CALLBACK_VHOST_CERT_UPDATE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_NEW_CLIENT_INSTANTIATED",LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_IDLE",LWS_CALLBACK_MQTT_IDLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_CLIENT_ESTABLISHED",LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_SUBSCRIBED",LWS_CALLBACK_MQTT_SUBSCRIBED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_CLIENT_WRITEABLE",LWS_CALLBACK_MQTT_CLIENT_WRITEABLE, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_CLIENT_RX",LWS_CALLBACK_MQTT_CLIENT_RX, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_UNSUBSCRIBED",LWS_CALLBACK_MQTT_UNSUBSCRIBED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_DROP_PROTOCOL",LWS_CALLBACK_MQTT_DROP_PROTOCOL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_CLIENT_CLOSED",LWS_CALLBACK_MQTT_CLIENT_CLOSED, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_ACK",LWS_CALLBACK_MQTT_ACK, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_RESEND",LWS_CALLBACK_MQTT_RESEND, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_UNSUBSCRIBE_TIMEOUT",LWS_CALLBACK_MQTT_UNSUBSCRIBE_TIMEOUT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("MQTT_SHADOW_TIMEOUT",LWS_CALLBACK_MQTT_SHADOW_TIMEOUT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("USER",LWS_CALLBACK_USER, JS_PROP_ENUMERABLE),
};

static const JSCFunctionListEntry tjs_lws_write_protocols[] = {
    JS_PROP_INT32_DEF("TEXT", LWS_WRITE_TEXT, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("BINARY", LWS_WRITE_BINARY, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CONTINUATION", LWS_WRITE_CONTINUATION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP", LWS_WRITE_HTTP, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("PING", LWS_WRITE_PING, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("PONG", LWS_WRITE_PONG, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_FINAL", LWS_WRITE_HTTP_FINAL, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_HEADERS", LWS_WRITE_HTTP_HEADERS, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("HTTP_HEADERS_CONTINUATION", LWS_WRITE_HTTP_HEADERS_CONTINUATION, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("BUFLIST", LWS_WRITE_BUFLIST, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("NO_FIN", LWS_WRITE_NO_FIN, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("H2_STREAM_END", LWS_WRITE_H2_STREAM_END, JS_PROP_ENUMERABLE),
    JS_PROP_INT32_DEF("CLIENT_IGNORE_XOR_MASK", LWS_WRITE_CLIENT_IGNORE_XOR_MASK, JS_PROP_ENUMERABLE),
};

static JSValue tjs_lws_load_native(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue lwsobj = JS_NewObject(ctx);

    JS_NewClassID(JS_GetRuntime(ctx), &tjs_lws_ctx_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_lws_ctx_class_id, &tjs_lws_ctx_class);
    JSValue tjs_lws_ctx_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tjs_lws_ctx_proto, tjs_lws_ctx_methods, countof(tjs_lws_ctx_methods));
    JS_SetClassProto(ctx, tjs_lws_ctx_class_id, tjs_lws_ctx_proto);
    JSValue tjs_lws_ctx_constructor = JS_NewCFunction2(ctx, tjs_mod_lws_create_ctx, tjs_lws_ctx_class.class_name, 1, JS_CFUNC_constructor, 0);
    JS_DefinePropertyValueStr(ctx, lwsobj, tjs_lws_ctx_class.class_name, tjs_lws_ctx_constructor, JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE | JS_PROP_ENUMERABLE);

    JS_NewClassID(JS_GetRuntime(ctx), &tjs_lws_wsi_class_id);
    JS_NewClass(JS_GetRuntime(ctx), tjs_lws_wsi_class_id, &tjs_lws_wsi_class);
    JSValue tjs_lws_wsi_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tjs_lws_wsi_proto, tjs_lws_wsi_methods, countof(tjs_lws_wsi_methods));
    JS_SetClassProto(ctx, tjs_lws_wsi_class_id, tjs_lws_wsi_proto);

    JSValue protocol_types = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, protocol_types, tjs_lws_protocol_types, countof(tjs_lws_protocol_types));
    JS_SetPropertyStr(ctx, lwsobj, "protocol_types", protocol_types);

    JSValue reasons = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, reasons, tjs_lws_reasons, countof(tjs_lws_reasons));
    JS_SetPropertyStr(ctx, lwsobj, "reasons", reasons);

    JSValue write_protocols = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, write_protocols, tjs_lws_write_protocols, countof(tjs_lws_write_protocols));
    JS_SetPropertyStr(ctx, lwsobj, "write_protocols", write_protocols);

    return lwsobj;
}

void tjs__mod_lws_init(JSContext *ctx, JSValue ns) {
    JSValue func = JS_NewCFunction(ctx, tjs_lws_load_native, "lws_load_native", 0);
    JS_SetPropertyStr(ctx, ns, "lws_load_native", func);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_DEBUG, NULL);
}
