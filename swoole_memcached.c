#include "php_swoole.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <math.h>

extern swServerG SwooleG;

/* 1M */
#define AMC_WARN_BUFFER_SIZE 1048576

/* 1K */
#define AMC_DEFAULT_BUFFER_SIZE 1024

#define AMC_MIN_RECV_BUFFER_SIZE 16

#define AMC_HEAD_LINE_MAX_LEN 1024

#define AMC_BUFFER_THRESHOLD_RATIO 0.8

#define AMC_BUFFER_MIN_THRESHOLD_ALIGN_CPY_TIME 2

#define AMC_BUFFER_MAX_THRESHOLD_ALIGN_CPY_TIME 8

#define AMC_SET_NONBLOCK swSetNonBlock

#define AMC_OK 0
#define AMC_ERR -1
#define AMC_DONE 1
#define AMC_AGAIN 0

#ifndef MIN
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/*
 * {{{ list
 */

typedef struct _amc_list_node_t amc_list_node_t;

struct _amc_list_node_t {
    amc_list_node_t *prev;
    amc_list_node_t *next;

    void *ptr;
};

typedef struct _amc_list_t amc_list_t;

struct _amc_list_t {
    amc_list_node_t *head;
    amc_list_node_t *tail;

    size_t length;
};

#define amc_list_is_empty(list) (!list || !list->tail || !list->head || list->length <= 0)

static amc_list_node_t *_amc_list_pend(amc_list_t *list, void *ptr) {
    amc_list_node_t *node = ecalloc(1, sizeof(*node));
    if (node == NULL) {
        return NULL;
    }
    node->ptr = ptr;

    if (list->length == 0) {
        list->head = list->tail = node->next = node->prev = node;
    } else {
        node->next = list->head;
        node->prev = list->tail;
        list->head->prev = list->tail->next = node;
    }

    list->length++;

    return node;
}

static int amc_list_append(amc_list_t *list, void *ptr) {
    amc_list_node_t *node = _amc_list_pend(list, ptr);
    if (node == NULL) {
        return AMC_ERR;
    }
    list->tail = node;

    return AMC_OK;
}

static void *_amc_list_remove_node(amc_list_t *list, amc_list_node_t *node) {

    if (list->length == 1) {
        list->head = list->tail = NULL;
    } else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }

    void *ptr = node->ptr;
    list->length--;
    efree(node);
    return ptr;
}

static void *amc_list_pop_head(amc_list_t *list) {
    if (!list->head) {
        return NULL;
    }

    amc_list_node_t *node = list->head;
    list->head = node->next;
    return _amc_list_remove_node(list, node);
}

static void *amc_list_head(amc_list_t *list) {
    if (!list->head) {
        return NULL;
    }
    return list->head->ptr;
}
static void *amc_list_tail(amc_list_t *list) {
    if (!list->tail) {
        return NULL;
    }
    return list->tail->ptr;
}

static void *amc_list_pop_tail(amc_list_t *list) {
    if (!list->tail) {
        return NULL;
    }

    amc_list_node_t *node = list->head;
    list->tail = node->prev;
    return _amc_list_remove_node(list, node);
}

static amc_list_t *amc_list_create() {
    amc_list_t *list = (amc_list_t *) ecalloc(1, sizeof(*list));
    if (!list) {
        return NULL;
    }
    list->length = 0;

    return list;
}

static void inline amc_list_destory(amc_list_t *list) {
    if (!list) {
        return;
    }
    while (!amc_list_is_empty(list)) {
        amc_list_pop_tail(list);
    }
    efree(list);
}

/*
 * }}} list
 */

/*
 * {{{ utils
 */
/**
 * @return boolean of equal
 */
static int inline amc_strnequal(char *str1, char *str2, size_t n) {
    int i = 0;
    while (i < n && str1[i] == str2[i]) {
        i++;
    }

    return i < n ? 0 : 1;
}

#define amc_str_equal(s, cs) amc_strnequal(s, cs, sizeof(cs) - 1)

typedef struct {
    char *ptr;
    size_t len;
    /* the max value of len (exclude the terminating) */
    size_t max_len;
} amc_string;

#define amc_string_free_len(s) ((s)->max_len - (s)->len)

static int amc_string_init(amc_string *str, size_t len) {
    /* add a terminating byte */
    if (str->ptr && str->max_len < len) {
        erealloc(str->ptr, len + 1);
    } else if (!str->ptr) {
        str->ptr = emalloc(len + 1);
    }

    if (!str->ptr) {
        str->max_len = str->len = 0;
        return AMC_ERR;
    }

    str->len = 0;
    str->max_len = len;
    str->ptr[str->max_len] = '\0';
    return AMC_OK;
}

static amc_string *amc_stringl(amc_string *str, char *ptr, size_t len, int dup) {
    if (dup) {
        str->ptr = estrndup(ptr, len);
    } else {
        str->ptr = ptr;
    }
    str->len = len;
    str->max_len = len;

    return str;
}
/*
 * }}} utils
 */

/*
 * {{{ buffer_entry
 */
typedef struct _amc_buffer_entry {
    char *ptr;

    /* current buffer cursor*/
    size_t pos;
    /* buffer size */
    size_t len;
    /* size of buffer */
    size_t total_size;
} amc_buffer_t;

#define amc_buffer_size(b) b.len
#define amc_buffer_tail_size(b) ((b)->total_size - (b)->pos - (b)->len)
#define amc_buffer_tail_ptr(b) ((b)->ptr + (b)->len + (b)->pos)

#define amc_buffer_delete_bytes(b, n) \
do {\
    if (n <= 0) {\
        break;\
    }\
    if (n >= (b)->len) {\
        (b)->pos = (b)->len = 0;\
    } else {\
        (b)->pos += n;\
        (b)->len -= n;\
    }\
} while(0)

#define amc_buffer_move_to(b, ptr) \
do {\
    int n = (ptr) - ((b)->ptr + (b)->pos);\
    amc_buffer_delete_bytes(b, n);\
} while(0)

#define amc_buffer_clean(b) \
do {\
    b->pos = b->len = 0;\
} while(0)

static int inline amc_buffer_align_cpytime(amc_buffer_t *buffer) {
    if (buffer->len == 0 || buffer->pos == 0) {
        return 0;
    }

    return (int) ceil(buffer->len / (MIN(buffer->pos, buffer->len) * 1.0));
}

static int amc_buffer_align(amc_buffer_t *buffer) {
    if (buffer->pos == 0 || buffer->len == 0) {
        return AMC_OK;
    }

    size_t batch_size = MIN(buffer->pos, buffer->len);
    size_t copied = 0;
    size_t left = buffer->len;

    while (left > 0) {
        size_t n = MIN(left, batch_size);
        memcpy(buffer->ptr + copied, buffer->ptr + buffer->pos + copied, n);
        copied += n;
        left -= n;
    }

    buffer->pos = 0;
    return AMC_OK;
}

/*
 * @desc try to align (when it is rational) or resize buffer for storing data
 */
static int inline amc_buffer_make_room(amc_buffer_t *buffer, size_t need_size) {

    int align_copy_time = amc_buffer_align_cpytime(buffer);

    size_t new_size = buffer->total_size;
    size_t pos = buffer->pos;
    size_t len = buffer->len;

    /* MUST realloc when buffer is not large enough. */
    while ((new_size < len + need_size) ||
        /* SHOULD realloc, when tail of buffer is not large enough, and aligning is too expensive. */
        ((new_size - pos - len) < need_size && align_copy_time > AMC_BUFFER_MAX_THRESHOLD_ALIGN_CPY_TIME &&
         new_size <= AMC_WARN_BUFFER_SIZE)) {
        if (new_size >= AMC_WARN_BUFFER_SIZE) {
            new_size += AMC_WARN_BUFFER_SIZE;
        } else {
            new_size <<= 1;
        }
    }

    if (new_size > buffer->total_size) {
        buffer->ptr = erealloc(buffer->ptr, new_size);
        if (buffer->ptr == NULL) {
            return AMC_ERR;
        }
        buffer->total_size = new_size;
    }

    if ((align_copy_time > 0 && align_copy_time <= AMC_BUFFER_MIN_THRESHOLD_ALIGN_CPY_TIME) || amc_buffer_tail_size(buffer) < len) {
        amc_buffer_align(buffer);
    }

    return AMC_OK;
}

#define amc_buffer_ptr(b) ((b)->ptr + (b)->pos)

static amc_buffer_t *amc_buffer_create() {
    amc_buffer_t *buffer = emalloc(sizeof(amc_buffer_t));
    if (!buffer) {
        return NULL;
    }
    memset(buffer, 0, sizeof(amc_buffer_t));

    buffer->total_size = AMC_DEFAULT_BUFFER_SIZE;
    buffer->ptr = emalloc(buffer->total_size);
    if (!buffer->ptr) {
        efree(buffer);
        return NULL;
    }

    return buffer;
}

#define amc_buffer_destroy(b) do { if (!b) break; if (b->ptr) efree(b->ptr); efree(b); b = NULL;} while (0)

/*
 *}}} buffer_entry
 */

/* {{{ context and connection
 */
typedef struct _amc_async_context amc_async_context_t;
typedef struct _amc_connection amc_connection_t;

typedef struct _amc_reply amc_reply_t;
typedef struct _amc_kv_pair amc_kv_pair_t;

static void amc_swoole_event_add_write(amc_connection_t *conn);

static void amc_swoole_event_add_read(amc_connection_t *conn);

static void amc_swoole_event_del_write(amc_connection_t *conn);

static void amc_swoole_event_del_read(amc_connection_t *conn);

struct _amc_async_context {
    unsigned int err:2;

    struct {
        void *data;
        void (*addRead)(amc_connection_t *conn);
        void (*delRead)(amc_connection_t *conn);
        void (*addWrite)(amc_connection_t *conn);
        void (*delWrite)(amc_connection_t *conn);
        void (*cleanup)(amc_connection_t *conn);
    } ev;

    amc_buffer_t *in_buffer;
    amc_buffer_t *out_buffer;

    amc_list_t *operation_list;

    amc_reply_t *reply;
};

struct _amc_connection {
    amc_async_context_t context;

    zval *object;
    zval _object;

    struct sockaddr_in server_addr;

    int fd;

    zval *on_connect;

    zval *on_disconnect;
    unsigned int connected:1;
    unsigned int active:1;
};

static amc_connection_t* amc_connection_create() {
    amc_connection_t *conn = ecalloc(1, sizeof(amc_connection_t));
    if (!conn) {
        return NULL;
    }

    conn->context.in_buffer = amc_buffer_create();
    conn->context.out_buffer = amc_buffer_create();

    /* TODO connection->context.ev */
    conn->context.ev.data = conn;
    conn->context.ev.addWrite = amc_swoole_event_add_write;
    conn->context.ev.addRead = amc_swoole_event_add_read;
    conn->context.ev.delWrite = amc_swoole_event_del_write;
    conn->context.ev.delRead = amc_swoole_event_del_read;

    conn->context.operation_list = amc_list_create();

    if (!conn->context.in_buffer || !conn->context.out_buffer) {
        amc_buffer_destroy(conn->context.in_buffer);
        amc_buffer_destroy(conn->context.out_buffer);
        efree(conn);
        return NULL;
    }
    return conn;
}

#define amc_connection_destroy(conn) do { if (!conn) break; \
                                    amc_buffer_destroy(conn->context.in_buffer);\
                                    amc_buffer_destroy(conn->context.out_buffer);\
                                    amc_list_destory(conn->context.operation_list);\
                                    efree(conn);\
                                } while(0)

/*
 * }}} context and connection
 */

typedef enum {
    REPLY_VALUE = 0x1,
    REPLY_STORED = 0x2,
    REPLY_NOT_STORED = 0x4,
    REPLY_DELETED = 0x8,
    REPLY_NOT_FOUND = 0x10,
    REPLY_END = 0x20
} amc_reply_type_t;

typedef enum {
    OPERATION_GET = 0,
    OPERATION_SET,
    OPERATION_ADD,
    OPERATION_REP,
    OPERATION_DEL,
} amc_operation_type_t;

static char *amc_operation_names[] = {
    "get",
    "set",
    "add",
    "replace",
    "delete"
};

/* relate to amc_operation_type_t */
static int _AMC_EXPECT_REPLYS[] = {
    REPLY_VALUE | REPLY_END,
    REPLY_STORED,
    REPLY_STORED | REPLY_NOT_STORED,
    REPLY_STORED | REPLY_NOT_STORED,
    REPLY_DELETED | REPLY_NOT_FOUND
};

#define amc_expect_reply_types_of(r) _AMC_EXPECT_REPLYS[(r)->operation_type]

typedef enum {
    REPLY_ERR_ERROR = 1,
    REPLY_ERR_CLIENT,
    REPLY_ERR_SERVER,
} amc_reply_error_type_t;

struct _amc_reply {
    union {
        int effect;
        amc_list_t *values;
    } response;

    amc_operation_type_t operation_type;

    char *errstr;

    /* Is it as expected */

    amc_reply_error_type_t err;
};

struct _amc_kv_pair {
    amc_string key;
    amc_string value;

    int flag;
    size_t value_len;

    /* include \r\n, namely value_len + 2 */
    size_t left_len;
};

typedef struct _amc_operation {
    amc_operation_type_t type;

    zval *cb;
} amc_operation_t;

static amc_operation_t *amc_operation_create(amc_operation_type_t type, zval *cb) {
    amc_operation_t *operation = ecalloc(1, sizeof(*operation));
    if (!operation) {
        return NULL;
    }
    operation->cb = cb;
    operation->type = type;
    return operation;
}

static int amc_helper_build_zarray_from_list(zval *zarr, amc_list_t *list) {
    if (list->length <= 0) {
        ZVAL_NULL(zarr);
        return 0;
    }
    array_init_size(zarr, list->length);

    while (!amc_list_is_empty(list)) {
        amc_kv_pair_t *kv = amc_list_pop_head(list);
        if (!kv) {
            continue;
        }

        add_assoc_stringl(zarr, kv->key.ptr, kv->value.ptr, kv->value.len, 0);

        if (kv->key.ptr) {
            efree(kv->key.ptr);
        }
        efree(kv);
    }
    amc_list_destory(list);
    return 0;
}

static int amc_on_reply(amc_connection_t *conn, amc_reply_t *reply) {
    amc_async_context_t *context = &conn->context;

    amc_operation_t *operation = amc_list_pop_head(context->operation_list);

    int ret = AMC_OK;

    if (!operation) {
        ret = AMC_ERR;
        goto clean;
    }

    zval *zerr, *zparam, *retval = NULL;
    zval **args[] = {&zerr, &zparam};
    size_t argc = 2;
    MAKE_STD_ZVAL(zerr);
    MAKE_STD_ZVAL(zparam);
    ZVAL_NULL(zparam);
    ZVAL_NULL(zerr);

    if (reply->err || reply->errstr) {
        /* TODO error type */
        if (reply->errstr) {
            ZVAL_STRING(zerr, reply->errstr, 0);
        } else {
            ZVAL_LONG(zerr, reply->err);
        }
    } else {
        switch (operation->type) {
            case OPERATION_GET:
                if (!amc_list_is_empty(reply->response.values)) {
                    amc_helper_build_zarray_from_list(zparam, reply->response.values);
                }
                break;
            default:
                ZVAL_BOOL(zparam, reply->response.effect);
                break;
        }
    }

    if (sw_call_user_function_ex(EG(function_table), NULL, operation->cb, &retval, argc, args, 0, NULL)
        != SUCCESS) {
    }
    swTrace("after callback reply");
    if (retval) {
        sw_zval_ptr_dtor(&retval);
    }

clean:
    sw_zval_ptr_dtor(&zparam);
    sw_zval_ptr_dtor(&zerr);
    efree(reply);

    if (operation) {
        sw_zval_ptr_dtor(&operation->cb);
        sw_zval_ptr_dtor(&conn->object);
        efree(operation);
    }

    return ret;
}

/**
 *
 * @return bytes of received or -1 if error
 */
static int amc_recv_to_buffer(amc_connection_t *conn) {
    amc_buffer_t *buffer = conn->context.in_buffer;

    size_t free_size, old_len = buffer->len;
    int nread;
    char *buf;

    do {
        if (amc_buffer_make_room(buffer, AMC_MIN_RECV_BUFFER_SIZE) == AMC_ERR) {
            return AMC_ERR;
        }

        free_size = amc_buffer_tail_size(buffer);
        buf = amc_buffer_tail_ptr(buffer);

        while ((nread = read(conn->fd, buf, free_size)) < 0 &&
               errno == EINTR) {}

        if (nread < 0) {
            /* TODO error */
            break;
        } else if (nread == 0) {
            break;
        }

        buffer->len += nread;
    } while (nread == free_size);

    return buffer->len - old_len;
}

/**
 * @return
 */
static int amc_send_buffer(amc_connection_t *conn) {
    amc_buffer_t *buffer = conn->context.out_buffer;

    if (buffer->len <= 0) {
        goto send_done;
    }

    int nwrite = 0;
    while ((nwrite = write(conn->fd, amc_buffer_ptr(buffer), buffer->len)) < 0 && errno == EINTR) {}

    swTrace("write data:%s.", amc_buffer_ptr(buffer));
    swTrace("the last char:%d %d, and they should be:%d, %d", *(buffer->ptr + 8), *(buffer->ptr + 9), '\r', '\n');

    if (nwrite < 0) {
        /* TODO error */
        return AMC_ERR;
    }

    if (nwrite > 0) {
        amc_buffer_delete_bytes(buffer, nwrite);
    }
    swTrace("write %d bytes, left %lu bytes in buffer.", nwrite, buffer->len);

    return buffer->len == 0 ? AMC_DONE : AMC_OK;

send_done:
    amc_buffer_clean(buffer);
    return AMC_DONE;
}

/**
 * @return the offset of '\r' (followed by '\n'), or 0 if cannot find (because util parse a head line, we will not take away from buffer)
 * , or -1 if something is wrong.
 */
static int amc_buffer_find_eol(amc_buffer_t *buffer) {
    size_t nfind = MIN(buffer->len, AMC_HEAD_LINE_MAX_LEN);
    if (nfind <= 0) {
        return 0;
    }

    char *buf = buffer->ptr + buffer->pos;
    /* start pos */
    char *ptr = buf;
    /* end pos */
    char *last = buf + nfind; /* exclude */
    char *rchar = NULL;
    /* the last char can not be '\r' (need more one byte to store '\n') */
    int left = nfind - 1;

    do {
        rchar = memchr(ptr, '\r', left);

        /* step */
        ptr = rchar + 1;
        left = last - ptr - 1;

        /* when find '\r' that not followed by '\n' and buffer has more than 2 bytes to find than retry */
    } while (rchar && *(rchar + 1) != '\n' && left > 2);

    if (!rchar) {
        return nfind == AMC_HEAD_LINE_MAX_LEN ? -1 : 0;
    }

    return (rchar && (*(rchar + 1)) == '\n') ? (rchar - buf) : 0;
}

static int amc_read_value_section_from_buffer(amc_buffer_t *buffer, amc_kv_pair_t *kv) {
    if (!kv) {
        return AMC_ERR;
    }
    if (kv->left_len <= 0) {
        return AMC_DONE;
    }

    if (kv->left_len > 2) {
        size_t ncopy = MIN(kv->left_len - 2, buffer->len);
        if (ncopy <= 0) {
            return AMC_AGAIN;
        }
        memcpy(kv->value.ptr + kv->value.len, buffer->ptr + buffer->pos, ncopy);

        kv->value.len += ncopy;
        kv->left_len -= ncopy;
        amc_buffer_delete_bytes(buffer, ncopy);
    }

    if (kv->left_len > 0 && kv->left_len <= 2) {
        size_t ndelete = MIN(kv->left_len, buffer->len);
        kv->left_len -= ndelete;
        amc_buffer_delete_bytes(buffer, ndelete);
    }

    if (kv->left_len > 0) {
        return AMC_AGAIN;
    }

    return AMC_DONE;
}

static int amc_parse_value_reply(amc_buffer_t *buffer, amc_reply_t *reply) {
    if (!reply->response.values) {
        reply->response.values = amc_list_create();
    }

    amc_list_t *values = reply->response.values;
    amc_kv_pair_t *last_kv = amc_list_tail(values);
    if (last_kv && last_kv->left_len > 0 && (amc_read_value_section_from_buffer(buffer, last_kv) != AMC_DONE)) {
        goto again;
    }
    if (buffer->len <= 0) {
        goto again;
    }

    swTrace("start parse value");

    do {
        int roffset = amc_buffer_find_eol(buffer);
        if (roffset < 0) {
            goto error;
        } else if (roffset == 0) {
            goto again;
        }

        char *buf = amc_buffer_ptr(buffer);
        char *last = buf + roffset;
        char *sp_find = NULL;
        char *key_str = NULL;
        size_t key_len = 0;
        int value_len = 0;
        int flag = 0;

        if (amc_str_equal(buf, "END")) {
            amc_buffer_delete_bytes(buffer, 5);
            goto done;
        }

        /* skip "VALUE " */
        if (!amc_str_equal(buf, "VALUE")) {
            /* err */
            goto error;
        }

        /* parse key name */
        buf += sizeof("VALUE");
        sp_find = memchr(buf, ' ', last - buf);
        if (!sp_find) {
            goto error;
        }
        key_len = sp_find - buf;
        key_str = buf;

        /* parse flag */
        buf = sp_find + 1;
        sp_find = memchr(buf, ' ', last - buf);
        if (!sp_find) {
            goto error;
        }
        *sp_find = '\0';
        flag = atoi(buf);
        if (flag < 0) {
            goto error;
        }

        /* parse value length */
        buf = sp_find + 1;
        if (buf >= last) {
            goto error;
        }
        *last = '\0';
        value_len = atoi(buf);
        if (value_len < 0) {
            goto error;
        }

        amc_kv_pair_t *kv = emalloc(sizeof(*kv));
        memset(kv, 0, sizeof(*kv));
        amc_list_append(values, kv);

        amc_stringl(&kv->key, key_str, key_len, 1);
        kv->flag = flag;
        kv->value_len = value_len;
        kv->left_len = value_len + 2;

        if (value_len > 0) {
            amc_string_init(&kv->value, value_len);
        }

        /* first line done */
        amc_buffer_delete_bytes(buffer, roffset + 2);

        if (amc_read_value_section_from_buffer(buffer, kv) != AMC_DONE ||
            buffer->len <= 0) {
            goto again;
        }
    } while (1);

error:
    amc_buffer_clean(buffer);
    return AMC_ERR;

again:
    return AMC_AGAIN;
done:
    return AMC_DONE;
}

static int amc_continue_reply(amc_buffer_t *buffer, amc_reply_t *reply) {
    int expect_reply_types = amc_expect_reply_types_of(reply);

    if (expect_reply_types & REPLY_VALUE) {
        return amc_parse_value_reply(buffer, reply);
    } else {
        return AMC_ERR;
    }
}

/**
 * @param reply, An empty reply
 */
static int amc_parse_reply(amc_buffer_t *buffer, amc_reply_t *reply) {
    /* parse first line */
    int roffset = amc_buffer_find_eol(buffer);
    if (roffset <= 0) {
        return roffset < 0 ? AMC_ERR : AMC_OK;
    }
    /* length of first line (exclude \r\n)*/
    size_t head_length = roffset;
    char *buf = amc_buffer_ptr(buffer);

    /* {{{ error */
    if (amc_str_equal(buf, "ERROR")) {
        reply->err = REPLY_ERR_ERROR;
        goto after_one_line_reply;
    }
    if (amc_str_equal(buf, "CLIENT_ERROR")) {
        reply->err = REPLY_ERR_CLIENT;
        /* CLIENT_ERROR <errstr>\r\n */
        int prefix_len = sizeof("CLIENT_ERROR");
        reply->errstr = estrndup(buf + prefix_len, head_length - prefix_len);
        goto after_one_line_reply;
    }
    if (amc_str_equal(buf, "SERVER_ERROR")) {
        reply->err = REPLY_ERR_SERVER;
        /* SERVER_ERROR <errstr>\r\n */
        int prefix_len = sizeof("SERVER_ERROR");
        reply->errstr = estrndup(buf + prefix_len, head_length - prefix_len);
        goto after_one_line_reply;
    }
    /* }}} error */

    int expect_reply_types = amc_expect_reply_types_of(reply);

    if ((expect_reply_types & REPLY_STORED) && amc_str_equal(buf, "STORED")) {
        reply->response.effect = 1;
        goto after_one_line_reply;
    }
    if ((expect_reply_types & REPLY_STORED) && amc_str_equal(buf, "NOT_STORED")) {
        reply->response.effect = 0;
        goto after_one_line_reply;
    }

    if ((expect_reply_types & REPLY_DELETED) && amc_str_equal(buf, "DELETED")) {
        reply->response.effect = 1;
        goto after_one_line_reply;
    }
    if ((expect_reply_types & REPLY_NOT_FOUND) && amc_str_equal(buf, "NOT_FOUND")) {
        reply->response.effect = 0;
        goto after_one_line_reply;
    }

    /* TODO more operation (eg. incr/decr) */

    if ((expect_reply_types & REPLY_END) && amc_str_equal(buf, "END")) {
        goto after_one_line_reply;
    }

    /* All reply that has only one line is parsed */

    /* try to parse VALUE section */
    if (expect_reply_types & REPLY_VALUE) {
        return amc_parse_value_reply(buffer, reply);
    }

after_one_line_reply:
    /* move to next line */
    amc_buffer_delete_bytes(buffer, (head_length + 2));
    return 1;
}

static int amc_try_parse_reply(amc_connection_t *conn, amc_reply_t **preply) {
    swTrace("start try parse");
    amc_async_context_t *context = &conn->context;
    amc_reply_t *reply = context->reply;

    if (!reply) {
        if (amc_list_is_empty(context->operation_list)) {
            swTrace("operation list is empty");
            return AMC_ERR;
        }

        amc_operation_t *operation = amc_list_head(context->operation_list);
        reply = ecalloc(1, sizeof(amc_reply_t));
        if (!reply) {
            return AMC_ERR;
        }
        reply->operation_type = operation->type;
    }

    int res;
    if (context->reply) {
        res = amc_continue_reply(context->in_buffer, reply);
        swTrace("continue parse reply: %d", res);
    } else {
        res = amc_parse_reply(context->in_buffer, reply);
        swTrace("parse reply: %d", res);
    }

    if (res == AMC_DONE) {
        context->reply = NULL;
        *preply = reply;
        return AMC_DONE;
    } else if (res == AMC_AGAIN) {
        context->reply = reply;
        return AMC_AGAIN;
    } else {
        efree(reply);
        return AMC_ERR;
    }
}

static void amc_connection_on_read(amc_connection_t *conn) {
    amc_async_context_t *context = &conn->context;
    size_t nread = amc_recv_to_buffer(conn);
    swTrace("read return:%lu", nread);
    if (nread <= 0) {
        return;
    }
    swTrace("recv %lu bytes", nread);

    amc_reply_t *reply = NULL;

    int res;
    while (context->in_buffer->len > 0 && (res = amc_try_parse_reply(conn, &reply)) == AMC_DONE && reply) {
        int is_last = 0;
        if (context->in_buffer->len == 0) {
            is_last = 1;
        }
        amc_on_reply(conn, reply);
        if (is_last) {
            /* Avoid to operating connection after destruct */
            break;
        }
    }
}

static void amc_connection_on_connect(amc_connection_t *conn);
//static void amc_connection_on_read(amc_connection_t *conn);
static void amc_connection_on_write(amc_connection_t *conn) {
    swTrace("fd:%d is on write", conn->fd);
    /* TODO get sock err */
    int res = amc_send_buffer(conn);

    if (res == AMC_DONE) {
        swTrace("send done, del write");
        conn->context.ev.delWrite(conn);
    }
}

static void amc_connection_on_connect(amc_connection_t *conn) {
    if (conn->on_connect) {
        zval *retval;
        zval *on_connect = conn->on_connect, *object = conn->object;
        conn->on_connect = NULL;
        if (sw_call_user_function_ex(EG(function_table), NULL, on_connect,
                                     &retval, 0, NULL, 0, NULL) != SUCCESS) {
            swoole_php_fatal_error(E_WARNING, "Executing on connect callback failure.");
        }
        swTrace("after on connect");

        if (retval) {
            sw_zval_ptr_dtor(&retval);
        }
        swTrace("on connect done (1)");
        sw_zval_ptr_dtor(&on_connect);
        sw_zval_ptr_dtor(&object);
        swTrace("on connect done (2)");
        /* Should not do anything change */
    } else {
        swTrace("on connect callback is not exists.");
    }
}

static int amc_connection_close(amc_connection_t *conn) {
    if (conn->fd > 0) {
        swConnection *swConn = swReactor_get(SwooleG.main_reactor, conn->fd);
        swConn->object = NULL;
        swTrace("reactor delete");
        SwooleG.main_reactor->del(SwooleG.main_reactor, conn->fd);
    }

    swTrace("closing connection");
    if (!conn->connected) {
        swoole_php_error(E_WARNING, "Swoole memcached is not connected to server.");
        goto error;
    }
    conn->connected = 0;

    int res = 0;
    while ((res = close(conn->fd)) < 0 && errno == EINTR) {}
    if (res < 0) {
        swoole_php_error(E_WARNING, "When close connection:%d, error:%s.", conn->fd, strerror(errno));
        goto error;
    }
    swTrace("closing connection done");

    conn->connected = conn->active = conn->fd = 0;
    return AMC_OK;
error:
    conn->connected = conn->active = conn->fd = 0;
    return AMC_ERR;
}

static int amc_swoole_read_handle(swReactor *reactor, swEvent *event) {
    amc_connection_on_read(event->socket->object);

    return SW_OK;
}

static int amc_swoole_write_handle(swReactor *reactor, swEvent *event) {
    amc_connection_t *conn = event->socket->object;
    if (!conn) {
        return SW_OK;
    }

    amc_connection_on_write(conn);
    if (!conn->active && conn->connected) {
        conn->active = 1;
        amc_connection_on_connect(conn);
    }

    return SW_OK;
}

static int amc_swoole_error_handle(swReactor *reactor, swEvent *event) {

    return SW_OK;
}

static void amc_swoole_event_add_write(amc_connection_t *conn) {
    swTrace("add write");
    swReactor_add_event(SwooleG.main_reactor, conn->fd, SW_EVENT_WRITE);
}

static void amc_swoole_event_add_read(amc_connection_t *conn) {
    swTrace("add read");
    swReactor_add_event(SwooleG.main_reactor, conn->fd, SW_EVENT_READ);
}

static void amc_swoole_event_del_write(amc_connection_t *conn) {
    swTrace("del write");
    swReactor_del_event(SwooleG.main_reactor, conn->fd, SW_EVENT_WRITE);
}

static void amc_swoole_event_del_read(amc_connection_t *conn) {
    swTrace("del read");
    swReactor_del_event(SwooleG.main_reactor, conn->fd, SW_EVENT_READ);
}

/* PHP */

static PHP_METHOD(swoole_memcached, __construct);
static PHP_METHOD(swoole_memcached, __destruct);
static PHP_METHOD(swoole_memcached, connect);
static PHP_METHOD(swoole_memcached, close);
static PHP_METHOD(swoole_memcached, on);

static PHP_METHOD(swoole_memcached, set);
static PHP_METHOD(swoole_memcached, add);
static PHP_METHOD(swoole_memcached, replace);

static PHP_METHOD(swoole_memcached, get);

static PHP_METHOD(swoole_memcached, delete);


static zend_class_entry swoole_memcached_ce;
zend_class_entry *swoole_memcached_class_entry_ptr;

static const zend_function_entry swoole_memcached_methods[] = {
    PHP_ME(swoole_memcached, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_memcached, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_memcached, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, close, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, on, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, set, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, add, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, replace, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, get, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_memcached, delete, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_memcached_init(int module_number TSRMLS_DC) {
    SWOOLE_INIT_CLASS_ENTRY(swoole_memcached_ce, "swoole_memcached", "Swoole\\Memcached", swoole_memcached_methods);
    swoole_memcached_class_entry_ptr = zend_register_internal_class(&swoole_memcached_ce TSRMLS_CC);
}

static PHP_METHOD(swoole_memcached, __construct) {
    char *host;
    zend_size_t host_len;
    long port;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &host, &host_len, &port) == FAILURE) {
        RETURN_FALSE;
    }

    if (host_len <= 0 || port <= 0) {
        RETURN_FALSE;
    }

    amc_connection_t *conn = amc_connection_create();
    if (!conn) {
        RETURN_FALSE;
    }

    conn->server_addr.sin_family = AF_INET;
    conn->server_addr.sin_addr.s_addr = inet_addr(host);
    conn->server_addr.sin_port = htons(port);

#if PHP_MAJOR_VERSION < 7
    conn->object = getThis();
#else
    memcpy(&conn->_object, getThis(), sizeof(zval));
    conn->object = &conn->_object;
#endif

    swoole_set_object(getThis(), conn);
}

static PHP_METHOD(swoole_memcached, __destruct) {
    zval *object = getThis();

    swTrace("call __destruct");

    amc_connection_t *conn = swoole_get_object(object);

    if (conn) {
        if (conn->connected) {
            amc_connection_close(conn);
        }

        amc_connection_destroy(conn);
        swoole_set_object(object, NULL);
    }
}

static PHP_METHOD(swoole_memcached, connect) {
    zval *object = getThis();

    amc_connection_t *conn = swoole_get_object(object);
    zval *on_connect = NULL;

    if (conn->connected) {
        swoole_php_error(E_WARNING, "Memcached is already connected to server.\n");
        goto error;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z!", &on_connect) == FAILURE) {
        goto error;
    }

    if (!on_connect) {
        swoole_php_error(E_WARNING, "Callback function could not be empty.");
    }

    conn->connected = 1;

    conn->on_connect = on_connect;
    sw_zval_add_ref(&on_connect);
    sw_zval_add_ref(&conn->object);

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd <= 0) {
        goto error;
    }
    AMC_SET_NONBLOCK(conn->fd);

    swReactor *reactor = SwooleG.main_reactor;

    swConnection *swConn = swReactor_get(reactor, conn->fd);
    swConn->object = conn;
    php_swoole_check_reactor();
    reactor->setHandle(reactor, PHP_SWOOLE_FD_MEMCACHED | SW_EVENT_READ, amc_swoole_read_handle);
    reactor->setHandle(reactor, PHP_SWOOLE_FD_MEMCACHED | SW_EVENT_WRITE, amc_swoole_write_handle);
    reactor->setHandle(reactor, PHP_SWOOLE_FD_MEMCACHED | SW_EVENT_ERROR, amc_swoole_error_handle);

    int res = 0;
    while ((res = connect(conn->fd, (struct sockaddr*) &conn->server_addr, sizeof(struct sockaddr))) < 0 &&
           errno == EINTR) {}
    if ((res < 0 && errno == EINPROGRESS) || res >= 0) {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, conn->fd, PHP_SWOOLE_FD_MEMCACHED | SW_EVENT_WRITE) < 0) {
            swoole_php_error(E_WARNING, "Adding to reactor failure.");
            goto error;
        }
    } else {
        swoole_php_error(E_WARNING, "Connecting to memcached server error:%s", strerror(errno));
        goto error;
    }

    RETURN_TRUE;
error:
    conn->connected = 0;
    conn->on_connect = NULL;
    if (on_connect) {
        sw_zval_ptr_dtor(&on_connect);
    }
    if (conn->fd > 0) {
        close(conn->fd);
        conn->fd = 0;
    }
    RETURN_FALSE;
}

static PHP_METHOD(swoole_memcached, close) {
    zval *object = getThis();

    amc_connection_t *conn = swoole_get_object(object);
    int res = amc_connection_close(conn);

    if (res == AMC_ERR) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_memcached, on) {

}

static PHP_METHOD(swoole_memcached, get) {
    char *key;
    zend_size_t key_len;
    zval *cb;

    if (ZEND_NUM_ARGS() < 2) {
        WRONG_PARAM_COUNT;
    }

    zend_fcall_info;

    zval ***args = ecalloc(ZEND_NUM_ARGS(), sizeof(zval **));
    zend_uint argc = ZEND_NUM_ARGS();

    if (zend_get_parameters_array_ex(argc, args) == FAILURE) {
        efree(args);
        RETURN_FALSE;
    }

    zval *object = getThis();
    amc_connection_t *conn = swoole_get_object(object);
    amc_async_context_t *context = &conn->context;
    amc_buffer_t *buffer = context->out_buffer;

    amc_buffer_make_room(buffer, 6);
    memcpy(amc_buffer_tail_ptr(buffer), "get", 3);
    buffer->len += 3;
    size_t need_size;

    zend_uint argi = 0;
    int nwrite = 0;
    for (; argi < argc - 1; ++argi) {
        zval *zkey = *(args[argi]);
        convert_to_string(zkey);
        if (Z_STRLEN_P(zkey) <= 0) {
            swoole_php_error(E_WARNING, "key can not be empty.");
            continue;
        }
        need_size = Z_STRLEN_P(zkey) + 2;
        amc_buffer_make_room(buffer, need_size);
        nwrite = snprintf(amc_buffer_tail_ptr(buffer), need_size, " %s", Z_STRVAL_P(zkey));
        buffer->len += nwrite;
    }
    amc_buffer_make_room(buffer, 2);
    memcpy(amc_buffer_tail_ptr(buffer), "\r\n", 2);
    buffer->len += 2;
    cb = *(args[argi]);

    efree(args);

    amc_operation_t *operation = ecalloc(1, sizeof(*operation));
    operation->cb = cb;
    operation->type = OPERATION_GET;
    amc_list_append(context->operation_list, operation);

    sw_zval_add_ref(&conn->object);

    sw_zval_add_ref(&cb);

    context->ev.addWrite(conn);

    RETURN_TRUE;
}

static void memcached_store_command_process(amc_operation_type_t type, INTERNAL_FUNCTION_PARAMETERS) {
    char *key, *value;
    zend_size_t key_len, value_len;
    long expire;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslz", &key, &key_len, &value, &value_len,
                              &expire, &cb) == FAILURE) {
        RETURN_FALSE;
    }

    if (key_len <= 0 || value_len <= 0) {
        RETURN_FALSE;
    }

    amc_connection_t *conn = swoole_get_object(getThis());
    amc_async_context_t *context = &conn->context;
    amc_buffer_t *buffer = context->out_buffer;

    size_t need_size = 7 + 1 + key_len + 11 * 3 + 3 + 3;
    amc_buffer_make_room(buffer, need_size);
    int nwrite = snprintf(amc_buffer_tail_ptr(buffer), need_size, "%s key2 0 0 %d\r\n", amc_operation_names[type], value_len);

    if (nwrite > 0) {
        buffer->len += nwrite;
    } else {
        RETURN_FALSE;
    }

    amc_buffer_make_room(buffer, value_len);

    memcpy(amc_buffer_tail_ptr(buffer), value, value_len);
    buffer->len += value_len;

    amc_buffer_make_room(buffer, 2);
    memcpy(amc_buffer_tail_ptr(buffer), "\r\n", 2);
    buffer->len += 2;

    amc_operation_t *operation = amc_operation_create(type, cb);
    amc_list_append(context->operation_list, operation);

    sw_zval_add_ref(&conn->object);

    sw_zval_add_ref(&cb);

    context->ev.addWrite(conn);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_memcached, set) {
    memcached_store_command_process(OPERATION_SET, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_memcached, add) {
    memcached_store_command_process(OPERATION_ADD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_memcached, replace) {
    memcached_store_command_process(OPERATION_REP, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static PHP_METHOD(swoole_memcached, delete) {
    char *key;
    zend_size_t key_len;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &key, &key_len, &cb) == FAILURE) {
        RETURN_FALSE;
    }

    if (key_len <= 0) {
        RETURN_FALSE;
    }

    amc_connection_t *conn = swoole_get_object(getThis());
    amc_async_context_t *context = &conn->context;
    amc_buffer_t *buffer = context->out_buffer;

    /* tail: \r\n\0 */
    size_t need_size = sizeof("delete") + key_len + 3;
    amc_buffer_make_room(buffer, need_size);
    int nwrite = snprintf(amc_buffer_tail_ptr(buffer), need_size, "delete %s\r\n", key);
    if (nwrite <= 0) {
        RETURN_FALSE;
    }
    buffer->len += nwrite;

    amc_operation_t *operation = amc_operation_create(OPERATION_DEL, cb);
    amc_list_append(context->operation_list, operation);

    sw_zval_add_ref(&cb);
    sw_zval_add_ref(&conn->object);

    context->ev.addWrite(conn);

    RETURN_TRUE;
}
