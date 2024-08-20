/**
 * parser.c -- web log parsing
 *    ______      ___
 *   / ____/___  /   | _____________  __________
 *  / / __/ __ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 * / /_/ / /_/ / ___ / /__/ /__/  __(__  |__  )
 * \____/\____/_/  |_\___/\___/\___/____/____/
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2024 Gerardo Orellana <hello @ goaccess.io>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * "_XOPEN_SOURCE" is required for the GNU libc to export "strptime(3)"
 * correctly.
 */
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE

#include <ctype.h>
#include <errno.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_FOUND 1
#define KEY_NOT_FOUND -1
#define LINE_BUFFER 4096 /* read at most this num of chars */
#define NUM_TESTS 20     /* test this many lines from the log */
#define MAX_LOG_ERRORS 20
#define READ_BYTES 4096u
#define MAX_BATCH_LINES                                                        \
  8192u /* max number of lines to read per batch before a reflow */

#define LINE_LEN 23
#define ERROR_LEN 255
#define REF_SITE_LEN 511 /* maximum length of a referring site */
#define CACHE_STATUS_LEN 7
#define HASH_HEX 64

#define ERR_SPEC_TOKN_NUL 0x1
#define ERR_SPEC_TOKN_INV 0x2
#define ERR_SPEC_SFMT_MIS 0x3
#define ERR_SPEC_LINE_INV 0x4
#define ERR_LOG_NOT_FOUND 0x5
#define ERR_LOG_REALLOC_FAILURE 0x6

#define LOG_DEBUG(x, ...)                                                      \
  do {                                                                         \
    dbg_fprintf x;                                                             \
  } while (0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a < _b ? _a : _b;                                                         \
  })

typedef struct GSLList_ {
  void *data;
  struct GSLList_ *next;
} GSLList;

/* Write formatted debug log data to the logfile. */
static void dbg_fprintf(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

typedef struct GLogProp_ {
  char *filename; /* filename including path */
  char *fname;    /* basename(filename) */
  uint64_t inode; /* inode of the log */
  uint64_t size;  /* original size of log */
} GLogProp;

/* Log properties. Note: This is per line parsed */
typedef struct GLogItem_ {
  char *agent;
  char *date;
  char *host;
  char *keyphrase;
  char *method;
  char *protocol;
  char *qstr;
  char *ref;
  char *req;
  int status;
  char *time;
  char *vhost;
  char *userid;
  char *cache_status;

  char site[REF_SITE_LEN + 1];

  uint64_t resp_size;
  uint64_t serve_time;

  uint32_t numdate;
  int ignorelevel;
  int type_ip;

  /* UMS */
  char *mime_type;
  char *tls_type;
  char *tls_cypher;
  char *tls_type_cypher;

  char *errstr;
  struct tm dt;
} GLogItem;

typedef struct GLastParse_ {
  uint32_t line;
  int64_t ts;
  uint64_t size;
  uint16_t snippetlen;
  char snippet[READ_BYTES + 1];
} GLastParse;

/* Overall parsed log properties */
typedef struct GLog_ {
  uint8_t piping : 1;
  uint8_t log_erridx;
  uint32_t read;      /* lines read/parsed */
  uint64_t bytes;     /* bytes read on each iteration */
  uint64_t length;    /* length read from the log so far */
  uint64_t invalid;   /* invalid lines for this log */
  uint64_t processed; /* lines proceeded for this log */

  /* file test for persisted/restored data */
  uint16_t snippetlen;
  char snippet[READ_BYTES + 1];

  GLastParse lp;
  GLogProp props;
  struct tm start_time;

  char *fname_as_vhost;
  char **errors;

  FILE *pipe;
} GLog;

/* Container for all logs */
typedef struct Logs_ {
  uint8_t restored : 1;
  uint8_t load_from_disk_only : 1;
  uint64_t *processed;
  uint64_t offset;
  int size; /* num items */
  int idx;
  char *filename;
  GLog *glog;
} Logs;

/* Pthread jobs for multi-thread */
typedef struct GJob_ {
  uint32_t cnt;
  int p, test, dry_run, running;
  GLog *glog;
  GLogItem **logitems;
  char **lines;
} GJob;

/* Raw data field type */
typedef enum { U32, STR } datatype;

/* Raw Data extracted from table stores */
typedef struct GRawDataItem_ {
  uint32_t nkey;
  union {
    const char *data;
    uint32_t hits;
  };
} GRawDataItem;

typedef enum MODULES {
  VISITORS,
  REQUESTS,
  REQUESTS_STATIC,
  NOT_FOUND,
  HOSTS,
  OS,
  BROWSERS,
  VISIT_TIMES,
  VIRTUAL_HOSTS,
  REFERRERS,
  REFERRING_SITES,
  KEYPHRASES,
  STATUS_CODES,
  REMOTE_USER,
  CACHE_STATUS,
  MIME_TYPE,
  TLS_TYPE,
} GModule;

/* Raw Data per module */
typedef struct GRawData_ {
  GRawDataItem *items; /* data */
  GModule module;      /* current module */
  datatype type;
  int idx;  /* first level index */
  int size; /* total num of items on ht */
} GRawData;

#define FATAL(fmt, ...)                                                        \
  do {                                                                         \
    fprintf(stderr, "\nGoAccess parser module - %s %s\n", __DATE__, __TIME__); \
    fprintf(stderr, "\nFatal error has occurred");                             \
    fprintf(stderr, "\nError occurred at: %s - %s - %d\n", __FILE__,           \
            __FUNCTION__, __LINE__);                                           \
    fprintf(stderr, fmt, ##__VA_ARGS__);                                       \
    fprintf(stderr, "\n\n");                                                   \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

/* Self-checking wrapper to malloc() */
static void *xmalloc(size_t size) {
  void *ptr;

  if ((ptr = malloc(size)) == NULL)
    FATAL("Unable to allocate memory - failed.");

  return (ptr);
}

static char *xstrdup(const char *s) {
  char *ptr;
  size_t len;

  len = strlen(s) + 1;
  ptr = xmalloc(len);

  strncpy(ptr, s, len);
  return (ptr);
}

/* Self-checking wrapper to calloc() */
static void *xcalloc(size_t nmemb, size_t size) {
  void *ptr;

  if ((ptr = calloc(nmemb, size)) == NULL)
    FATAL("Unable to calloc memory - failed.");

  return (ptr);
}

/* Self-checking wrapper to realloc() */
static void *xrealloc(void *oldptr, size_t size) {
  void *newptr;

  if ((newptr = realloc(oldptr, size)) == NULL)
    FATAL("Unable to reallocate memory - failed");

  return (newptr);
}

/* Allocate memory for a new GRawData instance.
 *
 * On success, the newly allocated GRawData is returned . */
GRawData *new_grawdata(void) {
  GRawData *raw_data = xmalloc(sizeof(*raw_data));
  memset(raw_data, 0, sizeof *raw_data);

  return raw_data;
}

#define MAX_LINE_CONF 4096
#define MAX_EXTENSIONS 128
#define MAX_GEOIP_DBS 3
#define MAX_IGNORE_IPS 1024 + 128
#define MAX_IGNORE_REF 64
#define MAX_CUSTOM_COLORS 64
#define MAX_IGNORE_STATUS 64
#define MAX_OUTFORMATS 3
#define MAX_FILENAMES 3072
#define MIN_DATENUM_FMT_LEN 7

#define TOTAL_MODULES 17

/* maximum number of items within a panel */
#define MAX_CHOICES 366
/* real-time */
#define MAX_CHOICES_RT 50
/* max default items when date-spec = min */
#define MAX_CHOICES_MINUTE 1440 /* 24hrs */

/* date and time length - e.g., 2016/12/12 12:12:12 -0600 */
#define DATE_TIME 25 + 1
/* date length -  e.g., 2016/12/12 */
#define DATE_LEN 10 + 1
/* date length -  e.g., 12:12:12 */
#define TIME_LEN 8 + 1
/* hour + ':' + min length - e.g., 12:12 */
#define HRMI_LEN 4 + 1 + 1

#define YR_FMT "%Y"
#define MO_FMT "%M"
#define DT_FMT "%d"

/* maximum protocol string length */
#define REQ_PROTO_LEN 9

#define IGNORE_LEVEL_PANEL 1
#define IGNORE_LEVEL_REQ 2

/* Type of IP */
typedef enum { TYPE_IPINV, TYPE_IPV4, TYPE_IPV6 } GTypeIP;

/* Total number of storage metrics (GSMetric) */
#define GSMTRC_TOTAL 19

/* Enumerated Storage Metrics */
typedef enum GSMetric_ {
  MTRC_KEYMAP,
  MTRC_ROOTMAP,
  MTRC_DATAMAP,
  MTRC_UNIQMAP,
  MTRC_ROOT,
  MTRC_HITS,
  MTRC_VISITORS,
  MTRC_BW,
  MTRC_CUMTS,
  MTRC_MAXTS,
  MTRC_METHODS,
  MTRC_PROTOCOLS,
  MTRC_AGENTS,
  MTRC_METADATA,
  MTRC_UNIQUE_KEYS,
  MTRC_AGENT_KEYS,
  MTRC_AGENT_VALS,
  MTRC_CNT_VALID,
  MTRC_CNT_BW,
} GSMetric;

/* Metric totals. These are metrics that have a percent value and are
 * calculated values. */
typedef struct GPercTotals_ {
  uint32_t hits;     /* total valid hits */
  uint32_t visitors; /* total visitors */
  uint64_t bw;       /* total bandwidth */
} GPercTotals;

/* Metrics within GHolder or GDashData */
typedef struct GMetrics {
  /* metric id can be used to identify
   * a specific data field */
  uint8_t id;
  char *data;
  char *method;
  char *protocol;

  float hits_perc;
  float visitors_perc;
  float bw_perc;

  uint64_t hits;
  uint64_t visitors;

  /* holder has a numeric value, while
   * dashboard has a displayable string value */
  union {
    char *sbw;
    uint64_t nbw;
  } bw;

  /* holder has a numeric value, while
   * dashboard has a displayable string value */
  union {
    char *sts;
    uint64_t nts;
  } avgts;

  /* holder has a numeric value, while
   * dashboard has a displayable string value */
  union {
    char *sts;
    uint64_t nts;
  } cumts;

  /* holder has a numeric value, while
   * dashboard has a displayable string value */
  union {
    char *sts;
    uint64_t nts;
  } maxts;
} GMetrics;

/* Holder sub item */
typedef struct GSubItem_ {
  GModule module;
  GMetrics *metrics;
  struct GSubItem_ *prev;
  struct GSubItem_ *next;
} GSubItem;

/* Double linked-list of sub items */
typedef struct GSubList_ {
  int size;
  struct GSubItem_ *head;
  struct GSubItem_ *tail;
} GSubList;

/* Holder item */
typedef struct GHolderItem_ {
  GSubList *sub_list;
  GMetrics *metrics;
} GHolderItem;

/* Holder of GRawData */
typedef struct GHolder_ {
  GHolderItem *items; /* holder items */
  GModule module;     /* current module  */
  int idx;            /* holder index  */
  int holder_size;    /* number of allocated items */
  uint32_t ht_size;   /* size of the hash table/store */
  int sub_items_size; /* number of sub items  */
} GHolder;

/* Enum-to-string */
typedef struct GEnum_ {
  const char *str;
  int idx;
} GEnum;

/* A metric can contain a root/data/uniq node id */
typedef struct GDataMap_ {
  int data;
  int root;
} GDataMap;

typedef struct GAgentItem_ {
  char *agent;
} GAgentItem;

typedef struct GAgents_ {
  int size;
  int idx;
  struct GAgentItem_ *items;
} GAgents;

#define FOREACH_MODULE(item, array)                                            \
  for (; (item < ARRAY_SIZE(array)) && array[item] != -1; ++item)

typedef struct GConf_ {
  /* Log/date/time formats */
  const char *tz_name;         /* Canonical TZ name, e.g., America/Chicago */
  char *date_time_format;      /* date & time format */
  char *date_format;           /* date format */
  char *date_num_format;       /* numeric date format %Y%m%d */
  char *time_format;           /* time format as given by the user */
  char *spec_date_time_format; /* date format w/ specificity */
  char *spec_date_time_num_format; /* numeric date format w/ specificity */
  char *log_format;                /* log format */

  /* User flags */
  int append_method;              /* append method to the req key */
  int append_protocol;            /* append protocol to the req key */
  int chunk_size;                 /* chunk size for each thread */
  int daemonize;                  /* run program as a Unix daemon */
  int double_decode;              /* need to double decode */
  int ignore_qstr;                /* ignore query string */
  int ignore_statics;             /* ignore static files */
  int list_agents;                /* show list of agents per host */
  int load_conf_dlg;              /* load curses config dialog */
  int load_global_config;         /* use global config file */
  int max_items;                  /* max number of items to output */
  int no_strict_status;           /* don't enforce 100-599 status codes */
  int no_ip_validation;           /* don't validate client IP addresses */
  int is_json_log_format;         /* is a json log format */

  /* Internal flags */
  int bandwidth;    /* is there bandwidth within the req line */
  int date_spec_hr; /* date specificity - hour */
  int hour_spec_min;   /* hour specificity - min */
  int serve_usecs;     /* is there time served within req line */
} GConf;

GConf conf = {
    .append_method = 1,
    .append_protocol = 1,
    .chunk_size = 1024,
};

pthread_mutex_t tz_mutex = PTHREAD_MUTEX_INITIALIZER;

#define STATUS_CODE_0XX ("0xx Unofficial Codes")
#define STATUS_CODE_1XX ("1xx Informational")
#define STATUS_CODE_2XX ("2xx Success")
#define STATUS_CODE_3XX ("3xx Redirection")
#define STATUS_CODE_4XX ("4xx Client Errors")
#define STATUS_CODE_5XX ("5xx Server Errors")

#define STATUS_CODE_0 ("0 - Caddy: Unhandled - No configured routes")
#define STATUS_CODE_100                                                        \
  ("100 - Continue: Server received the initial part of the request")
#define STATUS_CODE_101                                                        \
  ("101 - Switching Protocols: Client asked to switch protocols")
#define STATUS_CODE_200                                                        \
  ("200 - OK: The request sent by the client was successful")
#define STATUS_CODE_201                                                        \
  ("201 - Created: The request has been fulfilled and created")
#define STATUS_CODE_202                                                        \
  ("202 - Accepted: The request has been accepted for processing")
#define STATUS_CODE_203                                                        \
  ("203 - Non-authoritative Information: Response from a third party")
#define STATUS_CODE_204 ("204 - No Content: Request did not return any content")
#define STATUS_CODE_205                                                        \
  ("205 - Reset Content: Server asked the client to reset the document")
#define STATUS_CODE_206                                                        \
  ("206 - Partial Content: The partial GET has been successful")
#define STATUS_CODE_207 ("207 - Multi-Status: WebDAV; RFC 4918")
#define STATUS_CODE_208 ("208 - Already Reported: WebDAV; RFC 5842")
#define STATUS_CODE_218                                                        \
  ("218 - This is fine: Apache servers. A catch-all error condition")
#define STATUS_CODE_300                                                        \
  ("300 - Multiple Choices: Multiple options for the resource")
#define STATUS_CODE_301                                                        \
  ("301 - Moved Permanently: Resource has permanently moved")
#define STATUS_CODE_302 ("302 - Moved Temporarily (redirect)")
#define STATUS_CODE_303                                                        \
  ("303 - See Other Document: The response is at a different URI")
#define STATUS_CODE_304 ("304 - Not Modified: Resource has not been modified")
#define STATUS_CODE_305                                                        \
  ("305 - Use Proxy: Can only be accessed through the proxy")
#define STATUS_CODE_307 ("307 - Temporary Redirect: Resource temporarily moved")
#define STATUS_CODE_308 ("308 - Permanent Redirect")
#define STATUS_CODE_400                                                        \
  ("400 - Bad Request: The syntax of the request is invalid")
#define STATUS_CODE_401                                                        \
  ("401 - Unauthorized: Request needs user authentication")
#define STATUS_CODE_402 ("402 - Payment Required")
#define STATUS_CODE_403 ("403 - Forbidden: Server is refusing to respond to it")
#define STATUS_CODE_404                                                        \
  ("404 - Not Found: Requested resource could not be found")
#define STATUS_CODE_405                                                        \
  ("405 - Method Not Allowed: Request method not supported")
#define STATUS_CODE_406 ("406 - Not Acceptable")
#define STATUS_CODE_407 ("407 - Proxy Authentication Required")
#define STATUS_CODE_408                                                        \
  ("408 - Request Timeout: Server timed out waiting for the request")
#define STATUS_CODE_409 ("409 - Conflict: Conflict in the request")
#define STATUS_CODE_410                                                        \
  ("410 - Gone: Resource requested is no longer available")
#define STATUS_CODE_411 ("411 - Length Required: Invalid Content-Length")
#define STATUS_CODE_412                                                        \
  ("412 - Precondition Failed: Server does not meet preconditions")
#define STATUS_CODE_413 ("413 - Payload Too Large")
#define STATUS_CODE_414 ("414 - Request-URI Too Long")
#define STATUS_CODE_415                                                        \
  ("415 - Unsupported Media Type: Media type is not supported")
#define STATUS_CODE_416                                                        \
  ("416 - Requested Range Not Satisfiable: Cannot supply that portion")
#define STATUS_CODE_417 ("417 - Expectation Failed")
#define STATUS_CODE_418 ("418 - I'm a teapot")
#define STATUS_CODE_419                                                        \
  ("419 - Page Expired: Laravel Framework when a CSRF Token is missing")
#define STATUS_CODE_420                                                        \
  ("420 - Method Failure: Spring Framework when a method has failed")
#define STATUS_CODE_421 ("421 - Misdirected Request")
#define STATUS_CODE_422                                                        \
  ("422 - Unprocessable Entity due to semantic errors: WebDAV")
#define STATUS_CODE_423 ("423 - The resource that is being accessed is locked")
#define STATUS_CODE_424 ("424 - Failed Dependency: WebDAV")
#define STATUS_CODE_426                                                        \
  ("426 - Upgrade Required: Client should switch to a different protocol")
#define STATUS_CODE_428 ("428 - Precondition Required")
#define STATUS_CODE_429                                                        \
  ("429 - Too Many Requests: The user has sent too many requests")
#define STATUS_CODE_430                                                        \
  ("430 - Request Header Fields Too Large: Too many URLs are requested "       \
   "within a certain time frame")
#define STATUS_CODE_431 ("431 - Request Header Fields Too Large")
#define STATUS_CODE_440                                                        \
  ("440 - Login Time-out: The client's session has expired")
#define STATUS_CODE_449                                                        \
  ("449 - Retry With: The server cannot honour the request")
#define STATUS_CODE_450                                                        \
  ("450 - Blocked by Windows Parental Controls: The Microsoft extension code " \
   "indicated")
#define STATUS_CODE_451 ("451 - Unavailable For Legal Reasons")
#define STATUS_CODE_444                                                        \
  ("444 - (Nginx) Connection closed without sending any headers")
#define STATUS_CODE_460                                                        \
  ("460 - AWS Elastic Load Balancing: Client closed the connection ")
#define STATUS_CODE_463                                                        \
  ("463 - AWS Elastic Load Balancing: The load balancer received more than "   \
   "30 IP addresses")
#define STATUS_CODE_464                                                        \
  ("464 - AWS Elastic Load Balancing: Incompatible protocol versions")
#define STATUS_CODE_494 ("494 - (Nginx) Request Header Too Large")
#define STATUS_CODE_495 ("495 - (Nginx) SSL client certificate error")
#define STATUS_CODE_496 ("496 - (Nginx) Client didn't provide certificate")
#define STATUS_CODE_497 ("497 - (Nginx) HTTP request sent to HTTPS port")
#define STATUS_CODE_498                                                        \
  ("498 - Invalid Token: an expired or otherwise invalid token")
#define STATUS_CODE_499                                                        \
  ("499 - (Nginx) Connection closed by client while processing request")
#define STATUS_CODE_500 ("500 - Internal Server Error")
#define STATUS_CODE_501 ("501 - Not Implemented")
#define STATUS_CODE_502                                                        \
  ("502 - Bad Gateway: Received an invalid response from the upstream")
#define STATUS_CODE_503                                                        \
  ("503 - Service Unavailable: The server is currently unavailable")
#define STATUS_CODE_504                                                        \
  ("504 - Gateway Timeout: The upstream server failed to send request")
#define STATUS_CODE_505 ("505 - HTTP Version Not Supported")
#define STATUS_CODE_509                                                        \
  ("509 - Bandwidth Limit Exceeded: The server has exceeded the bandwidth")
#define STATUS_CODE_520                                                        \
  ("520 - CloudFlare - Web server is returning an unknown error")
#define STATUS_CODE_521 ("521 - CloudFlare - Web server is down")
#define STATUS_CODE_522 ("522 - CloudFlare - Connection timed out")
#define STATUS_CODE_523 ("523 - CloudFlare - Origin is unreachable")
#define STATUS_CODE_524 ("524 - CloudFlare - A timeout occurred")
#define STATUS_CODE_525                                                        \
  ("525 - SSL Handshake Failed: Cloudflare could not negotiate a SSL/TLS "     \
   "handshake")
#define STATUS_CODE_526                                                        \
  ("526 - Invalid SSL Certificate: Cloudflare could not validate the SSL "     \
   "certificate")
#define STATUS_CODE_527 ("527 - Railgun Error: An interrupted connection")
#define STATUS_CODE_529                                                        \
  ("529 - Site is overloaded: A site can not process the request")
#define STATUS_CODE_530                                                        \
  ("530 - Site is frozen: A site has been frozen due to inactivity")
#define STATUS_CODE_540                                                        \
  ("540 - Temporarily Disabled: The requested endpoint has been temporarily "  \
   "disabled")
#define STATUS_CODE_561 ("561 - Unauthorized: An error around authentication")
#define STATUS_CODE_598                                                        \
  ("598 - Network read timeout error: some HTTP proxies to signal a network "  \
   "read timeout")
#define STATUS_CODE_599                                                        \
  ("599 - Network Connect Timeout Error: An error used by some HTTP proxies")
#define STATUS_CODE_783                                                        \
  ("783 - Unexpected Token: The request includes a JSON syntax error")

/* HTTP status codes categories */
static const char *const code_type[] = {
    STATUS_CODE_0XX, STATUS_CODE_1XX, STATUS_CODE_2XX,
    STATUS_CODE_3XX, STATUS_CODE_4XX, STATUS_CODE_5XX,
};

/* HTTP status codes */
static const char *const codes[600] = {
    [0] = STATUS_CODE_0,     [100] = STATUS_CODE_100,
    STATUS_CODE_101,         [200] = STATUS_CODE_200,
    STATUS_CODE_201,         STATUS_CODE_202,
    STATUS_CODE_203,         STATUS_CODE_204,
    [205] = STATUS_CODE_205, STATUS_CODE_206,
    STATUS_CODE_207,         STATUS_CODE_208,
    [218] = STATUS_CODE_218, [300] = STATUS_CODE_300,
    STATUS_CODE_301,         STATUS_CODE_302,
    STATUS_CODE_303,         STATUS_CODE_304,
    [305] = STATUS_CODE_305, NULL,
    STATUS_CODE_307,         STATUS_CODE_308,
    [400] = STATUS_CODE_400, STATUS_CODE_401,
    STATUS_CODE_402,         STATUS_CODE_403,
    STATUS_CODE_404,         [405] = STATUS_CODE_405,
    STATUS_CODE_406,         STATUS_CODE_407,
    STATUS_CODE_408,         STATUS_CODE_409,
    [410] = STATUS_CODE_410, STATUS_CODE_411,
    STATUS_CODE_412,         STATUS_CODE_413,
    STATUS_CODE_414,         [415] = STATUS_CODE_415,
    STATUS_CODE_416,         STATUS_CODE_417,
    STATUS_CODE_418,         STATUS_CODE_419,
    [420] = STATUS_CODE_420, STATUS_CODE_421,
    STATUS_CODE_422,         STATUS_CODE_423,
    STATUS_CODE_424,         [425] = NULL,
    STATUS_CODE_426,         NULL,
    STATUS_CODE_428,         STATUS_CODE_429,
    STATUS_CODE_430,         [431] = STATUS_CODE_431,
    [440] = STATUS_CODE_440, [444] = STATUS_CODE_444,
    [449] = STATUS_CODE_449, [450] = STATUS_CODE_450,
    [451] = STATUS_CODE_451, [460] = STATUS_CODE_460,
    STATUS_CODE_463,         STATUS_CODE_464,
    [494] = STATUS_CODE_494, [495] = STATUS_CODE_495,
    STATUS_CODE_496,         STATUS_CODE_497,
    STATUS_CODE_498,         STATUS_CODE_499,
    [500] = STATUS_CODE_500, STATUS_CODE_501,
    STATUS_CODE_502,         STATUS_CODE_503,
    STATUS_CODE_504,         [505] = STATUS_CODE_505,
    [509] = STATUS_CODE_509, [520] = STATUS_CODE_520,
    STATUS_CODE_521,         STATUS_CODE_522,
    STATUS_CODE_523,         STATUS_CODE_524,
    STATUS_CODE_525,         STATUS_CODE_526,
    STATUS_CODE_527,         STATUS_CODE_529,
    [530] = STATUS_CODE_530, [540] = STATUS_CODE_540,
    [561] = STATUS_CODE_561, [598] = STATUS_CODE_598,
    STATUS_CODE_599,
};

/* A pointer to the allocated memory of the new string
 *
 * On success, a pointer to a new string is returned */
static char *alloc_string(const char *str) {
  char *new = xmalloc(strlen(str) + 1);
  strcpy(new, str);
  return new;
}

/* Append the source string to destination and reallocates and
 * updating the destination buffer appropriately. */
static size_t append_str(char **dest, const char *src) {
  size_t curlen = strlen(*dest);
  size_t srclen = strlen(src);
  size_t newlen = curlen + srclen;

  char *str = xrealloc(*dest, newlen + 1);
  memcpy(str + curlen, src, srclen + 1);
  *dest = str;

  return newlen;
}

/* Count the number of matches on the string `s1` given a character `c`
 *
 * If the character is not found, 0 is returned
 * On success, the number of characters found */
static int count_matches(const char *s1, char c) {
  const char *ptr = s1;
  int n = 0;
  do {
    if (*ptr == c)
      n++;
  } while (*(ptr++));
  return n;
}

#define MILS 1000ULL
#define SECS 1000000ULL
#define MINS 60000000ULL
#define HOUR 3600000000ULL
#define DAY 86400000000ULL
#define TZ_NAME_LEN 48

static void set_tz(void) {
  /* this will persist for the duration of the program but also assumes that all
   * threads have the same conf.tz_name values */
  static char tz[TZ_NAME_LEN] = {0};

  if (!conf.tz_name)
    return;

  if (pthread_mutex_lock(&tz_mutex) != 0) {
    LOG_DEBUG(("Failed to acquire tz_mutex"));
    return;
  }

  snprintf(tz, TZ_NAME_LEN, "TZ=%s", conf.tz_name);
  if ((putenv(tz)) != 0) {
    int old_errno = errno;
    LOG_DEBUG(("Can't set TZ env variable %s: %s: %d\n", tz,
               strerror(old_errno), old_errno));
    goto release;
  }

  tzset();

release:

  if (pthread_mutex_unlock(&tz_mutex) != 0) {
    LOG_DEBUG(("Failed to release tz_mutex"));
  }

  return;
}

static time_t tm2time(const struct tm *src) {
  struct tm tmp;

  tmp = *src;
  return timegm(&tmp) - src->tm_gmtoff;
}

/* Format the given date/time according the given format.
 *
 * On error, 1 is returned.
 * On success, 0 is returned. */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static int str_to_time(const char *str, const char *fmt, struct tm *tm,
                       int tz) {
  time_t t;
  char *end = NULL, *sEnd = NULL;
  unsigned long long ts = 0;
  int us, ms;

  time_t seconds = 0;

  if (str == NULL || *str == '\0' || fmt == NULL || *fmt == '\0')
    return 1;

  us = strcmp("%f", fmt) == 0;
  ms = strcmp("%*", fmt) == 0;

  /* check if char string needs to be converted from milli/micro seconds */
  /* note that MUSL doesn't have %s under strptime(3) */

  if (us || ms) {
    errno = 0;

    ts = strtoull(str, &sEnd, 10);
    if (str == sEnd || *sEnd != '\0' || errno == ERANGE)
      return 1;

    seconds = (us) ? ts / SECS : ((ms) ? ts / MILS : ts);

    if (conf.tz_name && tz)
      set_tz();

    /* if GMT needed, gmtime_r instead of localtime_r. */
    localtime_r(&seconds, tm);

    return 0;
  }

  end = strptime(str, fmt, tm);
  if (end == NULL || *end != '\0')
    return 1;

  if (!tz || !conf.tz_name)
    return 0;

  if ((t = tm2time(tm)) == -1) {
    LOG_DEBUG(("Can't set time via tm2time() %s: %s\n", str, strerror(errno)));
    return 0;
  }

  set_tz();
  localtime_r(&t, tm);

  return 0;
}

/* Determine if the given date format is a timestamp.
 *
 * If not a timestamp, 0 is returned.
 * If it is a timestamp, 1 is returned. */
static int has_timestamp(const char *fmt) {
  if (strcmp("%s", fmt) == 0 || strcmp("%f", fmt) == 0)
    return 1;
  return 0;
}

/* Determine if the given IP is a valid IPv4/IPv6 address.
 *
 * On error, 1 is returned.
 * On success, 0 is returned. */
static int invalid_ipaddr(const char *str, int *ipvx) {
  union {
    struct sockaddr addr;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
  } a;

  (*ipvx) = TYPE_IPINV;
  if (str == NULL || *str == '\0')
    return 1;

  memset(&a, 0, sizeof(a));
  if (1 == inet_pton(AF_INET, str, &a.addr4.sin_addr)) {
    (*ipvx) = TYPE_IPV4;
    return 0;
  } else if (1 == inet_pton(AF_INET6, str, &a.addr6.sin6_addr)) {
    (*ipvx) = TYPE_IPV6;
    return 0;
  }

  return 1;
}

static int is_valid_http_status(int code) {
  return code >= 0 && code <= 599 && code_type[code / 100] != NULL &&
         codes[code] != NULL;
}

/* Strip whitespace from the beginning of a string.
 *
 * On success, a string with whitespace stripped from the beginning of
 * the string is returned. */
static char *ltrim(char *s) {
  char *begin = s;

  while (isspace((unsigned char)*begin))
    ++begin;
  memmove(s, begin, strlen(begin) + 1);

  return s;
}

/* Strip whitespace from the end of a string.
 *
 * On success, a string with whitespace stripped from the end of the
 * string is returned. */
static char *rtrim(char *s) {
  char *end = s + strlen(s);

  while ((end != s) && isspace((unsigned char)*(end - 1)))
    --end;
  *end = '\0';

  return s;
}

/* Strip whitespace from the beginning and end of the string.
 *
 * On success, the trimmed string is returned. */
static char *trim_str(char *str) { return rtrim(ltrim(str)); }

#define KIB(n) (n << 10)
#define MIB(n) (n << 20)
#define GIB(n) (n << 30)
#define TIB(n) (n << 40)
#define PIB(n) (n << 50)

static int str2int(const char *date) {
  char *sEnd = NULL;
  int d = strtol(date, &sEnd, 10);
  if (date == sEnd || *sEnd != '\0' || errno == ERANGE)
    return -1;
  return d;
}

/* Replace all occurrences of the given char with the replacement
 * char.
 *
 * On error the original string is returned.
 * On success, a string with the replaced values is returned. */
static char *char_replace(char *str, char o, char n) {
  char *p = str;

  if (str == NULL || *str == '\0')
    return str;

  while ((p = strchr(p, o)) != NULL)
    *p++ = n;

  return str;
}

/* Remove all occurrences of a new line.
 *
 * On success, a string with the replaced new lines is returned. */
static void strip_newlines(char *str) {
  char *src, *dst;
  for (src = dst = str; *src != '\0'; src++) {
    *dst = *src;
    if (*dst != '\r' && *dst != '\n')
      dst++;
  }
  *dst = '\0';
}

/* Make a string uppercase.
 *
 * On error the original string is returned.
 * On success, the uppercased string is returned. */
static char *strtoupper(char *str) {
  char *p = str;
  if (str == NULL || *str == '\0')
    return str;

  while (*p != '\0') {
    *p = toupper((unsigned char)*p);
    p++;
  }

  return str;
}

/* Get an unescaped malloc'd string
 *
 * On error NULL is returned.
 * On success the unescaped string is returned */
static char *unescape_str(const char *src) {
  char *dest, *q;
  const char *p = src;

  if (src == NULL || *src == '\0')
    return NULL;

  dest = xmalloc(strlen(src) + 1);
  q = dest;

  while (*p) {
    if (*p == '\\') {
      p++;
      switch (*p) {
      case '\0':
        /* warning... */
        goto out;
      case 'n':
        *q++ = '\n';
        break;
      case 'r':
        *q++ = '\r';
        break;
      case 't':
        *q++ = '\t';
        break;
      default:
        *q++ = *p;
        break;
      }
    } else
      *q++ = *p;
    p++;
  }
out:
  *q = 0;

  return dest;
}

#define ERR_FORMAT_HEADER ("Format Errors - Verify your log/date/time format")
#define ERR_FORMAT_NO_DATE_FMT ("No date format was found on your conf file.")
#define ERR_FORMAT_NO_LOG_FMT ("No log format was found on your conf file.")
#define ERR_FORMAT_NO_TIME_FMT ("No time format was found on your conf file.")
#define ERR_NODEF_CONF_FILE ("No default config file found.")
#define ERR_NODEF_CONF_FILE_DESC ("You may specify one with")
#define ERR_PARSED_NLINES_DESC ("producing the following errors")
#define ERR_PARSED_NLINES ("Parsed %1$d lines")
#define ERR_PLEASE_REPORT ("Please report it by opening an issue on GitHub")
#define ERR_FORMAT_NO_TIME_FMT_DLG ("Select a time format.")
#define ERR_FORMAT_NO_DATE_FMT_DLG ("Select a date format.")
#define ERR_FORMAT_NO_LOG_FMT_DLG ("Select a log format.")
#define ERR_PANEL_DISABLED ("'%1$s' panel is disabled")
#define ERR_NO_DATA_PASSED                                                     \
  ("No input data was provided nor there's data to restore.")
#define ERR_LOG_REALLOC_FAILURE_MSG                                            \
  ("Unable to allocate memory for a log instance.")
#define ERR_LOG_NOT_FOUND_MSG ("Unable to find the given log.")

/* Initialize a new GLogItem instance.
 *
 * On success, the new GLogItem instance is returned. */
GLogItem *init_log_item() {
  GLogItem *logitem;
  logitem = xmalloc(sizeof(GLogItem));
  memset(logitem, 0, sizeof *logitem);

  logitem->agent = NULL;
  logitem->date = NULL;
  logitem->errstr = NULL;
  logitem->host = NULL;
  logitem->keyphrase = NULL;
  logitem->method = NULL;
  logitem->protocol = NULL;
  logitem->qstr = NULL;
  logitem->ref = NULL;
  logitem->req = NULL;
  logitem->resp_size = 0LL;
  logitem->serve_time = 0;
  logitem->status = -1;
  logitem->time = NULL;
  logitem->vhost = NULL;
  logitem->userid = NULL;
  logitem->cache_status = NULL;

  /* UMS */
  logitem->mime_type = NULL;
  logitem->tls_type = NULL;
  logitem->tls_cypher = NULL;
  logitem->tls_type_cypher = NULL;

  memset(logitem->site, 0, sizeof(logitem->site));
  // memset(logitem->agent_hex, 0, sizeof(logitem->agent_hex));
  // logitem->dt = glog->start_time;

  logitem->dt.tm_year = 2000;
  logitem->dt.tm_mon = 1;
  logitem->dt.tm_mday = 1;
  logitem->dt.tm_hour = 0;
  logitem->dt.tm_min = 0;
  logitem->dt.tm_sec = 0;
  logitem->dt.tm_isdst = -1;
  logitem->dt.tm_wday = 0;
  logitem->dt.tm_yday = 0;

  return logitem;
}

/* Free all members of a GLogItem */
static void free_glog(GLogItem *logitem) {
  if (logitem->agent != NULL)
    free(logitem->agent);
  if (logitem->date != NULL)
    free(logitem->date);
  if (logitem->errstr != NULL)
    free(logitem->errstr);
  if (logitem->host != NULL)
    free(logitem->host);
  if (logitem->keyphrase != NULL)
    free(logitem->keyphrase);
  if (logitem->method != NULL)
    free(logitem->method);
  if (logitem->protocol != NULL)
    free(logitem->protocol);
  if (logitem->qstr != NULL)
    free(logitem->qstr);
  if (logitem->ref != NULL)
    free(logitem->ref);
  if (logitem->req != NULL)
    free(logitem->req);
  if (logitem->time != NULL)
    free(logitem->time);
  if (logitem->userid != NULL)
    free(logitem->userid);
  if (logitem->cache_status != NULL)
    free(logitem->cache_status);
  if (logitem->vhost != NULL)
    free(logitem->vhost);

  if (logitem->mime_type != NULL)
    free(logitem->mime_type);
  if (logitem->tls_type != NULL)
    free(logitem->tls_type);
  if (logitem->tls_cypher != NULL)
    free(logitem->tls_cypher);
  if (logitem->tls_type_cypher != NULL)
    free(logitem->tls_type_cypher);

  free(logitem);
}

/* Decodes the given URL-encoded string.
 *
 * On success, the decoded string is assigned to the output buffer. */
#define B16210(x)                                                              \
  (((x) >= '0' && (x) <= '9') ? ((x) - '0')                                    \
                              : (toupper((unsigned char)(x)) - 'A' + 10))
static void decode_hex(char *url, char *out) {
  char *ptr;
  const char *c;

  for (c = url, ptr = out; *c; c++) {
    if (*c != '%' || !isxdigit((unsigned char)c[1]) ||
        !isxdigit((unsigned char)c[2])) {
      *ptr++ = *c;
    } else {
      *ptr++ = (char)((B16210(c[1]) * 16) + (B16210(c[2])));
      c += 2;
    }
  }
  *ptr = 0;
}

/* Entry point to decode the given URL-encoded string.
 *
 * On success, the decoded trimmed string is assigned to the output
 * buffer. */
static char *decode_url(char *url) {
  char *out, *decoded;

  if ((url == NULL) || (*url == '\0'))
    return NULL;

  out = decoded = xstrdup(url);
  decode_hex(url, out);
  /* double encoded URL? */
  if (conf.double_decode)
    decode_hex(decoded, out);
  strip_newlines(out);

  return trim_str(out);
}

/* Process keyphrases from Google search, cache, and translate.
 * Note that the referer hasn't been decoded at the entry point
 * since there could be '&' within the search query.
 *
 * On error, 1 is returned.
 * On success, the extracted keyphrase is assigned and 0 is returned. */
static int extract_keyphrase(char *ref, char **keyphrase) {
  char *r, *ptr, *pch, *referer;
  int encoded = 0;

  if (!(strstr(ref, "http://www.google.")) &&
      !(strstr(ref, "http://webcache.googleusercontent.com/")) &&
      !(strstr(ref, "http://translate.googleusercontent.com/")) &&
      !(strstr(ref, "https://www.google.")) &&
      !(strstr(ref, "https://webcache.googleusercontent.com/")) &&
      !(strstr(ref, "https://translate.googleusercontent.com/")))
    return 1;

  /* webcache.googleusercontent */
  if ((r = strstr(ref, "/+&")) != NULL)
    return 1;
  /* webcache.googleusercontent */
  else if ((r = strstr(ref, "/+")) != NULL)
    r += 2;
  /* webcache.googleusercontent */
  else if ((r = strstr(ref, "q=cache:")) != NULL) {
    pch = strchr(r, '+');
    if (pch)
      r += pch - r + 1;
  }
  /* www.google.* or translate.googleusercontent */
  else if ((r = strstr(ref, "&q=")) != NULL || (r = strstr(ref, "?q=")) != NULL)
    r += 3;
  else if ((r = strstr(ref, "%26q%3D")) != NULL ||
           (r = strstr(ref, "%3Fq%3D")) != NULL)
    encoded = 1, r += 7;
  else
    return 1;

  if (!encoded && (ptr = strchr(r, '&')) != NULL)
    *ptr = '\0';
  else if (encoded && (ptr = strstr(r, "%26")) != NULL)
    *ptr = '\0';

  referer = decode_url(r);
  if (referer == NULL || *referer == '\0') {
    free(referer);
    return 1;
  }

  referer = char_replace(referer, '+', ' ');
  *keyphrase = trim_str(referer);

  return 0;
}

/* Parse a URI and extracts the *host* part from it
 * i.e., //www.example.com/path?googleguy > www.example.com
 *
 * On error, 1 is returned.
 * On success, the extracted referer is set and 0 is returned. */
static int extract_referer_site(const char *referer, char *host) {
  char *url, *begin, *end;
  int len = 0;

  if ((referer == NULL) || (*referer == '\0'))
    return 1;

  url = strdup(referer);
  if ((begin = strstr(url, "//")) == NULL)
    goto clean;

  begin += 2;
  if ((len = strlen(begin)) == 0)
    goto clean;

  if ((end = strpbrk(begin, "/?")) != NULL)
    len = end - begin;

  if (len == 0)
    goto clean;

  if (len >= REF_SITE_LEN)
    len = REF_SITE_LEN;

  memcpy(host, begin, len);
  host[len] = '\0';
  free(url);
  return 0;
clean:
  free(url);

  return 1;
}

typedef struct httpmethods_ {
  const char *method;
  int len;
} httpmethods;

typedef struct httpprotocols_ {
  const char *protocol;
  int len;
} httpprotocols;

static const httpmethods http_methods[] = {
    {"OPTIONS", 7},
    {"GET", 3},
    {"HEAD", 4},
    {"POST", 4},
    {"PUT", 3},
    {"DELETE", 6},
    {"TRACE", 5},
    {"CONNECT", 7},
    {"PATCH", 5},
    {"SEARCH", 6},
    /* WebDav */
    {"PROPFIND", 8},
    {"PROPPATCH", 9},
    {"MKCOL", 5},
    {"COPY", 4},
    {"MOVE", 4},
    {"LOCK", 4},
    {"UNLOCK", 6},
    {"VERSION-CONTROL", 15},
    {"REPORT", 6},
    {"CHECKOUT", 8},
    {"CHECKIN", 7},
    {"UNCHECKOUT", 10},
    {"MKWORKSPACE", 11},
    {"UPDATE", 6},
    {"LABEL", 5},
    {"MERGE", 5},
    {"BASELINE-CONTROL", 16},
    {"MKACTIVITY", 10},
    {"ORDERPATCH", 10},
};
static const size_t http_methods_len = ARRAY_SIZE(http_methods);

static const httpprotocols http_protocols[] = {
    {"HTTP/1.0", 8},
    {"HTTP/1.1", 8},
    {"HTTP/2", 6},
    {"HTTP/3", 6},
};
static const size_t http_protocols_len = ARRAY_SIZE(http_protocols);

/* Extract the HTTP method.
 *
 * On error, or if not found, NULL is returned.
 * On success, the HTTP method is returned. */
static const char *extract_method(const char *token) {
  size_t i;
  for (i = 0; i < http_methods_len; i++) {
    if (strncasecmp(token, http_methods[i].method, http_methods[i].len) == 0) {
      return http_methods[i].method;
    }
  }
  return NULL;
}

static int is_cache_hit(const char *tkn) {
  if (strcasecmp("MISS", tkn) == 0)
    return 1;
  else if (strcasecmp("BYPASS", tkn) == 0)
    return 1;
  else if (strcasecmp("EXPIRED", tkn) == 0)
    return 1;
  else if (strcasecmp("STALE", tkn) == 0)
    return 1;
  else if (strcasecmp("UPDATING", tkn) == 0)
    return 1;
  else if (strcasecmp("REVALIDATED", tkn) == 0)
    return 1;
  else if (strcasecmp("HIT", tkn) == 0)
    return 1;
  return 0;
}

/* Determine if the given token is a valid HTTP protocol.
 *
 * If not valid, 1 is returned.
 * If valid, 0 is returned. */
static const char *extract_protocol(const char *token) {
  size_t i;
  for (i = 0; i < http_protocols_len; i++) {
    if (strncasecmp(token, http_protocols[i].protocol, http_protocols[i].len) ==
        0) {
      return http_protocols[i].protocol;
    }
  }
  return NULL;
}

/* Parse a request containing the method and protocol.
 *
 * On error, or unable to parse, NULL is returned.
 * On success, the HTTP request is returned and the method and
 * protocol are assigned to the corresponding buffers. */
static char *parse_req(char *line, char **method, char **protocol) {
  char *req = NULL, *request = NULL, *dreq = NULL, *ptr = NULL;
  const char *meth, *proto;
  ptrdiff_t rlen;

  meth = extract_method(line);

  /* couldn't find a method, so use the whole request line */
  if (meth == NULL) {
    request = xstrdup(line);
  }
  /* method found, attempt to parse request */
  else {
    req = line + strlen(meth);
    if (!(ptr = strrchr(req, ' ')) || !(proto = extract_protocol(++ptr)))
      return alloc_string("-");

    req++;
    if ((rlen = ptr - req) <= 0)
      return alloc_string("-");

    request = xmalloc(rlen + 1);
    strncpy(request, req, rlen);
    request[rlen] = 0;

    if (conf.append_method)
      (*method) = strtoupper(xstrdup(meth));

    if (conf.append_protocol)
      (*protocol) = strtoupper(xstrdup(proto));
  }

  if (!(dreq = decode_url(request)))
    return request;
  else if (*dreq == '\0') {
    free(dreq);
    return request;
  }

  free(request);
  return dreq;
}

/* Extract the next delimiter given a log format and copy the delimiter to the
 * destination buffer.
 *
 * On error, the dest buffer will be empty.
 * On success, the delimiter(s) are stored in the dest buffer. */
static void get_delim(char *dest, const char *p) {
  /* done, nothing to do */
  if (p[0] == '\0' || p[1] == '\0') {
    dest[0] = '\0';
    return;
  }
  /* add the first delim */
  dest[0] = *(p + 1);
}

/* Extract and malloc a token given the parsed rule.
 *
 * On success, the malloc'd token is returned. */
static char *parsed_string(const char *pch, const char **str, int move_ptr) {
  char *p;
  size_t len = (pch - *str + 1);

  p = xmalloc(len);
  memcpy(p, *str, (len - 1));
  p[len - 1] = '\0';
  if (move_ptr)
    *str += len - 1;

  return trim_str(p);
}

/* Find and extract a token given a log format rule.
 *
 * On error, or unable to parse it, NULL is returned.
 * On success, the malloc'd token is returned. */
static char *parse_string(const char **str, const char *delims, int cnt) {
  int idx = 0;
  const char *pch = *str, *p = NULL;
  char end;

  if ((*delims != 0x0) && (p = strpbrk(*str, delims)) == NULL)
    return NULL;

  end = !*delims ? 0x0 : *p;
  do {
    /* match number of delims */
    if (*pch == end)
      idx++;
    /* delim found, parse string then */
    if ((*pch == end && cnt == idx) || *pch == '\0')
      return parsed_string(pch, str, 1);
    /* advance to the first unescaped delim */
    if (*pch == '\\')
      pch++;
  } while (*pch++);

  return NULL;
}

/* Move forward through the log string until a non-space (!isspace)
 * char is found. */
static void find_alpha(const char **str) {
  const char *s = *str;
  while (*s) {
    if (isspace((unsigned char)*s))
      s++;
    else
      break;
  }
  *str += s - *str;
}

/* Move forward through the log string until a non-space (!isspace)
 * char is found and returns the count. */
static int find_alpha_count(const char *str) {
  int cnt = 0;
  const char *s = str;
  while (*s) {
    if (isspace((unsigned char)*s))
      s++, cnt++;
    else
      break;
  }
  return cnt;
}

/* Format the broken-down time tm to a numeric date format.
 *
 * On error, or unable to format the given tm, 1 is returned.
 * On success, a malloc'd format is returned. */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static int set_date(char **fdate, struct tm tm) {
  char buf[DATE_LEN] = ""; /* Ymd */

  memset(buf, 0, sizeof(buf));
  if (strftime(buf, DATE_LEN, conf.date_num_format, &tm) <= 0)
    return 1;
  *fdate = xstrdup(buf);

  return 0;
}

/* Format the broken-down time tm to a numeric time format.
 *
 * On error, or unable to format the given tm, 1 is returned.
 * On success, a malloc'd format is returned. */
static int set_time(char **ftime, struct tm tm) {
  char buf[TIME_LEN] = "";

  memset(buf, 0, sizeof(buf));
  if (strftime(buf, TIME_LEN, "%H:%M:%S", &tm) <= 0)
    return 1;
  *ftime = xstrdup(buf);

  return 0;
}

/* Determine the parsing specifier error and construct a message out
 * of it.
 *
 * On success, a malloc'd error message is assigned to the log
 * structure and 1 is returned. */
static int spec_err(GLogItem *logitem, int code, const char spec,
                    const char *tkn) {
  char *err = NULL;
  const char *fmt = NULL;

  switch (code) {
  case ERR_SPEC_TOKN_NUL:
    fmt = "Token for '%%%c' specifier is NULL.";
    err = xmalloc(snprintf(NULL, 0, fmt, spec) + 1);
    sprintf(err, fmt, spec);
    break;
  case ERR_SPEC_TOKN_INV:
    fmt = "Token '%s' doesn't match specifier '%%%c'";
    err = xmalloc(snprintf(NULL, 0, fmt, (tkn ? tkn : "-"), spec) + 1);
    sprintf(err, fmt, (tkn ? tkn : "-"), spec);
    break;
  case ERR_SPEC_SFMT_MIS:
    fmt = "Missing braces '%s' and ignore chars for specifier '%%%c'";
    err = xmalloc(snprintf(NULL, 0, fmt, (tkn ? tkn : "-"), spec) + 1);
    sprintf(err, fmt, (tkn ? tkn : "-"), spec);
    break;
  case ERR_SPEC_LINE_INV:
    fmt = "Incompatible format due to early parsed line ending '\\0'.";
    err = xmalloc(snprintf(NULL, 0, fmt, (tkn ? tkn : "-")) + 1);
    sprintf(err, fmt, (tkn ? tkn : "-"));
    break;
  }
  logitem->errstr = err;

  return code;
}

static void set_tm_dt_logitem(GLogItem *logitem, struct tm tm) {
  logitem->dt.tm_year = tm.tm_year;
  logitem->dt.tm_mon = tm.tm_mon;
  logitem->dt.tm_mday = tm.tm_mday;
}

static void set_tm_tm_logitem(GLogItem *logitem, struct tm tm) {
  logitem->dt.tm_hour = tm.tm_hour;
  logitem->dt.tm_min = tm.tm_min;
  logitem->dt.tm_sec = tm.tm_sec;
}

static void set_numeric_date(uint32_t *numdate, const char *date) {
  int res = 0;
  if ((res = str2int(date)) == -1)
    FATAL("Unable to parse date to integer %s", date);
  *numdate = res;
}

static int handle_default_case_token(const char **str, const char *p) {
  char *pch = NULL;
  if ((pch = strchr(*str, p[1])) != NULL)
    *str += pch - *str;
  return 0;
}

#pragma GCC diagnostic warning "-Wformat-nonliteral"

/* Parse the log string given log format rule.
 *
 * On error, or unable to parse it, 1 is returned.
 * On success, the malloc'd token is assigned to a GLogItem member. */
static int parse_specifier(GLogItem *logitem, const char **str, const char *p,
                           const char *end) {
  struct tm tm;
  const char *dfmt = conf.date_format;
  const char *tfmt = conf.time_format;

  char *pch, *sEnd, *bEnd, *tkn = NULL;
  double serve_secs = 0.0;
  uint64_t bandw = 0, serve_time = 0;
  int dspc = 0, fmtspcs = 0;

  errno = 0;
  memset(&tm, 0, sizeof(tm));
  tm.tm_isdst = -1;
  tm = logitem->dt;

  switch (*p) {
    /* date */
  case 'd':
    if (logitem->date)
      return handle_default_case_token(str, p);

    /* Attempt to parse date format containing spaces,
     * i.e., syslog date format (Jul\s15, Nov\s\s2).
     * Note that it's possible a date could contain some padding, e.g.,
     * Dec\s\s2 vs Nov\s22, so we attempt to take that into consideration by
     * looking ahead the log string and counting the # of spaces until we find
     * an alphanum char. */
    if ((fmtspcs = count_matches(dfmt, ' ')) && (pch = strchr(*str, ' ')))
      dspc = find_alpha_count(pch);

    if (!(tkn = parse_string(&(*str), end, MAX(dspc, fmtspcs) + 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    if (str_to_time(tkn, dfmt, &tm, 1) != 0 ||
        set_date(&logitem->date, tm) != 0) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }

    set_numeric_date(&logitem->numdate, logitem->date);
    set_tm_dt_logitem(logitem, tm);
    free(tkn);
    break;
    /* time */
  case 't':
    if (logitem->time)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    if (str_to_time(tkn, tfmt, &tm, 1) != 0 ||
        set_time(&logitem->time, tm) != 0) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }

    set_tm_tm_logitem(logitem, tm);
    free(tkn);
    break;
    /* date/time as decimal, i.e., timestamps, ms/us  */
  case 'x':
    if (logitem->time && logitem->date)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    if (str_to_time(tkn, tfmt, &tm, 1) != 0 ||
        set_date(&logitem->date, tm) != 0 ||
        set_time(&logitem->time, tm) != 0) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    set_numeric_date(&logitem->numdate, logitem->date);
    set_tm_dt_logitem(logitem, tm);
    set_tm_tm_logitem(logitem, tm);
    free(tkn);
    break;
    /* Virtual Host */
  case 'v':
    if (logitem->vhost)
      return handle_default_case_token(str, p);
    tkn = parse_string(&(*str), end, 1);
    if (tkn == NULL)
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    logitem->vhost = tkn;
    break;
    /* remote user */
  case 'e':
    if (logitem->userid)
      return handle_default_case_token(str, p);
    tkn = parse_string(&(*str), end, 1);
    if (tkn == NULL)
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    logitem->userid = tkn;
    break;
    /* cache status */
  case 'C':
    if (logitem->cache_status)
      return handle_default_case_token(str, p);
    tkn = parse_string(&(*str), end, 1);
    if (tkn == NULL)
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    if (is_cache_hit(tkn))
      logitem->cache_status = tkn;
    else
      free(tkn);
    break;
    /* remote hostname (IP only) */
  case 'h':
    if (logitem->host)
      return handle_default_case_token(str, p);
    /* per https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2 */
    /* square brackets are possible */
    if (*str[0] == '[' && (*str += 1) && **str)
      end = "]";
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    if (!conf.no_ip_validation && invalid_ipaddr(tkn, &logitem->type_ip)) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    /* require a valid host token (e.g., ord38s18-in-f14.1e100.net) even when
     * we're not validating the IP */
    if (conf.no_ip_validation && *tkn == '\0') {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    logitem->host = tkn;
    break;
    /* request method */
  case 'm':
    if (logitem->method)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    {
      const char *meth = NULL;
      if (!(meth = extract_method(tkn))) {
        spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
        free(tkn);
        return 1;
      }
      logitem->method = xstrdup(meth);
      free(tkn);
    }
    break;
    /* request not including method or protocol */
  case 'U':
    if (logitem->req)
      return handle_default_case_token(str, p);
    tkn = parse_string(&(*str), end, 1);
    if (tkn == NULL || *tkn == '\0') {
      free(tkn);
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    }

    if ((logitem->req = decode_url(tkn)) == NULL) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    free(tkn);
    break;
    /* query string alone, e.g., ?param=goaccess&tbm=shop */
  case 'q':
    if (logitem->qstr)
      return handle_default_case_token(str, p);
    tkn = parse_string(&(*str), end, 1);
    if (tkn == NULL || *tkn == '\0') {
      free(tkn);
      return 0;
    }

    if ((logitem->qstr = decode_url(tkn)) == NULL) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    free(tkn);
    break;
    /* request protocol */
  case 'H':
    if (logitem->protocol)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);
    {
      const char *proto = NULL;
      if (!(proto = extract_protocol(tkn))) {
        spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
        free(tkn);
        return 1;
      }
      logitem->protocol = xstrdup(proto);
      free(tkn);
    }
    break;
    /* request, including method + protocol */
  case 'r':
    if (logitem->req)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    logitem->req = parse_req(tkn, &logitem->method, &logitem->protocol);
    free(tkn);
    break;
    /* Status Code */
  case 's':
    if (logitem->status >= 0)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    logitem->status = strtol(tkn, &sEnd, 10);
    if (tkn == sEnd || *sEnd != '\0' || errno == ERANGE ||
        (!conf.no_strict_status && !is_valid_http_status(logitem->status))) {
      spec_err(logitem, ERR_SPEC_TOKN_INV, *p, tkn);
      free(tkn);
      return 1;
    }
    free(tkn);
    break;
    /* size of response in bytes - excluding HTTP headers */
  case 'b':
    if (logitem->resp_size)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    bandw = strtoull(tkn, &bEnd, 10);
    if (tkn == bEnd || *bEnd != '\0' || errno == ERANGE)
      bandw = 0;
    logitem->resp_size = bandw;
    __sync_bool_compare_and_swap(&conf.bandwidth, 0, 1); /* set flag */
    free(tkn);
    break;
    /* referrer */
  case 'R':
    if (logitem->ref)
      return handle_default_case_token(str, p);

    if (!(tkn = parse_string(&(*str), end, 1)))
      tkn = alloc_string("-");
    if (*tkn == '\0') {
      free(tkn);
      tkn = alloc_string("-");
    }
    if (strcmp(tkn, "-") != 0) {
      extract_keyphrase(tkn, &logitem->keyphrase);
      extract_referer_site(tkn, logitem->site);

      /* hide referrers from report */
      logitem->ref = tkn;
      break;
    }
    logitem->ref = tkn;

    break;
    /* user agent */
  case 'u':
    if (logitem->agent)
      return handle_default_case_token(str, p);

    tkn = parse_string(&(*str), end, 1);
    if (tkn != NULL && *tkn != '\0') {
      /* Make sure the user agent is decoded (i.e.: CloudFront) */
      logitem->agent = decode_url(tkn);

      // set_browser_os (logitem);
      // set_agent_hash(logitem);
      free(tkn);
      break;
    } else if (tkn != NULL && *tkn == '\0') {
      free(tkn);
      tkn = alloc_string("-");
    }
    /* must be null */
    else {
      tkn = alloc_string("-");
    }
    logitem->agent = tkn;
    // set_agent_hash(logitem);
    break;
    /* time taken to serve the request, in milliseconds as a decimal number */
  case 'L':
    /* ignore it if we already have served time */
    if (logitem->serve_time)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    serve_secs = strtoull(tkn, &bEnd, 10);
    if (tkn == bEnd || *bEnd != '\0' || errno == ERANGE)
      serve_secs = 0;
    /* convert it to microseconds */
    logitem->serve_time = (serve_secs > 0) ? serve_secs * MILS : 0;

    /* Determine if time-served data was stored on-disk. */
    __sync_bool_compare_and_swap(&conf.serve_usecs, 0, 1); /* set flag */
    free(tkn);
    break;
    /* time taken to serve the request, in seconds with a milliseconds
     * resolution */
  case 'T':
    /* ignore it if we already have served time */
    if (logitem->serve_time)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    if (strchr(tkn, '.') != NULL)
      serve_secs = strtod(tkn, &bEnd);
    else
      serve_secs = strtoull(tkn, &bEnd, 10);

    if (tkn == bEnd || *bEnd != '\0' || errno == ERANGE)
      serve_secs = 0;
    /* convert it to microseconds */
    logitem->serve_time = (serve_secs > 0) ? serve_secs * SECS : 0;

    /* Determine if time-served data was stored on-disk. */
    __sync_bool_compare_and_swap(&conf.serve_usecs, 0, 1); /* set flag */
    free(tkn);
    break;
    /* time taken to serve the request, in microseconds */
  case 'D':
    /* ignore it if we already have served time */
    if (logitem->serve_time)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    serve_time = strtoull(tkn, &bEnd, 10);
    if (tkn == bEnd || *bEnd != '\0' || errno == ERANGE)
      serve_time = 0;
    logitem->serve_time = serve_time;

    /* Determine if time-served data was stored on-disk. */
    __sync_bool_compare_and_swap(&conf.serve_usecs, 0, 1); /* set flag */
    free(tkn);
    break;
    /* time taken to serve the request, in nanoseconds */
  case 'n':
    /* ignore it if we already have served time */
    if (logitem->serve_time)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    serve_time = strtoull(tkn, &bEnd, 10);
    if (tkn == bEnd || *bEnd != '\0' || errno == ERANGE)
      serve_time = 0;

    /* convert it to microseconds */
    logitem->serve_time = (serve_time > 0) ? serve_time / MILS : 0;

    /* Determine if time-served data was stored on-disk. */
    __sync_bool_compare_and_swap(&conf.serve_usecs, 0, 1); /* set flag */
    free(tkn);
    break;
    /* UMS: Krypto (TLS) "ECDHE-RSA-AES128-GCM-SHA256" */
  case 'k':
    /* error to set this twice */
    if (logitem->tls_cypher)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    logitem->tls_cypher = tkn;

    break;

    /* UMS: Krypto (TLS) parameters like "TLSv1.2" */
  case 'K':
    /* error to set this twice */
    if (logitem->tls_type)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    logitem->tls_type = tkn;
    break;

    /* UMS: Mime-Type like "text/html" */
  case 'M':
    /* error to set this twice */
    if (logitem->mime_type)
      return handle_default_case_token(str, p);
    if (!(tkn = parse_string(&(*str), end, 1)))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, *p, NULL);

    logitem->mime_type = tkn;

    break;
    /* move forward through str until not a space */
  case '~':
    find_alpha(&(*str));
    break;
    /* everything else skip it */
  default:
    handle_default_case_token(str, p);
  }

  return 0;
}

/* Parse the special host specifier and extract the characters that
 * need to be rejected when attempting to parse the XFF field.
 *
 * If no unable to find both curly braces (boundaries), NULL is returned.
 * On success, the malloc'd reject set is returned. */
static char *extract_braces(const char **p) {
  const char *b1 = NULL, *b2 = NULL, *s = *p;
  char *ret = NULL;
  int esc = 0;
  ptrdiff_t len = 0;

  /* iterate over the log format */
  for (; *s; s++) {
    if (*s == '\\') {
      esc = 1;
    } else if (*s == '{' && !esc) {
      b1 = s;
    } else if (*s == '}' && !esc) {
      b2 = s;
      break;
    } else {
      esc = 0;
    }
  }

  if ((!b1) || (!b2))
    return NULL;
  if ((len = b2 - (b1 + 1)) <= 0)
    return NULL;

  /* Found braces, extract 'reject' character set. */
  ret = xmalloc(len + 1);
  memcpy(ret, b1 + 1, len);
  ret[len] = '\0';
  (*p) = b2 + 1;

  return ret;
}

/* Attempt to extract the client IP from an X-Forwarded-For (XFF) field.
 *
 * If no IP is found, 1 is returned.
 * On success, the malloc'd token is assigned to a GLogItem->host and
 * 0 is returned. */
static int set_xff_host(GLogItem *logitem, const char *str, const char *skips,
                        int out) {
  const char *ptr = NULL, *tkn = NULL;
  int invalid_ip = 1, len = 0, type_ip = TYPE_IPINV;
  int idx = 0, skips_len = 0;

  skips_len = strlen(skips);
  ptr = str;
  while (*ptr != '\0') {
    if ((len = strcspn(ptr, skips)) == 0) {
      len++, ptr++, idx++;
      goto move;
    }
    /* If our index does not match the number of delimiters and we have already
     * a valid client IP, then we assume we have reached the length of the XFF
     */
    if (idx < skips_len && logitem->host)
      break;

    ptr += len;
    /* extract possible IP */
    if (!(tkn = parsed_string(ptr, &str, 0)))
      break;

    invalid_ip = invalid_ipaddr(tkn, &type_ip);
    /* done, already have IP and current token is not a host */
    if (logitem->host && invalid_ip) {
      free((void *)tkn);
      break;
    }
    if (!logitem->host && !invalid_ip) {
      logitem->host = xstrdup(tkn);
      logitem->type_ip = type_ip;
    }
    free((void *)tkn);
    idx = 0;

    /* found the client IP, break then */
    if (logitem->host && out)
      break;

  move:
    str += len;
  }

  return logitem->host == NULL;
}

/* Attempt to find possible delimiters in the X-Forwarded-For (XFF) field.
 *
 * If no IP is found, 1 is returned.
 * On success, the malloc'd token is assigned to a GLogItem->host and 0 is
 * returned. */
static int find_xff_host(GLogItem *logitem, const char **str, const char **p) {
  char *skips = NULL, *extract = NULL;
  char pch[2] = {0};
  int res = 0;

  if (!(skips = extract_braces(p)))
    return spec_err(logitem, ERR_SPEC_SFMT_MIS, **p, "{}");

  /* if the log format current char is not within the braces special chars, then
   * we assume the range of IPs are within hard delimiters */
  if (!strchr(skips, **p) && strchr(*str, **p)) {
    *pch = **p;
    *(pch + 1) = '\0';
    if (!(extract = parse_string(&(*str), pch, 1)))
      goto clean;

    res = set_xff_host(logitem, extract, skips, 1);
    free(extract);
    (*str)++; /* move a char forward from the trailing delim */
  } else {
    res = set_xff_host(logitem, *str, skips, 0);
  }

clean:
  free(skips);

  return res;
}

/* Handle special specifiers.
 *
 * On error, or unable to parse it, 1 is returned.
 * On success, the malloc'd token is assigned to a GLogItem member and
 * 0 is returned. */
static int special_specifier(GLogItem *logitem, const char **str,
                             const char **p) {
  switch (**p) {
    /* XFF remote hostname (IP only) */
  case 'h':
    if (find_xff_host(logitem, str, p))
      return spec_err(logitem, ERR_SPEC_TOKN_NUL, 'h', NULL);
    break;
  }

  return 0;
}

/* Iterate over the given log format.
 *
 * On error, or unable to parse it, 1 is returned.
 * On success, the malloc'd token is assigned to a GLogItem member and
 * 0 is returned. */
static int parse_format(GLogItem *logitem, const char *str, const char *lfmt) {
  char end[2 + 1] = {0};
  const char *p = NULL, *last = NULL;
  int perc = 0, tilde = 0, ret = 0;

  if (str == NULL || *str == '\0')
    return 1;

  /* iterate over the log format */
  last = lfmt + strlen(lfmt);
  for (p = lfmt; p < last; p++) {
    if (*p == '%') {
      perc++;
      continue;
    }
    if (*p == '~' && perc == 0) {
      tilde++;
      continue;
    }
    if (*str == '\0')
      return spec_err(logitem, ERR_SPEC_LINE_INV, '-', NULL);
    if (*str == '\n')
      return 0;

    if (tilde && *p != '\0') {
      if (*str == '\0')
        return 0;
      if (special_specifier(logitem, &str, &p) == 1)
        return 1;
      tilde = 0;
    }
    /* %h */
    else if (perc && *p != '\0') {
      if (*str == '\0')
        return 0;

      memset(end, 0, sizeof end);
      get_delim(end, p);
      /* attempt to parse format specifiers */
      if ((ret = parse_specifier(logitem, &str, p, end)))
        return ret;
      perc = 0;
    } else if (perc && isspace((unsigned char)p[0])) {
      return 1;
    } else {
      str++;
    }
  }

  return 0;
}

/* Determine if the log string is valid and if it's not a comment.
 *
 * On error, or invalid, 1 is returned.
 * On success, or valid line, 0 is returned. */
static int valid_line(char *line) {
  /* invalid line */
  if ((line == NULL) || (*line == '\0'))
    return 1;
  /* ignore comments */
  if (*line == '#' || *line == '\n')
    return 1;

  return 0;
}

/* Ensure we have the following fields. */
static int verify_missing_fields(GLogItem *logitem) {
  /* must have the following fields */
  if (logitem->host == NULL)
    logitem->errstr = xstrdup("IPv4/6 is required.");
  else if (logitem->date == NULL)
    logitem->errstr = xstrdup("A valid date is required.");
  else if (logitem->req == NULL)
    logitem->errstr = xstrdup("A request is required.");

  return logitem->errstr != NULL;
}

enum json_type {
  JSON_ERROR = 1,
  JSON_DONE,
  JSON_OBJECT,
  JSON_OBJECT_END,
  JSON_ARRAY,
  JSON_ARRAY_END,
  JSON_STRING,
  JSON_NUMBER,
  JSON_TRUE,
  JSON_FALSE,
  JSON_NULL
};

typedef int (*json_user_io)(void *user);

typedef struct json_stream json_stream;
typedef struct json_allocator json_allocator;

struct json_allocator {
  void *(*malloc)(size_t);
  void *(*realloc)(void *, size_t);
  void (*free)(void *);
};

struct json_source {
  int (*get)(struct json_source *);
  int (*peek)(struct json_source *);
  size_t position;
  union {
    struct {
      FILE *stream;
    } stream;
    struct {
      const char *buffer;
      size_t length;
    } buffer;
    struct {
      void *ptr;
      json_user_io get;
      json_user_io peek;
    } user;
  } source;
};

struct json_stream {
  size_t lineno;

  struct json_stack *stack;
  size_t stack_top;
  size_t stack_size;
  enum json_type next;
  unsigned flags;

  struct {
    char *string;
    size_t string_fill;
    size_t string_size;
  } data;

  size_t ntokens;

  struct json_source source;
  struct json_allocator alloc;
  char errmsg[128];
};

#define JSON_FLAG_ERROR (1u << 0)
#define JSON_FLAG_STREAMING (1u << 1)


#define json_error(json, format, ...)                                          \
  if (!(json->flags & JSON_FLAG_ERROR)) {                                      \
    json->flags |= JSON_FLAG_ERROR;                                            \
    snprintf(json->errmsg, sizeof(json->errmsg), format, __VA_ARGS__);         \
  }

/* See also PDJSON_STACK_MAX below. */
#define PDJSON_STACK_INC 4

struct json_stack {
  enum json_type type;
  long count;
};

static enum json_type push(json_stream *json, enum json_type type) {
  json->stack_top++;

  if (json->stack_top >= json->stack_size) {
    struct json_stack *stack;
    size_t size = (json->stack_size + PDJSON_STACK_INC) * sizeof(*json->stack);
    stack = (struct json_stack *)json->alloc.realloc(json->stack, size);
    if (stack == NULL) {
      json_error(json, "%s", "out of memory");
      return JSON_ERROR;
    }

    json->stack_size += PDJSON_STACK_INC;
    json->stack = stack;
  }

  json->stack[json->stack_top].type = type;
  json->stack[json->stack_top].count = 0;

  return type;
}

static enum json_type pop(json_stream *json, int c, enum json_type expected) {
  if (json->stack == NULL || json->stack[json->stack_top].type != expected) {
    json_error(json, "unexpected byte '%c'", c);
    return JSON_ERROR;
  }
  json->stack_top--;
  return expected == JSON_ARRAY ? JSON_ARRAY_END : JSON_OBJECT_END;
}

static int buffer_peek(struct json_source *source) {
  if (source->position < source->source.buffer.length)
    return source->source.buffer.buffer[source->position];
  else
    return EOF;
}

static int buffer_get(struct json_source *source) {
  int c = source->peek(source);
  source->position++;
  return c;
}

static void init(json_stream *json) {
  json->lineno = 1;
  json->flags = JSON_FLAG_STREAMING;
  json->errmsg[0] = '\0';
  json->ntokens = 0;
  json->next = (enum json_type)0;

  json->stack = NULL;
  json->stack_top = (size_t)-1;
  json->stack_size = 0;

  json->data.string = NULL;
  json->data.string_size = 0;
  json->data.string_fill = 0;
  json->source.position = 0;

  json->alloc.malloc = malloc;
  json->alloc.realloc = realloc;
  json->alloc.free = free;
}

static enum json_type is_match(json_stream *json, const char *pattern,
                               enum json_type type) {
  int c;
  const char *p = NULL;
  for (p = pattern; *p; p++) {
    if (*p != (c = json->source.get(&json->source))) {
      json_error(json, "expected '%c' instead of byte '%c'", *p, c);
      return JSON_ERROR;
    }
  }
  return type;
}

static int pushchar(json_stream *json, int c) {
  if (json->data.string_fill == json->data.string_size) {
    size_t size = json->data.string_size * 2;
    char *buffer = (char *)json->alloc.realloc(json->data.string, size);
    if (buffer == NULL) {
      json_error(json, "%s", "out of memory");
      return -1;
    } else {
      json->data.string_size = size;
      json->data.string = buffer;
    }
  }
  json->data.string[json->data.string_fill++] = c;
  return 0;
}

static int init_string(json_stream *json) {
  json->data.string_fill = 0;
  if (json->data.string == NULL) {
    json->data.string_size = 1024;
    json->data.string = (char *)json->alloc.malloc(json->data.string_size);
    if (json->data.string == NULL) {
      json_error(json, "%s", "out of memory");
      return -1;
    }
  }
  json->data.string[0] = '\0';
  return 0;
}

static int encode_utf8(json_stream *json, unsigned long c) {
  if (c < 0x80UL) {
    return pushchar(json, c);
  } else if (c < 0x0800UL) {
    return !((pushchar(json, (c >> 6 & 0x1F) | 0xC0) == 0) &&
             (pushchar(json, (c >> 0 & 0x3F) | 0x80) == 0));
  } else if (c < 0x010000UL) {
    if (c >= 0xd800 && c <= 0xdfff) {
      json_error(json, "invalid codepoint %06lx", c);
      return -1;
    }
    return !((pushchar(json, (c >> 12 & 0x0F) | 0xE0) == 0) &&
             (pushchar(json, (c >> 6 & 0x3F) | 0x80) == 0) &&
             (pushchar(json, (c >> 0 & 0x3F) | 0x80) == 0));
  } else if (c < 0x110000UL) {
    return !((pushchar(json, (c >> 18 & 0x07) | 0xF0) == 0) &&
             (pushchar(json, (c >> 12 & 0x3F) | 0x80) == 0) &&
             (pushchar(json, (c >> 6 & 0x3F) | 0x80) == 0) &&
             (pushchar(json, (c >> 0 & 0x3F) | 0x80) == 0));
  } else {
    json_error(json, "unable to encode %06lx as UTF-8", c);
    return -1;
  }
}

static int hexchar(int c) {
  switch (c) {
  case '0':
    return 0;
  case '1':
    return 1;
  case '2':
    return 2;
  case '3':
    return 3;
  case '4':
    return 4;
  case '5':
    return 5;
  case '6':
    return 6;
  case '7':
    return 7;
  case '8':
    return 8;
  case '9':
    return 9;
  case 'a':
  case 'A':
    return 10;
  case 'b':
  case 'B':
    return 11;
  case 'c':
  case 'C':
    return 12;
  case 'd':
  case 'D':
    return 13;
  case 'e':
  case 'E':
    return 14;
  case 'f':
  case 'F':
    return 15;
  default:
    return -1;
  }
}

static long read_unicode_cp(json_stream *json) {
  long cp = 0;
  int shift = 12;
  size_t i = 0;

  for (i = 0; i < 4; i++) {
    int c = json->source.get(&json->source);
    int hc;

    if (c == EOF) {
      json_error(json, "%s", "unterminated string literal in Unicode");
      return -1;
    } else if ((hc = hexchar(c)) == -1) {
      json_error(json, "invalid escape Unicode byte '%c'", c);
      return -1;
    }

    cp += hc * (1 << shift);
    shift -= 4;
  }

  return cp;
}

static int read_unicode(json_stream *json) {
  long cp, h, l;
  int c;

  if ((cp = read_unicode_cp(json)) == -1) {
    return -1;
  }

  if (cp >= 0xd800 && cp <= 0xdbff) {
    /* This is the high portion of a surrogate pair; we need to read the
     * lower portion to get the codepoint
     */
    h = cp;

    c = json->source.get(&json->source);
    if (c == EOF) {
      json_error(json, "%s", "unterminated string literal in Unicode");
      return -1;
    } else if (c != '\\') {
      json_error(json,
                 "invalid continuation for surrogate pair '%c', "
                 "expected '\\'",
                 c);
      return -1;
    }

    c = json->source.get(&json->source);
    if (c == EOF) {
      json_error(json, "%s", "unterminated string literal in Unicode");
      return -1;
    } else if (c != 'u') {
      json_error(json,
                 "invalid continuation for surrogate pair '%c', "
                 "expected 'u'",
                 c);
      return -1;
    }

    if ((l = read_unicode_cp(json)) == -1) {
      return -1;
    }

    if (l < 0xdc00 || l > 0xdfff) {
      json_error(json,
                 "surrogate pair continuation \\u%04lx out "
                 "of range (dc00-dfff)",
                 l);
      return -1;
    }

    cp = ((h - 0xd800) * 0x400) + ((l - 0xdc00) + 0x10000);
  } else if (cp >= 0xdc00 && cp <= 0xdfff) {
    json_error(json, "dangling surrogate \\u%04lx", cp);
    return -1;
  }

  return encode_utf8(json, cp);
}

static int read_escaped(json_stream *json) {
  int c = json->source.get(&json->source);
  if (c == EOF) {
    json_error(json, "%s", "unterminated string literal in escape");
    return -1;
  } else if (c == 'u') {
    if (read_unicode(json) != 0)
      return -1;
  } else {
    switch (c) {
    case '\\':
    case 'b':
    case 'f':
    case 'n':
    case 'r':
    case 't':
    case '/':
    case '"': {
      const char *codes = "\\bfnrt/\"";
      const char *p = strchr(codes, c);
      if (pushchar(json, "\\\b\f\n\r\t/\""[p - codes]) != 0)
        return -1;
    } break;
    default:
      json_error(json, "invalid escaped byte '%c'", c);
      return -1;
    }
  }
  return 0;
}

static int char_needs_escaping(int c) {
  if ((c >= 0) && (c < 0x20 || c == 0x22 || c == 0x5c)) {
    return 1;
  }

  return 0;
}

static int utf8_seq_length(char byte) {
  unsigned char u = (unsigned char)byte;
  if (u < 0x80)
    return 1;

  if (0x80 <= u && u <= 0xBF) {
    // second, third or fourth byte of a multi-byte
    // sequence, i.e. a "continuation byte"
    return 0;
  } else if (u == 0xC0 || u == 0xC1) {
    // overlong encoding of an ASCII byte
    return 0;
  } else if (0xC2 <= u && u <= 0xDF) {
    // 2-byte sequence
    return 2;
  } else if (0xE0 <= u && u <= 0xEF) {
    // 3-byte sequence
    return 3;
  } else if (0xF0 <= u && u <= 0xF4) {
    // 4-byte sequence
    return 4;
  } else {
    // u >= 0xF5
    // Restricted (start of 4-, 5- or 6-byte sequence) or invalid UTF-8
    return 0;
  }
}

static int is_legal_utf8(const unsigned char *bytes, int length) {
  unsigned char a;
  const unsigned char *srcptr;

  if (0 == bytes || 0 == length)
    return 0;

  srcptr = bytes + length;
  switch (length) {
  default:
    return 0;
    // Everything else falls through when true.
  case 4:
    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
      return 0;
    /* FALLTHRU */
  case 3:
    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
      return 0;
    /* FALLTHRU */
  case 2:
    a = (*--srcptr);
    switch (*bytes) {
    case 0xE0:
      if (a < 0xA0 || a > 0xBF)
        return 0;
      break;
    case 0xED:
      if (a < 0x80 || a > 0x9F)
        return 0;
      break;
    case 0xF0:
      if (a < 0x90 || a > 0xBF)
        return 0;
      break;
    case 0xF4:
      if (a < 0x80 || a > 0x8F)
        return 0;
      break;
    default:
      if (a < 0x80 || a > 0xBF)
        return 0;
      break;
    }
    /* FALLTHRU */
  case 1:
    if (*bytes >= 0x80 && *bytes < 0xC2)
      return 0;
  }
  return *bytes <= 0xF4;
}

static int read_utf8(json_stream *json, int next_char) {
  int i;
  char buffer[4];
  int count = utf8_seq_length(next_char);
  if (!count) {
    json_error(json, "%s", "invalid UTF-8 character");
    return -1;
  }

  buffer[0] = next_char;
  for (i = 1; i < count; ++i) {
    buffer[i] = json->source.get(&json->source);
  }

  if (!is_legal_utf8((unsigned char *)buffer, count)) {
    json_error(json, "%s", "invalid UTF-8 text");
    return -1;
  }

  for (i = 0; i < count; ++i) {
    if (pushchar(json, buffer[i]) != 0)
      return -1;
  }
  return 0;
}

static enum json_type read_string(json_stream *json) {
  if (init_string(json) != 0)
    return JSON_ERROR;
  while (1) {
    int c = json->source.get(&json->source);
    if (c == EOF) {
      json_error(json, "%s", "unterminated string literal");
      return JSON_ERROR;
    } else if (c == '"') {
      if (pushchar(json, '\0') == 0)
        return JSON_STRING;
      else
        return JSON_ERROR;
    } else if (c == '\\') {
      if (read_escaped(json) != 0)
        return JSON_ERROR;
    } else if ((unsigned)c >= 0x80) {
      if (read_utf8(json, c) != 0)
        return JSON_ERROR;
    } else {
      if (char_needs_escaping(c)) {
        json_error(json, "%s", "unescaped control character in string");
        return JSON_ERROR;
      }

      if (pushchar(json, c) != 0)
        return JSON_ERROR;
    }
  }
  return JSON_ERROR;
}

static int is_digit(int c) { return c >= 48 /*0 */ && c <= 57 /*9 */; }

static int read_digits(json_stream *json) {
  int c;
  unsigned nread = 0;
  while (is_digit(c = json->source.peek(&json->source))) {
    if (pushchar(json, json->source.get(&json->source)) != 0)
      return -1;

    nread++;
  }

  if (nread == 0) {
    json_error(json, "expected digit instead of byte '%c'", c);
    return -1;
  }

  return 0;
}

static enum json_type read_number(json_stream *json, int c) {
  if (pushchar(json, c) != 0)
    return JSON_ERROR;
  if (c == '-') {
    c = json->source.get(&json->source);
    if (is_digit(c)) {
      return read_number(json, c);
    } else {
      json_error(json, "unexpected byte '%c' in number", c);
      return JSON_ERROR;
    }
  } else if (strchr("123456789", c) != NULL) {
    c = json->source.peek(&json->source);
    if (is_digit(c)) {
      if (read_digits(json) != 0)
        return JSON_ERROR;
    }
  }
  /* Up to decimal or exponent has been read. */
  c = json->source.peek(&json->source);
  if (strchr(".eE", c) == NULL) {
    if (pushchar(json, '\0') != 0)
      return JSON_ERROR;
    else
      return JSON_NUMBER;
  }
  if (c == '.') {
    json->source.get(&json->source); // consume .
    if (pushchar(json, c) != 0)
      return JSON_ERROR;
    if (read_digits(json) != 0)
      return JSON_ERROR;
  }
  /* Check for exponent. */
  c = json->source.peek(&json->source);
  if (c == 'e' || c == 'E') {
    json->source.get(&json->source); // consume e/E
    if (pushchar(json, c) != 0)
      return JSON_ERROR;
    c = json->source.peek(&json->source);
    if (c == '+' || c == '-') {
      json->source.get(&json->source); // consume
      if (pushchar(json, c) != 0)
        return JSON_ERROR;
      if (read_digits(json) != 0)
        return JSON_ERROR;
    } else if (is_digit(c)) {
      if (read_digits(json) != 0)
        return JSON_ERROR;
    } else {
      json_error(json, "unexpected byte '%c' in number", c);
      return JSON_ERROR;
    }
  }
  if (pushchar(json, '\0') != 0)
    return JSON_ERROR;
  else
    return JSON_NUMBER;
}

static bool json_isspace(int c) {
  switch (c) {
  case 0x09:
  case 0x0a:
  case 0x0d:
  case 0x20:
    return true;
  }

  return false;
}

/* Returns the next non-whitespace character in the stream. */
static int next(json_stream *json) {
  int c;
  while (json_isspace(c = json->source.get(&json->source)))
    if (c == '\n')
      json->lineno++;
  return c;
}

static enum json_type read_value(json_stream *json, int c) {
  json->ntokens++;
  switch (c) {
  case EOF:
    json_error(json, "%s", "unexpected end of text");
    return JSON_ERROR;
  case '{':
    return push(json, JSON_OBJECT);
  case '[':
    return push(json, JSON_ARRAY);
  case '"':
    return read_string(json);
  case 'n':
    return is_match(json, "ull", JSON_NULL);
  case 'f':
    return is_match(json, "alse", JSON_FALSE);
  case 't':
    return is_match(json, "rue", JSON_TRUE);
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
  case '-':
    if (init_string(json) != 0)
      return JSON_ERROR;
    return read_number(json, c);
  default:
    json_error(json, "unexpected byte '%c' in value", c);
    return JSON_ERROR;
  }
}

static enum json_type json_next(json_stream *json) {
  int c;
  enum json_type value;
  if (json->flags & JSON_FLAG_ERROR)
    return JSON_ERROR;
  if (json->next != 0) {
    enum json_type next = json->next;
    json->next = (enum json_type)0;
    return next;
  }
  if (json->ntokens > 0 && json->stack_top == (size_t)-1) {

    /* In the streaming mode leave any trailing whitespaces in the stream.
     * This allows the user to validate any desired separation between
     * values (such as newlines) using json_source_get/peek() with any
     * remaining whitespaces ignored as leading when we parse the next
     * value. */
    if (!(json->flags & JSON_FLAG_STREAMING)) {
      do {
        c = json->source.peek(&json->source);
        if (json_isspace(c)) {
          c = json->source.get(&json->source);
        }
      } while (json_isspace(c));

      if (c != EOF) {
        json_error(json, "expected end of text instead of byte '%c'", c);
        return JSON_ERROR;
      }
    }

    return JSON_DONE;
  }
  c = next(json);
  if (json->stack_top == (size_t)-1) {
    if (c == EOF && (json->flags & JSON_FLAG_STREAMING))
      return JSON_DONE;

    return read_value(json, c);
  }
  if (json->stack[json->stack_top].type == JSON_ARRAY) {
    if (json->stack[json->stack_top].count == 0) {
      if (c == ']') {
        return pop(json, c, JSON_ARRAY);
      }
      json->stack[json->stack_top].count++;
      return read_value(json, c);
    } else if (c == ',') {
      json->stack[json->stack_top].count++;
      return read_value(json, next(json));
    } else if (c == ']') {
      return pop(json, c, JSON_ARRAY);
    } else {
      json_error(json, "unexpected byte '%c'", c);
      return JSON_ERROR;
    }
  } else if (json->stack[json->stack_top].type == JSON_OBJECT) {
    if (json->stack[json->stack_top].count == 0) {
      if (c == '}') {
        return pop(json, c, JSON_OBJECT);
      }

      /* No member name/value pairs yet. */
      value = read_value(json, c);
      if (value != JSON_STRING) {
        if (value != JSON_ERROR)
          json_error(json, "%s", "expected member name or '}'");
        return JSON_ERROR;
      } else {
        json->stack[json->stack_top].count++;
        return value;
      }
    } else if ((json->stack[json->stack_top].count % 2) == 0) {
      /* Expecting comma followed by member name. */
      if (c != ',' && c != '}') {
        json_error(json, "%s", "expected ',' or '}' after member value");
        return JSON_ERROR;
      } else if (c == '}') {
        return pop(json, c, JSON_OBJECT);
      } else {
        value = read_value(json, next(json));
        if (value != JSON_STRING) {
          if (value != JSON_ERROR)
            json_error(json, "%s", "expected member name");
          return JSON_ERROR;
        } else {
          json->stack[json->stack_top].count++;
          return value;
        }
      }
    } else if ((json->stack[json->stack_top].count % 2) == 1) {
      /* Expecting colon followed by value. */
      if (c != ':') {
        json_error(json, "%s", "expected ':' after member name");
        return JSON_ERROR;
      } else {
        json->stack[json->stack_top].count++;
        return read_value(json, next(json));
      }
    }
  }
  json_error(json, "%s", "invalid parser state");
  return JSON_ERROR;
}

static const char *json_get_string(json_stream *json, size_t *length) {
  if (length != NULL)
    *length = json->data.string_fill;
  if (json->data.string == NULL)
    return "";
  else
    return json->data.string;
}

/* Return the current parsing context, that is, JSON_OBJECT if we are inside
   an object, JSON_ARRAY if we are inside an array, and JSON_DONE if we are
   not yet/anymore in either.

   Additionally, for the first two cases, also return the number of parsing
   events that have already been observed at this level with json_next/peek().
   In particular, inside an object, an odd number would indicate that the just
   observed JSON_STRING event is a member name.
*/
static enum json_type json_get_context(json_stream *json, size_t *count) {
  if (json->stack_top == (size_t)-1)
    return JSON_DONE;

  if (count != NULL)
    *count = json->stack[json->stack_top].count;

  return json->stack[json->stack_top].type;
}

static void json_open_buffer(json_stream *json, const void *buffer,
                             size_t size) {
  init(json);
  json->source.get = buffer_get;
  json->source.peek = buffer_peek;
  json->source.source.buffer.buffer = (const char *)buffer;
  json->source.source.buffer.length = size;
}

static void json_open_string(json_stream *json, const char *string) {
  json_open_buffer(json, string, strlen(string));
}

static void json_set_streaming(json_stream *json, bool streaming) {
  if (streaming)
    json->flags |= JSON_FLAG_STREAMING;
  else
    json->flags &= ~JSON_FLAG_STREAMING;
}

static void json_close(json_stream *json) {
  json->alloc.free(json->stack);
  json->alloc.free(json->data.string);
}

/* Delete the given key from a nested object key or empty the key. */
static void dec_json_key(char *key, int has_dot) {
  if (!key || has_dot < 0)
    return;

  /* Designed to iterate has_dot + 1 times */
  /* if has_dot is 2, the loop will run three times (when i is 0, 1, and 2).
   * Each iteration of the loop removes one dot from the end of the key string.
   * Therefore, if has_dot is 2, it will remove up to three dots from the end of
   * the key string. */
  for (int i = 0; i <= has_dot; i++) {
    char *last_dot = strrchr(key, '.');
    if (last_dot)
      *last_dot = '\0';
    else {
      *key = '\0';
      return;
    }
  }
}

/* Given a JSON string, parse it and call the given function pointer after each
 * value.
 *
 * On error, a non-zero value is returned.
 * On success, 0 is returned. */
static int parse_json_string(void *ptr_data, const char *str,
                             int (*cb)(void *, char *, char *)) {
  char *key = NULL, *val = NULL;
  enum json_type ctx = JSON_ERROR, t = JSON_ERROR;
  int ret = 0, has_dot = 0;
  size_t len = 0, level = 0;
  json_stream json;

  json_open_string(&json, str);
  do {
    t = json_next(&json);

    switch (t) {
    case JSON_OBJECT:
      if (key == NULL)
        key = xstrdup("");
      break;
    case JSON_ARRAY_END:
    case JSON_OBJECT_END:
      dec_json_key(key, 0);
      break;
    case JSON_TRUE:
      val = xstrdup("true");
      if (!key || (ret = (*cb)(ptr_data, key, val)))
        goto clean;
      ctx = json_get_context(&json, &level);
      if (ctx != JSON_ARRAY)
        dec_json_key(key, 0);
      free(val);
      val = NULL;
      break;
    case JSON_FALSE:
      val = xstrdup("false");
      if (!key || (ret = (*cb)(ptr_data, key, val)))
        goto clean;
      ctx = json_get_context(&json, &level);
      if (ctx != JSON_ARRAY)
        dec_json_key(key, 0);
      free(val);
      val = NULL;
      break;
    case JSON_NULL:
      val = xstrdup("-");
      if (!key || (ret = (*cb)(ptr_data, key, val)))
        goto clean;
      ctx = json_get_context(&json, &level);
      if (ctx != JSON_ARRAY)
        dec_json_key(key, 0);
      free(val);
      val = NULL;
      break;
    case JSON_STRING:
    case JSON_NUMBER:
      ctx = json_get_context(&json, &level);
      /* key */
      if ((level % 2) != 0 && ctx != JSON_ARRAY) {
        /* check if key contains a dot, to account for it on dec_json_key */
        has_dot = count_matches(json_get_string(&json, &len), '.');

        if (strlen(key) != 0)
          append_str(&key, ".");
        append_str(&key, json_get_string(&json, &len));
      }
      /* val */
      else if (key &&
               (ctx == JSON_ARRAY || ((level % 2) == 0 && ctx != JSON_ARRAY))) {
        val = xstrdup(json_get_string(&json, &len));
        if (!key || (ret = (*cb)(ptr_data, key, val)))
          goto clean;
        if (ctx != JSON_ARRAY)
          dec_json_key(key, has_dot);

        free(val);
        val = NULL;
      }
      break;
    case JSON_ERROR:
      ret = -1;
      goto clean;
      break;
    default:
      break;
    }
  } while (t != JSON_DONE && t != JSON_ERROR);

clean:
  free(val);
  free(key);
  json_close(&json);

  return ret;
}

static char *ht_get_json_logfmt(const char *key);

static int parse_json_specifier(void *ptr_data, char *key, char *str) {
  GLogItem *logitem = (GLogItem *)ptr_data;
  char *spec = NULL;
  int ret = 0;

  if (!key || !str)
    return 0;
  /* empty JSON value, e.g., {method: ""} */
  if (0 == strlen(str))
    return 0;
  if (!(spec = ht_get_json_logfmt(key)))
    return 0;

  ret = parse_format(logitem, str, spec);
  free(spec);

  return ret;
}

static int parse_json_format(GLogItem *logitem, char *str) {
  return parse_json_string(logitem, str, parse_json_specifier);
}

static int cleanup_logitem(int ret, GLogItem *logitem) {
  free_glog(logitem);
  return ret;
}

/* Process a line from the log and store it accordingly taking into
 * account multiple parsing options prior to setting data into the
 * corresponding data structure.
 *
 * On error, logitem->errstr will contains the error message. */
static int parse_line(char *line, GLogItem **logitem_out) {
  char *fmt = conf.log_format;
  int ret = 0;
  GLogItem *logitem = NULL;

  /* soft ignore these lines */
  if (valid_line(line))
    return -1;

  logitem = init_log_item();

  /* Parse a line of log, and fill structure with appropriate values */
  if (conf.is_json_log_format)
    ret = parse_json_format(logitem, line);
  else
    ret = parse_format(logitem, line, fmt);

  /* invalid log line (format issue) */
  if (ret) {
    // process_invalid (glog, logitem, line);
    return cleanup_logitem(ret, logitem);
  }

  // if (!glog->piping && conf.fname_as_vhost && glog->fname_as_vhost)
  //   logitem->vhost = xstrdup (glog->fname_as_vhost);

  /* valid format but missing fields */
  if (ret || (ret = verify_missing_fields(logitem))) {
    return cleanup_logitem(ret, logitem);
  }

  /* agent will be null in cases where %u is not specified */
  if (logitem->agent == NULL) {
    logitem->agent = alloc_string("-");
    // set_agent_hash(logitem);
  }

  *logitem_out = logitem;

  return ret;
}

/* Determine if the log/date/time were set, otherwise exit the program
 * execution. */
static const char *verify_formats(void) {
  if (conf.time_format == NULL || *conf.time_format == '\0')
    return ERR_FORMAT_NO_TIME_FMT;

  if (conf.date_format == NULL || *conf.date_format == '\0')
    return ERR_FORMAT_NO_DATE_FMT;

  if (conf.log_format == NULL || *conf.log_format == '\0')
    return ERR_FORMAT_NO_LOG_FMT;

  return NULL;
}

/* predefined log times */
typedef struct GPreConfTime_ {
  const char *fmt24;
  const char *usec;
  const char *sec;
} GPreConfTime;

/* predefined log dates */
typedef struct GPreConfDate_ {
  const char *apache;
  const char *w3c;
  const char *usec;
  const char *sec;
} GPreConfDate;

/* predefined log formats */
typedef struct GPreConfLog_ {
  const char *combined;
  const char *vcombined;
  const char *common;
  const char *vcommon;
  const char *w3c;
  const char *cloudfront;
  const char *cloudstorage;
  const char *awselb;
  const char *squid;
  const char *awss3;
  const char *caddy;
  const char *awsalb;
  const char *traefikclf;
} GPreConfLog;

static const GPreConfLog logs = {
    "%h %^[%d:%t %^] \"%r\" %s %b \"%R\" \"%u\"",       /* NCSA */
    "%v:%^ %h %^[%d:%t %^] \"%r\" %s %b \"%R\" \"%u\"", /* NCSA + VHost
                                                         */
    "%h %^[%d:%t %^] \"%r\" %s %b",                     /* CLF */
    "%v:%^ %h %^[%d:%t %^] \"%r\" %s %b",               /* CLF+VHost */
    "%d %t %^ %m %U %q %^ %^ %h %u %R %s %^ %^ %L",     /* W3C */
    "%d\\t%t\\t%^\\t%b\\t%h\\t%m\\t%v\\t%U\\t%s\\t%R\\t%u\\t%q\\t%^\\t%"
    "C\\t%^"
    "\\t%^\\t%^\\t%^\\t%T\\t%^\\t%K\\t%k\\t%^\\t%H\\t%^", /* CloudFront
                                                           */
    "\"%x\",\"%h\",%^,%^,\"%m\",\"%U\",\"%s\",%^,\"%b\",\"%D\",%^,\"%"
    "R\",\"%"
    "u\"", /* Cloud Storage */
    "%^ %dT%t.%^ %^ %h:%^ %^ %^ %T %^ %s %^ %^ %b \"%r\" \"%u\" %k %K "
    "%^ "
    "\"%^\" \"%v\"", /* AWS Elastic Load Balancing */
    "%^ %^ %^ %v %^: %x.%^ %~%L %h %^/%s %b %m %U", /* Squid Native */
    "%^ %v [%d:%t %^] %h %^\"%r\" %s %^ %b %^ %L %^ \"%R\" \"%u\"", /* Amazon
                                                                     * S3
                                                                     */

    /* Caddy JSON */
    "{ \"ts\": \"%x.%^\", \"request\": { \"client_ip\": \"%h\", "
    "\"proto\":"
    "\"%H\", \"method\": \"%m\", \"host\": \"%v\", \"uri\": \"%U\", "
    "\"headers\": {"
    "\"User-Agent\": [\"%u\"], \"Referer\": [\"%R\"] }, \"tls\": { "
    "\"cipher_suite\":"
    "\"%k\", \"proto\": \"%K\" } }, \"duration\": \"%T\", \"size\": "
    "\"%b\","
    "\"status\": \"%s\", \"resp_headers\": { \"Content-Type\": "
    "[\"%M\"] } }",

    "%^ %dT%t.%^ %v %h:%^ %^ %^ %T %^ %s %^ %^ %b \"%r\" \"%u\" %k %K "
    "%^", /* Amazon
             ALB
           */

    "%h - %e [%d:%t %^] \"%r\" %s %b \"%R\" \"%u\" %^ \"%v\" \"%U\" "
    "%Lms" /* Traefik's
              CLF
              flavor
              with
              header
            */
};

static const GPreConfTime times = {
    "%H:%M:%S", "%f", /* Cloud Storage (usec) */
    "%s",             /* Squid (sec) */
};

static const GPreConfDate dates = {
    "%d/%b/%Y", /* Apache */
    "%Y-%m-%d", /* W3C */
    "%f",       /* Cloud Storage (usec) */
    "%s",       /* Squid (sec) */
};

/* Iterate over the given format and clean unwanted chars and keep all
 * date/time specifiers such as %b%Y%d%M%S.
 *
 * On error NULL is returned.
 * On success, a clean format containing only date/time specifiers is
 * returned. */
static char *clean_date_time_format(const char *format) {
  char *fmt = NULL, *pr = NULL, *pw = NULL;
  int special = 0;

  if (format == NULL || *format == '\0')
    return NULL;

  fmt = xstrdup(format);
  pr = fmt;
  pw = fmt;
  while (*pr) {
    *pw = *pr++;
    if (*pw == '%' || special) {
      special = !special;
      pw++;
    }
  }
  *pw = '\0';

  return fmt;
}

/* A wrapper to extract date specifiers from a date format.
 *
 * On error NULL is returned.
 * On success, a clean format containing only date specifiers is
 * returned. */
static char *set_format_date(void) {
  char *fdate = NULL;

  if (has_timestamp(conf.date_format))
    fdate = xstrdup("%Y%m%d");
  else
    fdate = clean_date_time_format(conf.date_format);

  return fdate;
}

/* Determine if the given specifier character is an abbreviated type
 * of date.
 *
 * If it is, 1 is returned, otherwise, 0 is returned. */
static int is_date_abbreviated(const char *fdate) {
  if (strpbrk(fdate, "cDF"))
    return 1;

  return 0;
}

/* Normalize the date format from the date format given by the user to
 * Ymd so it can be sorted out properly afterwards.
 *
 * On error or unable to determine the format, 1 is returned.
 * On success, the numeric date format as Ymd is set and 0 is
 * returned. */
static int set_date_num_format(void) {
  char *fdate = NULL, *buf = NULL;
  int buflen = 0, flen = 0;

  fdate = set_format_date();
  if (!fdate)
    return 1;

  if (is_date_abbreviated(fdate)) {
    free(fdate);
    conf.date_num_format = xstrdup("%Y%m%d");
    return 0;
  }

  flen = strlen(fdate) + 1;
  flen = MAX(MIN_DATENUM_FMT_LEN, flen); /* at least %Y%m%d + 1 */
  buf = xcalloc(flen, sizeof(char));

  /* always add a %Y */
  buflen += snprintf(buf + buflen, flen - buflen, "%%Y");
  if (strpbrk(fdate, "hbmBf*"))
    buflen += snprintf(buf + buflen, flen - buflen, "%%m");
  if (strpbrk(fdate, "def*"))
    buflen += snprintf(buf + buflen, flen - buflen, "%%d");

  conf.date_num_format = buf;
  free(fdate);

  return buflen == 0 ? 1 : 0;
}

/* Get the enumerated value given a string.
 *
 * On error, -1 is returned.
 * On success, the enumerated module value is returned. */
static int str2enum(const GEnum map[], int len, const char *str) {
  int i;

  for (i = 0; i < len; ++i) {
    if (!strcmp(str, map[i].str))
      return map[i].idx;
  }

  return -1;
}

typedef enum LOGTYPE {
  COMBINED,
  VCOMBINED,
  COMMON,
  VCOMMON,
  W3C,
  CLOUDFRONT,
  CLOUDSTORAGE,
  AWSELB,
  SQUID,
  AWSS3,
  CADDY,
  AWSALB,
  TRAEFIKCLF,
} GLogType;

static const GEnum LOGTYPE[] = {
    {"COMBINED", COMBINED},
    {"VCOMBINED", VCOMBINED},
    {"COMMON", COMMON},
    {"VCOMMON", VCOMMON},
    {"W3C", W3C},
    {"CLOUDFRONT", CLOUDFRONT},
    {"CLOUDSTORAGE", CLOUDSTORAGE},
    {"AWSELB", AWSELB},
    {"SQUID", SQUID},
    {"AWSS3", AWSS3},
    {"CADDY", CADDY},
    {"AWSALB", AWSALB},
    {"TRAEFIKCLF", TRAEFIKCLF},
};

/* Get the enumerated log format given its equivalent format string.
 * The case in the format string does not matter.
 *
 * On error, -1 is returned.
 * On success, the enumerated format is returned. */
static int get_log_format_item_enum(const char *str) {
  int ret;
  char *upstr;

  ret = str2enum(LOGTYPE, ARRAY_SIZE(LOGTYPE), str);
  if (ret >= 0)
    return ret;

  /* uppercase the input string and try again */
  upstr = strtoupper(xstrdup(str));
  ret = str2enum(LOGTYPE, ARRAY_SIZE(LOGTYPE), upstr);
  free(upstr);

  return ret;
}

/* Determine if we have a valid JSON format */
static int is_json_log_format(const char *fmt) {
  enum json_type t = JSON_ERROR;
  json_stream json;

  json_open_string(&json, fmt);
  /* ensure we use strict JSON when determining if we're using a JSON format */
  json_set_streaming(&json, false);
  do {
    t = json_next(&json);
    switch (t) {
    case JSON_ERROR:
      json_close(&json);
      return 0;
    default:
      break;
    }
  } while (t != JSON_DONE && t != JSON_ERROR);
  json_close(&json);

  return 1;
}

/* Determine if some global flags were set through log-format. */
static void contains_specifier(void) {
  conf.serve_usecs = conf.bandwidth = 0; /* flag */
  if (!conf.log_format)
    return;

  if (strstr(conf.log_format, "%b"))
    conf.bandwidth = 1; /* flag */
  if (strstr(conf.log_format, "%D"))
    conf.serve_usecs = 1; /* flag */
  if (strstr(conf.log_format, "%T"))
    conf.serve_usecs = 1; /* flag */
  if (strstr(conf.log_format, "%L"))
    conf.serve_usecs = 1; /* flag */
}

/* Determine the selected log format from the config file or command line
 * option.
 *
 * On error, NULL is returned.
 * On success, an allocated string containing the log format is returned. */
static char *get_selected_format_str(size_t idx) {
  char *fmt = NULL;
  switch (idx) {
  case COMBINED:
    fmt = alloc_string(logs.combined);
    break;
  case VCOMBINED:
    fmt = alloc_string(logs.vcombined);
    break;
  case COMMON:
    fmt = alloc_string(logs.common);
    break;
  case VCOMMON:
    fmt = alloc_string(logs.vcommon);
    break;
  case W3C:
    fmt = alloc_string(logs.w3c);
    break;
  case CLOUDFRONT:
    fmt = alloc_string(logs.cloudfront);
    break;
  case CLOUDSTORAGE:
    fmt = alloc_string(logs.cloudstorage);
    break;
  case AWSELB:
    fmt = alloc_string(logs.awselb);
    break;
  case SQUID:
    fmt = alloc_string(logs.squid);
    break;
  case AWSS3:
    fmt = alloc_string(logs.awss3);
    break;
  case CADDY:
    fmt = alloc_string(logs.caddy);
    break;
  case AWSALB:
    fmt = alloc_string(logs.awsalb);
    break;
  case TRAEFIKCLF:
    fmt = alloc_string(logs.traefikclf);
    break;
  }

  return fmt;
}

/* Determine the selected date format from the config file or command line
 * option.
 *
 * On error, NULL is returned.
 * On success, an allocated string containing the date format is returned. */
static char *get_selected_date_str(size_t idx) {
  char *fmt = NULL;
  switch (idx) {
  case COMMON:
  case VCOMMON:
  case COMBINED:
  case VCOMBINED:
  case AWSS3:
  case TRAEFIKCLF:
    fmt = alloc_string(dates.apache);
    break;
  case AWSELB:
  case AWSALB:
  case CLOUDFRONT:
  case W3C:
    fmt = alloc_string(dates.w3c);
    break;
  case CLOUDSTORAGE:
    fmt = alloc_string(dates.usec);
    break;
  case SQUID:
  case CADDY:
    fmt = alloc_string(dates.sec);
    break;
  }

  return fmt;
}

/* Attempt to set the date format given a command line option
 * argument. The supplied optarg can be either an actual format string
 * or the enumerated value such as VCOMBINED */
static void set_date_format_str(const char *oarg) {
  char *fmt = NULL;
  int type = get_log_format_item_enum(oarg);

  /* free date format if it was previously set by set_log_format_str() */
  if (conf.date_format)
    free(conf.date_format);

  /* type not found, use whatever was given by the user then */
  if (type == -1) {
    conf.date_format = unescape_str(oarg);
    return;
  }

  /* attempt to get the format string by the enum value */
  if ((fmt = get_selected_date_str(type)) == NULL) {
    LOG_DEBUG(("Unable to set date format from enum: %s\n", oarg));
    return;
  }

  conf.date_format = fmt;
}

static char *get_selected_time_str(size_t idx) {
  char *fmt = NULL;
  switch (idx) {
  case AWSELB:
  case AWSALB:
  case CLOUDFRONT:
  case COMBINED:
  case COMMON:
  case VCOMBINED:
  case VCOMMON:
  case W3C:
  case AWSS3:
  case TRAEFIKCLF:
    fmt = alloc_string(times.fmt24);
    break;
  case CLOUDSTORAGE:
    fmt = alloc_string(times.usec);
    break;
  case SQUID:
  case CADDY:
    fmt = alloc_string(times.sec);
    break;
  }

  return fmt;
}

/* Attempt to set the time format given a command line option
 * argument. The supplied optarg can be either an actual format string
 * or the enumerated value such as VCOMBINED */
static void set_time_format_str(const char *oarg) {
  char *fmt = NULL;
  int type = get_log_format_item_enum(oarg);

  /* free time format if it was previously set by set_log_format_str() */
  if (conf.time_format)
    free(conf.time_format);

  /* type not found, use whatever was given by the user then */
  if (type == -1) {
    conf.time_format = unescape_str(oarg);
    return;
  }

  /* attempt to get the format string by the enum value */
  if ((fmt = get_selected_time_str(type)) == NULL) {
    LOG_DEBUG(("Unable to set time format from enum: %s\n", oarg));
    return;
  }

  conf.time_format = fmt;
}

/* Attempt to set the log format given a command line option argument.
 * The supplied optarg can be either an actual format string or the
 * enumerated value such as VCOMBINED */
static void set_log_format_str(const char *oarg) {
  char *fmt = NULL;
  int type = get_log_format_item_enum(oarg);

  /* free log format if it was previously set */
  if (conf.log_format)
    free(conf.log_format);

  if (type == -1 && is_json_log_format(oarg)) {
    conf.is_json_log_format = 1;
    conf.log_format = unescape_str(oarg);
    contains_specifier(); /* set flag */
    return;
  }

  /* type not found, use whatever was given by the user then */
  if (type == -1) {
    conf.log_format = unescape_str(oarg);
    contains_specifier(); /* set flag */
    return;
  }

  /* attempt to get the format string by the enum value */
  if ((fmt = get_selected_format_str(type)) == NULL) {
    LOG_DEBUG(("Unable to set log format from enum: %s\n", oarg));
    return;
  }

  if (is_json_log_format(fmt))
    conf.is_json_log_format = 1;

  conf.log_format = unescape_str(fmt);
  contains_specifier(); /* set flag */

  /* assume we are using the default date/time formats */
  set_time_format_str(oarg);
  set_date_format_str(oarg);
  free(fmt);
}

#define DB_VERSION 2
#define DB_INSTANCE 1

#define GAMTRC_TOTAL 8

typedef enum GAMetric_ {
  MTRC_DATES,
  MTRC_SEQS,
  MTRC_CNT_OVERALL,
  MTRC_HOSTNAMES,
  MTRC_LAST_PARSE,
  MTRC_JSON_LOGFMT,
  MTRC_METH_PROTO,
  MTRC_DB_PROPS,
} GAMetric;

typedef enum GSMetricType_ {
  /* uint32_t key - uint32_t val */
  MTRC_TYPE_II32,
  /* uint32_t key - string val */
  MTRC_TYPE_IS32,
  /* uint32_t key - uint64_t val */
  MTRC_TYPE_IU64,
  /* string key   - uint32_t val */
  MTRC_TYPE_SI32,
  /* string key   - uint8_t val */
  MTRC_TYPE_SI08,
  /* uint32_t key - uint8_t val */
  MTRC_TYPE_II08,
  /* string key   - string val */
  MTRC_TYPE_SS32,
  /* uint32_t key - GSLList val */
  MTRC_TYPE_IGSL,
  /* string key   - uint64_t val */
  MTRC_TYPE_SU64,
  /* uint32_t key - GKHashStorage_ val */
  MTRC_TYPE_IGKH,
  /* uint64_t key - uint32_t val */
  MTRC_TYPE_U648,
  /* uint64_t key - GLastParse val */
  MTRC_TYPE_IGLP,
} GSMetricType;

typedef struct GKHashMetric_ {
  union {
    GSMetric storem;
    GAMetric dbm;
  } metric;
  GSMetricType type;
  void *(*alloc)(void);
  void (*des)(void *, uint8_t free_data);
  void (*del)(void *, uint8_t free_data);
  uint8_t free_data : 1;
  void *hash;
  const char *filename;
} GKHashMetric;

typedef struct GKHashDB_ {
  GKHashMetric metrics[GAMTRC_TOTAL];
} GKHashDB;

typedef struct GKHashModule_ {
  GModule module;
  GKHashMetric metrics[GSMTRC_TOTAL];
} GKHashModule;

/* Data store global */
typedef struct GKHashGlobal_ {
  GKHashMetric metrics[GSMTRC_TOTAL];
} GKHashGlobal;

typedef struct GKDB_ GKDB;

typedef struct GKHashStorage_ GKHashStorage;

struct GKHashStorage_ {
  GKHashModule *mhash; /* modules */
  GKHashGlobal *ghash; /* global */
};

struct GKDB_ {
  GKHashDB *hdb;        /* app-level hash tables */
  Logs *logs;           /* logs parsing per db instance */
  GKHashModule *cache;  /* cache modules */
  GKHashStorage *store; /* per date OR module */
};

typedef unsigned int khint32_t;
typedef khint32_t khint_t;
typedef khint_t khiter_t;
#define khash_t(name) kh_##name##_t

typedef unsigned long khint64_t;

#define kh_inline inline
#define klib_unused __attribute__((__unused__))

typedef khint32_t khint_t;
typedef khint_t khiter_t;

#define __ac_isempty(flag, i) ((flag[i >> 4] >> ((i & 0xfU) << 1)) & 2)
#define __ac_isdel(flag, i) ((flag[i >> 4] >> ((i & 0xfU) << 1)) & 1)
#define __ac_iseither(flag, i) ((flag[i >> 4] >> ((i & 0xfU) << 1)) & 3)
#define __ac_set_isdel_false(flag, i)                                          \
  (flag[i >> 4] &= ~(1ul << ((i & 0xfU) << 1)))
#define __ac_set_isempty_false(flag, i)                                        \
  (flag[i >> 4] &= ~(2ul << ((i & 0xfU) << 1)))
#define __ac_set_isboth_false(flag, i)                                         \
  (flag[i >> 4] &= ~(3ul << ((i & 0xfU) << 1)))
#define __ac_set_isdel_true(flag, i) (flag[i >> 4] |= 1ul << ((i & 0xfU) << 1))

#define __ac_fsize(m) ((m) < 16 ? 1 : (m) >> 4)

#define kroundup32(x)                                                          \
  (--(x), (x) |= (x) >> 1, (x) |= (x) >> 2, (x) |= (x) >> 4, (x) |= (x) >> 8,  \
   (x) |= (x) >> 16, ++(x))

#define kcalloc(N, Z) calloc(N, Z)

#define kmalloc(Z) malloc(Z)

#define krealloc(P, Z) realloc(P, Z)

#define kfree(P) free(P)

static const double __ac_HASH_UPPER = 0.77;

#define __KHASH_TYPE(name, khkey_t, khval_t)                                   \
  typedef struct kh_##name##_s {                                               \
    khint_t n_buckets, size, n_occupied, upper_bound;                          \
    khint32_t *flags;                                                          \
    khkey_t *keys;                                                             \
    khval_t *vals;                                                             \
  } kh_##name##_t;

#define __KHASH_PROTOTYPES(name, khkey_t, khval_t)                             \
  extern kh_##name##_t *kh_init_##name(void);                                  \
  extern void kh_destroy_##name(kh_##name##_t *h);                             \
  extern void kh_clear_##name(kh_##name##_t *h);                               \
  extern khint_t kh_get_##name(const kh_##name##_t *h, khkey_t key);           \
  extern int kh_resize_##name(kh_##name##_t *h, khint_t new_n_buckets);        \
  extern khint_t kh_put_##name(kh_##name##_t *h, khkey_t key, int *ret);       \
  extern void kh_del_##name(kh_##name##_t *h, khint_t x);

#define __KHASH_IMPL(name, SCOPE, khkey_t, khval_t, kh_is_map, __hash_func,    \
                     __hash_equal)                                             \
  SCOPE kh_##name##_t *kh_init_##name(void) {                                  \
    return (kh_##name##_t *)kcalloc(1, sizeof(kh_##name##_t));                 \
  }                                                                            \
  SCOPE void kh_destroy_##name(kh_##name##_t *h) {                             \
    if (h) {                                                                   \
      kfree((void *)h->keys);                                                  \
      kfree(h->flags);                                                         \
      kfree((void *)h->vals);                                                  \
      kfree(h);                                                                \
    }                                                                          \
  }                                                                            \
  SCOPE void kh_clear_##name(kh_##name##_t *h) {                               \
    if (h && h->flags) {                                                       \
      memset(h->flags, 0xaa, __ac_fsize(h->n_buckets) * sizeof(khint32_t));    \
      h->size = h->n_occupied = 0;                                             \
    }                                                                          \
  }                                                                            \
  SCOPE khint_t kh_get_##name(const kh_##name##_t *h, khkey_t key) {           \
    if (h->n_buckets) {                                                        \
      khint_t k, i, last, mask, step = 0;                                      \
      mask = h->n_buckets - 1;                                                 \
      k = __hash_func(key);                                                    \
      i = k & mask;                                                            \
      last = i;                                                                \
      while (!__ac_isempty(h->flags, i) &&                                     \
             (__ac_isdel(h->flags, i) || !__hash_equal(h->keys[i], key))) {    \
        i = (i + (++step)) & mask;                                             \
        if (i == last)                                                         \
          return h->n_buckets;                                                 \
      }                                                                        \
      return __ac_iseither(h->flags, i) ? h->n_buckets : i;                    \
    } else                                                                     \
      return 0;                                                                \
  }                                                                            \
  SCOPE int kh_resize_##name(kh_##name##_t *h, khint_t new_n_buckets) {        \
    /* This function uses 0.25*n_buckets bytes of working space instead of */  \
    /* [sizeof(key_t+val_t)+.25]*n_buckets. */                                 \
    khint32_t *new_flags = 0;                                                  \
    khint_t j = 1;                                                             \
    {                                                                          \
      kroundup32(new_n_buckets);                                               \
      if (new_n_buckets < 4)                                                   \
        new_n_buckets = 4;                                                     \
      if (h->size >= (khint_t)(new_n_buckets * __ac_HASH_UPPER + 0.5))         \
        j = 0; /* requested size is too small */                               \
      else {   /* hash table size to be changed (shrink or expand); rehash */  \
        new_flags = (khint32_t *)kmalloc(__ac_fsize(new_n_buckets) *           \
                                         sizeof(khint32_t));                   \
        if (!new_flags)                                                        \
          return -1;                                                           \
        memset(new_flags, 0xaa,                                                \
               __ac_fsize(new_n_buckets) * sizeof(khint32_t));                 \
        if (h->n_buckets < new_n_buckets) { /* expand */                       \
          khkey_t *new_keys = (khkey_t *)krealloc(                             \
              (void *)h->keys, new_n_buckets * sizeof(khkey_t));               \
          if (!new_keys) {                                                     \
            kfree(new_flags);                                                  \
            return -1;                                                         \
          }                                                                    \
          h->keys = new_keys;                                                  \
          if (kh_is_map) {                                                     \
            khval_t *new_vals = (khval_t *)krealloc(                           \
                (void *)h->vals, new_n_buckets * sizeof(khval_t));             \
            if (!new_vals) {                                                   \
              kfree(new_flags);                                                \
              return -1;                                                       \
            }                                                                  \
            h->vals = new_vals;                                                \
          }                                                                    \
        } /* otherwise shrink */                                               \
      }                                                                        \
    }                                                                          \
    if (j) { /* rehashing is needed */                                         \
      for (j = 0; j != h->n_buckets; ++j) {                                    \
        if (__ac_iseither(h->flags, j) == 0) {                                 \
          khkey_t key = h->keys[j];                                            \
          khval_t val;                                                         \
          khint_t new_mask;                                                    \
          new_mask = new_n_buckets - 1;                                        \
          if (kh_is_map)                                                       \
            val = h->vals[j];                                                  \
          __ac_set_isdel_true(h->flags, j);                                    \
          while (1) { /* kick-out process; sort of like in Cuckoo hashing */   \
            khint_t k, i, step = 0;                                            \
            k = __hash_func(key);                                              \
            i = k & new_mask;                                                  \
            while (!__ac_isempty(new_flags, i))                                \
              i = (i + (++step)) & new_mask;                                   \
            __ac_set_isempty_false(new_flags, i);                              \
            if (i < h->n_buckets &&                                            \
                __ac_iseither(h->flags, i) ==                                  \
                    0) { /* kick out the existing element */                   \
              {                                                                \
                khkey_t tmp = h->keys[i];                                      \
                h->keys[i] = key;                                              \
                key = tmp;                                                     \
              }                                                                \
              if (kh_is_map) {                                                 \
                khval_t tmp = h->vals[i];                                      \
                h->vals[i] = val;                                              \
                val = tmp;                                                     \
              }                                                                \
              __ac_set_isdel_true(                                             \
                  h->flags, i); /* mark it as deleted in the old hash table */ \
            } else { /* write the element and jump out of the loop */          \
              h->keys[i] = key;                                                \
              if (kh_is_map)                                                   \
                h->vals[i] = val;                                              \
              break;                                                           \
            }                                                                  \
          }                                                                    \
        }                                                                      \
      }                                                                        \
      if (h->n_buckets > new_n_buckets) { /* shrink the hash table */          \
        h->keys = (khkey_t *)krealloc((void *)h->keys,                         \
                                      new_n_buckets * sizeof(khkey_t));        \
        if (kh_is_map)                                                         \
          h->vals = (khval_t *)krealloc((void *)h->vals,                       \
                                        new_n_buckets * sizeof(khval_t));      \
      }                                                                        \
      kfree(h->flags); /* free the working space */                            \
      h->flags = new_flags;                                                    \
      h->n_buckets = new_n_buckets;                                            \
      h->n_occupied = h->size;                                                 \
      h->upper_bound = (khint_t)(h->n_buckets * __ac_HASH_UPPER + 0.5);        \
    }                                                                          \
    return 0;                                                                  \
  }                                                                            \
  SCOPE khint_t kh_put_##name(kh_##name##_t *h, khkey_t key, int *ret) {       \
    khint_t x;                                                                 \
    if (h->n_occupied >= h->upper_bound) { /* update the hash table */         \
      if (h->n_buckets > (h->size << 1)) {                                     \
        if (kh_resize_##name(h, h->n_buckets - 1) <                            \
            0) { /* clear "deleted" elements */                                \
          *ret = -1;                                                           \
          return h->n_buckets;                                                 \
        }                                                                      \
      } else if (kh_resize_##name(h, h->n_buckets + 1) <                       \
                 0) { /* expand the hash table */                              \
        *ret = -1;                                                             \
        return h->n_buckets;                                                   \
      }                                                                        \
    } /* TODO: to implement automatically shrinking; resize() already support  \
         shrinking */                                                          \
    {                                                                          \
      khint_t k, i, site, last, mask = h->n_buckets - 1, step = 0;             \
      x = site = h->n_buckets;                                                 \
      k = __hash_func(key);                                                    \
      i = k & mask;                                                            \
      if (__ac_isempty(h->flags, i))                                           \
        x = i; /* for speed up */                                              \
      else {                                                                   \
        last = i;                                                              \
        while (!__ac_isempty(h->flags, i) &&                                   \
               (__ac_isdel(h->flags, i) || !__hash_equal(h->keys[i], key))) {  \
          if (__ac_isdel(h->flags, i))                                         \
            site = i;                                                          \
          i = (i + (++step)) & mask;                                           \
          if (i == last) {                                                     \
            x = site;                                                          \
            break;                                                             \
          }                                                                    \
        }                                                                      \
        if (x == h->n_buckets) {                                               \
          if (__ac_isempty(h->flags, i) && site != h->n_buckets)               \
            x = site;                                                          \
          else                                                                 \
            x = i;                                                             \
        }                                                                      \
      }                                                                        \
    }                                                                          \
    if (__ac_isempty(h->flags, x)) { /* not present at all */                  \
      h->keys[x] = key;                                                        \
      __ac_set_isboth_false(h->flags, x);                                      \
      ++h->size;                                                               \
      ++h->n_occupied;                                                         \
      *ret = 1;                                                                \
    } else if (__ac_isdel(h->flags, x)) { /* deleted */                        \
      h->keys[x] = key;                                                        \
      __ac_set_isboth_false(h->flags, x);                                      \
      ++h->size;                                                               \
      *ret = 2;                                                                \
    } else                                                                     \
      *ret = 0; /* Don't touch h->keys[x] if present and not deleted */        \
    return x;                                                                  \
  }                                                                            \
  SCOPE void kh_del_##name(kh_##name##_t *h, khint_t x) {                      \
    if (x != h->n_buckets && !__ac_iseither(h->flags, x)) {                    \
      __ac_set_isdel_true(h->flags, x);                                        \
      --h->size;                                                               \
    }                                                                          \
  }

#define KHASH_DECLARE(name, khkey_t, khval_t)                                  \
  __KHASH_TYPE(name, khkey_t, khval_t)                                         \
  __KHASH_PROTOTYPES(name, khkey_t, khval_t)

#define KHASH_INIT2(name, SCOPE, khkey_t, khval_t, kh_is_map, __hash_func,     \
                    __hash_equal)                                              \
  __KHASH_TYPE(name, khkey_t, khval_t)                                         \
  __KHASH_IMPL(name, SCOPE, khkey_t, khval_t, kh_is_map, __hash_func,          \
               __hash_equal)

#define KHASH_INIT(name, khkey_t, khval_t, kh_is_map, __hash_func,             \
                   __hash_equal)                                               \
  KHASH_INIT2(name, static kh_inline klib_unused, khkey_t, khval_t, kh_is_map, \
              __hash_func, __hash_equal)

/* --- BEGIN OF HASH FUNCTIONS --- */

/*! @function
  @abstract     Integer hash function
  @param  key   The integer [khint32_t]
  @return       The hash value [khint_t]
 */
#define kh_int_hash_func(key) (khint32_t)(key)
/*! @function
  @abstract     Integer comparison function
 */
#define kh_int_hash_equal(a, b) ((a) == (b))
/*! @function
  @abstract     64-bit integer hash function
  @param  key   The integer [khint64_t]
  @return       The hash value [khint_t]
 */
#define kh_int64_hash_func(key) (khint32_t)((key) >> 33 ^ (key) ^ (key) << 11)
/*! @function
  @abstract     64-bit integer comparison function
 */
#define kh_int64_hash_equal(a, b) ((a) == (b))
/*! @function
  @abstract     const char* hash function
  @param  s     Pointer to a null terminated string
  @return       The hash value
 */
static kh_inline khint_t
__ac_X31_hash_string(const char *s) {
  khint_t h = (khint_t)*s;
  if (h)
    for (++s; *s; ++s)
      h = (h << 5) - h + (khint_t)*s;
  return h;
}

/*! @function
  @abstract     Another interface to const char* hash function
  @param  key   Pointer to a null terminated string [const char*]
  @return       The hash value [khint_t]
 */
#define kh_str_hash_func(key) __ac_X31_hash_string(key)
/*! @function
  @abstract     Const char* comparison function
 */
#define kh_str_hash_equal(a, b) (strcmp(a, b) == 0)

static kh_inline khint_t __ac_Wang_hash(khint_t key) {
  key += ~(key << 15);
  key ^= (key >> 10);
  key += (key << 3);
  key ^= (key >> 6);
  key += ~(key << 11);
  key ^= (key >> 16);
  return key;
}

#define kh_int_hash_func2(k) __ac_Wang_hash((khint_t)key)

/* --- END OF HASH FUNCTIONS --- */

/* Other convenient macros... */

/*!
  @abstract Type of the hash table.
  @param  name  Name of the hash table [symbol]
 */
#define khash_t(name) kh_##name##_t

/*! @function
  @abstract     Initiate a hash table.
  @param  name  Name of the hash table [symbol]
  @return       Pointer to the hash table [khash_t(name)*]
 */
#define kh_init(name) kh_init_##name()

/*! @function
  @abstract     Destroy a hash table.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
 */
#define kh_destroy(name, h) kh_destroy_##name(h)

/*! @function
  @abstract     Reset a hash table without deallocating memory.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
 */
#define kh_clear(name, h) kh_clear_##name(h)

/*! @function
  @abstract     Resize a hash table.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  s     New size [khint_t]
 */
#define kh_resize(name, h, s) kh_resize_##name(h, s)

/*! @function
  @abstract     Insert a key to the hash table.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  k     Key [type of keys]
  @param  r     Extra return code: -1 if the operation failed;
                0 if the key is present in the hash table;
                1 if the bucket is empty (never used); 2 if the element in
        the bucket has been deleted [int*]
  @return       Iterator to the inserted element [khint_t]
 */
#define kh_put(name, h, k, r) kh_put_##name(h, k, r)

/*! @function
  @abstract     Retrieve a key from the hash table.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  k     Key [type of keys]
  @return       Iterator to the found element, or kh_end(h) if the element is
  absent [khint_t]
 */
#define kh_get(name, h, k) kh_get_##name(h, k)

/*! @function
  @abstract     Remove a key from the hash table.
  @param  name  Name of the hash table [symbol]
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  k     Iterator to the element to be deleted [khint_t]
 */
#define kh_del(name, h, k) kh_del_##name(h, k)

/*! @function
  @abstract     Test whether a bucket contains data.
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  x     Iterator to the bucket [khint_t]
  @return       1 if containing data; 0 otherwise [int]
 */
#define kh_exist(h, x) (!__ac_iseither((h)->flags, (x)))

/*! @function
  @abstract     Get key given an iterator
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  x     Iterator to the bucket [khint_t]
  @return       Key [type of keys]
 */
#define kh_key(h, x) ((h)->keys[x])

/*! @function
  @abstract     Get value given an iterator
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  x     Iterator to the bucket [khint_t]
  @return       Value [type of values]
  @discussion   For hash sets, calling this results in segfault.
 */
#define kh_val(h, x) ((h)->vals[x])

/*! @function
  @abstract     Alias of kh_val()
 */
#define kh_value(h, x) ((h)->vals[x])

/*! @function
  @abstract     Get the start iterator
  @param  h     Pointer to the hash table [khash_t(name)*]
  @return       The start iterator [khint_t]
 */
#define kh_begin(h) (khint_t)(0)

/*! @function
  @abstract     Get the end iterator
  @param  h     Pointer to the hash table [khash_t(name)*]
  @return       The end iterator [khint_t]
 */
#define kh_end(h) ((h)->n_buckets)

/*! @function
  @abstract     Get the number of elements in the hash table
  @param  h     Pointer to the hash table [khash_t(name)*]
  @return       Number of elements in the hash table [khint_t]
 */
#define kh_size(h) ((h)->size)

/*! @function
  @abstract     Get the number of buckets in the hash table
  @param  h     Pointer to the hash table [khash_t(name)*]
  @return       Number of buckets in the hash table [khint_t]
 */
#define kh_n_buckets(h) ((h)->n_buckets)

/*! @function
  @abstract     Iterate over the entries in the hash table
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  kvar  Variable to which key will be assigned
  @param  vvar  Variable to which value will be assigned
  @param  code  Block of code to execute
 */
#define kh_foreach(h, kvar, vvar, code)                                        \
  {                                                                            \
    khint_t __i;                                                               \
    for (__i = kh_begin(h); __i != kh_end(h); ++__i) {                         \
      if (!kh_exist(h, __i))                                                   \
        continue;                                                              \
      (kvar) = kh_key(h, __i);                                                 \
      (vvar) = kh_val(h, __i);                                                 \
      code;                                                                    \
    }                                                                          \
  }

/*! @function
  @abstract     Iterate over the values in the hash table
  @param  h     Pointer to the hash table [khash_t(name)*]
  @param  vvar  Variable to which value will be assigned
  @param  code  Block of code to execute
 */
#define kh_foreach_value(h, vvar, code)                                        \
  {                                                                            \
    khint_t __i;                                                               \
    for (__i = kh_begin(h); __i != kh_end(h); ++__i) {                         \
      if (!kh_exist(h, __i))                                                   \
        continue;                                                              \
      (vvar) = kh_val(h, __i);                                                 \
      code;                                                                    \
    }                                                                          \
  }

/* More convenient interfaces */

/*! @function
  @abstract     Instantiate a hash set containing integer keys
  @param  name  Name of the hash table [symbol]
 */
#define KHASH_SET_INIT_INT(name)                                               \
  KHASH_INIT(name, khint32_t, char, 0, kh_int_hash_func, kh_int_hash_equal)

/*! @function
  @abstract     Instantiate a hash map containing integer keys
  @param  name  Name of the hash table [symbol]
  @param  khval_t  Type of values [type]
 */
#define KHASH_MAP_INIT_INT(name, khval_t)                                      \
  KHASH_INIT(name, khint32_t, khval_t, 1, kh_int_hash_func, kh_int_hash_equal)

/*! @function
  @abstract     Instantiate a hash map containing 64-bit integer keys
  @param  name  Name of the hash table [symbol]
 */
#define KHASH_SET_INIT_INT64(name)                                             \
  KHASH_INIT(name, khint64_t, char, 0, kh_int64_hash_func, kh_int64_hash_equal)

/*! @function
  @abstract     Instantiate a hash map containing 64-bit integer keys
  @param  name  Name of the hash table [symbol]
  @param  khval_t  Type of values [type]
 */
#define KHASH_MAP_INIT_INT64(name, khval_t)                                    \
  KHASH_INIT(name, khint64_t, khval_t, 1, kh_int64_hash_func,                  \
             kh_int64_hash_equal)

typedef const char *kh_cstr_t;
/*! @function
  @abstract     Instantiate a hash map containing const char* keys
  @param  name  Name of the hash table [symbol]
 */
#define KHASH_SET_INIT_STR(name)                                               \
  KHASH_INIT(name, kh_cstr_t, char, 0, kh_str_hash_func, kh_str_hash_equal)

/*! @function
  @abstract     Instantiate a hash map containing const char* keys
  @param  name  Name of the hash table [symbol]
  @param  khval_t  Type of values [type]
 */
#define KHASH_MAP_INIT_STR(name, khval_t)                                      \
  KHASH_INIT(name, kh_cstr_t, khval_t, 1, kh_str_hash_func, kh_str_hash_equal)

/* uint32_t keys           , GKDB payload */
KHASH_MAP_INIT_INT(igdb, GKDB *);
/* uint32_t keys           , GKHashStorage payload */
KHASH_MAP_INIT_INT(igkh, GKHashStorage *);
/* uint32_t keys           , uint32_t payload */
KHASH_MAP_INIT_INT(ii32, uint32_t);
/* uint32_t keys           , string payload */
KHASH_MAP_INIT_INT(is32, char *);
/* uint32_t keys           , uint64_t payload */
KHASH_MAP_INIT_INT(iu64, uint64_t);
/* string keys             , uint32_t payload */
KHASH_MAP_INIT_STR(si32, uint32_t);
/* string keys             , uint8_t payload */
KHASH_MAP_INIT_STR(si08, uint8_t);
/* uint8_t keys            , uint8_t payload */
KHASH_MAP_INIT_INT(ii08, uint8_t);
/* string keys             , string payload */
KHASH_MAP_INIT_STR(ss32, char *);
/* uint64_t key            , GLastParse payload */
KHASH_MAP_INIT_INT64(iglp, GLastParse);
/* uint32_t keys           , GSLList payload */
KHASH_MAP_INIT_INT(igsl, GSLList *);
/* string keys             , uint64_t payload */
KHASH_MAP_INIT_STR(su64, uint64_t);
/* uint64_t key            , uint8_t payload */
KHASH_MAP_INIT_INT64(u648, uint8_t);

static khash_t(igdb) *ht_db = NULL;

/* Given a key (date), get the relevant store
 *
 * On error or not found, NULL is returned.
 * On success, a pointer to that store is returned. */
static void *get_db_instance(uint32_t key) {
  GKDB *db = NULL;
  khint_t k;

  khash_t(igdb) *hash = ht_db;

  k = kh_get(igdb, hash, key);
  /* key not found, return NULL */
  if (k == kh_end(hash))
    return NULL;

  db = kh_val(hash, k);
  return db;
}

/* Get an app hash table given a DB instance and a GAMetric
 *
 * On success, a pointer to that store is returned. */
static void *get_hdb(GKDB *db, GAMetric mtrc) {
  return db->hdb->metrics[mtrc].hash;
}

/* Insert a JSON log format specification such as request.method => %m.
 *
 * On error -1 is returned.
 * On success or if key exists, 0 is returned */
static int ht_insert_json_logfmt(void *userdata, char *key, char *spec) {
  GKDB *db = get_db_instance(DB_INSTANCE);
  khash_t(ss32) *hash = get_hdb(db, MTRC_JSON_LOGFMT);
  khint_t k;
  int ret;
  char *dupkey = NULL;

  if (!hash)
    return -1;

  k = kh_get(ss32, hash, key);
  /* key found, free it then to insert */
  if (k != kh_end(hash))
    free(kh_val(hash, k));
  else {
    dupkey = xstrdup(key);
    k = kh_put(ss32, hash, dupkey, &ret);
    /* operation failed */
    if (ret == -1) {
      free(dupkey);
      return -1;
    }
  }
  kh_val(hash, k) = xstrdup(spec);

  return 0;
}

/* A wrapper to extract time specifiers from a time format.
 *
 * On error NULL is returned.
 * On success, a clean format containing only time specifiers is
 * returned. */
static char *set_format_time(void) {
  char *ftime = NULL;

  if (has_timestamp(conf.date_format) || !strcmp("%T", conf.time_format))
    ftime = xstrdup("%H%M%S");
  else
    ftime = clean_date_time_format(conf.time_format);

  return ftime;
}

/* A wrapper function to concat the given specificity to the date
 * format. */
static char *append_spec_date_format(const char *date_format,
                                     const char *spec_format) {
  char *s = xmalloc(snprintf(NULL, 0, "%s%s", date_format, spec_format) + 1);
  sprintf(s, "%s%s", date_format, spec_format);

  return s;
}

/* Once we have a numeric date format, we attempt to read the time
 * format and construct a date_time numeric specificity format (if any
 * specificity is given). The result may look like Ymd[HM].
 *
 * On success, the numeric date time specificity format is set. */
static void set_spec_date_time_num_format(void) {
  char *buf = NULL, *tf = set_format_time();
  const char *df = conf.date_num_format;

  if (!df || !tf) {
    free(tf);
    return;
  }

  if (conf.date_spec_hr == 1 && strchr(tf, 'H'))
    buf = append_spec_date_format(df, "%H");
  else if (conf.date_spec_hr == 2 && strchr(tf, 'M'))
    buf = append_spec_date_format(df, "%H%M");
  else
    buf = xstrdup(df);

  conf.spec_date_time_num_format = buf;
  free(tf);
}

/* Set a human-readable specificity date and time format.
 *
 * On success, the human-readable date time specificity format is set. */
static void set_spec_date_time_format(void) {
  char *buf = NULL;
  const char *fmt = conf.spec_date_time_num_format;
  int buflen = 0, flen = 0;

  if (!fmt)
    return;

  flen = (strlen(fmt) * 2) + 1;
  buf = xcalloc(flen, sizeof(char));

  if (strchr(fmt, 'd'))
    buflen += snprintf(buf + buflen, flen - buflen, "%%d/");
  if (strchr(fmt, 'm'))
    buflen += snprintf(buf + buflen, flen - buflen, "%%b/");
  if (strchr(fmt, 'Y'))
    buflen += snprintf(buf + buflen, flen - buflen, "%%Y");
  if (strchr(fmt, 'H'))
    buflen += snprintf(buf + buflen, flen - buflen, ":%%H");
  if (strchr(fmt, 'M'))
    buflen += snprintf(buf + buflen, flen - buflen, ":%%M");

  conf.spec_date_time_format = buf;
}

/* If specificity is supplied, then determine which value we need to
 * append to the date format. */
static void set_spec_date_format(void) {
  if (verify_formats())
    return;

  if (conf.is_json_log_format) {
    if (parse_json_string(NULL, conf.log_format, ht_insert_json_logfmt) == -1)
      FATAL("Invalid JSON log format. Verify the syntax.");
  }

  if (conf.date_num_format)
    free(conf.date_num_format);
  if (conf.spec_date_time_format)
    free(conf.spec_date_time_format);
  if (conf.spec_date_time_num_format)
    free(conf.spec_date_time_num_format);

  if (set_date_num_format() == 0) {
    set_spec_date_time_num_format();
    set_spec_date_time_format();
  }
}

/* Allocate memory for a new module GKHashModule instance.
 *
 * On success, the newly allocated GKHashStorage is returned . */
static GKHashModule *new_gkhmodule(uint32_t size) {
  GKHashModule *storage = xcalloc(size, sizeof(GKHashModule));
  return storage;
}

/* list of available modules/panels */
static int module_list[TOTAL_MODULES] = {[0 ... TOTAL_MODULES - 1] = -1};

/* Initialize a new uint32_t key - GSLList value hash table */
static void *new_igsl_ht(void) {
  khash_t(igsl) *h = kh_init(igsl);
  return h;
}

/* Initialize a new string key - uint32_t value hash table */
static void *new_ii08_ht(void) {
  khash_t(ii08) *h = kh_init(ii08);
  return h;
}

/* Initialize a new uint32_t key - uint32_t value hash table */
static void *new_ii32_ht(void) {
  khash_t(ii32) *h = kh_init(ii32);
  return h;
}

/* Initialize a new uint32_t key - string value hash table */
static void *new_is32_ht(void) {
  khash_t(is32) *h = kh_init(is32);
  return h;
}

/* Initialize a new uint32_t key - uint64_t value hash table */
static void *new_iu64_ht(void) {
  khash_t(iu64) *h = kh_init(iu64);
  return h;
}

/* Initialize a new string key - uint32_t value hash table */
static void *new_si32_ht(void) {
  khash_t(si32) *h = kh_init(si32);
  return h;
}

/* Initialize a new string key - uint64_t value hash table */
static void *new_su64_ht(void) {
  khash_t(su64) *h = kh_init(su64);
  return h;
}

/* Initialize a new uint64_t key - uint8_t value hash table */
static void *new_u648_ht(void) {
  khash_t(u648) *h = kh_init(u648);
  return h;
}

/* Initialize a new uint64_t key - GLastParse value hash table */
static void *new_iglp_ht(void) {
  khash_t(iglp) *h = kh_init(iglp);
  return h;
}

/* Initialize a new uint32_t key - GKHashStorage value hash table */
static void *new_igdb_ht(void) {
  khash_t(igdb) *h = kh_init(igdb);
  return h;
}

/* Initialize a new uint32_t key - GKHashStorage value hash table */
static void *new_igkh_ht(void) {
  khash_t(igkh) *h = kh_init(igkh);
  return h;
}

/* Initialize a new string key - uint32_t value hash table */
static void *new_si08_ht(void) {
  khash_t(si08) *h = kh_init(si08);
  return h;
}

/* Initialize a new string key - string value hash table */
static void *new_ss32_ht(void) {
  khash_t(ss32) *h = kh_init(ss32);
  return h;
}

/* Remove all nodes from the list.
 *
 * On success, 0 is returned. */
static int list_remove_nodes(GSLList *list) {
  GSLList *tmp;
  while (list != NULL) {
    tmp = list->next;
    if (list->data)
      free(list->data);
    free(list);
    list = tmp;
  }

  return 0;
}

/* Deletes all entries from the hash table and optionally frees its GSLList */
static void del_igsl_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(igsl) *hash = h;
  void *list = NULL;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (!kh_exist(hash, k))
      continue;

    if (free_data) {
      list = kh_value(hash, k);
      list_remove_nodes(list);
    }
    kh_del(igsl, hash, k);
  }
}

/* Deletes all entries from the hash table */
static void del_ii08(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(ii08) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      kh_del(ii08, hash, k);
    }
  }
}

/* Deletes all entries from the hash table */
static void del_ii32(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(ii32) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      kh_del(ii32, hash, k);
    }
  }
}

/* Deletes both the hash entry and its string values */
static void del_is32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(is32) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      if (free_data)
        free((char *)kh_value(hash, k));
      kh_del(is32, hash, k);
    }
  }
}

/* Deletes all entries from the hash table */
static void del_iu64(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(iu64) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      kh_del(iu64, hash, k);
    }
  }
}

/* Deletes an entry from the hash table and optionally the keys for a string
 * key - uint32_t value hash */
static void del_si32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(si32) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      if (free_data)
        free((char *)kh_key(hash, k));
      kh_del(si32, hash, k);
    }
  }
}

/* Deletes all entries from the hash table and optionally frees its string key
 */
static void del_su64_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(su64) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      if (free_data)
        free((char *)kh_key(hash, k));
      kh_del(su64, hash, k);
    }
  }
}

/* Deletes all entries from the hash table */
static void del_u648(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(u648) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      kh_del(u648, hash, k);
    }
  }
}

/* Destroys both the hash structure and its GSLList
 * values */
static void des_igsl_free(void *h, uint8_t free_data) {
  khash_t(igsl) *hash = h;
  khint_t k;
  void *list = NULL;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k) && (list = kh_value(hash, k))) {
      list_remove_nodes(list);
    }
  }
des:
  kh_destroy(igsl, hash);
}

/* Destroys the hash structure */
static void des_ii08(void *h, uint8_t free_data) {
  khash_t(ii08) *hash = h;
  if (!hash)
    return;
  kh_destroy(ii08, hash);
}

/* Destroys the hash structure */
static void des_ii32(void *h, uint8_t free_data) {
  khash_t(ii32) *hash = h;
  if (!hash)
    return;
  kh_destroy(ii32, hash);
}

/* Destroys both the hash structure and its string values */
static void des_is32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(is32) *hash = h;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      free((char *)kh_value(hash, k));
    }
  }
des:
  kh_destroy(is32, hash);
}

/* Destroys the hash structure */
static void des_iu64(void *h, uint8_t free_data) {
  khash_t(iu64) *hash = h;
  if (!hash)
    return;
  kh_destroy(iu64, hash);
}

/* Destroys both the hash structure and the keys for a
 * string key - uint32_t value hash */
static void des_si32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(si32) *hash = h;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      free((char *)kh_key(hash, k));
    }
  }

des:
  kh_destroy(si32, hash);
}

/* Destroys both the hash structure and the keys for a
 * string key - uint64_t value hash */
static void des_su64_free(void *h, uint8_t free_data) {
  khash_t(su64) *hash = h;
  khint_t k;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      free((char *)kh_key(hash, k));
    }
  }

des:
  kh_destroy(su64, hash);
}

/* Destroys the hash structure */
static void des_u648(void *h, uint8_t free_data) {
  khash_t(u648) *hash = h;
  if (!hash)
    return;
  kh_destroy(u648, hash);
}

/* Destroys both the hash structure and the keys for a
 * string key - uint32_t value hash */
static void des_si08_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(si08) *hash = h;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      free((char *)kh_key(hash, k));
    }
  }

des:
  kh_destroy(si08, hash);
}

/* Deletes an entry from the hash table and optionally the keys for a string
 * key - uint32_t value hash */
static void del_si08_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(si08) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      if (free_data)
        free((char *)kh_key(hash, k));
      kh_del(si08, hash, k);
    }
  }
}

/* Deletes an entry from the hash table and optionally the keys for a string
 * keys and string values */
static void del_ss32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(ss32) *hash = h;
  if (!hash)
    return;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      if (free_data) {
        free((char *)kh_key(hash, k));
        free((char *)kh_value(hash, k));
      }
      kh_del(ss32, hash, k);
    }
  }
}

/* Destroys both the hash structure and its string
 * keys and string values */
static void des_ss32_free(void *h, uint8_t free_data) {
  khint_t k;
  khash_t(ss32) *hash = h;
  if (!hash)
    return;

  if (!free_data)
    goto des;

  for (k = 0; k < kh_end(hash); ++k) {
    if (kh_exist(hash, k)) {
      free((char *)kh_key(hash, k));
      free((char *)kh_value(hash, k));
    }
  }

des:
  kh_destroy(ss32, hash);
}

/* Destroys the hash structure */
static void des_iglp(void *h, uint8_t free_data) {
  khash_t(iglp) *hash = h;
  if (!hash)
    return;
  kh_destroy(iglp, hash);
}

/* Per module & per date */
static const GKHashMetric module_metrics[] = {
    {.metric.storem = MTRC_KEYMAP,
     MTRC_TYPE_II32,
     new_ii32_ht,
     des_ii32,
     del_ii32,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_ROOTMAP,
     MTRC_TYPE_IS32,
     new_is32_ht,
     des_is32_free,
     del_is32_free,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_DATAMAP,
     MTRC_TYPE_IS32,
     new_is32_ht,
     des_is32_free,
     del_is32_free,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_UNIQMAP,
     MTRC_TYPE_U648,
     new_u648_ht,
     des_u648,
     del_u648,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_ROOT,
     MTRC_TYPE_II32,
     new_ii32_ht,
     des_ii32,
     del_ii32,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_HITS,
     MTRC_TYPE_II32,
     new_ii32_ht,
     des_ii32,
     del_ii32,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_VISITORS,
     MTRC_TYPE_II32,
     new_ii32_ht,
     des_ii32,
     del_ii32,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_BW,
     MTRC_TYPE_IU64,
     new_iu64_ht,
     des_iu64,
     del_iu64,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_CUMTS,
     MTRC_TYPE_IU64,
     new_iu64_ht,
     des_iu64,
     del_iu64,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_MAXTS,
     MTRC_TYPE_IU64,
     new_iu64_ht,
     des_iu64,
     del_iu64,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_METHODS,
     MTRC_TYPE_II08,
     new_ii08_ht,
     des_ii08,
     del_ii08,
     0,
     NULL,
     NULL},
    {.metric.storem = MTRC_PROTOCOLS,
     MTRC_TYPE_II08,
     new_ii08_ht,
     des_ii08,
     del_ii08,
     0,
     NULL,
     NULL},
    {.metric.storem = MTRC_AGENTS,
     MTRC_TYPE_IGSL,
     new_igsl_ht,
     des_igsl_free,
     del_igsl_free,
     1,
     NULL,
     NULL},
    {.metric.storem = MTRC_METADATA,
     MTRC_TYPE_SU64,
     new_su64_ht,
     des_su64_free,
     del_su64_free,
     1,
     NULL,
     NULL},
};
static const size_t module_metrics_len = ARRAY_SIZE(module_metrics);

/* Initialize module metrics and mallocs its hash structure */
static void init_tables(GModule module, GKHashModule *storage) {
  int n = 0, i;

  n = module_metrics_len;
  for (i = 0; i < n; i++) {
    storage[module].metrics[i] = module_metrics[i];
    storage[module].metrics[i].hash = module_metrics[i].alloc();
  }
}

/* Initialize a module hash structure.
 *
 * On success, a pointer to that hash structure is returned. */
static GKHashModule *init_gkhashmodule(void) {
  GKHashModule *storage = NULL;
  GModule module;
  size_t idx = 0;

  storage = new_gkhmodule(TOTAL_MODULES);
  FOREACH_MODULE(idx, module_list) {
    module = module_list[idx];

    storage[module].module = module;
    init_tables(module, storage);
  }

  return storage;
}

/* Initialize hash tables */
static void init_storage(void) {
  GKDB *db = get_db_instance(DB_INSTANCE);
  db->cache = init_gkhashmodule();
}

/* Allocate memory for a new GKDB instance.
 *
 * On success, the newly allocated GKHashDB is returned . */
static GKDB *new_gkdb(void) {
  GKDB *db = xcalloc(1, sizeof(GKDB));
  return db;
}

/* Allocate memory for a new global GKHashDB instance.
 *
 * On success, the newly allocated GKHashDB is returned . */
static GKHashDB *new_gkhdb(void) {
  GKHashDB *storage = xcalloc(1, sizeof(GKHashDB));
  return storage;
}

/* Whole application */
static const GKHashMetric app_metrics[] = {
    {.metric.dbm = MTRC_DATES,
     MTRC_TYPE_IGKH,
     new_igkh_ht,
     NULL,
     NULL,
     1,
     NULL,
     NULL},
    {.metric.dbm = MTRC_SEQS,
     MTRC_TYPE_SI32,
     new_si32_ht,
     des_si32_free,
     del_si32_free,
     1,
     NULL,
     "SI32_SEQS.db"},
    {.metric.dbm = MTRC_CNT_OVERALL,
     MTRC_TYPE_SI32,
     new_si32_ht,
     des_si32_free,
     del_si32_free,
     1,
     NULL,
     "SI32_CNT_OVERALL.db"},
    {.metric.dbm = MTRC_HOSTNAMES,
     MTRC_TYPE_SS32,
     new_ss32_ht,
     des_ss32_free,
     del_ss32_free,
     1,
     NULL,
     NULL},
    {.metric.dbm = MTRC_LAST_PARSE,
     MTRC_TYPE_IGLP,
     new_iglp_ht,
     des_iglp,
     NULL,
     1,
     NULL,
     "IGLP_LAST_PARSE.db"},
    {.metric.dbm = MTRC_JSON_LOGFMT,
     MTRC_TYPE_SS32,
     new_ss32_ht,
     des_ss32_free,
     del_ss32_free,
     1,
     NULL,
     NULL},
    {.metric.dbm = MTRC_METH_PROTO,
     MTRC_TYPE_SI08,
     new_si08_ht,
     des_si08_free,
     del_si08_free,
     1,
     NULL,
     "SI08_METH_PROTO.db"},
    {.metric.dbm = MTRC_DB_PROPS,
     MTRC_TYPE_SI32,
     new_si32_ht,
     des_si32_free,
     del_si32_free,
     1,
     NULL,
     "SI32_DB_PROPS.db"},
};

static const size_t app_metrics_len = ARRAY_SIZE(app_metrics);

/* Initialize a global hash structure.
 *
 * On success, a pointer to that hash structure is returned. */
static GKHashDB *init_gkhashdb(void) {
  GKHashDB *storage = NULL;

  int n = 0, i;

  storage = new_gkhdb();
  n = app_metrics_len;
  for (i = 0; i < n; i++) {
    storage->metrics[i] = app_metrics[i];
    storage->metrics[i].hash = app_metrics[i].alloc();
  }

  return storage;
}

/* Create a new GKDB instance given a uint32_t key
 *
 * On error, -1 is returned.
 * On key found, 1 is returned.
 * On success 0 is returned */
static GKDB *new_db(khash_t(igdb) * hash, uint32_t key) {
  GKDB *db = NULL;
  khint_t k;
  int ret;

  if (!hash)
    return NULL;

  k = kh_put(igdb, hash, key, &ret);
  /* operation failed */
  if (ret == -1)
    return NULL;
  /* the key is present in the hash table */
  if (ret == 0)
    return kh_val(hash, k);

  db = new_gkdb();
  db->hdb = init_gkhashdb();
  db->cache = NULL;
  db->store = NULL;
  db->logs = NULL;
  kh_val(hash, k) = db;

  return db;
}

static void init_pre_storage() {
  ht_db = (khash_t(igdb) *)new_igdb_ht();
  new_db(ht_db, DB_INSTANCE);
}

/* Get the string value of a given string key.
 *
 * On error, NULL is returned.
 * On success the string value for the given key is returned */
static char *get_ss32(khash_t(ss32) * hash, const char *key) {
  khint_t k;
  char *value = NULL;

  if (!hash)
    return NULL;

  k = kh_get(ss32, hash, key);
  /* key found, return current value */
  if (k != kh_end(hash) && (value = kh_val(hash, k)))
    return xstrdup(value);

  return NULL;
}

/* Get the string value from ht_json_logfmt given a JSON specifier key.
 *
 * On error, NULL is returned.
 * On success the string value for the given key is returned */
static char *ht_get_json_logfmt(const char *key) {
  GKDB *db = get_db_instance(DB_INSTANCE);
  khash_t(ss32) *hash = get_hdb(db, MTRC_JSON_LOGFMT);

  if (!hash)
    return NULL;

  return get_ss32(hash, key);
}

int main(void) {
  init_pre_storage();
  init_storage();
  set_log_format_str("COMBINED");
  set_spec_date_format();
  char *line =
      "114.5.1.4 - - [11/Jun/2023:01:23:45 +0800] \"GET /example/path/file.img "
      "HTTP/1.1\" 429 568 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36\"";
  GLogItem *logitem = NULL;
  int ret = parse_line(line, &logitem);
  if (ret != 0) {
    printf("err: %s\n", logitem->errstr);
  }
  printf("URL: %s\n", logitem->req);
  printf("Size: %ld\n", logitem->resp_size);
  printf("From: %s\n", logitem->host);
  line = "{\"level\":\"info\",\"ts\":1646861401.5241024,\"logger\":\"http.log."
         "access\",\"msg\":\"handled "
         "request\",\"request\":{\"remote_ip\":\"127.0.0.1\",\"remote_port\":"
         "\"41342\",\"client_ip\":\"127.0.0.1\",\"proto\":\"HTTP/"
         "2.0\",\"method\":\"GET\",\"host\":\"localhost\",\"uri\":\"/"
         "\",\"headers\":{\"User-Agent\":[\"curl/7.82.0\"],\"Accept\":[\"*/"
         "*\"],\"Accept-Encoding\":[\"gzip, deflate, "
         "br\"]},\"tls\":{\"resumed\":false,\"version\":772,\"cipher_suite\":"
         "4865,\"proto\":\"h2\",\"server_name\":\"example.com\"}},\"bytes_"
         "read\":0,\"user_id\":\"\",\"duration\":0.000929675,\"size\":10900,"
         "\"status\":200,\"resp_headers\":{\"Server\":[\"Caddy\"],\"Content-"
         "Encoding\":[\"gzip\"],\"Content-Type\":[\"text/html; "
         "charset=utf-8\"],\"Vary\":[\"Accept-Encoding\"]}}";
  set_log_format_str("CADDY");
  set_spec_date_format();
  logitem = NULL;
  ret = parse_line(line, &logitem);
  if (!logitem) {
    printf("logitem returns as NULL\n");
  } else {
    if (ret != 0) {
      printf("err: %s\n", logitem->errstr);
    }
    printf("URL: %s\n", logitem->req);
    printf("Size: %ld\n", logitem->resp_size);
    printf("From: %s\n", logitem->host);
  }
  return 0;
}
