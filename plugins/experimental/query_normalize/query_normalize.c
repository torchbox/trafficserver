/*
 * Copyright (c) 2015 Torchbox Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");    
 * you may not use this file except in compliance with the License.    
 * You may obtain a copy of the License at        
 *
 * http://www.apache.org/licenses/LICENSE-2.0    
 *
 * Unless required by applicable law or agreed to in writing, software    
 * distributed under the License is distributed on an "AS IS" BASIS,    
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    
 * See the License for the specific language governing permissions and    
 * limitations under the License. 
 */

/* query_normalize: normalise (sort) request query parameters,
 * optionally removing undesired parameters.
 */

#include <ts/ts.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PLUGIN_NAME "query_normalize"

#define QN_MODE_PERMIT  0x1
#define QN_MODE_DENY    0x2
#define QN_MODE_MASK    0x3
#define QN_CACHEURL     0x4

typedef struct qn_config {
  int flags;
  char **params;
  int nparams;
} qn_config_t;

static qn_config_t qn_global_config;

static int parse_config(qn_config_t *, char const *);
static int handle_hook(TSCont *, TSEvent, void *);
static void normalise_request(TSHttpTxn, qn_config_t *config);
static int sort_cmp(const void *, const void *);
static int search_cmp(const void *, const void *);
static int find_param(qn_config_t *config, char const *param);

static int
parse_config(qn_config_t *conf, char const *optstr)
{
  const char *p, *q, *r;
  int n;
  
  memset(conf, 0, sizeof(*conf));

  /* Parse flags */
  for (; strchr("+-%", *optstr); optstr++) {
    switch (*optstr) {
      case '+':
        conf->flags = (conf->flags & ~QN_MODE_MASK) | QN_MODE_PERMIT;
        break;

      case '-':
        conf->flags = (conf->flags & ~QN_MODE_MASK) | QN_MODE_DENY;
        break;

      case '%':
        conf->flags |= QN_CACHEURL;
        break;
    }
  }

  /* Count the number of params passed */
  for (conf->nparams = 1, p = optstr, q = optstr + strlen(optstr); p < q; p++) {
    if (*p == '&')
      conf->nparams++;
  }

  /* Split the params into an array */
  conf->params = calloc(sizeof(char *), conf->nparams);

  for (n = 0, p = optstr, q = optstr + strlen(optstr), r = NULL; p <= q;) {
    const char *end;

    if ((end = memchr(p, '&', (q - p) + 1)) == NULL)
      end = q;
    
    conf->params[n] = calloc(1, (end - p) + 1);
    memcpy(conf->params[n], p, (end - p));
    n++;
    p = end + 1;
  }

  /* Sort the params for fast lookup */
  qsort(&conf->params[0], conf->nparams, sizeof(char *), sort_cmp);
  return 0;
}

static int
find_param(qn_config_t *config, char const *param)
{
  return bsearch(param, &config->params[0], config->nparams, sizeof(char *), search_cmp) != NULL;
}

/* handle_hook
 * Called by TS on an incoming request; call normalise_request() to do
 * the actual work.  Always return success.
 */
static int
handle_hook(TSCont *contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn) edata;
  normalise_request(txnp, &qn_global_config);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 1;
}

static int
sort_cmp(const void *a, const void *b)
{
  return strcmp(*(char const **)a, *(char const **)b);
}

static int
search_cmp(const void *a, const void *b)
{
  return strcmp(a, *(char const **)b);
}

static void
normalise_request(TSHttpTxn txnp, qn_config_t *config)
{
  TSMBuffer bufp;
  TSMLoc offset, url_mloc;
  const char *query, *p, *q, *r;
  char **params;
  char *new_query;
  int query_length, nparams = 0;
  int n;

  /* Fetch client request */
  if (TSHttpTxnClientReqGet(txnp, &bufp, &offset) != TS_SUCCESS) {
    TSDebug(PLUGIN_NAME, "normalize_request: TSHttpTxnClientReqGet failed");
    return;
  }
  
  /* Fetch the URL from the request */
  if (TSHttpHdrUrlGet(bufp, offset, &url_mloc) != TS_SUCCESS) {
    TSDebug(PLUGIN_NAME, "normalize_request: TSHttpHdrUrlGet failed");
    return;
  }

  /* Fetch the query string from the URL */
  if ((query = TSUrlHttpQueryGet(bufp, url_mloc, &query_length)) == NULL) {
    TSDebug(PLUGIN_NAME, "normalise_request: TSUrlHttpQueryGet failed");
    return;
  }

  /* If there's no query, just return */
  if (query_length == 0)
    return;

  TSDebug(PLUGIN_NAME, "query params=[%.*s]", query_length, query);

  /* Count the number of query parameters and create an array to split
   * them into.
   */
  for (nparams = 1, p = query, q = query + query_length; p < q; p++) {
    if (*p == '&')
      nparams++;
  }

  /* Split the query string into individual components.  */
  params = calloc(nparams, sizeof(char *));
  for (n = 0, p = query, q = query + query_length, r = NULL; p <= q;) {
    const char *end;
    char *parm, *tparm;

    if ((end = memchr(p, '&', (q - p) + 1)) == NULL)
      end = q;
    
    /* Skip empty parameters */
    if ((end - p) == 0) {
      p = end + 1;
      continue;
    }

    parm = calloc(1, (end - p) + 1);
    memcpy(parm, p, (end - p));
    p = end + 1;

    if ((tparm = strchr(parm, '=')) != NULL)
      *tparm = 0;

    if ((config->flags & QN_MODE_DENY) && find_param(config, parm)) {
      /* Skip this parameter if it's on the blacklist */
      TSDebug(PLUGIN_NAME, "param [%s] is blacklisted", parm);
      free(parm);
      continue;
    } else if ((config->flags & QN_MODE_PERMIT) && !find_param(config, parm)) {
      /* ... or if it's not on the whitelist */
      TSDebug(PLUGIN_NAME, "param [%s] is not whitelisted", parm);
      free(parm);
      continue;
    }
    
    if (tparm)
      *tparm = '=';

    params[n] = parm;
    n++;
    p = end + 1;
    TSDebug(PLUGIN_NAME, "got query param [%s], n=%d, nparams=%d", params[n - 1], n, nparams);
  }

  nparams = n;

  qsort(&params[0], nparams, sizeof(char *), sort_cmp);
  new_query = calloc(1, query_length + 1);
  for (n = 0; n < nparams; n++) {
    if (n)
      TSstrlcat(new_query, "&", query_length + 1);
    TSstrlcat(new_query, params[n], query_length + 1);
  }

  TSDebug(PLUGIN_NAME, "reordered query [%s]", new_query);

  if (TSUrlHttpQuerySet(bufp, url_mloc, new_query, -1) != TS_SUCCESS)
    TSDebug(PLUGIN_NAME, "TSUrlHttpQuerySet failed");

  for (n = 0; n < nparams; n++)
    free(params[n]);
  free(params);
  free(new_query);
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = (char *)PLUGIN_NAME;
  info.vendor_name = (char *)"Apache Software Foundation";
  info.support_email = (char *)"dev@trafficserver.apache.org";

  if (argc > 1) {
    parse_config(&qn_global_config, argv[1]);
  } else {
    memset(&qn_global_config, 0, sizeof(qn_global_config));
  }

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] plugin registration failed.  check version.", PLUGIN_NAME);
    return;
  }

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate((TSEventFunc)handle_hook, NULL));
}
