/**
 * collectd - src/docker.c
 * Copyright 2019 Splunk, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 **/

#include "collectd.h"

#include "utils/common/common.h"
#include "plugin.h"

#include <curl/curl.h>
#include <yajl/yajl_parse.h>
#include "yajl/yajl_tree.h"

#define DOCKER_API_VERSION_DEFAULT "v1.30"
#define DOCKER_STATS_BUFFER_SIZE_DEFAULT 16 * 1024
#define DOCKER_CONTAINERS_BUFFER_SIZE_DEFAULT 8192

typedef struct docker_config {
  char *docker_sock;
  char *api_version;

  unsigned char *buffer;
  size_t buffersize;

  char *containers_list;
  size_t containers_bufferfilled;
  size_t containers_buffersize;

  CURL *curl;
  yajl_handle handle;
  yajl_val node;

  char container_id[16];
  _Bool is_container_id;
} docker_config_t;

static void pl_config_free(void *data) {
  // free all the allocated memory here
  docker_config_t *pl_config = data;

  sfree(pl_config->docker_sock);
  sfree(pl_config->api_version);
  sfree(pl_config->buffer);
  sfree(pl_config->containers_list);

  if (pl_config->curl != NULL) {
    curl_easy_cleanup(pl_config->curl);
    pl_config->curl = NULL;
  }

  sfree(pl_config);

} /* }}} void pl_config_free */

static void submit_value(const char *type_instance, const char *type,
                         const char *plugin_instance, value_t value) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = &value;
  vl.values_len = 1;

  sstrncpy(vl.plugin, "docker", sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));

  plugin_dispatch_values(&vl);
} /* }}} void submit_value */

static void submit_network_values(const char *type_instance, const char *type,
                                  const char *plugin_instance,
                                  value_t values[]) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = values;
  vl.values_len = 2;

  sstrncpy(vl.plugin, "docker", sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));

  plugin_dispatch_values(&vl);
} /* }}} void submit_network_values */

static int get_network_stats(docker_config_t *pl_config) {

  char type_instance[DATA_MAX_NAME_LEN];
  const char *path[] = {"networks", (const char *)0};
  const char *rx_metrics[4] = {"rx_bytes", "rx_dropped", "rx_errors",
                               "rx_packets"};
  const char *tx_metrics[4] = {"tx_bytes", "tx_dropped", "tx_errors",
                               "tx_packets"};
  const char *types[4] = {"if_octets", "if_dropped", "if_errors", "if_packets"};
  value_t values[2];

  yajl_val network_node = yajl_tree_get(pl_config->node, path, yajl_t_object);

  if (network_node) {
    size_t len = YAJL_GET_OBJECT(network_node)->len;
    const char **keys = YAJL_GET_OBJECT(network_node)->keys;

    for (int i = 0; i < len; ++i) {
      const char *path2[3];
      path2[0] = keys[i];
      path2[2] = (const char *)0;

      for (int j = 0; j < 4; ++j) {
        path2[1] = rx_metrics[j];

        yajl_val if_rx =
            yajl_tree_get(network_node, (const char **)path2, yajl_t_any);
        if (if_rx && YAJL_IS_INTEGER(if_rx))
          values[0].derive = YAJL_GET_INTEGER(if_rx);
        else
          continue;

        path2[1] = tx_metrics[j];
        yajl_val if_tx =
            yajl_tree_get(network_node, (const char **)path2, yajl_t_any);
        if (if_tx && YAJL_IS_INTEGER(if_tx))
          values[1].derive = YAJL_GET_INTEGER(if_tx);
        else
          continue;

        /* type instance example: network.bytes.eth0, network.dropped.eth0 */
        snprintf(type_instance, DATA_MAX_NAME_LEN, "network.%s.%s",
                 &rx_metrics[j][3], keys[i]);
        submit_network_values(type_instance, types[j], pl_config->container_id,
                              values);
      }
    }
  }

  return 0;
} /* }}} int get_network_stats */

static int get_memory_stats(docker_config_t *pl_config) {

  yajl_val yajl_node;
  char *path[4];
  path[0] = "memory_stats";
  path[1] = "stats";
  path[3] = (char *)0;

  char type_instance[40];

  char *memory_metrics[] = {
      "total_cache",       "active_file",         "total_active_file",
      "inactive_file",     "total_inactive_file", "unevictable",
      "writeback",         "total_writeback",     "active_anon",
      "total_active_anon", "mapped_file",         "rss"};

  size_t arr_len = sizeof(memory_metrics) / sizeof(const char *);

  for (int i = 0; i < arr_len; ++i) {
    path[2] = memory_metrics[i];

    yajl_node =
        yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);

    if (!YAJL_IS_INTEGER(yajl_node))
      continue;

    snprintf(type_instance, 40, "memory.%s", memory_metrics[i]);

    submit_value(type_instance, "memory", pl_config->container_id,
                 (value_t){.gauge = YAJL_GET_INTEGER(yajl_node)});
  }

  path[2] = "cache";
  gauge_t cache = 0;
  yajl_node =
      yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  if (YAJL_IS_INTEGER(yajl_node)) {
    cache = YAJL_GET_INTEGER(yajl_node);
    submit_value("memory.cache", "memory", pl_config->container_id,
                 (value_t){.gauge = cache});
  }

  path[2] = (char *)0;
  path[1] = "usage";
  yajl_node =
      yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  gauge_t usage = 0;
  if (YAJL_IS_INTEGER(yajl_node)) {
    usage = YAJL_GET_INTEGER(yajl_node);
    submit_value("memory.usage", "memory", pl_config->container_id,
                 (value_t){.gauge = usage});
  }

  path[1] = "limit";
  yajl_node =
      yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  gauge_t limit = 0;
  if (YAJL_IS_INTEGER(yajl_node))
    limit = YAJL_GET_INTEGER(yajl_node);

  // Caluculate and submit memory percent
  if (limit > 0 && usage > 0) {
    submit_value("memory.percent", "percent", pl_config->container_id,
                 (value_t){.gauge = ((usage - cache) / limit) * 100});
  }

  return 0;

} /* }}} int get_memory_stats */

static int get_blkio_stats(docker_config_t *pl_config) {

  char *path[3];
  path[0] = "blkio_stats";
  path[2] = (char *)0;
  char type_instance[DATA_MAX_NAME_LEN];

  // Extract blkio_stats.io_service_bytes_recursive &
  // blkio_stats.io_serviced_recursive
  char *metric_types[2] = {"io_service_bytes_recursive",
                           "io_serviced_recursive"};

  for (int types = 0; types < 2; ++types) {
    path[1] = metric_types[types];
    yajl_val obj_arr =
        yajl_tree_get(pl_config->node, (const char **)path, yajl_t_array);
    if (obj_arr) {
      size_t len = obj_arr->u.array.len;
      int i;
      for (i = 0; i < len; ++i) {
        yajl_val obj = obj_arr->u.array.values[i];
        size_t obj_len = obj->u.object.len;
        if (obj_len == 4 && YAJL_IS_NUMBER(obj->u.object.values[0]) &&
            YAJL_IS_NUMBER(obj->u.object.values[1]) &&
            YAJL_IS_STRING(obj->u.object.values[2]) &&
            YAJL_IS_INTEGER(obj->u.object.values[3])) {

          snprintf(type_instance, DATA_MAX_NAME_LEN, "%s.%s.%s.%s-%s", "blkio",
                   path[1], YAJL_GET_STRING(obj->u.object.values[2]),
                   YAJL_GET_NUMBER(obj->u.object.values[0]),
                   YAJL_GET_NUMBER(obj->u.object.values[1]));

          // submit value now
          submit_value(
              type_instance, "total_bytes", pl_config->container_id,
              (value_t){.derive = YAJL_GET_INTEGER(obj->u.object.values[3])});
        }
      }
    }
  }

  return 0;
} /* }}} int get_blkio_stats */

static int get_cpu_stats(docker_config_t *pl_config) {

  char *path[4];

  // Extract percpu_stats.system_cpu_usage
  path[0] = "precpu_stats";
  path[1] = "system_cpu_usage";
  path[2] = (char *)0;
  yajl_val value =
      yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  derive_t precpu_system_cpu_usage = 0;
  if (YAJL_IS_INTEGER(value))
    precpu_system_cpu_usage = YAJL_GET_INTEGER(value);

  // Extract cpu_stats.system_cpu_usage
  path[0] = "cpu_stats";
  path[1] = "system_cpu_usage";
  path[2] = (char *)0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  derive_t system_cpu_usage = 0;
  if (YAJL_IS_INTEGER(value)) {
    system_cpu_usage = YAJL_GET_INTEGER(value);
    submit_value("cpu.system", "cpu", pl_config->container_id,
                 (value_t){.derive = system_cpu_usage});
  }

  // Extract cpu_stats.cpu_usage.*
  path[0] = "cpu_stats";
  path[1] = "cpu_usage";
  path[3] = (char *)0;

  path[2] = "percpu_usage";
  size_t len = 0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_array);
  if (value)
    len = YAJL_GET_ARRAY(value)->len;

  path[2] = "total_usage";
  derive_t total_usage = 0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  if (YAJL_IS_INTEGER(value)) {
    total_usage = YAJL_GET_INTEGER(value);
    submit_value("cpu.total", "cpu", pl_config->container_id,
                 (value_t){.derive = total_usage});
  }

  path[2] = "usage_in_usermode";
  derive_t cpu_user = 0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  if (YAJL_IS_INTEGER(value)) {
    cpu_user = YAJL_GET_INTEGER(value);
    submit_value("cpu.user", "cpu", pl_config->container_id,
                 (value_t){.derive = cpu_user});
  }

  path[2] = "usage_in_kernelmode";
  derive_t cpu_kernel = 0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  if (YAJL_IS_INTEGER(value)) {
    cpu_kernel = YAJL_GET_INTEGER(value);
    submit_value("cpu.kernel", "cpu", pl_config->container_id,
                 (value_t){.derive = cpu_kernel});
  }

  // Extract percpu_stats.cpu_usage.total_usage
  path[0] = "precpu_stats";
  path[1] = "cpu_usage";
  path[2] = "total_usage";
  path[3] = (char *)0;
  derive_t precpu_total_usage = 0;
  value = yajl_tree_get(pl_config->node, (const char **)path, yajl_t_number);
  if (YAJL_IS_INTEGER(value))
    precpu_total_usage = YAJL_GET_INTEGER(value);

  // Calculate cpu.percent value
  derive_t system_delta = system_cpu_usage - precpu_system_cpu_usage;
  derive_t cpu_delta = total_usage - precpu_total_usage;

  if (system_delta > 0 && cpu_delta > 0 && len > 0) {
    gauge_t percent = 100 * ((double)(cpu_delta) / system_delta) * len;
    submit_value("cpu.percent", "percent", pl_config->container_id,
                 (value_t){.gauge = percent});
  }

  return 0;
} /* }}} int get_cpu_stats */

static size_t write_function_stats(void *data, size_t size, size_t nmemb,
                                   void *config) {
  docker_config_t *pl_config = (docker_config_t *)config;

  size_t current_size = strlen((char *)pl_config->buffer);
  size_t total = nmemb + current_size;

  // check buffer overflow
  if (total >= pl_config->buffersize) {
    ERROR("docker plugin: Buffer size is %zu, Data received so far=%zu. "
          "Increase ReadBufferSize.\n",
          pl_config->buffersize, total);
    return 0; // returns amount to data taken care of
  }

  memcpy(&pl_config->buffer[current_size], data, nmemb);
  pl_config->buffer[total] = '\0';

  return nmemb;
} /* }}} size_t write_function_stats */

static int docker_get_container_stats(docker_config_t *pl_config, char url[]) {
  char errstr[1024];

  // Get stats for this container
  curl_easy_setopt(pl_config->curl, CURLOPT_WRITEFUNCTION,
                   write_function_stats);
  curl_easy_setopt(pl_config->curl, CURLOPT_URL, url);

  // reset container stats buffer
  pl_config->buffer[0] = '\0';

  int response = curl_easy_perform(pl_config->curl);

  if (response != CURLE_OK) {
    ERROR("docker plugin: curl_easy_perform failed "
          "with status %i: %s",
          response, curl_easy_strerror(response));
    return response;
  }

  // ALL the stats data is memory now. Parse it into tree using yajl
  pl_config->node =
      yajl_tree_parse((const char *)pl_config->buffer, errstr, sizeof(errstr));

  /* parse error handling */
  if (pl_config->node == NULL) {
    ERROR("docker plugin: Container stats yajl parse error.");
    if (strlen(errstr))
      ERROR(" %s\n", errstr);
    return -1;
  }

  // Call all the stats functions here: cpu, network, memory etc...
  get_network_stats(pl_config);
  get_memory_stats(pl_config);
  get_cpu_stats(pl_config);
  get_blkio_stats(pl_config);

  // free the yajl library tree
  yajl_tree_free(pl_config->node);

  return 0;
} /* }}} int docker_get_container_stats */

static int cb_list_map_key(void *ctx, const unsigned char *stringVal,
                           size_t stringLen) {
  docker_config_t *pl_config = (docker_config_t *)ctx;

  if (stringLen == 2 && stringVal[0] == 'I' && stringVal[1] == 'd')
    pl_config->is_container_id = 1;
  else
    pl_config->is_container_id = 0;
  return 1;
} /* }}} int cb_list_map_key */

static int cb_list_string(void *ctx, const unsigned char *stringVal,
                          size_t stringLen) {
  docker_config_t *pl_config = (docker_config_t *)ctx;

  if (!pl_config->is_container_id)
    return 1;

  size_t curr_len = pl_config->containers_bufferfilled;

  while (curr_len + stringLen + 1 > pl_config->containers_buffersize) {
    char *new_containers_buffer =
        (char *)malloc(2 * pl_config->containers_buffersize);
    if (new_containers_buffer == NULL) {
      ERROR("docker plugin : malloc failed for containers");
      return 0;
    }
    strncpy(new_containers_buffer, pl_config->containers_list,
            pl_config->containers_bufferfilled + 1);
    sfree(pl_config->containers_list);
    pl_config->containers_list = new_containers_buffer;
    pl_config->containers_buffersize = 2 * pl_config->containers_buffersize;
  }

  memcpy(&(pl_config->containers_list[curr_len]), stringVal, stringLen);

  curr_len += stringLen;

  pl_config->containers_list[curr_len++] = ',';
  pl_config->containers_list[curr_len] = '\0';

  pl_config->containers_bufferfilled = curr_len;

  return 1;
} /* }}} int cb_list_string */

// This callback list is used to get list of running containers
static yajl_callbacks callbacks_list = {
    NULL, NULL, NULL, NULL, NULL, cb_list_string, NULL, cb_list_map_key,
    NULL, NULL, NULL};

static size_t write_function(void *data, size_t size, size_t nmemb,
                             void *config) {
  docker_config_t *pl_config = (docker_config_t *)config;

  // check buffer overflow
  if (nmemb >= pl_config->buffersize) {
    ERROR("docker plugin: Buffer size is %zu, Data received=%zu. Increase "
          "ReadBufferSize.\n",
          pl_config->buffersize, nmemb);
    return 0; // returns amount to data taken care of
  }

  memcpy(pl_config->buffer, data, nmemb);
  pl_config->buffer[nmemb] = '\0';

  yajl_parse(pl_config->handle, pl_config->buffer, nmemb);

  return nmemb;
} /* }}} size_t write_function */

// Get list of running containers to monitor
static int create_containers_list(docker_config_t *pl_config) {

  char url[256];
  snprintf(url, 256, "http://%s/containers/json",
           (pl_config->api_version == NULL) ? DOCKER_API_VERSION_DEFAULT
                                            : pl_config->api_version);

  curl_easy_setopt(pl_config->curl, CURLOPT_WRITEFUNCTION, write_function);
  curl_easy_setopt(pl_config->curl, CURLOPT_URL, url);

  // reset buffer that contains list of running containers
  pl_config->containers_list[0] = '\0';
  pl_config->containers_bufferfilled = 0;

  pl_config->handle = yajl_alloc(&callbacks_list, NULL, (void *)pl_config);

  int response = curl_easy_perform(pl_config->curl);

  if (response != CURLE_OK) {
    ERROR("docker plugin: curl_easy_perform failed "
          "with status %i: %s",
          response, curl_easy_strerror(response));
    return response;
  }

  yajl_status stat = yajl_complete_parse(pl_config->handle);

  if (stat != yajl_status_ok) {
    unsigned char *str = yajl_get_error(pl_config->handle, 1, pl_config->buffer,
                                        strlen((char *)pl_config->buffer));
    ERROR("docker plugin json parsing error: %s \n", str);
    yajl_free_error(pl_config->handle, str);
    yajl_free(pl_config->handle);
    return -1;
  }

  yajl_free(pl_config->handle);

  return 0;
} /* }}} int create_containers_list */

static int docker_read(user_data_t *ud) {
  docker_config_t *pl_config = (docker_config_t *)ud->data;

  char url[256];

  if (create_containers_list(pl_config) != 0) {
    ERROR("docker plugin: Failed to get list of running containers\n");
    return -1;
  }

  char *token, *saveptr;

  char *str = pl_config->containers_list;
  int count = 0;

  // Go through list of containers to collect stats
  while ((token = strtok_r(str, ",", &saveptr)) != NULL) {
    strncpy(pl_config->container_id, token, 16);
    pl_config->container_id[15] = '\0';
    snprintf(url, 256, "http://%s/containers/%s/stats?stream=false",
             (pl_config->api_version == NULL) ? DOCKER_API_VERSION_DEFAULT
                                              : pl_config->api_version,
             token);
    docker_get_container_stats(pl_config, url);

    str = NULL;
    ++count;
  }

  // submit running containers metrics
  submit_value("containers.running", "count", "all_running",
               (value_t){.gauge = count});

  return 0;
} /* }}} int docker_read */

static int docker_config_curl(docker_config_t *pl_config) {

  if (pl_config->docker_sock == NULL) {
    ERROR("docker plugin: dockersock conf required.");
    return -1;
  }

  pl_config->curl = curl_easy_init();

  if (pl_config->curl == NULL) {
    ERROR("docker plugin: curl_easy_init failed.");
    return -1;
  }

  curl_easy_setopt(pl_config->curl, CURLOPT_UNIX_SOCKET_PATH,
                   pl_config->docker_sock);
  curl_easy_setopt(pl_config->curl, CURLOPT_WRITEDATA, pl_config);
  curl_easy_setopt(pl_config->curl, CURLOPT_TIMEOUT,
                   5L); // timeout set to 5 seconds

  return 0;
} /* }}} int docker_config_curl */

static int docker_config(oconfig_item_t *ci) {

  docker_config_t *pl_config = NULL;

  pl_config = (docker_config_t *)calloc(1, sizeof(docker_config_t));
  if (pl_config == NULL) {
    ERROR("docker plugin: calloc failed.");
    pl_config_free(pl_config);
    return -1;
  }
  pl_config->buffersize = DOCKER_STATS_BUFFER_SIZE_DEFAULT;
  pl_config->containers_buffersize = DOCKER_CONTAINERS_BUFFER_SIZE_DEFAULT;
  pl_config->docker_sock = NULL;
  pl_config->api_version = NULL;

  int status = 0;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("dockersock", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->docker_sock);
    else if (strcasecmp("apiversion", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->api_version);
    else if (strcasecmp("readbuffersize", child->key) == 0) {
      int read_buffer_size = 0;
      status = cf_util_get_int(child, &read_buffer_size);
      if (read_buffer_size > 0)
        pl_config->buffersize = (size_t)read_buffer_size;
      else
        WARNING("docker plugin: Ignoring invalid config for ReadBufferSize=%d",
                read_buffer_size);
    } else
      WARNING("docker plugin: Ignored config `%s'.", child->key);

    if (status != 0)
      break;
  }

  if (status != 0) {
    pl_config_free(pl_config);
    return status;
  }

  // Check api_version is valid like v1.37
  if (pl_config->api_version &&
      (strlen(pl_config->api_version) != 5 ||
       strncmp("v1.", pl_config->api_version, 3) != 0 ||
       !isdigit(pl_config->api_version[3]) ||
       !isdigit(pl_config->api_version[4]))) {
    ERROR("docker plugin: invalid api version. It should look like v1.xx");
    return -1;
  }

  pl_config->buffer = (unsigned char *)malloc(pl_config->buffersize);
  if (pl_config->buffer == NULL) {
    ERROR("docker plugin: malloc failed for container stats buffer.");
    pl_config_free(pl_config);
    return -1;
  }

  pl_config->containers_list = (char *)malloc(pl_config->containers_buffersize);
  if (pl_config->containers_list == NULL) {
    ERROR("docker plugin: malloc failed for containers list buffer.");
    pl_config_free(pl_config);
    return -1;
  }

  // Config Curl options
  if (docker_config_curl(pl_config) != 0)
    return -1;

  // register read callback
  user_data_t user_data = {.data = pl_config, .free_func = pl_config_free};
  plugin_register_complex_read(NULL, "docker", docker_read, 0, &user_data);

  return 0;
} /* }}} int docker_config */

void module_register(void) {
  plugin_register_complex_config("docker", docker_config);
} /* void module_register */
