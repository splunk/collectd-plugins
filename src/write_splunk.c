/**
 * collectd - src/write_splunk.c
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

#include "utils/common/common.h"
#include "plugin.h"
#include "utils_cache.h"
#include "collectd.h"

#include <curl/curl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#if !defined(KERNEL_SOLARIS)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

/* splunk_event --> {"time": <epoch>, "host":<host info>, "event": "metric",
 * "fields": {<key: value pairs>}} */

#define WS_FORMAT_FIELDS_JSON_DIMS                                             \
  "{\"time\": %.2f, \"host\": \"%s\", \"event\": \"metric\", \"fields\": "     \
  "{\"metric_name\": \"%s\", \"metric_type\": \"%s\", "                        \
  "\"_value\": %s, %s, %s}}"

/* splunk event without metric specific dimensions like "cpu"=0 */
#define WS_FORMAT_FIELDS_JSON                                                  \
  "{\"time\": %.2f, \"host\": \"%s\", \"event\": \"metric\", \"fields\": "     \
  "{\"metric_name\": \"%s\", \"metric_type\": \"%s\", "                        \
  "\"_value\": %s, %s}}"

#define SEND_BUFFER_SIZE_DEFAULT 1048576
#define WS_POST_TIMEOUT_DEFAULT 30
#define WS_METRIC_MAX_NAME_LEN DATA_MAX_NAME_LEN * 5
#define WS_METRIC_MAX_VALUE_LEN 100
#define WS_HEADER_SIZE_MAX 256

struct plugin_config_s {
  char *server;
  char *token;
  char *port;
  char *curl_cainfo;
  char *curl_capath;
  char *location;
  _Bool ssl;
  _Bool verify_ssl;
  int batch_size;
  _Bool splunk_metric_transform;
  _Bool disk_as_dimensions;
  _Bool interface_as_dimensions;
  _Bool cpu_as_dimensions;
  _Bool df_as_dimensions;
  _Bool store_rates;
  _Bool use_udp;
  double last_sent;
  char *dims_json;
  size_t dims_json_l;
  char *buffer;
  size_t buffer_filled;
  int buffer_size;
  int ws_post_timeout;
  int udp_port;
  int sock;
  struct sockaddr_in serv_addr;
  size_t ws_count;
  pthread_mutex_t send_lock;
  CURL *curl;
  struct curl_slist *headers_l;
};

typedef struct plugin_config_s plugin_config_t;

void transform_cpu(char *dims_json, char *metric_name, const value_list_t *vl) {

  /* metric_name = "cpu.<type_instance>"
     dims_json = ""cpu": <plugin_instance>"  like ""cpu": 0" */
  if (strlen(vl->plugin_instance)) {
    snprintf(dims_json, WS_METRIC_MAX_NAME_LEN, "\"cpu\": %s",
             vl->plugin_instance);
  }

  snprintf(metric_name, 2 * DATA_MAX_NAME_LEN + 1, "%s.%s", vl->plugin,
           vl->type_instance);
} /* }}} int transform_cpu */

void transform_df(char *dims_json, char *metric_name, const value_list_t *vl) {

  /* metric_name = "df.<type_instance>" e.g. df.free
     dims_json = ""device": "<plugin_instance>"" */

  /* We are using "device" here because it is assumed that in the df plugin,
     ReportByDevice = true; if it were false, we would want to use "mount"
     instead. Ideally, we'd check the value of ReportByDevice, but since it's in
     a separate
     plugin, it's probably not available from within the write_splunk plugin. */

  if (strlen(vl->plugin_instance)) {
    snprintf(dims_json, WS_METRIC_MAX_NAME_LEN, "\"device\": \"%s\"",
             vl->plugin_instance);
  }

  snprintf(metric_name, 2 * DATA_MAX_NAME_LEN + 1, "%s.%s", vl->plugin,
           vl->type_instance);
} /* }}} int transform_df */

void transform_memory(char *dims_json, char *metric_name,
                      const value_list_t *vl) {

  /* metric_name = "memory.<type_instance>"
     dims_json = "" */
  snprintf(metric_name, 2 * DATA_MAX_NAME_LEN + 1, "%s.%s", vl->plugin,
           vl->type_instance);
} /* }}} int transform_memory */

void transform_load(char *dims_json, char *metric_name,
                    const value_list_t *vl) {
  /* metric_name = "load"
     dims_json = "" */
  strncpy(metric_name, "load", 5);

} /* }}} int transform_load */

void transform_disk(char *dims_json, char *metric_name,
                    const value_list_t *vl) {

  /* metric_name = "disk.<type>.<type_instance>"
     dims_json = ""disk": "<plugin_instance>"" */
  if (strlen(vl->plugin_instance)) {
    snprintf(dims_json, WS_METRIC_MAX_NAME_LEN, "\"disk\": \"%s\"",
             vl->plugin_instance);
  }

  strncpy(metric_name, vl->type, DATA_MAX_NAME_LEN);
  if (strncmp("disk_", metric_name, 5) == 0)
    metric_name[4] = '.';
  else
    snprintf(metric_name, 2 * DATA_MAX_NAME_LEN, "%s.%s", "disk", vl->type);

  if (strlen(vl->type_instance))
    snprintf(metric_name + strlen(metric_name), DATA_MAX_NAME_LEN + 1, ".%s",
             vl->type_instance);
} /* }}} int transform_disk */

void transform_docker(char *dims_json, char *metric_name,
                      const value_list_t *vl) {

  if (strlen(vl->plugin_instance)) {
    snprintf(dims_json, WS_METRIC_MAX_NAME_LEN, "\"container_id\": \"%s\"",
             vl->plugin_instance);
  }

  snprintf(metric_name, DATA_MAX_NAME_LEN, "docker.");

  if (strncmp("network", vl->type_instance, 7) == 0) {

    /* type_instance example: network.bytes.eth0*/
    /* metric_name = docker.network.bytes */
    /* dims_josn = "container_id": "xyzz", "interface" : "eth0" */
    char *interface = strrchr(vl->type_instance, '.');

    if (interface)
      snprintf(dims_json + strlen(dims_json), WS_METRIC_MAX_NAME_LEN,
               ", \"interface\": \"%s\"", interface + 1);

    size_t len = interface - vl->type_instance;
    snprintf(metric_name + strlen(metric_name), len + 1, "%s",
             vl->type_instance);

    return;
  } else if (strncmp("blkio", vl->type_instance, 5) == 0) {

    /* type_instance example: blkio.io_service_bytes_recursive.Read.11-2 */
    /* metric_name = docker.blkio.io_service_bytes_recursive.Read */
    /* dims_josn = "container_id": "xyzz", major-minor" : "11-2" */
    char *major = strrchr(vl->type_instance, '.');

    if (major)
      snprintf(dims_json + strlen(dims_json), WS_METRIC_MAX_NAME_LEN,
               ", \"major-minor\": \"%s\"", major + 1);

    size_t len = major - vl->type_instance;
    snprintf(metric_name + strlen(metric_name), len + 1, "%s",
             vl->type_instance);

    return;
  }

  /* type_instance example: cpu.system */
  /* metric_name = docker.cpu.system */
  /* dims_josn = "container_id": "xyzz" */
  if (strlen(vl->type_instance))
    snprintf(metric_name + strlen(metric_name), DATA_MAX_NAME_LEN, "%s",
             vl->type_instance);
} /* }}} int transform_docker */

void transform_interface(char *dims_json, char *metric_name,
                         const value_list_t *vl) {

  /* metric_name = "interface.<type>" (e.g. "interface.octets" if
     vl->type=="if_octets") dims_json = ""interface": "<plugin_instance>""
     Note: the interface plugin doesn't use type_instance. */
  if (strlen(vl->plugin_instance)) {
    snprintf(dims_json, WS_METRIC_MAX_NAME_LEN, "\"interface\": \"%s\"",
             vl->plugin_instance);
  }

  // skip 'if_' prefix if present
  const char *type = vl->type + (strncmp(vl->type, "if_", 3) ? 0 : 3);

  snprintf(metric_name, 2 * DATA_MAX_NAME_LEN, "%s.%s", "interface", type);
} /* }}} int transform_interface */

void transform_processmon(char *dims_json, char *metric_name,
                          const value_list_t *vl) {
  /* metric_name = "processmon.<type>" (e.g. processmon.cpu.percent)
     dims_json = ""pid": "123", "user": "root", "process_name": "collectd""
     plugin_instance looks like "<pid> <user> <pname>" */
  snprintf(metric_name, 2 * DATA_MAX_NAME_LEN, "%s.%s", vl->plugin,
           vl->type_instance);

  int i = 0;
  int j = 0;
  char pid[DATA_MAX_NAME_LEN];
  char uname[DATA_MAX_NAME_LEN];
  size_t len = strlen(vl->plugin_instance);

  if (!len)
    return;

  while (i < len && vl->plugin_instance[i] != ' ')
    pid[j++] = vl->plugin_instance[i++];

  pid[j] = '\0';

  ++i;
  j = 0;

  while (i < len && vl->plugin_instance[i] != ' ') {
    uname[j++] = vl->plugin_instance[i++];
  }
  uname[j] = '\0';

  ++i;
  if (i >= len)
    return;

  const char *pname = &vl->plugin_instance[i];

  snprintf(dims_json, WS_METRIC_MAX_NAME_LEN,
           "\"pid\": \"%s\", \"user\": \"%s\", \"process_name\": \"%s\"", pid,
           uname, pname);
} /* }}} int transform_processmon */

void transform_default(char *dims_json, char *metric_name,
                       const value_list_t *vl) {

  /* metric_name = "<plugin>.<plugin_instance>.<type>.<type_instance>"
     dims_json = "" */
  strncpy(metric_name, vl->plugin, DATA_MAX_NAME_LEN);

  if (strlen(vl->plugin_instance))
    snprintf(metric_name + strlen(metric_name), DATA_MAX_NAME_LEN + 1, ".%s",
             vl->plugin_instance);

  snprintf(metric_name + strlen(metric_name), DATA_MAX_NAME_LEN + 1, ".%s",
           vl->type);

  if (strlen(vl->type_instance))
    snprintf(metric_name + strlen(metric_name), DATA_MAX_NAME_LEN + 1, ".%s",
             vl->type_instance);
} /* }}} int transform_default */

void ws_transform(char *dims_json, char *metric_name, const value_list_t *vl,
                  plugin_config_t *pl_config) {

  if (!pl_config->splunk_metric_transform) {
    transform_default(dims_json, metric_name, vl);
    return;
  }

  if (strcmp(vl->plugin, "cpu") == 0 && pl_config->cpu_as_dimensions)
    transform_cpu(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "disk") == 0 && pl_config->disk_as_dimensions)
    transform_disk(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "df") == 0 && pl_config->df_as_dimensions)
    transform_df(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "interface") == 0 &&
           pl_config->interface_as_dimensions)
    transform_interface(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "memory") == 0)
    transform_memory(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "load") == 0)
    transform_load(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "docker") == 0)
    transform_docker(dims_json, metric_name, vl);
  else if (strcmp(vl->plugin, "processmon") == 0)
    transform_processmon(dims_json, metric_name, vl);
  else
    transform_default(dims_json, metric_name, vl);

} /* }}} int ws_write_json */

static int ws_add_dimension(plugin_config_t *pl_config, const char *key,
                            const char *value) {
  int dims_json_len = strlen(pl_config->dims_json);

  /* <key=value> */
  int reqd_dims = strlen(key) + strlen(value) + 2;
  /* <"key": "value"> */
  int reqd_dims_json = reqd_dims + 5;

  int free_dims_json = pl_config->dims_json_l - dims_json_len;

  if (dims_json_len != 0) {
    reqd_dims_json += 2;
  }

  while (reqd_dims_json > free_dims_json) {
    char *new_dims_json = malloc(2 * pl_config->dims_json_l);
    if (new_dims_json == NULL) {
      ERROR("write_splunk plugin : malloc failed");
      return -1;
    }
    strncpy(new_dims_json, pl_config->dims_json, pl_config->dims_json_l);
    sfree(pl_config->dims_json);
    pl_config->dims_json = new_dims_json;
    free_dims_json += pl_config->dims_json_l;
    pl_config->dims_json_l = 2 * pl_config->dims_json_l;
  }

  if (dims_json_len != 0) {
    snprintf(pl_config->dims_json + dims_json_len, reqd_dims_json,
             ", \"%s\": \"%s\"", key, value);
  } else {
    snprintf(pl_config->dims_json, reqd_dims_json, "\"%s\": \"%s\"", key,
             value);
  }

  return 0;
} /* }}} int ws_add_dimension */

#if defined(KERNEL_SOLARIS)
static int add_ip_dims(plugin_config_t *pl_config) {

  return 0;
} /* }}} int add_ip_dims */
#else
static int add_ip_dims(plugin_config_t *pl_config) {
  // Returns -1 for Errors and 0 for Warning/No-Errors
  struct ifaddrs *myaddrs, *ifa;
  char ipaddr[64];
  int status = 0;

  if (getifaddrs(&myaddrs) != 0) {
    WARNING("write splunk plugin: failed to add ip address as dimension. "
            "ignoring..");
    return 0;
  }

  for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK) ||
        (ifa->ifa_addr->sa_family != AF_INET))
      continue;

    struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;

    if (!inet_ntop(ifa->ifa_addr->sa_family, &saddr->sin_addr, ipaddr,
                   sizeof(ipaddr))) {
      continue;
    } else {
      status = ws_add_dimension(pl_config, "ip", ipaddr);
      break;
    }
  }

  if (ifa == NULL)
    WARNING("write splunk plugin: failed to add ip address as dimension. "
            "ignoring..");

  freeifaddrs(myaddrs);
  return status;
} /* }}} int add_ip_dims */
#endif

#if defined(__APPLE__)
static int add_os_dims(plugin_config_t *pl_config) {
  // Returns -1 for Errors and 0 for Warning/No-Errors
  if (ws_add_dimension(pl_config, "os", "Mac OS X") != 0)
    return -1;

  FILE *sw_version = popen("sw_vers -productVersion 2>/dev/null", "r");

  if (!sw_version) {
    WARNING(
        "write splunk plugin: failed to add os info as dimension. ignoring..");
    return 0;
  }

  char line[128];
  fgets(line, sizeof(line), sw_version);
  pclose(sw_version);

  // remove newline character
  if (line[strlen(line) - 1] == '\n')
    line[strlen(line) - 1] = '\0';

  return ws_add_dimension(pl_config, "os_version", line);
} /* }}} int add_os_dims */
#elif defined(KERNEL_SOLARIS)
static int add_os_dims(plugin_config_t *pl_config) {
  // Returns -1 for Errors and 0 for Warning/No-Errors
  char line[1024];
  char *os_version = NULL;
  FILE *file = fopen("/etc/release", "r");

  ws_add_dimension(pl_config, "os", "Solaris");

  if (file) {
    while (fgets(line, sizeof(line), file) != NULL) {
      if ((os_version = strstr(line, "Solaris")) == NULL)
        continue;
      /* Extract os_version from /etc/release file */
      os_version += strlen("Solaris");
      char *saveptr = NULL;
      os_version = strtok_r(os_version, "\"\n'", &saveptr);
      break;
    }
    fclose(file);
  }

  if (!file || !os_version || !strlen(os_version)) {
    WARNING(
        "write splunk plugin: failed to add os info as dimension. ignoring..");
    return 0;
  }

  return ws_add_dimension(pl_config, "os_version", os_version);
} /* }}} int add_os_dims */
#else
static int add_os_dims(plugin_config_t *pl_config) {
  // Returns -1 for Errors and 0 for Warning/No-Errors
  char line[1024];
  char *os_name = NULL;
  char *os_version = NULL;
  char *os_info = NULL;

  FILE *file = fopen("/etc/os-release", "r");

  if (file) {
    while (fgets(line, sizeof(line), file) != NULL) {
      if ((os_info = strstr(line, "PRETTY_NAME=")) == NULL)
        continue;
      /* Extract os_name & os_version from PRETTY_NAME="...." in /etc/os-release
       * file */
      os_info += strlen("PRETTY_NAME=");
      char *saveptr = NULL;
      os_name = strtok_r(os_info, "\"\n'", &saveptr);
      break;
    }

    fclose(file);
  } else if ((file = fopen("/etc/redhat-release", "r"))) {
    if (fgets(line, sizeof(line), file) != NULL)
      os_name = line;
    // remove newline character
    if (line[strlen(line) - 1] == '\n')
      line[strlen(line) - 1] = '\0';

    fclose(file);
  }

  if (!file || !os_name) {
    WARNING(
        "write splunk plugin: failed to add os info as dimension. ignoring..");
    return 0;
  }

  os_version = os_name + 1;

  char ch = *os_version;
  while (ch != '\0' && !(ch >= '0' && ch <= '9')) {
    ++os_version;
    ch = *os_version;
  }

  if (ch != '\0')
    *(os_version - 1) = '\0';

  if (!strlen(os_name))
    WARNING(
        "write splunk plugin: failed to add os name as dimension. ignoring..");
  else if (ws_add_dimension(pl_config, "os", os_name) != 0)
    return -1;

  if (!strlen(os_version))
    WARNING("write splunk plugin: failed to add os version as dimension. "
            "ignoring..");
  else if (ws_add_dimension(pl_config, "os_version", os_version) != 0)
    return -1;

  return 0;
} /* }}} int add_os_dims */
#endif

static int ws_add_system_dims(plugin_config_t *pl_config) {
  /* add uname info to dimensions */
  struct utsname ws_uname;

  if (uname(&ws_uname) == -1) {
    WARNING("write_splunk plugin: unable to get uname");
    return -1;
  }
  /* add kernel version as dimension */
  if (ws_add_dimension(pl_config, "kernel_version", ws_uname.release) != 0)
    return -1;
  /* To extract os_name:version like Centos:7 Ubuntu:16.04 */
  if (add_os_dims(pl_config) != 0)
    return -1;

  return add_ip_dims(pl_config);
} /* }}} int ws_add_system_dims */

static int verify_configuration(plugin_config_t *pl_config) {

  // For UDP
  if (pl_config->use_udp) {
    if (!pl_config->server || (pl_config->udp_port < 0))
      return -1;
    return 0;
  }

  // For HEC
  if (!pl_config->server || !pl_config->token || !pl_config->port)
    return -1;

  if (!(strlen(pl_config->server) > 0) && (strlen(pl_config->token) > 0) &&
      (strlen(pl_config->port) > 0))
    return -1;

  /* set up write location for HEC */
  char *protocol;
  char *addr = "/services/collector";
  if (pl_config->ssl)
    protocol = "https://";
  else
    protocol = "http://";

  int loc_len = strlen(protocol) + strlen(pl_config->server) +
                strlen(pl_config->port) + strlen(addr) + 2;
  pl_config->location = malloc(loc_len);
  if (pl_config->location == NULL) {
    ERROR("write_splunk plugin: malloc failed for location");
    return -1;
  }

  snprintf(pl_config->location, loc_len, "%s%s:%s%s", protocol,
           pl_config->server, pl_config->port, addr);

  return 0;
} /* }}} int verify_configuration */

static int post_data(plugin_config_t *pl_config) {
  int status = 0;

  // Nothing to send.
  if (!pl_config->buffer_filled)
    return 0;

  if (pl_config->use_udp) {
    /* USE UDP to send data */
    status =
        sendto(pl_config->sock, pl_config->buffer, strlen(pl_config->buffer), 0,
               (struct sockaddr *)&(pl_config->serv_addr),
               sizeof(pl_config->serv_addr));

    if (status < 0) {
      ERROR("write splunk plugin: UDP send failed to %s:%d with status %i %d",
            pl_config->server, pl_config->udp_port, status, errno);
      return status;
    }
  } else {
    /* USE HEC to send data */
    curl_easy_setopt(pl_config->curl, CURLOPT_POSTFIELDS, pl_config->buffer);
    status = curl_easy_perform(pl_config->curl);

    if (status != CURLE_OK) {
      ERROR("write splunk plugin: curl_easy_perform failed to connect to %s:%s "
            "with status %i: %s",
            pl_config->server, pl_config->port, status,
            curl_easy_strerror(status));
      return status;
    }
  }

  pl_config->buffer_filled = 0;
  pl_config->ws_count = 0;

  // used to calculate time since last post happened
  pl_config->last_sent = CDTIME_T_TO_DOUBLE(cdtime());

  return 0;
} /* }}} int post_data */

static int ws_write_buffer(const char *dims_json, const char *metric_name,
                           const value_list_t *vl, const data_set_t *ds,
                           user_data_t *user_data) {
  plugin_config_t *pl_config = user_data->data;
  char *buf_ptr = pl_config->buffer;
  int status = 0;

  size_t str_len;
  char value[WS_METRIC_MAX_VALUE_LEN] = {0};
  char metric_name2[WS_METRIC_MAX_NAME_LEN];
  double dtime = CDTIME_T_TO_DOUBLE(vl->time);
  gauge_t *rates = NULL;

  pthread_mutex_lock(&pl_config->send_lock);
  for (int i = 0; i < ds->ds_num; ++i) {
    if (strcmp(ds->ds[i].name, "value") != 0)
      snprintf(metric_name2, WS_METRIC_MAX_NAME_LEN, "%s.%s", metric_name,
               ds->ds[i].name);
    else
      snprintf(metric_name2, WS_METRIC_MAX_NAME_LEN, "%s", metric_name);

    if (ds->ds[i].type == DS_TYPE_GAUGE) {
      if (isfinite(vl->values[i].gauge))
        snprintf(value, WS_METRIC_MAX_VALUE_LEN, "%.15g", vl->values[i].gauge);
      else
        continue;
    } else if (pl_config->store_rates) {
      if (rates == NULL)
        rates = uc_get_rate(ds, vl);
      if (rates == NULL) {
        ERROR("write_splunk plugin: error with uc_get_rate");
        pthread_mutex_unlock(&pl_config->send_lock);
        return -1;
      }
      if (isnan(rates[i])) {
        DEBUG("%s: **SKIPPING**", metric_name2);
        continue; // most likely, this is the first counter value, so no rate
                  // can yet be computed
      } else {
        snprintf(value, WS_METRIC_MAX_VALUE_LEN, GAUGE_FORMAT, rates[i]);
        DEBUG("%s: value = %s", metric_name2, value);
      }
    } else if (ds->ds[i].type == DS_TYPE_COUNTER)
      snprintf(value, WS_METRIC_MAX_VALUE_LEN, "%" PRIu64,
               (uint64_t)vl->values[i].counter);
    else if (ds->ds[i].type == DS_TYPE_DERIVE)
      snprintf(value, WS_METRIC_MAX_VALUE_LEN, "%" PRIi64,
               vl->values[i].derive);
    else if (ds->ds[i].type == DS_TYPE_ABSOLUTE)
      snprintf(value, WS_METRIC_MAX_VALUE_LEN, "%" PRIu64,
               vl->values[i].absolute);
    else {
      ERROR("write_splunk plugin: Unknown data source type: %i",
            ds->ds[i].type);
      pthread_mutex_unlock(&pl_config->send_lock);
      sfree(rates);
      return -1;
    }

    /* write event to buffer. If buffer gets full, post data and do write again
     */
    while (1) {
      size_t buffer_free = pl_config->buffer_size - pl_config->buffer_filled;
      if (dims_json && strlen(dims_json))
        str_len = (size_t)snprintf(buf_ptr + pl_config->buffer_filled,
                                   buffer_free, WS_FORMAT_FIELDS_JSON_DIMS,
                                   dtime, vl->host, metric_name2, vl->plugin,
                                   value, dims_json, pl_config->dims_json);
      else
        str_len = (size_t)snprintf(buf_ptr + pl_config->buffer_filled,
                                   buffer_free, WS_FORMAT_FIELDS_JSON, dtime,
                                   vl->host, metric_name2, vl->plugin, value,
                                   pl_config->dims_json);

      /* not enough space in buffer */
      if (str_len >= buffer_free) {
        /* nothing to post */
        if (!pl_config->buffer_filled) {
          ERROR("write_splunk plugin: single event is size more than the total "
                "buffer size");
          pthread_mutex_unlock(&pl_config->send_lock);
          sfree(rates);
          return -1;
        }

        buf_ptr[pl_config->buffer_filled] = '\0';
        status = post_data(pl_config);
        if (status != 0) {
          ERROR("write_splunk plugin: post data failed");
          pthread_mutex_unlock(&pl_config->send_lock);
          sfree(rates);
          return -1;
        }
        continue; /* retry adding this event from top */
      }

      pl_config->buffer_filled += str_len;
      break; /* write to buffer done */
    }
    pl_config->ws_count++;
  }

  pthread_mutex_unlock(&pl_config->send_lock);
  sfree(rates);
  return status;
} /* }}} int ws_write_buffer */

static void pl_config_free(void *data) {
  // free all the allocated memory here
  plugin_config_t *pl_config = data;

  // close socket for udp
  if (pl_config->sock >= 0)
    close(pl_config->sock);

  sfree(pl_config->server);
  sfree(pl_config->token);
  sfree(pl_config->port);
  sfree(pl_config->curl_cainfo);
  sfree(pl_config->curl_capath);
  sfree(pl_config->location);
  sfree(pl_config->dims_json);

  if (pl_config->curl != NULL) {
    curl_easy_cleanup(pl_config->curl);
    pl_config->curl = NULL;
  }

  if (pl_config->headers_l != NULL) {
    curl_slist_free_all(pl_config->headers_l);
    pl_config->headers_l = NULL;
  }

  sfree(pl_config);

} /* }}} void pl_config_free */

static int ws_config_curl(plugin_config_t *pl_config) {

  pl_config->curl = curl_easy_init();
  CURL *curl = pl_config->curl;

  if (curl == NULL) {
    ERROR("curl plugin: curl_easy_init failed.");
    return -1;
  }

  /* set up splunk header for HEC */
  char ws_header[WS_HEADER_SIZE_MAX] = "Authorization: Splunk ";
  strncat(ws_header, pl_config->token,
          WS_HEADER_SIZE_MAX - strlen(ws_header) - 1);
  pl_config->headers_l = curl_slist_append(pl_config->headers_l, ws_header);

  DEBUG("write_splunk plugin header: %s", pl_config->header);

  if (!pl_config->verify_ssl) {
    /* disable verify ssl */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  } else {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    if (pl_config->curl_cainfo && strlen(pl_config->curl_cainfo))
      curl_easy_setopt(curl, CURLOPT_CAINFO, pl_config->curl_cainfo);

    if (pl_config->curl_capath && strlen(pl_config->curl_capath))
      curl_easy_setopt(curl, CURLOPT_CAPATH, pl_config->curl_capath);
  }

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pl_config->headers_l);
  curl_easy_setopt(curl, CURLOPT_URL, pl_config->location);

  return 0;
} /* }}} int ws_config_curl */

static int ws_config_udp(plugin_config_t *pl_config) {

  int sock = 0;
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    ERROR("\n write_splunk plugin: Socket creation error \n");
    return -1;
  }

  memset(&(pl_config->serv_addr), '0', sizeof(pl_config->serv_addr));
  pl_config->serv_addr.sin_family = AF_INET;
  pl_config->serv_addr.sin_port = htons(pl_config->udp_port);

  struct hostent *hp; /* host information */
  hp = gethostbyname(pl_config->server);

  if (!hp || !(hp->h_addrtype == AF_INET && hp->h_length == 4)) {
    ERROR("write_splunk plugin: Could not obtain IPv4 address for %s\n",
          pl_config->server);
    return -1;
  }

  memcpy((void *)&(pl_config->serv_addr).sin_addr, hp->h_addr_list[0],
         hp->h_length);

  pl_config->sock = sock;

  return 0;
} /* }}} int ws_config_udp */

static int config_dimensions(char *key, plugin_config_t *pl_config) {

  char *value = strchr(key, ':');
  if (value) {
    *value = '\0';
    value = value + 1;
    if (strlen(key) && strlen(value))
      return ws_add_dimension(pl_config, key, value);
  }

  ERROR("write splunk plugin : Invalid dimension %s", key);
  return -1;
} /* }}} int config_dimensions */

static int ws_write(const data_set_t *ds, const value_list_t *vl,
                    user_data_t *user_data) {

  plugin_config_t *pl_config = user_data->data;

  char metric_name[DATA_MAX_NAME_LEN * 4] = {0};
  char dims_json[WS_METRIC_MAX_NAME_LEN] = {0};

  ws_transform(dims_json, metric_name, vl, pl_config);

  int status = ws_write_buffer(dims_json, metric_name, vl, ds, user_data);

  return status;
} /* }}} int ws_write */

static int ws_flush(cdtime_t timeout,
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data) {
  int status = 0;

  plugin_config_t *pl_config = user_data->data;
  pthread_mutex_lock(&pl_config->send_lock);

  double now = CDTIME_T_TO_DOUBLE(cdtime());

  if ((now - pl_config->last_sent) > pl_config->ws_post_timeout ||
      (pl_config->ws_count >= pl_config->batch_size))
    status = post_data(pl_config);

  pthread_mutex_unlock(&pl_config->send_lock);

  return status;
} /* }}} int ws_flush */

static int ws_config(oconfig_item_t *ci) {
  plugin_config_t *pl_config;

  pl_config = calloc(1, sizeof(plugin_config_t));
  if (pl_config == NULL) {
    ERROR("write_splunk plugin: calloc failed.");
    pl_config_free(pl_config);
    return -1;
  }

  pl_config->buffer_size = SEND_BUFFER_SIZE_DEFAULT;
  pl_config->ws_post_timeout = WS_POST_TIMEOUT_DEFAULT;
  pl_config->server = NULL;
  pl_config->port = NULL;
  pl_config->token = NULL;
  pl_config->curl_cainfo = NULL;
  pl_config->curl_capath = NULL;
  pl_config->headers_l = NULL;
  pl_config->verify_ssl = 0;
  pl_config->ssl = 1;
  pl_config->splunk_metric_transform = 1;
  pl_config->disk_as_dimensions = 1;
  pl_config->interface_as_dimensions = 1;
  pl_config->cpu_as_dimensions = 1;
  pl_config->df_as_dimensions = 1;
  pl_config->store_rates = 1;
  pl_config->use_udp = 0;
  pl_config->udp_port = -1;
  pl_config->sock = -1;
  pl_config->ws_count = 0;
  pl_config->batch_size = 1024;
  pl_config->dims_json_l = 128;
  pl_config->last_sent = CDTIME_T_TO_DOUBLE(cdtime());
  pthread_mutex_init(&pl_config->send_lock, /* attr = */ NULL);

  pl_config->dims_json = malloc(pl_config->dims_json_l);
  if (pl_config->dims_json == NULL) {
    ERROR("write_splunk plugin: malloc failed.");
    pl_config_free(pl_config);
    return -1;
  }

  pl_config->dims_json[0] = '\0';

  int status = 0;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("dimension", child->key) == 0) {
      /* config format - Dimension "key:value" */
      char *str = NULL;
      status = cf_util_get_string(child, &str);
      if (status != 0)
        break;
      status = config_dimensions(str, pl_config);
      sfree(str);
    } else if (strcasecmp("port", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->port);
    else if (strcasecmp("token", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->token);
    else if (strcasecmp("server", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->server);
    else if (strcasecmp("cainfo", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->curl_cainfo);
    else if (strcasecmp("capath", child->key) == 0)
      status = cf_util_get_string(child, &pl_config->curl_capath);
    else if (strcasecmp("batchsize", child->key) == 0)
      status = cf_util_get_int(child, &pl_config->batch_size);
    else if (strcasecmp("buffersize", child->key) == 0)
      status = cf_util_get_int(child, &pl_config->buffer_size);
    else if (strcasecmp("posttimeout", child->key) == 0)
      status = cf_util_get_int(child, &pl_config->ws_post_timeout);
    else if (strcasecmp("udpport", child->key) == 0)
      status = cf_util_get_int(child, &pl_config->udp_port);
    else if (strcasecmp("ssl", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->ssl);
    else if (strcasecmp("verifyssl", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->verify_ssl);
    else if (strcasecmp("splunkmetrictransform", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->splunk_metric_transform);
    else if (strcasecmp("diskasdimensions", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->disk_as_dimensions);
    else if (strcasecmp("interfaceasdimensions", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->interface_as_dimensions);
    else if (strcasecmp("cpuasdimensions", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->cpu_as_dimensions);
    else if (strcasecmp("dfasdimensions", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->df_as_dimensions);
    else if (strcasecmp("storerates", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->store_rates);
    else if (strcasecmp("useudp", child->key) == 0)
      status = cf_util_get_boolean(child, &pl_config->use_udp);
    else
      WARNING("write_splunk plugin: Ignored config `%s'.", child->key);

    if (status != 0)
      break;
  }

  if (status != 0) {
    pl_config_free(pl_config);
    return status;
  }

  if (verify_configuration(pl_config) != 0) {

    if (pl_config->use_udp)
      ERROR(" Specify write_splunk udp port and server in conf file ");
    else
      ERROR(" Specify write_splunk plugin's port, token and server in conf "
            "file ");
    pl_config_free(pl_config);
    return -1;
  }

  user_data_t user_data = {.data = pl_config, .free_func = pl_config_free};
  plugin_register_write("write_splunk", ws_write, &user_data);
  user_data.free_func = NULL;
  plugin_register_flush("write_splunk", ws_flush, &user_data);

  // Configure UDP/HEC
  if (pl_config->use_udp)
    status = ws_config_udp(pl_config);
  else
    status = ws_config_curl(pl_config);

  if (status != 0) {
    ERROR(" write_splunk plugin: Failed to configure");
    pl_config_free(pl_config);
    return -1;
  }

  /* Error when adding system dimensions */
  if (ws_add_system_dims(pl_config) != 0) {
    pl_config_free(pl_config);
    return -1;
  }

  pl_config->buffer = malloc(pl_config->buffer_size);
  if (pl_config->buffer == NULL) {
    ERROR("write_splunk plugin: malloc failed.");
    pl_config_free(pl_config);
    return -1;
  }
  pl_config->buffer_filled = 0;

  return 0;
} /* }}} int ws_config */

static int ws_init(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  return 0;
} /* }}} int ws_init */

void module_register(void) {
  DEBUG(" Registering Callbacks for Write_Splunk plugin ");
  plugin_register_complex_config("write_splunk", ws_config);
  plugin_register_init("write_splunk", ws_init);
} /* }}} void module_register */
