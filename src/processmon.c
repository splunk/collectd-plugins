/**
 * collectd - src/processmon.c
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

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <regex.h>
#include "utils/common/common.h"
#include "plugin.h"

#define PM_MAX_PID_LEN 16
#define PM_MAX_USERNAME_LEN 32
#define PM_MAX_PROCESSNAME_LEN 80

typedef struct pm_list_s {
  regex_t preg;

  struct pm_list_s *next;
} pm_list_t;

typedef struct process_data_s {
  // process name, pid and user
  char pid[PM_MAX_PID_LEN];
  char process_name[PM_MAX_PROCESSNAME_LEN];
  char username[PM_MAX_USERNAME_LEN];

  // used for whitelisting/blacklisting process
  int is_monitored;

  // cpu metrics system/user time and use percent
  derive_t stime;
  derive_t utime;
  gauge_t cpu_percent;

  // memory metrics
  // all 3 values in kb
  gauge_t vmdata;
  gauge_t vmcode;
  gauge_t vmrss;

  gauge_t mem_percent;

  // uptime metrics
  gauge_t uptime;

  // io metrics
  // all 4 values in bytes
  derive_t rchar;
  derive_t wchar;
  derive_t read_bytes;
  derive_t write_bytes;

  // number of read/write syscall ops
  derive_t syscr;
  derive_t syscw;

  // number of threads for process
  gauge_t thread_count;

} process_data_t;

static pm_list_t *whitlelist_head = NULL;
static pm_list_t *blacklist_head = NULL;
static _Bool should_read_io = 0;
static long long unsigned total_mem_kb = 0;

static void submit_value(const char *type_instance, const char *type,
                         const char *plugin_instance, value_t value) {
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = &value;
  vl.values_len = 1;

  sstrncpy(vl.plugin, "processmon", sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  if (plugin_instance)
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));

  plugin_dispatch_values(&vl);
} /* }}} void submit_value */

static void pm_submit_process_data(process_data_t *pd) {
  // submit process uptime
  char process_instance[DATA_MAX_NAME_LEN];

  snprintf(process_instance, DATA_MAX_NAME_LEN, "%s %s %s", pd->pid,
           pd->username, pd->process_name);
  submit_value("uptime", "uptime", process_instance,
               (value_t){.gauge = pd->uptime});

  // Submit cpu usage
  submit_value("cpu.user_time", "cpu", process_instance,
               (value_t){.derive = pd->utime});
  submit_value("cpu.kernel_time", "cpu", process_instance,
               (value_t){.derive = pd->stime});

  if (pd->uptime)
    submit_value("cpu.percent", "percent", process_instance,
                 (value_t){.gauge = pd->cpu_percent});

  // submit memory data
  if (pd->vmdata)
    submit_value("memory.vmem_data_kb", "memory", process_instance,
                 (value_t){.gauge = pd->vmdata});
  if (pd->vmcode)
    submit_value("memory.vmem_code_kb", "memory", process_instance,
                 (value_t){.gauge = pd->vmcode});
  if (pd->vmrss)
    submit_value("memory.rss_kb", "memory", process_instance,
                 (value_t){.gauge = pd->vmrss});
  if (pd->mem_percent)
    submit_value("memory.percent", "percent", process_instance,
                 (value_t){.gauge = pd->mem_percent});

  // Submit IO values if enabled
  if (should_read_io) {
    if (pd->rchar)
      submit_value("io.read_char", "total_bytes", process_instance,
                   (value_t){.derive = pd->rchar});
    if (pd->wchar)
      submit_value("io.write_char", "total_bytes", process_instance,
                   (value_t){.derive = pd->wchar});
    if (pd->syscr)
      submit_value("io.read_syscalls", "total_operations", process_instance,
                   (value_t){.derive = pd->syscr});
    if (pd->syscw)
      submit_value("io.write_syscalls", "total_operations", process_instance,
                   (value_t){.derive = pd->syscw});

    if (pd->read_bytes)
      submit_value("io.read_bytes", "total_bytes", process_instance,
                   (value_t){.derive = pd->read_bytes});

    if (pd->write_bytes)
      submit_value("io.write_bytes", "total_bytes", process_instance,
                   (value_t){.derive = pd->write_bytes});
  }

  // Submit thread count
  if (pd->thread_count)
    submit_value("thread_count", "count", process_instance,
                 (value_t){.gauge = pd->thread_count});

} /* }}} void pm_submit_process_data */

static int is_whitelisted(char *string) {
  if (whitlelist_head == NULL)
    return 1;

  pm_list_t *ptr = whitlelist_head;
  while (ptr) {
    if (regexec(&ptr->preg, string, 0, NULL, 0) == 0)
      return 1;

    ptr = ptr->next;
  }

  return 0;
} /* }}} int is_whitelisted */

static int is_blacklisted(char *string) {
  if (blacklist_head == NULL)
    return 0;

  pm_list_t *ptr = blacklist_head;
  while (ptr) {
    if (regexec(&ptr->preg, string, 0, NULL, 0) == 0)
      return 1;

    ptr = ptr->next;
  }

  return 0;
} /* }}} int is_blacklisted */

static int add_to_list(char *string, int whitelist) {
  if (string == NULL)
    return 1;
  pm_list_t *wl = (pm_list_t *)malloc(sizeof(pm_list_t));
  if (wl == NULL) {
    ERROR("processmon plugin: add_to_list: malloc failed.");
    return -1;
  }

  if (regcomp(&wl->preg, string, REG_EXTENDED | REG_NOSUB) != 0) {
    ERROR("processmon plugin: add_to_list: regex compile failed.");
    sfree(wl);
    return -1;
  }
  // add new regex to white/black list
  if (whitelist) {
    wl->next = whitlelist_head;
    whitlelist_head = wl;
  } else {
    wl->next = blacklist_head;
    blacklist_head = wl;
  }

  return 0;
} /* }}} int add_to_list */

static int pm_read_stat(process_data_t *pd, char *process_state) {

  char *pname = NULL;
  char buf[2048];
  char fname[50];
  size_t length;

  // read the proc stat file for pid.
  snprintf(fname, sizeof(fname), "/proc/%s/stat", pd->pid);

  ssize_t status = read_file_contents(fname, buf, sizeof(buf) - 1);
  if (status <= 0) {
    ERROR("processmon plugin: Error reading %s", fname);
    return -1;
  }
  length = (size_t)status;
  buf[length] = '\0';

  // get the program name from the /proc/<pid>/stat enclosed in ()
  pname = buf;
  while (*pname != '\0' && *pname != '(')
    ++pname;

  if (*pname == '\0') {
    ERROR("processmon plugin: Failed to get process name from %s", fname);
    return -1;
  }

  ++pname;

  char *pname_end = buf + strlen(buf);

  while (pname_end != pname && *pname_end != ')')
    --pname_end;

  if (pname_end == pname) {
    // something is wrong, we could not get process name enclosed by ()
    ERROR("processmon plugin: Failed to get process name from %s", fname);
    return -1;
  }
  *pname_end = '\0';

  // state field in the /proc/<pid>/stat
  *process_state = *(pname_end + 2);

  // check if we need to monitor this process or not
  if (!is_whitelisted(pname) || is_blacklisted(pname))
    return 0;

  pd->is_monitored = 1;
  sstrncpy(pd->process_name, pname, PM_MAX_PROCESSNAME_LEN);

  // Extract rest of the fields in '/proc/pid/stat' after pname from buf.
  char *process_metrics[50];
  int count = strsplit(pname_end + 2, process_metrics,
                       STATIC_ARRAY_SIZE(process_metrics));
  if (count < 20) {
    ERROR("processmon plugin: Error reading %s", fname);
    return -1;
  }

  pd->utime = (derive_t)atol(process_metrics[11]);
  pd->stime = (derive_t)atol(process_metrics[12]);
  pd->thread_count = (gauge_t)atol(process_metrics[17]);
  long long unsigned starttime = strtoull(process_metrics[19], NULL, 10);

  // get system uptime
  status = read_file_contents("/proc/uptime", buf, sizeof(buf) - 1);
  if (status <= 0) {
    ERROR("processmon plugin: Failed to read file /proc/uptime");
    return -1;
  }
  char *uptimes[2];
  count = strsplit(buf, uptimes, STATIC_ARRAY_SIZE(uptimes));

  if (count != 2) {
    ERROR("processmon plugin: Failed to get system uptime from /proc/uptime");
    return -1;
  }

  double sys_uptime = strtod(uptimes[0], NULL);

  int hertz = sysconf(_SC_CLK_TCK);
  pd->uptime = sys_uptime - (double)starttime / hertz;

  pd->cpu_percent = 0;
  if (pd->uptime)
    pd->cpu_percent = 100 * ((pd->utime + pd->stime) / hertz) / pd->uptime;

  return 0;
} /* }}} int pm_read_stat */

static int pm_read_io(process_data_t *pd) {

  char buf[1024];
  char fname[50];
  FILE *file;

  snprintf(fname, sizeof(fname), "/proc/%s/io", pd->pid);

  if ((file = fopen(fname, "r")) == NULL) {
    ERROR("processmon plugin: Failed to fopen file %s, errno:%d '", fname,
          errno);
    return -1;
  }

  // All these values are in bytes
  pd->rchar = 0;
  pd->wchar = 0;
  pd->read_bytes = 0;
  pd->write_bytes = 0;

  pd->syscr = 0;
  pd->syscw = 0;

  char *tokens[2];
  int count;

  while (fgets(buf, sizeof(buf), file) != NULL) {
    count = strsplit(buf, tokens, STATIC_ARRAY_SIZE(tokens));
    if (count < 2)
      continue;

    if (strncmp(tokens[0], "rchar", 5) == 0)
      pd->rchar = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "wchar", 5) == 0)
      pd->wchar = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "syscr", 5) == 0)
      pd->syscr = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "syscw", 5) == 0)
      pd->syscw = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "read_bytes", 10) == 0)
      pd->read_bytes = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "write_bytes", 11) == 0)
      pd->write_bytes = strtoull(tokens[1], NULL, 10);
  }

  fclose(file);

  return 0;
} /* }}} int pm_read_io */

static int pm_read_status(process_data_t *pd) {
  char buf[2048];
  char fname[50];
  FILE *file;

  pd->username[0] = '\0';

  snprintf(fname, sizeof(fname), "/proc/%s/status", pd->pid);

  if ((file = fopen(fname, "r")) == NULL) {
    ERROR("processmon plugin: Failed to fopen file %s, errno:%d ", fname,
          errno);
    return -1;
  }

  // All these values are in kB
  pd->vmdata = 0;
  pd->vmcode = 0;
  pd->vmrss = 0;

  pd->mem_percent = 0;

  char *tokens[5];
  int count;

  unsigned long long vmlib = 0;
  unsigned long long vmexe = 0;

  while (fgets(buf, sizeof(buf), file) != NULL) {
    if (strncmp(buf, "Uid", 3) != 0 && strncmp(buf, "Vm", 2) != 0)
      continue;

    count = strsplit(buf, tokens, STATIC_ARRAY_SIZE(tokens));

    if (count < 2)
      continue;

    if (strncmp(tokens[0], "VmData", 6) == 0)
      pd->vmdata = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "VmExe", 5) == 0)
      vmexe = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "VmLib", 5) == 0)
      vmlib = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "VmRSS", 5) == 0)
      pd->vmrss = strtoull(tokens[1], NULL, 10);
    else if (strncmp(tokens[0], "Uid", 3) == 0) {
      // This is real UID of this process
      uid_t uid = (uid_t)strtoul(tokens[1], NULL, 10);
      struct passwd *pw;
      pw = getpwuid(uid);
      if (pw)
        sstrncpy(pd->username, pw->pw_name, PM_MAX_USERNAME_LEN);
      else
        WARNING("processmon plugin: Failed to get username for pid: %s",
                pd->pid);
    }
  }

  fclose(file);

  // caluclate vmcode from vmlib & vmexe
  if (vmlib && vmexe)
    pd->vmcode = vmlib + vmexe;

  // Caculate mem percent
  if (total_mem_kb && pd->vmrss)
    pd->mem_percent = pd->vmrss / total_mem_kb * 100;

  return 0;
} /* }}} int pm_read_status */

static void pm_get_memtotal() {

  char buf[1024];
  FILE *file;

  if ((file = fopen("/proc/meminfo", "r")) == NULL) {
    WARNING("processmon plugin: Failed to fopen file /proc/meminfo for "
            "MemTotal required to calculate mem_percent, errno: %d ",
            errno);
    return;
  }

  // look for MemTotal inn /proc/meminfo
  while (fgets(buf, sizeof(buf), file) != NULL) {
    if (strncmp(buf, "MemTotal", 8) != 0)
      continue;

    char *tokens[3];
    int count = strsplit(buf, tokens, STATIC_ARRAY_SIZE(tokens));

    if (count < 2) {
      WARNING("processmon plugin: Failed to get memtotal from /proc/meminfo");
      return;
    }
    total_mem_kb = strtoull(tokens[1], NULL, 10);
    break;
  }

  fclose(file);
}

static void pm_free_list(pm_list_t *ptr) {
  pm_list_t *tmp;

  while (ptr != NULL) {
    tmp = ptr->next;
    sfree(ptr);
    ptr = tmp;
  }
} /* }}} void pm_free_list */

static int pm_shutdown(void) {
  pm_free_list(blacklist_head);
  pm_free_list(whitlelist_head);
  return 0;
} /* }}} int pm_shutdown */

static int is_process_id(char *dir_name) {
  size_t length = strlen(dir_name);
  // check for process directories. directory name is the process id
  for (int i = 0; i < length; ++i)
    if (!isdigit((int)dir_name[i]))
      return 0;
  return 1;
} /* }}} int is_process_id */

static int pm_read(void) {
  DIR *proc_dir = opendir("/proc");
  if (proc_dir == NULL) {
    ERROR("processmon plugin: failed to opendir /proc errorno: %d", errno);
    return -1;
  }

  struct dirent *entry;
  process_data_t pd;
  int pm_read_error = 0;

  pm_get_memtotal();

  // variables to keep overall process count
  int monitored_count = 0;
  int total_count = 0;

  // variables to keep counts of process states
  char process_state;
  int state_R = 0;
  int state_S = 0;
  int state_D = 0;
  int state_Z = 0;
  int state_t_T = 0;

  while ((entry = readdir(proc_dir)) != NULL) {
    // check for process directories. directory name is the process id
    if (!is_process_id(entry->d_name))
      continue;

    sstrncpy(pd.pid, entry->d_name, PM_MAX_PID_LEN);
    pd.is_monitored = 0;
    ++total_count;

    // Read file /proc/<pid>/stat
    if (pm_read_stat(&pd, &process_state) != 0) {
      pm_read_error = 1;
      continue;
    }

    switch (process_state) {
    case 'R':
      ++state_R;
      break;
    case 'S':
      ++state_S;
      break;
    case 'D':
      ++state_D;
      break;
    case 'Z':
      ++state_Z;
      break;
    case 't':
    case 'T':
      ++state_t_T;
      break;
    }

    // check if we need to monitor this process
    if (!pd.is_monitored)
      continue;

    // Read file /proc/<pid>/status
    if (pm_read_status(&pd) != 0) {
      pm_read_error = 1;
      continue;
    }

    // By default, we do not read io values
    // It can be enable in collectd.conf file with "ReadIo true"
    if (should_read_io && pm_read_io(&pd) != 0) {
      pm_read_error = 1;
      continue;
    }

    // submit values for this process here
    pm_submit_process_data(&pd);
    ++monitored_count;
  }

  closedir(proc_dir);

  // submit overall process counts
  submit_value("count.monitored", "count", "NULL",
               (value_t){.gauge = monitored_count});
  submit_value("count.total", "count", "NULL", (value_t){.gauge = total_count});

  // submit process state counts
  submit_value("count.state.running", "count", "NULL",
               (value_t){.gauge = state_R});
  submit_value("count.state.sleeping", "count", "NULL",
               (value_t){.gauge = state_S});
  submit_value("count.state.waiting", "count", "NULL",
               (value_t){.gauge = state_D});
  submit_value("count.state.zombie", "count", "NULL",
               (value_t){.gauge = state_Z});
  submit_value("count.state.stopped", "count", "NULL",
               (value_t){.gauge = state_t_T});

  // There was some error in the while loop
  if (pm_read_error)
    return -1;

  return 0;
} /* }}} int pm_read */

static int pm_config(oconfig_item_t *ci) {

  int status = 0;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("whitelist", child->key) == 0 ||
        strcasecmp("blacklist", child->key) == 0) {
      char *pattern = NULL;
      status = cf_util_get_string(child, &pattern);
      if (status == 0) {
        status = add_to_list(pattern, strcasecmp("whitelist", child->key) == 0);
      }
      sfree(pattern);
    } else if (strcasecmp("readio", child->key) == 0)
      status = cf_util_get_boolean(child, &should_read_io);
    else
      WARNING("processmon plugin: Ignored config `%s'.", child->key);

    if (status != 0) {
      ERROR("processmon plugin: config error for %s", child->key);
      return -1;
    }
  }

  return 0;
} /* }}} int pm_config */

void module_register(void) {
  plugin_register_complex_config("processmon", pm_config);
  plugin_register_read("processmon", pm_read);
  plugin_register_shutdown("processmon", pm_shutdown);
} /* void module_register */
