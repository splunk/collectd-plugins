/**
 * collectd - src/write_splunk_test.c
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

#include "testing.h"
#include "write_splunk.c"

DEF_TEST(splunk_transforms) {
  struct {
    const char *plugin;
    const char *plugin_instance;
    const char *type;
    const char *type_instance;
    _Bool disk_as_dimensions;
    _Bool cpu_as_dimensions;
    _Bool df_as_dimensions;
    _Bool interface_as_dimensions;
    const char *expected_name;
    const char *expected_dims_json;
  } cases[] = {
      {.plugin = "load",
       .plugin_instance = "",
       .type = "",
       .type_instance = "",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "load",
       .expected_dims_json = ""},
      {.plugin = "memory",
       .plugin_instance = "",
       .type = "percent",
       .type_instance = "free",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "memory.free",
       .expected_dims_json = ""},
      {.plugin = "disk",
       .plugin_instance = "0-1",
       .type = "disk_ops",
       .type_instance = "",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "disk.ops",
       .expected_dims_json = "\"disk\": \"0-1\""},
      {.plugin = "disk",
       .plugin_instance = "",
       .type = "pending_ops",
       .type_instance = "read",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "disk.pending_ops.read",
       .expected_dims_json = ""},
      {.plugin = "df",
       .plugin_instance = "test",
       .type = "abc",
       .type_instance = "reserved",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "df.reserved",
       .expected_dims_json = "\"device\": \"test\""},
      {.plugin = "df",
       .plugin_instance = "",
       .type = "abc",
       .type_instance = "free",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "df.free",
       .expected_dims_json = ""},
      {.plugin = "swap",
       .plugin_instance = "s1",
       .type = "s2",
       .type_instance = "s3",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "swap.s1.s2.s3",
       .expected_dims_json = ""},
      {.plugin = "swap",
       .plugin_instance = "",
       .type = "s1",
       .type_instance = "s2",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "swap.s1.s2",
       .expected_dims_json = ""},
      {.plugin = "cpu",
       .plugin_instance = "0",
       .type_instance = "system",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "cpu.system",
       .expected_dims_json = "\"cpu\": 0"},
      {.plugin = "cpu",
       .plugin_instance = "",
       .type_instance = "idle",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "cpu.idle",
       .expected_dims_json = ""},
      {.plugin = "cpu",
       .plugin_instance = "1",
       .type = "percent",
       .type_instance = "idle",
       .cpu_as_dimensions = 0,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 1,
       .expected_name = "cpu.1.percent.idle",
       .expected_dims_json = ""},
      {.plugin = "disk",
       .plugin_instance = "0",
       .type = "disk_ops",
       .type_instance = "",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 0,
       .df_as_dimensions = 1,
       .expected_name = "disk.0.disk_ops",
       .expected_dims_json = ""},
      {.plugin = "df",
       .plugin_instance = "",
       .type = "ab",
       .type_instance = "reserved",
       .cpu_as_dimensions = 1,
       .disk_as_dimensions = 1,
       .df_as_dimensions = 0,
       .expected_name = "df.ab.reserved",
       .expected_dims_json = ""},
      {.plugin = "interface",
       .plugin_instance = "en0",
       .type = "if_octets",
       .type_instance = "",
       .interface_as_dimensions = 1,
       .expected_name = "interface.octets",
       .expected_dims_json = "\"interface\": \"en0\""},
      {.plugin = "interface",
       .plugin_instance = "en0",
       .type = "if_octets",
       .type_instance = "",
       .interface_as_dimensions = 0,
       .expected_name = "interface.en0.if_octets",
       .expected_dims_json = ""},
      {.plugin = "processmon",
       .plugin_instance = "12 root top",
       .type = "cpu",
       .type_instance = "cpu.percent",
       .interface_as_dimensions = 0,
       .expected_name = "processmon.cpu.percent",
       .expected_dims_json =
           "\"pid\": \"12\", \"user\": \"root\", \"process_name\": \"top\""},
      {.plugin = "docker",
       .plugin_instance = "aabbccdd",
       .type = "percent",
       .type_instance = "cpu.system",
       .interface_as_dimensions = 0,
       .expected_name = "docker.cpu.system",
       .expected_dims_json = "\"container_id\": \"aabbccdd\""},
  };

  for (size_t i = 0; i < STATIC_ARRAY_SIZE(cases); i++) {
    value_list_t vl;
    plugin_config_t pl_config;

    pl_config.splunk_metric_transform = 1;
    pl_config.cpu_as_dimensions = cases[i].cpu_as_dimensions;
    pl_config.disk_as_dimensions = cases[i].disk_as_dimensions;
    pl_config.df_as_dimensions = cases[i].df_as_dimensions;
    pl_config.interface_as_dimensions = cases[i].interface_as_dimensions;

    char metric_name[WS_METRIC_MAX_NAME_LEN];
    char dims_json[WS_METRIC_MAX_NAME_LEN] = {0};

    sstrncpy(vl.plugin, cases[i].plugin, sizeof(vl.plugin));
    if (cases[i].plugin_instance != NULL)
      strncpy(vl.plugin_instance, cases[i].plugin_instance,
              sizeof(vl.plugin_instance));
    if (cases[i].type != NULL)
      strncpy(vl.type, cases[i].type, sizeof(vl.type));
    if (cases[i].type_instance != NULL)
      strncpy(vl.type_instance, cases[i].type_instance,
              sizeof(vl.type_instance));

    ws_transform(dims_json, metric_name, &vl, &pl_config);
    EXPECT_EQ_STR(cases[i].expected_name, metric_name);
    EXPECT_EQ_STR(cases[i].expected_dims_json, dims_json);
  }

  return 0;
}

int main(void) {
  RUN_TEST(splunk_transforms);

  END_TEST;
}
