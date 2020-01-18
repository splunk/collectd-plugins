# Collectd-plugins

C plugins for collectd:
* write_splunk: write plugin: Write data to Splunk over HEC or UDP
* processmon: read plugin: monitor processes running on your system. Linux only.
* docker: read plugin: monitor docker containers running in your system.

## How to build the plugins

1. Clone the collectd repo from github:
``` git clone https://github.com/collectd/collectd.git ```

2. Switch to collectd-5.9 branch:
``` cd collectd && git checkout collectd-5.9 ```
For collectd-5.8, use collectd-5.8 branch here.

3. Copy the plugin source files to the collectd repo:
``` cp ${collectd_plugins_dir}/src/* src/ ```

4. Apply the patch file to the collectd repo:
``` git apply ${collectd_plugins_dir}/add-splunk-plugins.patch ```

5. Compile collectd:
``` ./build.sh && ./configure && make ```
Use ``` ./configure --help ``` to see the configuration options.
Read the collectd README file to see the requirements to compile it.
For docker plugin: libyajl2 and libcurl dev packages are required.
For write_splunk plugin: libcurl dev paackage is required.

6. Run Tests:
``` make check-TESTS ```

7. Install collectd:
``` make install ```

8. Update settings for the plugins in collectd.conf file:
``` vi /opt/collectd/etc/collectd.conf ```
Make sure you enable write_splunk and other plugins you want and also update the token, server etc. for write_splunk:
```
<LoadPlugin "write_splunk">
        FlushInterval 30
</LoadPlugin>
```

9. Start collectd:
``` /opt/collectd/sbin/collectd ```

## Example: Getting started on new Ubuntu 16.04 installation

```
apt-get update
git clone https://github.com/collectd/collectd.git
cd collectd
apt-get install -y autoconf libtool pkg-config bison byacc flex
apt-get install -y libyajl-dev libcurl4-openssl-dev
git checkout collectd-5.9
cp /collectd-plugins/src/* src/
git apply /collectd-plugins/add-splunk-plugins.patch
./build.sh
./configure CFLAGS="-g -O2 -fstack-protector -D_FORTIFY_SOURCE=2 -fpie" LDFLAGS="-Wl,-z,relro"
make
make check-TESTS
make install
vi /opt/collectd/etc/collectd.conf
/opt/collectd/sbin/collectd
```
