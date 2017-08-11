# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# vector packet processor
odp_arch = native
ifeq ($(shell uname -m),x86_64)
odp_march = corei7			# Nehalem Instruction set
odp_mtune = corei7-avx			# Optimize for Sandy Bridge
else
odp_march = native
odp_mtune = generic
endif
odp_native_tools = vppapigen

odp_uses_dpdk = no

# Uncoment to enable building unit tests
#odp_enable_tests = yes

odp_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	vpp-api gmod

vlib_configure_args_odp = --with-pre-data=128

#ODP configuration parameters
odp_uses_odp=yes
odp_odp_libs = -lodp-dpdk -ldpdk -lodphelper -lpcap
odp_odp_inc_dir=$(ODP_INST_PATH)/include
odp_odp_lib_dir=$(ODP_INST_PATH)/lib

vpp_configure_args_odp = --with-odplib --disable-dpdk-plugin --disable-acl-plugin
vnet_configure_args_odp = --disable-dpdk-plugin --disable-acl-plugin

odp_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror
odp_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror

odp_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror
odp_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror

odp_gcov_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -march=$(MARCH) \
	-fPIC -Werror -fprofile-arcs -ftest-coverage
odp_gcov_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -march=$(MARCH) \
	-fPIC -Werror -coverage
