/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once

#include <memory>
#include <unordered_set>

#include <sinsp.h>
#include <sys/utsname.h>

#include "logger.h"
#include "falco_outputs.h"

class resource_utilization_mgr
{
public:
	resource_utilization_mgr();
	virtual ~resource_utilization_mgr();

	void init(std::shared_ptr<sinsp> inspector,
		  std::shared_ptr<falco_outputs> outputs);

	// Call this for every event. The class will take care of
	// periodically measuring the scap stats, looking for syscall
	// event drops, and performing any actions.
	//
	// Returns whether event processing should continue or stop (with an error).
	// Performs all configured actions.
	bool process_event(std::shared_ptr<sinsp> inspector, sinsp_evt *evt, uint64_t &num_evts);

	void get_falco_current_rss_vsz_memory(uint32_t &rss, uint32_t &vsz);

	void get_falco_current_cpu_usage(float &cpu_usage_percentage, float &falco_duration_sec);

	void get_falco_container_memory_usage_bytes(uint32_t &cgroup_memory_used_bytes);

protected:
	std::shared_ptr<sinsp> m_inspector;
	std::shared_ptr<falco_outputs> m_outputs;
	const scap_machine_info* m_machine_info;
	uint64_t m_next_check_ts;
	uint64_t m_prev_num_evts;
	uint64_t m_prev_n_evts;
	int m_falco_pid;
	struct utsname m_uts;
	uint64_t m_falco_start_ts_epoch;
	bool m_do_cgroup_memory_lookup;
	char m_cgroups_memory_usage_path[256];

};
