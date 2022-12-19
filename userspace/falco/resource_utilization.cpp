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

#include "application.h"
#include "resource_utilization.h"
#include "falco_common.h"
#include <sys/utsname.h>
#include <sys/times.h>
#include <sys/stat.h>
#include "banned.h" // This raises a compilation error when certain functions are used


resource_utilization_mgr::resource_utilization_mgr():
	m_inspector(NULL),
	m_outputs(NULL),
	m_machine_info(NULL),
	m_next_check_ts(0),
	m_prev_num_evts(0),
	m_prev_n_evts(0),
	m_falco_pid(0),
	m_falco_start_ts_epoch(0),
	m_do_cgroup_memory_lookup(false)
{
}

resource_utilization_mgr::~resource_utilization_mgr()
{
}

void resource_utilization_mgr::init(std::shared_ptr<sinsp> inspector,
				std::shared_ptr<falco_outputs> outputs)
{
	m_inspector = inspector;
	m_outputs = outputs;
	m_machine_info = m_inspector->get_machine_info();
	m_falco_pid = getpid();
	uname(&m_uts);
	struct stat st = {0};
	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/", m_falco_pid);
	if(stat(path, &st) == 0)
	{
		m_falco_start_ts_epoch = st.st_ctim.tv_sec * ONE_SECOND_IN_NS + st.st_ctim.tv_nsec;
	}
	/* Kubernetes tailored path as seen from within Falco deployment container */
	snprintf(m_cgroups_memory_usage_path, sizeof(m_cgroups_memory_usage_path), "/sys/fs/cgroup/memory/memory.usage_in_bytes");
	if(stat(m_cgroups_memory_usage_path, &st) == 0)
	{
		m_do_cgroup_memory_lookup = true;
	}
}

void resource_utilization_mgr::get_falco_container_memory_usage_bytes(uint32_t &cgroup_memory_used_bytes)
{
	char line[512];
	FILE* f = fopen(m_cgroups_memory_usage_path, "r");
	if(f)
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			sscanf(line, "%" PRIu32, &cgroup_memory_used_bytes);		/* memory size returned in bytes */
		}
	}
	fclose(f);

}

void resource_utilization_mgr::get_falco_current_rss_vsz_memory(uint32_t &rss, uint32_t &vsz)
{
	char filename[1024] = "";
	char line[512];

	/* Approach adopted from falcosecurity/libs scap_procs file scan*/
	snprintf(filename, sizeof(filename), "/proc/%d/status", m_falco_pid);		/* No distinction between host or container needed. */
	FILE* f = fopen(filename, "r");
	if(f)
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			if(strstr(line, "VmSize:") == line)
			{
				sscanf(line, "VmSize: %" PRIu32, &vsz);		/* memory size returned in kb */
			} else if(strstr(line, "VmRSS:") == line)
			{
				sscanf(line, "VmRSS: %" PRIu32, &rss);		/* memory size returned in kb */
			}
		}
	}
	fclose(f);

}

void resource_utilization_mgr::get_falco_current_cpu_usage(float &cpu_usage_percentage, float &falco_duration_sec)
{

	/* Number of clock ticks per second. */
	float clocks_per_second = sysconf(_SC_CLK_TCK);

	struct tms time;
	if (times (&time) != (clock_t) -1)
	{
		/* utime is amount of processor time in user mode of calling process. Convert from clock_t to seconds. */
		float user_sec = (float) time.tms_utime / clocks_per_second;
		/* stime is amount of time the calling process has been scheduled in kernel mode. Convert from clock_t to seconds. */
		float system_sec = (float) time.tms_stime / clocks_per_second;

		/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the elapsed time of the process. Compare to `ps` linux util. */
		cpu_usage_percentage = (user_sec + system_sec) / falco_duration_sec;
		cpu_usage_percentage *= 100.0;
	}

}

bool resource_utilization_mgr::process_event(std::shared_ptr<sinsp> inspector, sinsp_evt *evt, uint64_t &num_evts)
{
	uint64_t now = evt->get_ts();
	///TODO: Placeholder interval for dev, decide on interval manager based on user input, could be presets or similar to stats_writer
	uint64_t interval = (ONE_SECOND_IN_NS * 2);
	uint64_t next_check_ts = now + interval;

	if(m_next_check_ts == 0)
	{
		/* Handle special initializations for initial metrics run. */
		scap_stats stats;
		m_inspector->get_capture_stats(&stats);
		m_next_check_ts = next_check_ts;
		m_prev_num_evts = num_evts;
		m_prev_n_evts = stats.n_evts;
	}
	
	if(m_next_check_ts < now)
	{
		/* Calculate exact duration between previous and current metrics runs for evt rate calculations. */
		float duration_sec = (next_check_ts - m_next_check_ts) / (float) ONE_SECOND_IN_NS;		/* Convert interval from nanoseconds to seconds. */
		
		/* Update next values used for prev <-> current comparisons for the next metrics run. */
		m_next_check_ts = next_check_ts;

		/* Retrieve current CPU and memory usages snapshots - ps like approach. */
		uint32_t rss = 0;
		uint32_t vsz = 0;
		float cpu_usage_percentage = 0;
		get_falco_current_rss_vsz_memory(rss, vsz);
		float falco_duration_sec = (now - m_falco_start_ts_epoch) / (float) ONE_SECOND_IN_NS;
		get_falco_current_cpu_usage(cpu_usage_percentage, falco_duration_sec);

		/* If applicable retrieve current cgroup memory usages snapshot. Kubernetes use case only. */
		uint32_t cgroup_memory_used_bytes = 0;
		if (m_do_cgroup_memory_lookup)
		{
			get_falco_container_memory_usage_bytes(cgroup_memory_used_bytes);
		}

		/* Retrieve stats from sinsp libscap */
		scap_stats stats;
		m_inspector->get_capture_stats(&stats);

		/* Resource utilization metrics rule output_fields */
		std::map<std::string, std::string> output_fields;
		output_fields["evt.time"] = std::to_string(now);		/* Current epoch in nanoseconds. */
		output_fields["machine.n_cpus"] = std::to_string(m_machine_info->num_cpus);		/* Total number of CPUs / processors. */
		output_fields["machine.boot_time"] = std::to_string(m_machine_info->boot_ts_epoch);		/* Host boot time - epoch in nanoseconds. */
		output_fields["machine.hostname"] = m_outputs->get_hostname();		/* Explicitly add hostname to log msg in case hostname rule output field is disabled. */
		output_fields["falco.version"] = FALCO_VERSION;		/* Falco version. */
		output_fields["falco.start_time"] = std::to_string(m_falco_start_ts_epoch);		/* Falco start time - epoch in nanoseconds. */
		output_fields["falco.duration_sec"] = std::to_string(falco_duration_sec);		/* Number of nanoseconds between Falco start time and now. */
		output_fields["falco.n_evts"] = std::to_string(num_evts);		/* Monotonic counter number of events Falco has processed. */
		output_fields["falco.n_evts_prev"] = std::to_string(m_prev_num_evts);		/* Previous metrics run - Monotonic counter number of events Falco has processed. */
		output_fields["falco.evt_rate"] = std::to_string((num_evts - m_prev_num_evts) / duration_sec);		/* Number of Falco events per second. */
		output_fields["falco.linux.cpu_usage_percentage"] = std::to_string(cpu_usage_percentage);		/* Falco CPU usage percentage of one CPU, compare to `ps` linux util */
		output_fields["falco.linux.memory_rss_bytes"] = std::to_string(rss * 1024);		/* Retrieved from /proc/<pid>/status, RSS - resident set size in bytes, compare to `ps` linux util */
		output_fields["falco.linux.memory_vsize_bytes"] = std::to_string(vsz * 1024);		/* Retrieved from /proc/<pid>/status, VSZ - virtual size in bytes, compare to `ps` linux util */
		output_fields["falco.cgroup.memory_usage_in_bytes"] = std::to_string(cgroup_memory_used_bytes);		/* Kubernetes only, container memory usage in bytes. */
		if(inspector->check_current_engine(BPF_ENGINE))
		{
			output_fields["falco.kernel_driver"] = "bpf";		/* Falco kernel driver type. */
		} else if(inspector->check_current_engine(MODERN_BPF_ENGINE))
		{
			output_fields["falco.kernel_driver"] = "modern-bpf";
		} else
		{
			output_fields["falco.kernel_driver"] = "kmod";
		}
		output_fields["kernel.release"] = std::string(m_uts.release);		/* Kernel release `uname -r`. */
		output_fields["kernel.n_evts"] = std::to_string(stats.n_evts);		/* Monotonic counter number of total kernel side events the driver has actively traced. */
		output_fields["kernel.n_evts_prev"] = std::to_string(m_prev_n_evts);		/* Previous metrics run - Monotonic counter number of total kernel side events the driver has actively traced. */
		output_fields["kernel.evt_rate"] = std::to_string((stats.n_evts - m_prev_n_evts) / duration_sec);		/* Number of kernel side events per second. */
		output_fields["kernel.n_drops"] = std::to_string(stats.n_drops);		/* Monotonic counter number of total kernel side drops. */

		/* Submit rule msg */
		std::string rule = "Falco internal: resource utilization metrics";
		std::string msg = "";
		m_outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, output_fields);

		/* Update previous values used for prev <-> current comparisons for the next metrics run */
		m_prev_num_evts = num_evts;
		m_prev_n_evts = stats.n_evts;
		
	}

	return true;
}
