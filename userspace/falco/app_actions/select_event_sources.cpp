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

using namespace falco::app;

application::run_result application::select_event_sources()
{
	for(const auto &src : m_options.disable_sources)
	{
		if (m_state->enabled_sources.find(src) == m_state->enabled_sources.end())
		{
			return run_result::fatal("Attempted disabling unknown event source: " + src);
		}
		m_state->enabled_sources.erase(src);
	}

	if(m_state->enabled_sources.empty())
	{
		return run_result::fatal("At least one event source needs to be enabled");
	}
	
	return run_result::ok();
}
