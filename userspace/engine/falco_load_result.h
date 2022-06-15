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

#include <string>

// Represents the result of loading a rules file.
class falco_load_result {
public:

	enum error_code {
		FE_LOAD_ERR_FILE_READ,
		FE_LOAD_ERR_YAML_PARSE,
		FE_LOAD_ERR_YAML_VALIDATE,
		FE_LOAD_ERR_COMPILE_CONDITION,
		FE_LOAD_ERR_COMPILE_OUTPUT,
		FE_LOAD_ERR_VALIDATE
	};

	// The error code as a string
	static const std::string& error_code_str(error_code ec);

	// A short string representation of the error
	static const std::string& error_str(error_code ec);

	// A longer description of what the error represents and the
	// impact.
	static const std::string& error_desc(error_code ec);

	enum warning_code {
		FE_LOAD_UNKNOWN_SOURCE,
		FE_LOAD_UNSAFE_NA_CHECK,
		FE_LOAD_NO_EVTTYPE,
		FE_LOAD_UNKNOWN_FIELD,
		FE_LOAD_UNUSED_MACRO,
		FE_LOAD_UNUSED_LIST,
		FE_LOAD_UNKNOWN_ITEM
	};

	// A string representation of the warning code
	static const std::string& warning_code_str(warning_code ec);

	// A short string representation of the warning
	static const std::string& warning_str(warning_code ec);

	// A longer description of what the error represents and the
	// impact.
	static const std::string& warning_desc(warning_code ec);

	virtual bool successful() = 0;

	virtual uint64_t required_engine_version() = 0;

	// This returns a short string with the success value and
	// a list of errors/warnings. Suitable for simple one-line
	// display.
	virtual const std::string& as_summary() = 0;

	// This contains a human-readable version of the result, with
	// full details on the result including document
	// locations/context. If verbose is true, also include full
	// descriptions of errors/warnings. Suitable for display to
	// end users.
	virtual const std::string& as_string() = 0;

	// This contains the full result structure as json, suitable
	// for automated parsing/interpretation later.
	virtual const std::string& as_json() = 0;
};
