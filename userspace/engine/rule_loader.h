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

#include <map>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>
#include "falco_rule.h"
#include "falco_source.h"
#include "indexed_vector.h"


/*!
	\brief Ruleset loader of the falco engine
*/
class rule_loader
{
public:
	class context
	{
	public:
		context();
		context(const YAML::Node& item, const context& parent);
		virtual ~context() = default;
	private:
		// A chain of locations up to the document root.
		std::list<YAML::Mark> m_marks;
	};

	struct warning
	{
		static const std::string code_strings[];

		std::string as_string(bool single_line);

		falco_engine::load_result::warning_code wc;
		std::string msg;
		context ctx;
	};

	struct error
	{
		static const std::string code_strings[];

		std::string as_string(bool single_line);

		falco_engine::load_result::error_code ec;
		std::string msg;
		context ctx;
	};

	class rule_load_exception : public std::exception {
	public:
		rule_load_exception(error::code ec, std::string msg, const context& ctx);
		virtual ~rule_load_exception();
		const char* what();

		error::code ec;
		std::string msg;
		context ctx;

		std::string errstr;
	};

	/*!
		\brief Contains the result of loading rule definitions
	*/
	class result : public falco_engine::load_result
	{
	public:
		result(const std::string &name);
		virtual ~result() = default;

		virtual bool successful() override;
		virtual uint64_t required_engine_version() override;
		virtual std::string as_string(bool single_line = false) override;

		void add_error(error::code ec, const char *msg, const context& ctx);
		void add_error(error::code ec, const std::string& msg, const context& ctx);
		void add_warning(warning::code ec, const std::string& msg, const context& ctx);
		void add_warning(warning::code ec, const char *msg, const context& ctx);

	protected:
		std::string name;
		uint64_t required_engine_version;
		bool success;

		std::vector<error> errors;
		std::vector<warning> warnings;
	};

	/*!
		\brief Contains the info required to load rule definitions
	*/
	struct configuration
	{
		// The result is a reference so it can be externally provided.
		explicit configuration(
			const std::string& cont,
			const indexed_vector<falco_source>& srcs,
			std::string name)
				: content(cont), sources(srcs), name(name)
			{
				res.reset(new result(name));
			}

		const std::string& content;
		const indexed_vector<falco_source>& sources;
		std::string name;
		std::unique_ptr<result> res;
		std::string output_extra;
		uint16_t default_ruleset_id;
		bool replace_output_container_info;
		falco_common::priority_type min_priority;
	};

	/*!
		\brief Represents infos about an engine version requirement
	*/
	struct engine_version_info
	{
		context ctx;
		uint32_t version;
	};

	/*!
		\brief Represents infos about a plugin version requirement
	*/
	struct plugin_version_info
	{
		context ctx;
		std::string name;
		std::string version;
	};

	/*!
		\brief Represents infos about a list
	*/
	struct list_info
	{
		context ctx;
		bool used;
		size_t index;
		size_t visibility;
		std::string name;
		std::vector<std::string> items;
	};

	/*!
		\brief Represents infos about a macro
	*/
	struct macro_info
	{
		context ctx;
		bool used;
		size_t index;
		size_t visibility;
		std::string name;
		std::string cond;
		std::string source;
		std::shared_ptr<libsinsp::filter::ast::expr> cond_ast;
	};

	/*!
		\brief Represents infos about a single rule exception
	*/
	struct rule_exception_info
	{
		/*!
			\brief This is necessary due to the dynamic-typed nature of
			exceptions. Each of fields, comps, and values, can either be a
			single value or a list of values. This is a simple hack to make
			this easier to implement in C++, that is not non-dynamic-typed.
		*/
		struct entry {
			bool is_list;
			std::string item;
			std::vector<entry> items;

			inline bool is_valid() const
			{
				return (is_list && !items.empty())
					|| (!is_list && !item.empty());
			}
		};

		context ctx;
		std::string name;
		entry fields;
		entry comps;
		std::vector<entry> values;
	};

	/*!
		\brief Represents infos about a rule
	*/
	struct rule_info
	{
		context ctx;
		size_t index;
		size_t visibility;
		std::string name;
		std::string cond;
		std::string source;
		std::string desc;
		std::string output;
		std::set<std::string> tags;
		std::vector<rule_exception_info> exceptions;
		falco_common::priority_type priority;
		bool append;
		bool enabled;
		bool warn_evttypes;
		bool skip_if_unknown_filter;
	};

	virtual ~rule_loader() = default;

	/*!
		\brief Erases all the internal state and definitions
	*/
	virtual void clear();

	/*!
		\brief Uses the internal state to compile a list of falco_rules
	*/
	virtual bool compile(configuration& cfg, indexed_vector<falco_rule>& out) const;

	/*!
		\brief Returns the set of all required versions for each plugin according
		to the internal definitions.
	*/
	virtual const std::map<std::string, std::set<std::string>> required_plugin_versions() const;

	/*!
		\brief Defines an info block. If a similar info block is found
		in the internal state (e.g. another rule with same name), then
		the previous definition gets overwritten
	*/

	virtual void define(configuration& cfg, engine_version_info& info);
	virtual void define(configuration& cfg, plugin_version_info& info);
	virtual void define(configuration& cfg, list_info& info);
	virtual void define(configuration& cfg, macro_info& info);
	virtual void define(configuration& cfg, rule_info& info);

	/*!
		\brief Appends an info block to an existing one. An exception
		is thrown if no existing definition can be matched with the appended
		one
	*/
	virtual void append(configuration& cfg, list_info& info);
	virtual void append(configuration& cfg, macro_info& info);
	virtual void append(configuration& cfg, rule_info& info);

	/*!
		\brief Updates the 'enabled' flag of an existing definition
	*/
	virtual void enable(configuration& cfg, rule_info& info);
private:
	void compile_list_infos(
		configuration& cfg,
		indexed_vector<list_info>& out) const;
        void compile_macros_infos(
		configuration& cfg,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& out) const;
	void compile_rule_infos(
		configuration& cfg,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& macros,
		indexed_vector<falco_rule>& out) const;

	uint32_t m_cur_index;
	indexed_vector<rule_info> m_rule_infos;
	indexed_vector<macro_info> m_macro_infos;
	indexed_vector<list_info> m_list_infos;
	std::map<std::string, std::set<std::string>> m_required_plugin_versions;
};
