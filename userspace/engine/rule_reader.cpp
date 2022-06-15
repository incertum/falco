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

#include "rule_reader.h"

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco_load_result::FE_LOAD_ERR_YAML_VALIDATE, (err), (ctx)); } }

template <typename T>
static void decode_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx, bool optional=false)
{
	const YAML::Node& val = item[key];

	if(!val.IsDefined() && optional)
	{
		return;
	}

	THROW(!val.IsDefined(), std::string("Item has no mapping for key ") + key, ctx);
	THROW(!val.IsScalar(), "Value is not a scalar value", ctx);
	THROW(val.Scalar().empty(), "Value must be non-empty", ctx);

	THROW(!YAML::convert<T>::decode(val, out), "Can't decode YAML scalar value", ctx);
}

template <typename T>
static void decode_seq_generic(const YAML::Node& item, const char *key,
			       std::function<void(T)> inserter,
			       const rule_loader::context &ctx, bool optional=false)
{
	const YAML::Node& val = item[key];

	if(!val.IsDefined() && optional)
	{
		return;
	}

	THROW(!val.IsDefined(), std::string("Item has no mapping for key ") + key, ctx);

	rule_loader::context sctx(val, ctx);

	THROW(!val.IsSequence(), "Value is not a sequence", sctx);

	T value;
	for(const YAML::Node& v : val)
	{
		rule_loader::context ictx(v, sctx);
		THROW(!v.IsScalar(), "sequence value is not scalar", ictx);
		THROW(!YAML::convert<T>::decode(v, value), "Can't decode YAML sequence value", ictx);
		inserter(value);
	}
}

template <typename T>
static void decode_seq(const YAML::Node& item, const char *key, vector<T>& out,
		       const rule_loader::context& ctx, bool optional=false)
{
	std::function<void(T)> inserter = [&out] (T value) {
		out.push_back(value);
	};

	decode_seq_generic(item, key, inserter, ctx, optional);
}

template <typename T>
static void decode_seq(const YAML::Node& item, const char *key, set<T>& out,
		       const rule_loader::context& ctx, bool optional=false)
{
	std::function<void(T)> inserter = [&out] (T value) {
		out.insert(value);
	};

	decode_seq_generic(item, key, inserter, ctx, optional);
}

static void decode_exception_info_entry(
	const YAML::Node& item,
	const char *key,
	rule_loader::rule_exception_info::entry& out,
	const rule_loader::context& ctx)
{
	const YAML::Node& val = (key == NULL ? item : item[key]);

	THROW(!val.IsDefined(), std::string("Item has no mapping for key ") + key, ctx);

	if (val.IsScalar())
	{
		out.is_list = false;
		THROW(!YAML::convert<string>::decode(val, out.item), "Could not decode scalar value", ctx);
	}
	if (val.IsSequence())
	{
		out.is_list = true;
		rule_loader::rule_exception_info::entry tmp;
		for(const YAML::Node& v : val)
		{
			rule_loader::context lctx(v, ctx);
			decode_exception_info_entry(v, NULL, tmp, lctx);
			out.items.push_back(tmp);
		}
	}
}

static void read_rule_exceptions(
	const YAML::Node& item,
	rule_loader::rule_info& v,
	const rule_loader::context& parent)
{
	const YAML::Node& exs = item["exceptions"];

	// No exceptions property, or an exceptions property with
	// nothing in it, are allowed
	if(!exs.IsDefined() || exs.IsNull())
	{
		return;
	}

	rule_loader::context ctx(exs, parent);

	THROW(!exs.IsSequence(), "Rule exceptions must be a sequence", ctx);

	for (auto &ex : exs)
	{
		rule_loader::context ectx(ex, ctx);
		rule_loader::rule_exception_info v_ex;

		decode_val(ex, "name", v_ex.name, ectx);

		// note: the legacy lua loader used to throw a "xxx must strings" error
		decode_exception_info_entry(ex, "fields", v_ex.fields, ectx);
		decode_exception_info_entry(ex, "comps", v_ex.comps, ectx);
		if (ex["values"].IsDefined())
		{
			THROW(!ex["values"].IsSequence(),
			       "Rule exception values must be a sequence", ectx);
			for (auto &val : ex["values"])
			{
				rule_loader::context vctx(val, ectx);
				rule_loader::rule_exception_info::entry v_ex_val;

				decode_exception_info_entry(val, NULL, v_ex_val, vctx);
				v_ex.values.push_back(v_ex_val);
			}
		}
		v.exceptions.push_back(v_ex);
	}
}

static void read_item(
	rule_loader::configuration& cfg,
	rule_loader& loader,
	const YAML::Node& item,
	const rule_loader::context& ctx)
{
	bool optional = true;

	THROW(!item.IsMap(), "Unexpected element type. "
	      "Each element should be a yaml associative array.", ctx);

	if (item["required_engine_version"].IsDefined())
	{
		rule_loader::engine_version_info v;
		v.ctx = ctx;

		decode_val(item, "required_engine_version", v.version, ctx);
		loader.define(cfg, v);
	}
	else if(item["required_plugin_versions"].IsDefined())
	{
		const YAML::Node& req_plugin_vers = item["required_plugin_versions"];

		THROW(!req_plugin_vers.IsSequence(),
		       "Value of required_plugin_versions must be a sequence",
		       ctx);

		for(const YAML::Node& plugin : item["required_plugin_versions"])
		{
			rule_loader::context pctx(plugin, ctx);
			rule_loader::plugin_version_info v;
			v.ctx = pctx;

			decode_val(plugin, "name", v.name, pctx);
			decode_val(plugin, "version", v.version, pctx);

			loader.define(cfg, v);
		}
	}
	else if(item["list"].IsDefined())
	{
		rule_loader::list_info v;
		v.ctx = ctx;
		bool append = false;
		decode_val(item, "list", v.name, ctx);
		decode_seq(item, "items", v.items, ctx);

		decode_val(item, "append", append, ctx, optional);

		if(append)
		{
			loader.append(cfg, v);
		}
		else
		{
			loader.define(cfg, v);
		}
	}
	else if(item["macro"].IsDefined())
	{
		rule_loader::macro_info v;
		v.ctx = ctx;
		bool append = false;
		v.source = falco_common::syscall_source;

		decode_val(item, "macro", v.name, ctx);
		decode_val(item, "condition", v.cond, ctx);
		decode_val(item, "source", v.source, ctx, optional);

		decode_val(item, "append", append, ctx, optional);

		if(append)
		{
			loader.append(cfg, v);
		}
		else
		{
			loader.define(cfg, v);
		}
	}
	else if(item["rule"].IsDefined())
	{
		rule_loader::rule_info v;
		v.ctx = ctx;
		v.append = false;
		v.enabled = true;
		v.warn_evttypes = true;
		v.skip_if_unknown_filter = false;

		decode_val(item, "rule", v.name, ctx);
		decode_val(item, "append", v.append, ctx, optional);

		if(v.append)
		{
			decode_val(item, "condition", v.cond, ctx);
			read_rule_exceptions(item, v, ctx);
			loader.append(cfg, v);
		}
		else
		{
			decode_val(item, "enabled", v.enabled, ctx, optional);

			// If the rule has enabled=true, and does
			// *not* have any of
			// condition/output/desc/priority, simply
			// enable the earlier definition of the rule.
			//
			// XXX/mstemm shouldn't this be in the
			// append=true section?

			if (v.enabled &&
			    !item["condition"].IsDefined() &&
			    !item["output"].IsDefined() &&
			    !item["desc"].IsDefined() &&
			    !item["priority"].IsDefined())
			{
				loader.enable(cfg, v);
			}
			else
			{
				string priority;

				// All of these are required
				decode_val(item, "condition", v.cond, ctx);
				decode_val(item, "output", v.output, ctx);
				decode_val(item, "desc", v.desc, ctx);
				decode_val(item, "priority", priority, ctx);

				v.output = trim(v.output);
				v.source = falco_common::syscall_source;
				THROW(!falco_common::parse_priority(priority, v.priority),
				       "Invalid priority", ctx);
				decode_val(item, "source", v.source, ctx, optional);
				decode_val(item, "warn_evttypes", v.warn_evttypes, ctx, optional);
				decode_val(item, "skip-if-unknown-filter", v.skip_if_unknown_filter, ctx, optional);
				decode_seq(item, "tags", v.tags, ctx, optional);
				read_rule_exceptions(item, v, ctx);
				loader.define(cfg, v);
			}
		}
	}
	else
	{
		cfg.res->add_warning(falco_load_result::FE_LOAD_UNKNOWN_ITEM, "Unknown item", ctx);
	}
}

bool rule_reader::load(rule_loader::configuration& cfg, rule_loader& loader)
{
	rule_loader::context docs_ctx;
	std::vector<YAML::Node> docs;
	try
	{
		docs = YAML::LoadAll(cfg.content);
	}
	catch(const exception& e)
	{
		cfg.res->add_error(falco_load_result::FE_LOAD_ERR_YAML_PARSE, e.what(), docs_ctx);
		cfg.res->build(cfg.content, cfg.verbose);
		return false;
	}

	for (auto doc = docs.begin(); doc != docs.end(); doc++)
	{
		if (doc->IsDefined() && !doc->IsNull())
		{
			rule_loader::context root(*doc, docs_ctx);

			try {

				THROW(!doc->IsMap() && !doc->IsSequence(),
				       "Rules content is not yaml",
				       root);

				THROW(!doc->IsSequence(),
				       "Rules content is not yaml array of objects",
				       root);

				for (auto it = doc->begin(); it != doc->end(); it++)
				{
					if (!it->IsNull())
					{
						rule_loader::context ctx(*it, root);
						read_item(cfg, loader, *it, ctx);
					}
				}
			}
			catch (rule_loader::rule_load_exception &e)
			{
				cfg.res->add_error(e.ec, e.msg, e.ctx);
			};
		}
	}

	cfg.res->build(cfg.content, cfg.verbose);
	return true;
}
