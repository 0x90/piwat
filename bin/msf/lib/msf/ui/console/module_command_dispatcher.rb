# -*- coding: binary -*-
require 'msf/ui/console/command_dispatcher'

module Msf
module Ui
module Console

###
#
# Module-specific command dispatcher.
#
###
module ModuleCommandDispatcher

	include Msf::Ui::Console::CommandDispatcher

	def commands
		{
			"pry"    => "Open a Pry session on the current module",
			"reload" => "Reload the current module from disk"
		}
	end

	#
	# The active driver module, if any.
	#
	def mod
		return driver.active_module
	end

	#
	# Sets the active driver module.
	#
	def mod=(m)
		self.driver.active_module = m
	end

	def cmd_pry_help
		print_line "Usage: pry"
		print_line
		print_line "Open a pry session on the current module.  Be careful, you"
		print_line "can break things."
		print_line
	end

	def cmd_pry(*args)
		begin
			require 'pry'
		rescue LoadError
			print_error("Failed to load pry, try 'gem install pry'")
			return
		end
		mod.pry
	end

	#
	# Reloads the active module
	#
	def cmd_reload(*args)
		begin
			reload
		rescue
			log_error("Failed to reload: #{$!}")
		end
	end

	@@reload_opts =  Rex::Parser::Arguments.new(
		'-k' => [ false,  'Stop the current job before reloading.' ],
		'-h' => [ false,  'Help banner.' ])

	def cmd_reload_help
		print_line "Usage: reload [-k]"
		print_line
		print_line "Reloads the current module."
		print @@reload_opts.usage
	end

	#
	# Reload the current module, optionally stopping existing job
	#
	def reload(should_stop_job=false)
		if should_stop_job and mod.job_id
			print_status('Stopping existing job...')

			framework.jobs.stop_job(mod.job_id)
			mod.job_id = nil
		end

		print_status('Reloading module...')

		original_mod = self.mod
		reloaded_mod = framework.modules.reload_module(original_mod)

		unless reloaded_mod
      error = framework.modules.module_load_error_by_path[original_mod.file_path]

			print_error("Failed to reload module: #{error}")

			self.mod = original_mod
    else
      self.mod = reloaded_mod

      self.mod.init_ui(driver.input, driver.output)
    end

    reloaded_mod
	end

end


end end end

