# -*- coding: binary -*-
#
# Core
#
require 'pathname'

#
# Project
#
require 'fastlib'
require 'msf/core'
require 'msf/core/module_set'

module Msf
  # Upper management decided to throw in some middle management # because the modules were getting out of hand.  This
  # bad boy takes care of the work of managing the interaction with modules in terms of loading and instantiation.
  #
  # @todo add unload support
  class ModuleManager < ModuleSet
    require 'msf/core/payload_set'

    # require here so that Msf::ModuleManager is already defined
    require 'msf/core/module_manager/cache'
    require 'msf/core/module_manager/loading'
    require 'msf/core/module_manager/module_paths'
    require 'msf/core/module_manager/module_sets'
    require 'msf/core/module_manager/reloading'

    include Msf::ModuleManager::Cache
    include Msf::ModuleManager::Loading
    include Msf::ModuleManager::ModulePaths
    include Msf::ModuleManager::ModuleSets
    include Msf::ModuleManager::Reloading

    #
    # CONSTANTS
    #

    # Maps module type directory to its module type.
    TYPE_BY_DIRECTORY = Msf::Modules::Loader::Base::DIRECTORY_BY_TYPE.invert

    # Overrides the module set method for adding a module so that some extra steps can be taken to subscribe the module
    # and notify the event dispatcher.
    #
    # @param (see Msf::ModuleSet#add_module)
    # @return (see Msf::ModuleSet#add_module)
    def add_module(mod, name, file_paths)
      # Call {Msf::ModuleSet#add_module} with same arguments
      dup = super

      # Automatically subscribe a wrapper around this module to the necessary
      # event providers based on whatever events it wishes to receive.  We
      # only do this if we are the module manager instance, as individual
      # module sets need not subscribe.
      auto_subscribe_module(dup)

      # Notify the framework that a module was loaded
      framework.events.on_module_load(name, dup)

      dup
    end

    # Creates a module instance using the supplied reference name.
    #
    # @param [String] name a module reference name.  It may optionally be prefixed with a "<type>/", in which case the
    #   module will be created from the {Msf::ModuleSet} for the given <type>.
    # @return (see Msf::ModuleSet#create)
    def create(name)
      # Check to see if it has a module type prefix.  If it does,
      # try to load it from the specific module set for that type.
      names = name.split(File::SEPARATOR)
      potential_type_or_directory = names.first

      # if first name is a type
      if Msf::Modules::Loader::Base::DIRECTORY_BY_TYPE.has_key? potential_type_or_directory
        type = potential_type_or_directory
      # if first name is a type directory
      else
        type = TYPE_BY_DIRECTORY[potential_type_or_directory]
      end

      if type
        module_set = module_set_by_type[type]

        module_reference_name = names[1 .. -1].join(File::SEPARATOR)
        module_set.create(module_reference_name)
      # Otherwise, just try to load it by name.
      else
        super
      end
    end


    # @param [Msf::Framework] framework The framework for which this instance is managing the modules.
    # @param [Array<String>] types List of module types to load.  Defaults to all module types in {Msf::MODULE_TYPES}.
    def initialize(framework, types=Msf::MODULE_TYPES)
      #
      # defaults
      #

      self.module_info_by_path = {}
      self.enablement_by_type = {}
      self.module_load_error_by_path = {}
      self.module_paths = []
      self.module_set_by_type = {}

      #
      # from arguments
      #

      self.framework = framework

      types.each { |type|
        init_module_set(type)
      }

      super(nil)
    end

    protected

    # This method automatically subscribes a module to whatever event providers it wishes to monitor.  This can be used
    # to allow modules to automatically # execute or perform other tasks when certain events occur.  For instance, when
    # a new host is detected, other aux modules may wish to run such that they can collect more information about the
    # host that was detected.
    #
    # @param [Class] mod a Msf::Module subclass
    # @return [void]
    def auto_subscribe_module(mod)
      # If auto-subscribe has been disabled
      if (framework.datastore['DisableAutoSubscribe'] and
          framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
        return
      end

      # If auto-subscription is enabled (which it is by default), figure out
      # if it subscribes to any particular interfaces.
      inst = nil

      #
      # Exploit event subscriber check
      #
      if (mod.include?(Msf::ExploitEvent) == true)
        framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
      end

      #
      # Session event subscriber check
      #
      if (mod.include?(Msf::SessionEvent) == true)
        framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
      end
    end
  end
end
