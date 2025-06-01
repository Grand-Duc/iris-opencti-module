# Import the module types list,  so we can indicate the type of our module 
from iris_interface.IrisModuleInterface import IrisModuleTypes 

# Human name displayed in the GUI Manage > Modules. This can be anything, 
# but try to put something meaningful, so users recognize your module. 
module_name = "IrisOpenCTI"

# Description displayed when editing the module configuration in the UI. 
# This can be anything, 
module_description = "Provides an OpenCTI to send IOCs"

# Set the interface version used. This needs to be the version of 
# the IrisModuleInterface package. This version is check by the server to
# to ensure our module can run on this specific server 
interface_version = 1.1

# The version of the module itself, it can be anything 
module_version = 1.0

# The type of the module, here processor 
module_type = IrisModuleTypes.module_processor

# Our module is a processor type, so it doesn't offer any pipeline 
pipeline_support = False

# Provide no pipeline information as our module don't implement any 
pipeline_info = {}

# The configuration of the module that will be displayed and configurable 
# by administrators on the UI. This describes every parameter that can 
# be set. 
module_configuration = [
    {
        "param_name": "opencti_on_ioc_create_hook_enabled",
        "param_human_name": "OpenCTI receive hook on IOC creation",
        "param_description": "If set to true, the module will register to the OpenCTI hook on IOC creation. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "opencti_on_ioc_update_hook_enabled",
        "param_human_name": "OpenCTI receive hook on IOC update",
        "param_description": "If set to true, the module will register to the OpenCTI hook on IOC update. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "opencti_on_ioc_delete_hook_enabled",
        "param_human_name": "OpenCTI receive hook on IOC deletion",
        "param_description": "If set to true, the module will register to the OpenCTI hook on IOC deletion. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "opencti_on_case_create_hook_enabled",
        "param_human_name": "OpenCTI receive hook on case creation",
        "param_description": "If set to true, the module will register to the OpenCTI hook on Case creation. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "opencti_on_case_update_hook_enabled",
        "param_human_name": "OpenCTI receive hook on case update",
        "param_description": "If set to true, the module will register to the OpenCTI hook on Case update. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "opencti_on_case_delete_hook_enabled",
        "param_human_name": "OpenCTI receive hook on case deletion",
        "param_description": "If set to true, the module will register to the OpenCTI hook on Case deletion. Otherwise, it will not register.",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    # {
    #     "param_name": "priority_on_delete",
    #     "param_human_name": "DFIRI IRIS priority on delete action",
    #     "param_description": "If set to true, IOC / Case delete on DFIR IRIS will also be deleted in OpenCTI evene if not created by IRIS.",
    #     "default": False,
    #     "mandatory": True,
    #     "type": "bool"
    # },
    # {
    #     "param_name": "priority_on_update",
    #     "param_human_name": "DFIRI IRIS priority on update action",
    #     "param_description": "If set to true, IOC / Case update on DFIR IRIS will also be updated in OpenCTI evene if not created by IRIS.",
    #     "default": False,
    #     "mandatory": True,
    #     "type": "bool"
    # },
    {
      "param_name": "opencti_api_key",
      "param_human_name": "OpenCTI API Key",
      "param_description": "OpenCTI API key",
      "default": None,
      "mandatory": True,
      "type": "sensitive_string"
    },
    {
      "param_name": "opencti_url",
      "param_human_name": "OpenCTI URL",
      "param_description": "OpenCTI URL",
      "default": None,
      "mandatory": True,
      "type": "string"
    },
]