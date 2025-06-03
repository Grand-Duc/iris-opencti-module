from iris_interface.IrisModuleInterface import IrisModuleTypes 

module_name = "IrisOpenCTI"
module_description = "Provides an OpenCTI to send IOCs"
interface_version = "1.2.0"
module_version = 1.0
module_type = IrisModuleTypes.module_processor
pipeline_support = False
pipeline_info = {}

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