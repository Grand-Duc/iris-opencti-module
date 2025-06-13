#!/usr/bin/env python3

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
import iris_opencti_module.IrisOpenCTIConfig as interface_conf
from iris_opencti_module.opencti_handler.opencti_handler import OpenCTIHandler


class IrisOpenCTIModule(IrisModuleInterface):

    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = interface_conf.module_type


    def register_hooks(self, module_id: int):
        self.module_id = module_id
        module_conf = self.module_dict_conf

        HOOKS_CONFIG = {
            'opencti_on_ioc_create_hook_enabled': 'on_postload_ioc_create',
            'opencti_on_ioc_update_hook_enabled': 'on_postload_ioc_update',
            'opencti_on_ioc_delete_hook_enabled': 'on_postload_ioc_delete',
            'opencti_on_case_create_hook_enabled': 'on_postload_case_create',
            'opencti_on_case_update_hook_enabled': 'on_postload_case_update',
            'opencti_on_case_delete_hook_enabled': 'on_postload_case_delete',
        }

        for config_key, hook_name in HOOKS_CONFIG.items():
            if module_conf.get(config_key):
                status = self.register_to_hook(module_id=self.module_id, iris_hook_name=hook_name)
                if status.is_failure():
                    self.log.error(f"Failed to register '{hook_name}' hook: {status.get_message()} - {status.get_data()}")
                else:
                    self.log.info(f"Successfully registered '{hook_name}' hook.")
            else:
                status = self.deregister_from_hook(module_id=self.module_id, iris_hook_name=hook_name)
                if status.is_failure():
                    self.log.warning(f"Attempted to deregister '{hook_name}' hook, encountered status: {status.get_message()}")
                else:
                    self.log.info(f"Ensured '{hook_name}' hook is deregistered (if it was active).")


    def hooks_handler(self, hook_name: str, hook_ui_name: str, data):
        self.log.info(f"Received hook: '{hook_name}' (UI: '{hook_ui_name}')")

        HOOK_PROCESSORS = {
            'on_postload_ioc_create': self._process_ioc_creation,
            'on_postload_ioc_update': self._process_ioc_update,
            'on_postload_ioc_delete': self._process_ioc_deletion,
            'on_postload_case_create': self._process_case_creation,  # Reusing IOC creation logic for case creation
            'on_postload_case_update': self._process_case_update,  # Reusing IOC update logic for case update
            'on_postload_case_delete': self._process_case_deletion,  # Reusing IOC deletion logic for case deletcase
        }

        processor_method = HOOK_PROCESSORS.get(hook_name)
        if not processor_method:
            self.log.critical(f"Received unsupported hook '{hook_name}'. No processor defined.")
            return InterfaceStatus.I2Error(data=data, message=f"Unsupported hook: {hook_name}")

        try:
            processor_method(data)

            self.log.info(f"Successfully processed hook '{hook_name}'.")
            return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
        except Exception as e:
            self.log.error(f"Encountered an unhandled error while processing hook '{hook_name}': {e}", exc_info=True)
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

    def _process_case_creation(self, cases) -> InterfaceStatus.IIStatus:
        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)
        for case in cases:
            self.log.info(f"Processing case creation for: {case.name} (ID: {case.case_id})")
            try:
                opencti_handler.iris_case = case
                opencti_case = opencti_handler.check_and_create_case()

                if not opencti_case:
                    self.log.error(f"Failed to create or find OpenCTI case for IRIS case '{case.name}'. Skipping IOC processing.")
                    continue

                self.log.info(f"OpenCTI case created/verified successfully: {opencti_case.get('id')}")

            except Exception as e:
                self.log.error(f"Error processing case creation for {case.name}: {e}", exc_info=True)

        self.log.info("Case creation processing complete.")
        return InterfaceStatus.I2Success(data=cases, logs=list(self.message_queue))

    def _process_case_deletion(self, case_numbers) -> InterfaceStatus.IIStatus:
        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)

        for case_number in case_numbers:
            self.log.info(f"Starting case deletion process for case #{case_number}.")
            if case_number:
                try:
                    existing_opencti_case = opencti_handler.check_case_exists_from_iris_id(case_number)

                    if existing_opencti_case and existing_opencti_case.get('id'):
                        opencti_case_id = existing_opencti_case.get('id')

                        success = opencti_handler.delete_case(opencti_case_id = opencti_case_id)
                        if success:
                            self.log.info(f"Successfully initiated deletion for OpenCTI case ID {opencti_case_id}.")
                        else:
                            self.log.warning(f"Deletion command for OpenCTI case ID {opencti_case_id} may have failed or status unclear.")

                except Exception as e:
                    self.log.error(f"Error processing case deletion for {case_number}: {e}", exc_info=True)

        self.log.info("Case deletion processing complete.")
        return InterfaceStatus.I2Success(data=case_numbers, logs=list(self.message_queue))

    def _process_case_update(self, cases) -> InterfaceStatus.IIStatus:
        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)
        # TODO
        return InterfaceStatus.I2Success(data=cases, logs=list(self.message_queue))


    def _process_ioc_creation(self, iocs) -> InterfaceStatus.IIStatus:
        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)
        for ioc in iocs:
            self.log.info(f"Processing IOC creation for: {ioc.ioc_value} (Type: {ioc.ioc_type.type_name}, Case: {ioc.case.name if ioc.case else 'N/A'})")
            try:
                opencti_handler.ioc = ioc
                opencti_handler.iris_case = ioc.case
                opencti_case = opencti_handler.check_and_create_case()

                opencti_observable = opencti_handler.check_ioc_exists()

                ioc.ioc_tags = ','.join([tag for tag in ioc.ioc_tags.split(',') if not tag.startswith('OCTI_')])

                if not opencti_observable:
                    self.log.info(f"OpenCTI observable for IOC '{ioc.ioc_value}' not found, attempting creation.")
                    opencti_observable = opencti_handler.create_ioc() # Uses self.ioc from handler
                    if not opencti_observable:
                        self.log.error(f"Failed to create or find OpenCTI observable for IOC '{ioc.ioc_value}'. Skipping relationship.")
                        continue
                else:
                    # If observable already exists, it must have been either already present in OpenCTI OR modified by IRIS. (e.g. -> TLP, description, etc.)
                    # Even if we can re-create the same IOC it has a major flaws which is that you cannot lower the TLP with a creation (the higher TLP will stay).
                    # That's why an UPDATE is made instead of a CREATION.
                    self.log.info(f"OpenCTI observable (ID: {opencti_observable.get('id')}) for IOC '{ioc.ioc_value}' found.")
                    if opencti_handler.check_ioc_ownership(opencti_observable):
                        opencti_observable = opencti_handler.update_ioc(opencti_ioc_id = opencti_observable.get('id'))
                    else:
                        self.log.info(f"OpenCTI observable (ID: {opencti_observable.get('id')}) for IOC '{ioc.ioc_value}' is not owned by IRIS. Updating tags and TLP.")
                        score = opencti_observable.get('x_opencti_score')
                        if score and f'OCTI_score:{score}' not in ioc.ioc_tags.split(','):
                            ioc.ioc_tags = f"{ioc.ioc_tags},OCTI_score:{score}"
                        if opencti_observable.get('objectLabel', []):
                            temp_tag = ''
                            for label in opencti_observable.get('objectLabel'):
                                tag = label.get('value', None)
                                if tag and f'OCTI_tag:{tag}' not in ioc.ioc_tags.split(','):
                                    temp_tag += f'OCTI_tag:{tag},'
                            ioc.ioc_tags = f"{ioc.ioc_tags},{temp_tag}"
                            self.log.info(f"Updated IOC tags for {ioc.ioc_value} to: {ioc.ioc_tags}")

                        if opencti_observable.get('objectMarking', []):
                            iris_tlp = opencti_handler.get_iris_marking(opencti_observable.get('objectMarking')[0].get('definition'))
                            if iris_tlp and iris_tlp != ioc.ioc_tlp_id:
                                old_tlp = ioc.tlp.tlp_name if ioc.tlp else 'N/A'
                                ioc.ioc_tlp_id = iris_tlp
                                self.log.info(f"Updated IOC TLP for {ioc.ioc_value} from {old_tlp} to {ioc.tlp.tlp_name}.")

                if opencti_case and opencti_observable:
                    opencti_case_id = opencti_case.get('id')
                    observable_id = opencti_observable.get('id')
                    if opencti_case_id and observable_id:
                        self.log.info(f"Attempting to link OpenCTI case '{opencti_case_id}' with observable '{observable_id}'.")
                        opencti_handler.create_relationship(case_id=opencti_case_id, ioc_id=observable_id, relationship_type="object")
                    else:
                        self.log.warning(f"Missing OpenCTI case ID or observable ID for IOC {ioc.ioc_value}. Cannot create relationship.")
                else:
                    self.log.warning(f"Skipping relationship creation for IOC {ioc.ioc_value} due to missing OpenCTI case or observable.")

            except Exception as e:
                self.log.error(f"Error processing IOC creation for {ioc.ioc_value}: {e}", exc_info=True)


    def _process_ioc_update(self, iocs) -> InterfaceStatus.IIStatus:
        self.log.info("Starting IOC update process. Ensuring all IOCs and cases exist first (creation logic).")

        self._process_ioc_creation(iocs)


        self.log.info("Creation/existence check complete. Proceeding with update-specific logic (comparison).")
        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)

        for ioc in iocs:
            opencti_handler.ioc = ioc
            opencti_handler.iris_case = ioc.case
            try:
                if not opencti_handler.opencti_case:
                    opencti_handler.opencti_case = opencti_handler.check_case_exists()
                if opencti_handler.opencti_case and opencti_handler.opencti_case.get('id'):
                    self.log.info(f"OpenCTI case (ID: {opencti_handler.opencti_case.get('id')}) found for IOC {ioc.ioc_value}. Proceeding with comparison.")
                    opencti_handler.compare_ioc(opencti_case_id=opencti_handler.opencti_case.get('id'))
                else:
                    self.log.warning(f"No OpenCTI case found for IOC {ioc.ioc_value} during update's comparison phase. Skipping comparison.")

            except Exception as e:
                self.log.error(f"Error processing IOC update (comparison phase) for {ioc.ioc_value}: {e}", exc_info=True)


    def _process_ioc_deletion(self, iocs) -> InterfaceStatus.IIStatus:
        #TODO Not functional yet

        opencti_handler = OpenCTIHandler(mod_config=self._dict_conf, logger=self.log)
        # self.log.info(f"Starting IOC deletion process. {iocs}")
        # for ioc in iocs:
        #     opencti_handler.ioc = ioc
        #     opencti_handler.iris_case = ioc.case
        #     self.log.info(f"Processing IOC deletion for: {ioc.ioc_value} (Type: {ioc.ioc_type.type_name})")
        #     try:
        #         existing_opencti_ioc = opencti_handler.check_ioc_exists()

        #         if existing_opencti_ioc and existing_opencti_ioc.get('id'):
        #             opencti_ioc_id = existing_opencti_ioc.get('id')
        #             self.log.info(f"IOC {ioc.ioc_value} (OpenCTI ID: {opencti_ioc_id}) exists in OpenCTI. Attempting deletion.")

        #             success = opencti_handler.delete_ioc(opencti_ioc_id)
        #             if success:
        #                 self.log.info(f"Successfully initiated deletion for OpenCTI IOC ID {opencti_ioc_id}.")
        #             else:
        #                 self.log.warning(f"Deletion command for OpenCTI IOC ID {opencti_ioc_id} may have failed or status unclear.")
        #         else:
        #             self.log.info(f"IOC {ioc.ioc_value} does not exist in OpenCTI or could not be verified. Skipping deletion.")

        #     except Exception as e:
        #         self.log.error(f"Error processing IOC deletion for {ioc.ioc_value}: {e}", exc_info=True)