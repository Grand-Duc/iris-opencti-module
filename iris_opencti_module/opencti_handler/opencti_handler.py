import requests
from iris_opencti_module.opencti_handler.query import *
from iris_opencti_module.opencti_handler.opencti_stix_cyber_observable import make_query
from app.datamgmt.case.case_iocs_db import get_detailed_iocs
from app.datamgmt.case.case_iocs_db import get_tlps_dict


class OpenCTIHandler:

    HASH_TYPES = ['md5', 'sha1', 'sha256', 'sha512']
    IP_TYPES = ['ip-any', 'ip-dst', 'ip-src']
    EMAIL_TYPES = ['email-src', 'email-dst']
    EMAIL_DISPLAY_NAMES = ['email-src-display-name', 'email-dst-display-name']
    X509_TYPES = ['x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256']


    ATTRIBUTE_CONFIG = { # key -> type.attribute (except for hashes and extensions)
        'md5': { 
            'key' : 'File.hashes.MD5'
            # Hashes type need to be UPPERCASE to match OpenCTI's expected format for key filtering
            # (For IOC creation, hashes are correctly put in lowercase)
        },
        'sha1': {
            'key': 'File.hashes.SHA-1',
        },
        'sha256': {
            'key': 'File.hashes.SHA-256',
        },
        # 'sha512': {
        #     'key': 'file.hashes.SHA-512', # TODO: check if this is supported by OpenCTI
        # },
        'ip-any': {
            'key': 'IPv4-Addr.value',
        },
        'ip-src': {
            'key': 'IPv4-Addr.value',
        },
        'ip-dst': {
            'key': 'IPv4-Addr.value',
        },
        'email-src': {
            'key': 'Email-Addr.value',
        },
        'email-dst': {
            'key': 'Email-Addr.value',
        },
        'email-src-display-name': { #TODO handle only if also email-src is present
            'key': 'Email-Addr.display_name',
        },
        'email-dst-display-name': { #TODO handle only if also email-dst is present
            'key': 'Email-Addr.display_name',
        },
        'domain': {
            'key': 'Domain-Name.value',
        },
        'filename': {
            'key': 'File.name',
        },
        'AS': {
            'key': 'Autonomous-System.number',
        },
        "hostname": {
            'key': 'Hostname.value',
        },
        'btc': {
            'key': 'Cryptocurrency-Wallet.value',
        },
        'url': {
            'key': 'Url.value',
        },
        'uri': {
            'key': 'Url.value',
        },
        "user-agent": {
            'key': 'User-Agent.value',
        },
        "pgp-private-key": {
            'key': 'Cryptographic-Key.value',
        },
        "pgp-public-key": {
            'key': 'Cryptographic-Key.value',
        },
        "file-path": {
            'key': 'Directory.path',
        },
        "email-body": {
            'key': 'Email-Message.body',
        },
        "email-mime-boundary": { #TODO doesn't work
            'key': 'Email-Mime-Part-Type.body',
        },
        "mime-type": { #TODO doesn't work -> artefacts needs hashs etc.
            'key': 'Artifact.mime_type',
        },
        "x509-fingerprint-md5": {
            'key': 'X509-Certificate.hashes.MD5',
        },
        "x509-fingerprint-sha1": {
            'key': 'X509-Certificate.hashes.SHA-1',
        },
        "x509-fingerprint-sha256": {
            'key': 'X509-Certificate.hashes.SHA-256',
        },
        "mac-address": {
            'key': 'Mac-Addr.value',
        },
        "mutex": {
            'key': 'Mutex.name',
        },
        "malware-type": {
            'key': 'Software.name',
        },
        "malware-sample": {
            'key': 'Software.name',
        },
        "target-user":{
            'key': 'User-Account.user_id',
        },
        "account":{
            'key': 'User-Account.user_id',
        },
        "regkey": {
            'key': 'Windows-Registry-Key.key',
        },
        "text": {
            'key': 'Text.value',
        },
        "phone-number": {
            'key': 'Phone-Number.value',
        },
        "regkey|value": { # since Windows-Registry-Key only supports key, we need to handle the value with Windows-Registry-Value-Type
            "regkey" : { 'key': 'Windows-Registry-Value-Type.name', },
            "value" : { 'key': 'Windows-Registry-Value-Type.data', }
        },
    }


    def __init__(self, mod_config, logger, ioc = None):
        self.mod_config = mod_config
        self.log = logger
        self.opencti_api_url = mod_config.get('opencti_url', None)
        self.opencti_api_key = mod_config.get('opencti_api_key', None)
        self.ioc = ioc
        self.iris_case = ioc.case if ioc and hasattr(ioc, 'case') else None
        self.api_user_id = self.get_api_user().get('id')
        self.opencti_case = None

    def _execute_graphql_query(self, query: str, variables: dict = None):
        """
        Helper method to execute a GraphQL query against the OpenCTI API.

        Args:
            query (str): The GraphQL query string.
            variables (dict, optional): Variables for the GraphQL query.

        Returns:
            dict: The 'data' part of the JSON response if successful, None otherwise.
        """

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.opencti_api_key}",
        }
        json_payload = {"query": query}
        if variables:
            json_payload["variables"] = variables

        try:
            response = requests.post(self.opencti_api_url, headers=headers, json=json_payload, verify=False)
            response.raise_for_status()

            response_json = response.json()
            if "errors" in response_json:
                self.log.error(f"OpenCTI API returned errors: {response_json['errors']}")
                return None
            return response_json.get('data')

        except requests.exceptions.RequestException as e:
            self.log.error(f"Error sending query to OpenCTI: {e}")
        except ValueError as e: # JSON decoding error
            self.log.error(f"Error decoding JSON response from OpenCTI: {e}")
        return None

    def get_api_user(self):
        """
        Retrieves the API user information from OpenCTI.

        Returns:
            dict: The API user information if successful, None otherwise.
        """
        self.log.info("Retrieving OpenCTI API user information.")
        data = self._execute_graphql_query(GET_API_USER_QUERY)

        if data and data.get('me'):
            api_user = data['me']
            self.log.info(f"OpenCTI API user retrieved: {api_user.get('name')} (ID: {api_user.get('id')})")
            return api_user

        self.log.error("Failed to retrieve OpenCTI API user information.")
        return None

    def check_and_create_case(self):
        """
        Checks if the case associated with self.iris_case exists in OpenCTI.
        If it does not exist, creates a new case.

        Returns:
            dict: The OpenCTI case node if it exists or was created, None otherwise.
        """
        existing_case = self.check_case_exists()
        if existing_case:
            return existing_case

        return self.create_case()

    def check_case_exists(self):
        """
        Checks if the case associated with self.iris_case exists in OpenCTI.
        Uses self.iris_case.name for checking.

        Returns:
            dict: The OpenCTI case node if it exists, None otherwise.
        """
        if not self.iris_case:
            self.log.warning("No Iris case information available to check in OpenCTI.")
            return None

        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "name", "values": [self.iris_case.name]}], # TODO: Consider unique case identifier
                "filterGroups": []
            }
        }
        self.log.info(f"Checking if OpenCTI case '{self.iris_case.name}' exists.")
        data = self._execute_graphql_query(CHECK_CASE_EXISTS_QUERY, variables)

        if data and data.get('caseIncidents') and data['caseIncidents'].get('edges'):
            case_node = data['caseIncidents']['edges'][0]['node']
            self.log.info(f"OpenCTI case '{case_node.get('name')}' (ID: {case_node.get('id')}) exists.")
            return case_node

        self.log.info(f"OpenCTI case '{self.iris_case.name}' does not exist or query failed.")
        return None

    def check_case_exists_from_iris_id(self, case_iris_id):
        """
        Checks if the case associated with self.iris_case exists in OpenCTI.
        Uses self.iris_case.case_id for checking.
        Returns:
            dict: The OpenCTI case node if it exists, None otherwise.
        """
        if not case_iris_id:
            self.log.warning("No Iris case information available to check in OpenCTI.")
            return None

        variables = {
            "filters": {
                "mode": "and",
                "filters": [{
                    "key": "name",
                    "values": [f"#{case_iris_id} - "],
                    "operator": "starts_with"
                }],
                "filterGroups": []
                }
            }
        self.log.info(f"Checking if OpenCTI case with Iris ID '{case_iris_id}' exists.")
        data = self._execute_graphql_query(CHECK_CASE_EXISTS_QUERY, variables)

        if data and data.get('caseIncidents') and data['caseIncidents'].get('edges'):
            case_node = data['caseIncidents']['edges'][0]['node']
            self.log.info(f"OpenCTI case '{case_node.get('name')}' (ID: {case_node.get('id')}) exists.")
            return case_node

        self.log.info(f"OpenCTI case with Iris ID '{case_iris_id}' does not exist or query failed.")
        return None

    def check_ioc_exists(self):
        """
        Checks if the IOC (self.ioc) exists in OpenCTI.

        Returns:
            dict: The OpenCTI observable node if it exists, None otherwise.
        """
        ioc_type_name = self.ioc.ioc_type.type_name
        ioc_value = self.ioc.ioc_value
        CONFIG = self.ATTRIBUTE_CONFIG.get(ioc_type_name, None)

        if '|' in ioc_type_name:
            ioc_parts = ioc_type_name.split('|')
            part = ioc_parts[0]
            ioc_value = ioc_value.split('|')[0] if '|' in ioc_value else ioc_value
            if CONFIG and part in CONFIG:
                type, _, attribute = CONFIG.get(part).get('key').partition(".")
            else:
                key_part = self.ATTRIBUTE_CONFIG[part].get('key', None)
                if key_part:
                    type, _, attribute = self.ATTRIBUTE_CONFIG[part].get('key', None).partition(".")
                else:
                    self.log.error(f"Unsupported IOC type: {part} for IOC value {ioc_value}")
                    return None
        else:
            type, _, attribute = CONFIG.get('key').partition(".")

        variables = {
            "types": [type],
            "filters": {
                "mode": "and",
                "filters": [{"key": attribute, "values": [ioc_value]}],
                "filterGroups": []
            }
        }

        self.log.info(f"Checking if OpenCTI IOC '{self.ioc.ioc_value}' (Type: {ioc_type_name}) exists.")
        data = self._execute_graphql_query(CHECK_IOC_EXISTS_QUERY, variables)

        if data and data.get('stixCyberObservables') and data['stixCyberObservables'].get('edges'):
            ioc_node = data['stixCyberObservables']['edges'][0]['node']
            self.log.info(f"OpenCTI IOC '{ioc_node.get('observable_value')}' (ID: {ioc_node.get('id')}) exists.")
            return ioc_node

        self.log.info(f"OpenCTI IOC '{self.ioc.ioc_value}' does not exist or query failed.")
        return None

    def create_ioc(self):
        """
        Creates a new IOC in OpenCTI based on the current IOC variable (self.ioc).
        Returns:
            dict: The created OpenCTI observable node if successful, None otherwise.
        """
        ioc_value = self.ioc.ioc_value
        ioc_type = self.ioc.ioc_type.type_name
        field_names = ioc_type.split('|')
        CONFIG = self.ATTRIBUTE_CONFIG.get(ioc_type, None)
        object_marking = self.get_marking(self.ioc.tlp.tlp_name) if self.ioc.tlp else None
        simple_observable_description = self.ioc.ioc_description if self.ioc.ioc_description else None
        if len(field_names) > 1:
            ioc_value = ioc_value.split('|')

            observable_data = {}
            for i, field_name in enumerate(field_names):
                if not CONFIG or field_name not in CONFIG:
                    details = self.ATTRIBUTE_CONFIG.get(field_name, {})
                    if not details:
                        self.log.error(f"Unsupported IOC field: {field_name} for IOC value {ioc_value[i]}")
                        return None
                else:
                    details = CONFIG[field_name]

                value = ioc_value[i]
                parts = details.get('key').split('.')
                if 'type' not in observable_data:
                    observable_data['type'] = parts[0]
                parts = parts[1:]
                current = observable_data
                for j, part in enumerate(parts):
                    if j == len(parts) - 1:
                        current[part] = value
                    else:
                        if part not in current:
                            current[part] = {}
                        current = current[part]

            variables = make_query(observableData=observable_data,
                            objectMarking=object_marking,
                            simple_observable_description=simple_observable_description)
        else:
            simple_observable_key = CONFIG.get('key', 'None')
            variables = make_query(simple_observable_key=simple_observable_key,
                                simple_observable_value=ioc_value,
                                objectMarking=object_marking,
                                simple_observable_description=simple_observable_description)
        try:
            result = self._execute_graphql_query(CREATE_IOC_QUERY, variables)
            if result:
                self.log.info(f"IOC created successfully {result}")
                return result.get('stixCyberObservableAdd', {})
            else:
                self.log.error("Failed to create IOC")
                return None
        except ValueError as e:
            self.log.error(f"Create IOC failed: {str(e)}")
            return None

    def update_ioc(self, opencti_ioc_id: str):
        """
        Updates an existing IOC in OpenCTI with the current IOC variable (description, objectmarking).

        Args:
            opencti_ioc_id (str): The ID of the OpenCTI observable to update.

        Returns:
            dict: The updated OpenCTI observable node if successful, None otherwise.
        """
        if not opencti_ioc_id:
            self.log.error("OpenCTI IOC ID is required for update.")
            return None

        variables = {
            "id": opencti_ioc_id,
            "input": []
        }

        if self.ioc.ioc_description:
            variables["input"].append({
                "key": "x_opencti_description",
                "value": self.ioc.ioc_description
            })
        if self.ioc.tlp:
            object_marking = self.get_marking(self.ioc.tlp.tlp_name)
            if object_marking:
                variables["input"].append({
                    "key": "objectMarking",
                    "value": [object_marking]
                })
        if not variables["input"]:
            self.log.info("No updates to apply to the IOC. Skipping update.")
            return None
        self.log.info(f"Updating OpenCTI IOC ID: {opencti_ioc_id} with input: {variables['input']}")
        try:
            result = self._execute_graphql_query(UPDATE_IOC_QUERY, variables)
            if result and result.get('stixCyberObservableEdit'):
                updated_ioc = result['stixCyberObservableEdit'].get('fieldPatch')
                if updated_ioc:
                    self.log.info(f"OpenCTI IOC ID: {opencti_ioc_id} updated successfully.")
                    return updated_ioc
                else:
                    self.log.error("Update IOC failed: No fieldPatch in response.")
                    return None
            else:
                self.log.error("Update IOC failed: No stixCyberObservableEdit in response.")
                return None
        except ValueError as e:
            self.log.error(f"Update IOC failed: {str(e)}")
            return None

    def delete_ioc(self, opencti_ioc_id: str):
        """
        Deletes an IOC from OpenCTI by its OpenCTI ID.

        Args:
            opencti_ioc_id (str): The ID of the OpenCTI observable to delete.

        Returns:
            bool: True if deletion was successful (or seemed to be), False otherwise.
        """
        if not opencti_ioc_id:
            self.log.error("OpenCTI IOC ID is required for deletion.")
            return False

        variables = {"id": opencti_ioc_id}
        self.log.info(f"Attempting to delete OpenCTI IOC ID: {opencti_ioc_id}.")
        data = self._execute_graphql_query(DELETE_IOC_QUERY, variables)


        if data is not None:
            if data.get('stixCyberObservableDelete') is not None:
                self.log.info(f"OpenCTI IOC ID: {opencti_ioc_id} deletion command sent successfully.")
                return True
            elif 'stixCyberObservableEdit' in data and data['stixCyberObservableEdit'].get('delete'):
                 self.log.info(f"OpenCTI IOC ID: {opencti_ioc_id} deletion via edit successful.")
                 return True


        self.log.error(f"Failed to delete OpenCTI IOC ID: {opencti_ioc_id}.")
        return False

    def create_case(self):
        """
        Creates a case in OpenCTI based on self.iris_case.

        Returns:
            dict: The created OpenCTI case node if successful, None otherwise.
        """
        if not self.iris_case:
            self.log.error("No Iris case information available to create in OpenCTI.")
            return None

        case_input = {
            "name": self.iris_case.name,
            "description": self.iris_case.description or "",
        }

        if hasattr(self.iris_case, 'initial_date') and self.iris_case.initial_date:
            case_input["created"] = self.iris_case.initial_date.isoformat() + 'Z'

        variables = {"input": case_input}
        self.log.info(f"Creating OpenCTI case for Iris case '{self.iris_case.name}'.")
        data = self._execute_graphql_query(CREATE_CASE_QUERY, variables)

        if data and data.get('caseIncidentAdd'):
            created_case = data['caseIncidentAdd']
            self.log.info(f"OpenCTI case '{created_case.get('name')}' (ID: {created_case.get('id')}) created successfully.")
            return created_case

        self.log.error(f"Failed to create OpenCTI case for Iris case '{self.iris_case.name}'.")
        return None

    def delete_case(self, opencti_case_id: str):
        """
        Deletes the OpenCTI case associated with self.iris_case.

        Returns:
            bool: True if deletion was successful, False otherwise.
        """
        if not opencti_case_id:
            self.log.error("OpenCTI case ID is required for deletion.")
            return False

        variables = {"id": opencti_case_id}
        self.log.info(f"Attempting to delete OpenCTI case ID: {opencti_case_id}.")
        existing_case = self.check_case_exists() # TODO adapt result from this function return value
        data = self._execute_graphql_query(DELETE_CASE_QUERY, variables)

        if data and data.get('caseIncidentDelete'):
            self.log.info(f"OpenCTI case ID: {opencti_case_id} deleted successfully.")
            return True

        self.log.error(f"Failed to delete OpenCTI case ID: {opencti_case_id}.")
        return False

    def create_relationship(self, case_id: str, ioc_id: str, relationship_type: str = "object"):
        """
        Creates a relationship in OpenCTI between two entities.
        Typically used to link an IOC (to_id) to a case (from_id).

        Args:
            from_id (str): The ID of the source entity (e.g., OpenCTI Case ID).
            to_id (str): The ID of the target entity (e.g., OpenCTI Observable ID).
            relationship_type (str, optional): The type of relationship. Defaults to "object".

        Returns:
            dict: The created relationship node if successful, None otherwise.
        """
        variables = {
            "id": case_id,
            "input": {
                "toId": ioc_id,
                "relationship_type": relationship_type
            }
        }
        self.log.info(f"Creating relationship from {case_id} to {ioc_id} of type '{relationship_type}'.")
        data = self._execute_graphql_query(CREATE_RELATIONSHIP_QUERY, variables)

        if data and data.get('containerEdit') and data['containerEdit'].get('relationAdd'):
            relationship = data['containerEdit']['relationAdd']
            self.log.info(f"Relationship (ID: {relationship.get('id')}) created successfully.")
            return relationship

        self.log.error(f"Failed to create relationship from {case_id} to {ioc_id}.")
        return None
    
    def remove_relationship(self, case_id: str, ioc_id: str, relationship_type: str = "object"):
        """
        Creates a relationship in OpenCTI between a case and an IOC.
        Args:
            case_id (str): The ID of the OpenCTI case to which the IOC will be linked.
            ioc_id (str): The ID of the OpenCTI IOC to link to the case.
            relationship_type (str): The type of relationship to create. Defaults to "object".
        Returns:
            dict: The created relationship node if successful, None otherwise.
        """
        variables = {
            "id": case_id,
            "toId": ioc_id,
            "relationship_type": relationship_type
        }
        self.log.info(f"Removing relationship from {case_id} to {ioc_id} of type '{relationship_type}'.")
        data = self._execute_graphql_query(REMOVE_RELATIONSHIP_QUERY, variables)

        if data and data.get('stixDomainObjectEdit') and data['stixDomainObjectEdit'].get('relationDelete'):
            relationship = data['stixDomainObjectEdit']['relationDelete']
            self.log.info(f"Relationship (from case ID: {relationship.get('id')}) removed successfully.")
            return relationship

        self.log.error(f"Failed to remove relationship from {case_id} to {ioc_id}.")
        return None

    def compare_ioc(self, opencti_case_id: str):
        """
        Compares IOCs in the linked Iris case (self.iris_case) with IOCs in the
        specified OpenCTI case. Deletes IOCs from the OpenCTI case if they are
        no longer present in the Iris case.

        Args:
            opencti_case_id (str): The ID of the OpenCTI case to compare against.
        """
        if not self.iris_case:
            self.log.error("No Iris case provided for IOC comparison.")
            return
        if not opencti_case_id:
            self.log.error("No OpenCTI case ID provided for IOC comparison.")
            return

        self.log.info(f"Comparing IOCs for Iris case '{self.iris_case.name}' with OpenCTI case ID '{opencti_case_id}'.")

        try:
            iris_iocs_detailed = get_detailed_iocs(self.iris_case.case_id)
        except Exception as e:
            self.log.error(f"Failed to get detailed IOCs from Iris for case ID {self.iris_case.case_id}: {e}")
            return

        if not iris_iocs_detailed:
            self.log.info(f"No IOCs found in Iris case '{self.iris_case.name}' to compare.")
            iris_ioc_values = set()
        else:
            iris_ioc_values = {ioc.ioc_value for ioc in iris_iocs_detailed}
            self.log.info(f"Iris IOC values for case '{self.iris_case.name}': {iris_ioc_values}")

        variables = {"id": opencti_case_id}
        opencti_data = self._execute_graphql_query(LIST_IOC_FROM_CASE_QUERY, variables)

        if not opencti_data or not opencti_data.get('container') or \
           not opencti_data['container'].get('objects') or \
           not isinstance(opencti_data['container']['objects'].get('edges'), list):
            self.log.error(f"Failed to list IOCs from OpenCTI case ID '{opencti_case_id}' or data format is unexpected.")
            return

        opencti_ioc_nodes = opencti_data['container']['objects']['edges']

        if not opencti_ioc_nodes:
            self.log.info(f"No IOCs found in OpenCTI case ID '{opencti_case_id}'. No comparison needed.")
            return

        for edge in opencti_ioc_nodes:
            opencti_ioc = edge.get('node')
            if not opencti_ioc:
                continue

            opencti_ioc_value = opencti_ioc.get('observable_value') or opencti_ioc.get('name')
            opencti_ioc_id = opencti_ioc.get('id')

            if not opencti_ioc_value or not opencti_ioc_id:
                self.log.warning(f"Skipping OpenCTI IOC due to missing value or ID: {opencti_ioc}")
                continue

            is_present = False
            for iris_ioc_value in iris_ioc_values:
                if opencti_ioc_value in iris_ioc_value.split('|'): #TODO while this verification works, it will not work for iocs sharing a part of the value (e.g. domain|ip)
                    is_present = True
            if not is_present:
                self.log.info(f"IOC '{opencti_ioc_value}' (ID: {opencti_ioc_id}) exists in OpenCTI case "
                            f"but not in Iris case '{self.iris_case.name}'. Attempting deletion.")
                if self.check_ioc_ownership(opencti_ioc):
                    self.delete_ioc(opencti_ioc_id)
                else:
                    self.remove_relationship(opencti_case_id, opencti_ioc_id, "object")

    def check_ioc_ownership(self, opencti_ioc, mode = 'strict'):
        """
        Checks the ownership of the OpenCTI IOC.
        Args:
            opencti_ioc (dict): The OpenCTI IOC node to check ownership for.
            mode (str): Ownership check mode, 'strict' or 'loose'. Defaults to 'strict'.
        Returns:
            bool: True if the IOC is own by IRIS, False otherwise. If 'strict', it checks if the IOC is ONLY owned by IRIS.
        """
        opencti_ioc_owners = opencti_ioc.get('creators', {})
        for opencti_ioc_owner in opencti_ioc_owners:
            owner_id = opencti_ioc_owner.get('id')
            if mode != 'strict' and owner_id == self.api_user_id:
                return True
            if owner_id != self.api_user_id:
                self.log.warning(f"IOC {opencti_ioc.get('observable_value')} is owned by another user (ID: {owner_id}).")
                return False
        return True

    def get_marking(self, tlp):
        variable = {
            "filters": {
                "mode": "and",
                "filters": [
                {
                    "key": "definition",
                    "values": [
                    f"TLP:{tlp.upper()}"
                    ]
                }
                ],
                "filterGroups": []
            }
        }
        markings = self._execute_graphql_query(LIST_MARKING_DEFINITIONS_QUERY, variable)
        if markings and markings.get('markingDefinitions') and markings['markingDefinitions'].get('edges'):
            marking_edges = markings['markingDefinitions']['edges']
            for edge in marking_edges:
                tlp_result = edge.get('node')
                self.log.info(f"Retrieved {tlp_result.get('definition')} marking definitions from OpenCTI.")
                return tlp_result.get('id')
        return None
    
    def get_iris_marking(self, tlp, from_opencti=True):
        """
        Retrieves the IRIS marking for a given OpenCTI TLP level.

        Args:
            tlp (str): The TLP level to retrieve the marking for.
            from_opencti (bool): If True, retrieves the marking from OpenCTI naming convention,
                                 otherwise uses the IRIS naming convention.
        Returns:
            str: The IRIS marking ID if found, None otherwise.
        """

        if not tlp:
            self.log.error("TLP level is required to retrieve IRIS marking.")
            return None

        if from_opencti:
            # OpenCTI uses TLP naming convention like TLP:CLEAR while IRIS uses TLP naming convention like clear. Change tlp from OpenCTI to IRIS.
            tlp = tlp.lower().replace("tlp:", "")

        # now look for the IRIS marking from Tlp object
        iris_marking = get_tlps_dict().get(tlp)
        if iris_marking:
            return iris_marking
        else:
            self.log.error(f"No IRIS marking found for TLP '{tlp}'.")
            return None
