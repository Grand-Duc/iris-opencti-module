import requests
from iris_opencti_module.opencti_handler.query import *
from app.models.cases import Cases
from app.datamgmt.case.case_iocs_db import get_detailed_iocs



class OpenCTIHandler:

    HASH_TYPES = ['md5', 'sha1', 'sha256', 'sha512']
    IP_TYPES = ['ip-any', 'ip-dst', 'ip-src']

    ATTRIBUTE_CONFIG = {
        hash: {
            'key_conversion': f'hashes.{hash.upper()}',
            'type_conversion': 'File',
            'create_type_conversion': 'StixFile',
            'other_type_conversion': 'StixFile',
        } for hash in HASH_TYPES
    }
    ATTRIBUTE_CONFIG.update({
        ip: {
            'key_conversion': 'value',
            'type_conversion': 'IPv4-Addr',
            'create_type_conversion': 'IPv4-Addr',
            'other_type_conversion': 'IPv4Addr',
        } for ip in IP_TYPES
    })


    ATTRIBUTE_CONFIG.update({
        'url': {
            'key_conversion': 'value',
            'type_conversion': 'Url',
            'create_type_conversion': 'Url',
            'other_type_conversion': 'Url',
        },
        'domain': {
            'key_conversion': 'value',
            'type_conversion': 'Domain-Name',
            'create_type_conversion': 'DomainName',
            'other_type_conversion': 'DomainName',
        },
        'md5': {
            'upload_type': 'MD5',
        },
        'sha1': {
            'upload_type': 'SHA-1',
        },
        'sha256': {
            'upload_type': 'SHA-256',
        },
        'sha512': {
            'upload_type': 'SHA-512',
        },
    })


    def __init__(self, mod_config, logger, ioc = None):
        self.mod_config = mod_config
        self.log = logger
        self.opencti_api_url = mod_config.get('opencti_url', None)
        self.opencti_api_key = mod_config.get('opencti_api_key', None)
        self.ioc = ioc
        self.iris_case = ioc.case if ioc and hasattr(ioc, 'case') else None
        self.api_user_id = self.get_api_user().get('id')

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
        config = self.ATTRIBUTE_CONFIG.get(ioc_type_name)

        if not config:
            self.log.error(f"Unsupported IOC type: {ioc_type_name} for IOC value {self.ioc.ioc_value}")
            return None

        variables = {
            "types": [config['type_conversion']],
            "filters": {
                "mode": "and",
                "filters": [{"key": config['key_conversion'], "values": [self.ioc.ioc_value]}],
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
        ioc_type = self.ioc.ioc_type.type_name
        ioc_value = self.ioc.ioc_value
        variables = {
            "type": self.ATTRIBUTE_CONFIG[ioc_type].get('create_type_conversion', 'None'),
        }
        variable_type = self.ATTRIBUTE_CONFIG[ioc_type].get('other_type_conversion', 'None')
        if variable_type == 'StixFile':
            variables['StixFile'] = {
                'name': ioc_value,
                'hashes': {
                    "algorithm" : self.ATTRIBUTE_CONFIG[ioc_type].get('upload_type'),
                    "hash": ioc_value
                },
            }
        else:
            variables[variable_type] = {
                'value': ioc_value,
            }
        self.log.info(
            f"Creating IOC with type: {variables}")
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
            return {'ERROR': str(e)}

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
            self.log.debug(f"Iris IOC values for case '{self.iris_case.name}': {iris_ioc_values}")

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

            if opencti_ioc_value not in iris_ioc_values:
                self.log.info(f"IOC '{opencti_ioc_value}' (ID: {opencti_ioc_id}) exists in OpenCTI case "
                              f"but not in Iris case '{self.iris_case.name}'. Attempting deletion.")
                if self.check_ioc_ownership(opencti_ioc):
                    self.delete_ioc(opencti_ioc_id)
                else:
                    self.remove_relationship(opencti_case_id, opencti_ioc_id, "object") #TODO

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
                self.log.warning(f"IOC {opencti_ioc.get('observable_value')} is owned by another user (ID: {owner_id}). Cannot delete.")
                return False
        return True