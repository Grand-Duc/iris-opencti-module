GET_API_USER_QUERY = """
    query Me {
        me {id name }
    }
"""

CHECK_IOC_EXISTS_QUERY = """
    query StixCyberObservables($types: [String], $filters: FilterGroup) {
        stixCyberObservables(types: $types, filters: $filters) {
            edges {
            node {
                id
                entity_type
                observable_value
                x_opencti_score
                creators {
                id
                }
                objectMarking {
                id
                definition
                }
            }
            }
            pageInfo {
            globalCount
            }
        }
    }
"""

CREATE_IOC_QUERY = """
    mutation StixCyberObservableAdd(
        $type: String!,
        $stix_id: StixId,
        $x_opencti_score: Int,
        $x_opencti_description: String,
        $createIndicator: Boolean,
        $createdBy: String,
        $objectMarking: [String],
        $objectLabel: [String],
        $objectOrganization: [String],
        $externalReferences: [String],
        $update: Boolean,
        $AutonomousSystem: AutonomousSystemAddInput,
        $Directory: DirectoryAddInput,
        $DomainName: DomainNameAddInput,
        $EmailAddr: EmailAddrAddInput,
        $EmailMessage: EmailMessageAddInput,
        $EmailMimePartType: EmailMimePartTypeAddInput,
        $Artifact: ArtifactAddInput,
        $StixFile: StixFileAddInput,
        $X509Certificate: X509CertificateAddInput,
        $IPv4Addr: IPv4AddrAddInput,
        $IPv6Addr: IPv6AddrAddInput,
        $MacAddr: MacAddrAddInput,
        $Mutex: MutexAddInput,
        $NetworkTraffic: NetworkTrafficAddInput,
        $Process: ProcessAddInput,
        $Software: SoftwareAddInput,
        $Url: UrlAddInput,
        $UserAccount: UserAccountAddInput,
        $WindowsRegistryKey: WindowsRegistryKeyAddInput,
        $WindowsRegistryValueType: WindowsRegistryValueTypeAddInput,
        $CryptographicKey: CryptographicKeyAddInput,
        $CryptocurrencyWallet: CryptocurrencyWalletAddInput,
        $Hostname: HostnameAddInput
        $Text: TextAddInput,
        $UserAgent: UserAgentAddInput
        $BankAccount: BankAccountAddInput
        $PhoneNumber: PhoneNumberAddInput
        $Credential: CredentialAddInput
        $TrackingNumber: TrackingNumberAddInput
        $PaymentCard: PaymentCardAddInput
        $Persona: PersonaAddInput
        $MediaContent: MediaContentAddInput
    ) {
        stixCyberObservableAdd(
            type: $type,
            stix_id: $stix_id,
            x_opencti_score: $x_opencti_score,
            x_opencti_description: $x_opencti_description,
            createIndicator: $createIndicator,
            createdBy: $createdBy,
            objectMarking: $objectMarking,
            objectLabel: $objectLabel,
            update: $update,
            externalReferences: $externalReferences,
            objectOrganization: $objectOrganization,
            AutonomousSystem: $AutonomousSystem,
            Directory: $Directory,
            DomainName: $DomainName,
            EmailAddr: $EmailAddr,
            EmailMessage: $EmailMessage,
            EmailMimePartType: $EmailMimePartType,
            Artifact: $Artifact,
            StixFile: $StixFile,
            X509Certificate: $X509Certificate,
            IPv4Addr: $IPv4Addr,
            IPv6Addr: $IPv6Addr,
            MacAddr: $MacAddr,
            Mutex: $Mutex,
            NetworkTraffic: $NetworkTraffic,
            Process: $Process,
            Software: $Software,
            Url: $Url,
            UserAccount: $UserAccount,
            WindowsRegistryKey: $WindowsRegistryKey,
            WindowsRegistryValueType: $WindowsRegistryValueType,
            CryptographicKey: $CryptographicKey,
            CryptocurrencyWallet: $CryptocurrencyWallet,
            Hostname: $Hostname,
            Text: $Text,
            UserAgent: $UserAgent
            BankAccount: $BankAccount
            PhoneNumber: $PhoneNumber
            Credential: $Credential
            TrackingNumber: $TrackingNumber
            PaymentCard: $PaymentCard
            Persona: $Persona
            MediaContent: $MediaContent
        ) {
            id
        }
    }
"""

UPDATE_IOC_QUERY = """
    mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
        stixCyberObservableEdit(id: $id) {
            fieldPatch(input: $input) {
            id
            standard_id
            entity_type
            observable_value
            objectMarking { id definition }
            x_opencti_description
            x_opencti_score
            creators { id }
            }
        }
    }
"""

DELETE_IOC_QUERY = """
    mutation StixCyberObservableEdit($id: ID!) {
        stixCyberObservableEdit(id: $id) {
            delete
        }
    }
"""

CHECK_CASE_EXISTS_QUERY = """
    query CaseIncidents($filters: FilterGroup) {
        caseIncidents(filters: $filters) {
            edges { node { id name } }
            pageInfo { globalCount }
        }
    }
"""

CREATE_CASE_QUERY = """
    mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
        caseIncidentAdd(input: $input) { id }
    }
"""

DELETE_CASE_QUERY = """
    mutation caseIncidentDelete($id: ID!) {
        caseIncidentDelete(id: $id)
    }
"""

CREATE_RELATIONSHIP_QUERY = """
    mutation ContainerEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
        containerEdit(id: $id) {
            relationAdd(input: $input) { id } 
        }
    }
"""

REMOVE_RELATIONSHIP_QUERY = """
    mutation CaseIncidentEditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        stixDomainObjectEdit(id: $id) {
            relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            }
        }
    }
"""

LIST_IOC_FROM_CASE_QUERY = """
    query ContainerObjects($id: String!) {
        container(id: $id) {
            objects(all: true) {
                edges {
                    node {
                        ... on BasicObject { id }
                        ... on Indicator { name id creators { id } }
                        ... on StixCyberObservable { observable_value creators { id } }
                    }
                }
            }
        }
    }
"""

LIST_MARKING_DEFINITIONS_QUERY = """
query MarkingDefinitions($filters: FilterGroup) {
  markingDefinitions(filters: $filters) {
    edges { node { id definition } }
  }
}
"""


