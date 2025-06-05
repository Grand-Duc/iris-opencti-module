def make_query(**kwargs):
    observable_data = kwargs.get("observableData", {})
    simple_observable_id = kwargs.get("simple_observable_id", None)
    simple_observable_key = kwargs.get("simple_observable_key", None)
    simple_observable_value = kwargs.get("simple_observable_value", None)
    # simple_observable_description = kwargs.get("simple_observable_description", None)
    x_opencti_score = kwargs.get("x_opencti_score", None)
    object_marking = kwargs.get("objectMarking", None)
    object_label = kwargs.get("objectLabel", None)
    external_references = kwargs.get("externalReferences", None)
    granted_refs = kwargs.get("objectOrganization", None)
    update = kwargs.get("update", False)

    create_indicator = (
        observable_data["x_opencti_create_indicator"]
        if "x_opencti_create_indicator" in observable_data
        else kwargs.get("createIndicator", False)
    )
    attribute = None
    if simple_observable_key is not None:
        key_split = simple_observable_key.split(".")
        type = key_split[0].title()
        attribute = key_split[1]
        if attribute not in ["hashes", "extensions"]:
            observable_data[attribute] = simple_observable_value
    else:
        type = (
            observable_data["type"].title() if "type" in observable_data else None
        )
    if type is None:
        return
    if type.lower() == "file":
        type = "StixFile"
    elif type.lower() == "ipv4-addr":
        type = "IPv4-Addr"
    elif type.lower() == "ipv6-addr":
        type = "IPv6-Addr"
    elif type.lower() == "persona":
        type = "Persona"
    elif type.lower() == "hostname" or type.lower() == "x-opencti-hostname":
        type = "Hostname"
    elif type.lower() == "payment-card" or type.lower() == "x-opencti-payment-card":
        type = "Payment-Card"
    elif type.lower() == "credential" or type.lower() == "x-opencti-credential":
        type = "Credential"
    elif (
        type.lower() == "tracking-number"
        or type.lower() == "x-opencti-tracking-number"
    ):
        type = "Tracking-Number"
    elif (
        type.lower() == "cryptocurrency-wallet"
        or type.lower() == "x-opencti-cryptocurrency-wallet"
    ):
        type = "Cryptocurrency-Wallet"
    elif type.lower() == "user-agent" or type.lower() == "x-opencti-user-agent":
        type = "User-Agent"
    elif (
        type.lower() == "cryptographic-key"
        or type.lower() == "x-opencti-cryptographic-key"
    ):
        type = "Cryptographic-Key"
    elif type.lower() == "text" or type.lower() == "x-opencti-text":
        type = "Text"


    if "x_opencti_score" in observable_data:
        x_opencti_score = observable_data["x_opencti_score"]
    else:
        x_opencti_score = (
            x_opencti_score if x_opencti_score is not None else 50
        )

    stix_id = observable_data["id"] if "id" in observable_data else None
    if simple_observable_id is not None:
        stix_id = simple_observable_id

    hashes = []
    if (
        simple_observable_key is not None
        and "hashes.md5" in simple_observable_key.lower()
    ):
        hashes.append({"algorithm": "MD5", "hash": simple_observable_value})
    elif (
        simple_observable_key is not None
        and "hashes.sha-1" in simple_observable_key.lower()
    ):
        hashes.append({"algorithm": "SHA-1", "hash": simple_observable_value})
    elif (
        simple_observable_key is not None
        and "hashes.sha-256" in simple_observable_key.lower()
    ):
        hashes.append({"algorithm": "SHA-256", "hash": simple_observable_value})
    if "hashes" in observable_data:
        for key, value in observable_data["hashes"].items():
            hashes.append({"algorithm": key, "hash": value})

    if type is not None:
        input_variables = {
            "type": type,
            "stix_id": stix_id,
            "x_opencti_score": x_opencti_score,
            # "x_opencti_description": x_opencti_description,
            "createIndicator": create_indicator,
            # "createdBy": created_by,
            "objectMarking": object_marking,
            "objectOrganization": granted_refs,
            "objectLabel": object_label,
            "externalReferences": external_references,
            "update": update,
        }
        if type == "Autonomous-System":
            input_variables["AutonomousSystem"] = {
                "number": observable_data["number"],
                "name": (
                    observable_data["name"] if "name" in observable_data else None
                ),
                "rir": observable_data["rir"] if "rir" in observable_data else None,
            }
        elif type == "Directory":
            input_variables["Directory"] = {
                "path": observable_data["path"],
                "path_enc": (
                    observable_data["path_enc"]
                    if "path_enc" in observable_data
                    else None
                ),
                "ctime": (
                    observable_data["ctime"] if "ctime" in observable_data else None
                ),
                "mtime": (
                    observable_data["mtime"] if "mtime" in observable_data else None
                ),
                "atime": (
                    observable_data["atime"] if "atime" in observable_data else None
                ),
            }
        elif type == "Domain-Name":
            input_variables["DomainName"] = {"value": observable_data["value"]}
            if attribute is not None:
                input_variables["DomainName"][attribute] = simple_observable_value
        elif type == "Email-Addr":
            input_variables["EmailAddr"] = {
                "value": observable_data["value"],
                "display_name": (
                    observable_data["display_name"]
                    if "display_name" in observable_data
                    else None
                ),
            }
        elif type == "Email-Message":
            input_variables["EmailMessage"] = {
                "is_multipart": (
                    observable_data["is_multipart"]
                    if "is_multipart" in observable_data
                    else None
                ),
                "attribute_date": (
                    observable_data["date"] if "date" in observable_data else None
                ),
                "message_id": (
                    observable_data["message_id"]
                    if "message_id" in observable_data
                    else None
                ),
                "subject": (
                    observable_data["subject"]
                    if "subject" in observable_data
                    else None
                ),
                "received_lines": (
                    observable_data["received_lines"]
                    if "received_lines" in observable_data
                    else None
                ),
                "body": (
                    observable_data["body"] if "body" in observable_data else None
                ),
            }
        elif type == "Email-Mime-Part-Type":
            input_variables["EmailMimePartType"] = {
                "body": (
                    observable_data["body"] if "body" in observable_data else None
                ),
                "content_type": (
                    observable_data["content_type"]
                    if "content_type" in observable_data
                    else None
                ),
                "content_disposition": (
                    observable_data["content_disposition"]
                    if "content_disposition" in observable_data
                    else None
                ),
            }
        elif type == "Artifact":
            # if (
            #     "x_opencti_additional_names" not in observable_data
            #     and self.opencti.get_attribute_in_extension(
            #         "additional_names", observable_data
            #     )
            #     is not None
            # ):
            #     observable_data["x_opencti_additional_names"] = (
            #         self.opencti.get_attribute_in_extension(
            #             "additional_names", observable_data
            #         )
            #     )
            input_variables["Artifact"] = {
                "hashes": hashes if len(hashes) > 0 else None,
                "mime_type": (
                    observable_data["mime_type"]
                    if "mime_type" in observable_data
                    else None
                ),
                "url": observable_data["url"] if "url" in observable_data else None,
                "encryption_algorithm": (
                    observable_data["encryption_algorithm"]
                    if "encryption_algorithm" in observable_data
                    else None
                ),
                "decryption_key": (
                    observable_data["decryption_key"]
                    if "decryption_key" in observable_data
                    else None
                ),
                "x_opencti_additional_names": (
                    observable_data["x_opencti_additional_names"]
                    if "x_opencti_additional_names" in observable_data
                    else None
                ),
            }
        elif type == "StixFile":
            # if (
            #     "x_opencti_additional_names" not in observable_data
            #     and self.opencti.get_attribute_in_extension(
            #         "additional_names", observable_data
            #     )
            #     is not None
            # ):
            #     observable_data["x_opencti_additional_names"] = (
            #         self.opencti.get_attribute_in_extension(
            #             "additional_names", observable_data
            #         )
            #     )
            input_variables["StixFile"] = {
                "hashes": hashes if len(hashes) > 0 else None,
                "size": (
                    observable_data["size"] if "size" in observable_data else None
                ),
                "name": (
                    observable_data["name"] if "name" in observable_data else None
                ),
                "name_enc": (
                    observable_data["name_enc"]
                    if "name_enc" in observable_data
                    else None
                ),
                "magic_number_hex": (
                    observable_data["magic_number_hex"]
                    if "magic_number_hex" in observable_data
                    else None
                ),
                "mime_type": (
                    observable_data["mime_type"]
                    if "mime_type" in observable_data
                    else None
                ),
                "mtime": (
                    observable_data["mtime"] if "mtime" in observable_data else None
                ),
                "ctime": (
                    observable_data["ctime"] if "ctime" in observable_data else None
                ),
                "atime": (
                    observable_data["atime"] if "atime" in observable_data else None
                ),
                "x_opencti_additional_names": (
                    observable_data["x_opencti_additional_names"]
                    if "x_opencti_additional_names" in observable_data
                    else None
                ),
            }
        elif type == "X509-Certificate":
            input_variables["X509Certificate"] = {
                "hashes": hashes if len(hashes) > 0 else None,
                "is_self_signed": (
                    observable_data["is_self_signed"]
                    if "is_self_signed" in observable_data
                    else False
                ),
                "version": (
                    observable_data["version"]
                    if "version" in observable_data
                    else None
                ),
                "serial_number": (
                    observable_data["serial_number"]
                    if "serial_number" in observable_data
                    else None
                ),
                "signature_algorithm": (
                    observable_data["signature_algorithm"]
                    if "signature_algorithm" in observable_data
                    else None
                ),
                "issuer": (
                    observable_data["issuer"]
                    if "issuer" in observable_data
                    else None
                ),
                "validity_not_before": (
                    observable_data["validity_not_before"]
                    if "validity_not_before" in observable_data
                    else None
                ),
                "validity_not_after": (
                    observable_data["validity_not_after"]
                    if "validity_not_after" in observable_data
                    else None
                ),
                "subject": (
                    observable_data["subject"]
                    if "subject" in observable_data
                    else None
                ),
                "subject_public_key_algorithm": (
                    observable_data["subject_public_key_algorithm"]
                    if "subject_public_key_algorithm" in observable_data
                    else None
                ),
                "subject_public_key_modulus": (
                    observable_data["subject_public_key_modulus"]
                    if "subject_public_key_modulus" in observable_data
                    else None
                ),
                "subject_public_key_exponent": (
                    observable_data["subject_public_key_exponent"]
                    if "subject_public_key_exponent" in observable_data
                    else None
                ),
            }
        elif type == "IPv4-Addr":
            input_variables["IPv4Addr"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "IPv6-Addr":
            input_variables["IPv6Addr"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Mac-Addr":
            input_variables["MacAddr"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Mutex":
            input_variables["Mutex"] = {
                "name": (
                    observable_data["name"] if "name" in observable_data else None
                ),
            }
        elif type == "Network-Traffic":
            input_variables["NetworkTraffic"] = {
                "start": (
                    observable_data["start"] if "start" in observable_data else None
                ),
                "end": observable_data["end"] if "end" in observable_data else None,
                "is_active": (
                    observable_data["is_active"]
                    if "is_active" in observable_data
                    else None
                ),
                "src_port": (
                    observable_data["src_port"]
                    if "src_port" in observable_data
                    else None
                ),
                "dst_port": (
                    observable_data["dst_port"]
                    if "dst_port" in observable_data
                    else None
                ),
                "networkSrc": (
                    observable_data["src_ref"]
                    if "src_ref" in observable_data
                    else None
                ),
                "networkDst": (
                    observable_data["dst_ref"]
                    if "dst_ref" in observable_data
                    else None
                ),
                "protocols": (
                    observable_data["protocols"]
                    if "protocols" in observable_data
                    else None
                ),
                "src_byte_count": (
                    observable_data["src_byte_count"]
                    if "src_byte_count" in observable_data
                    else None
                ),
                "dst_byte_count": (
                    observable_data["dst_byte_count"]
                    if "dst_byte_count" in observable_data
                    else None
                ),
                "src_packets": (
                    observable_data["src_packets"]
                    if "src_packets" in observable_data
                    else None
                ),
                "dst_packets": (
                    observable_data["dst_packets"]
                    if "dst_packets" in observable_data
                    else None
                ),
            }
        elif type == "Process":
            input_variables["Process"] = {
                "is_hidden": (
                    observable_data["is_hidden"]
                    if "is_hidden" in observable_data
                    else None
                ),
                "pid": observable_data["pid"] if "pid" in observable_data else None,
                "created_time": (
                    observable_data["created_time"]
                    if "created_time" in observable_data
                    else None
                ),
                "cwd": observable_data["cwd"] if "cwd" in observable_data else None,
                "command_line": (
                    observable_data["command_line"]
                    if "command_line" in observable_data
                    else None
                ),
                "environment_variables": (
                    observable_data["environment_variables"]
                    if "environment_variables" in observable_data
                    else None
                ),
            }
        elif type == "Software":
            input_variables["Software"] = {
                "name": (
                    observable_data["name"] if "name" in observable_data else None
                ),
                "cpe": observable_data["cpe"] if "cpe" in observable_data else None,
                "swid": (
                    observable_data["swid"] if "swid" in observable_data else None
                ),
                "languages": (
                    observable_data["languages"]
                    if "languages" in observable_data
                    else None
                ),
                "vendor": (
                    observable_data["vendor"]
                    if "vendor" in observable_data
                    else None
                ),
                "version": (
                    observable_data["version"]
                    if "version" in observable_data
                    else None
                ),
            }
        elif type == "Url":
            input_variables["Url"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "User-Account":
            input_variables["UserAccount"] = {
                "user_id": (
                    observable_data["user_id"]
                    if "user_id" in observable_data
                    else None
                ),
                "credential": (
                    observable_data["credential"]
                    if "credential" in observable_data
                    else None
                ),
                "account_login": (
                    observable_data["account_login"]
                    if "account_login" in observable_data
                    else None
                ),
                "account_type": (
                    observable_data["account_type"]
                    if "account_type" in observable_data
                    else None
                ),
                "display_name": (
                    observable_data["display_name"]
                    if "display_name" in observable_data
                    else None
                ),
                "is_service_account": (
                    observable_data["is_service_account"]
                    if "is_service_account" in observable_data
                    else None
                ),
                "is_privileged": (
                    observable_data["is_privileged"]
                    if "is_privileged" in observable_data
                    else None
                ),
                "can_escalate_privs": (
                    observable_data["can_escalate_privs"]
                    if "can_escalate_privs" in observable_data
                    else None
                ),
                "is_disabled": (
                    observable_data["is_disabled"]
                    if "is_disabled" in observable_data
                    else None
                ),
                "account_created": (
                    observable_data["account_created"]
                    if "account_created" in observable_data
                    else None
                ),
                "account_expires": (
                    observable_data["account_expires"]
                    if "account_expires" in observable_data
                    else None
                ),
                "credential_last_changed": (
                    observable_data["credential_last_changed"]
                    if "credential_last_changed" in observable_data
                    else None
                ),
                "account_first_login": (
                    observable_data["account_first_login"]
                    if "account_first_login" in observable_data
                    else None
                ),
                "account_last_login": (
                    observable_data["account_last_login"]
                    if "account_last_login" in observable_data
                    else None
                ),
            }
        elif type == "Windows-Registry-Key":
            input_variables["WindowsRegistryKey"] = {
                "attribute_key": (
                    observable_data["key"] if "key" in observable_data else None
                ),
                "modified_time": (
                    observable_data["modified_time"]
                    if "modified_time" in observable_data
                    else None
                ),
                "number_of_subkeys": (
                    observable_data["number_of_subkeys"]
                    if "number_of_subkeys" in observable_data
                    else None
                ),
            }
        elif type == "Windows-Registry-Value-Type":
            input_variables["WindowsRegistryKeyValueType"] = {
                "name": (
                    observable_data["name"] if "name" in observable_data else None
                ),
                "data": (
                    observable_data["data"] if "data" in observable_data else None
                ),
                "data_type": (
                    observable_data["data_type"]
                    if "data_type" in observable_data
                    else None
                ),
            }
        elif type == "User-Agent":
            input_variables["UserAgent"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Cryptographic-Key":
            input_variables["CryptographicKey"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Hostname":
            input_variables["Hostname"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Text":
            input_variables["Text"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Bank-Account":
            input_variables["BankAccount"] = {
                "iban": (
                    observable_data["iban"] if "iban" in observable_data else None
                ),
                "bic": observable_data["bic"] if "bic" in observable_data else None,
                "account_number": (
                    observable_data["account_number"]
                    if "account_number" in observable_data
                    else None
                ),
            }
        elif type == "Phone-Number":
            input_variables["PhoneNumber"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Payment-Card":
            input_variables["PaymentCard"] = {
                "card_number": (
                    observable_data["card_number"]
                    if "card_number" in observable_data
                    else None
                ),
                "expiration_date": (
                    observable_data["expiration_date"]
                    if "expiration_date" in observable_data
                    else None
                ),
                "cvv": observable_data["cvv"] if "cvv" in observable_data else None,
                "holder_name": (
                    observable_data["holder_name"]
                    if "holder_name" in observable_data
                    else None
                ),
            }
        elif type == "Media-Content":
            input_variables["MediaContent"] = {
                "title": (
                    observable_data["title"] if "title" in observable_data else None
                ),
                "content": (
                    observable_data["content"]
                    if "content" in observable_data
                    else None
                ),
                "media_category": (
                    observable_data["media_category"]
                    if "media_category" in observable_data
                    else None
                ),
                "url": observable_data["url"] if "url" in observable_data else None,
                "publication_date": (
                    observable_data["publication_date"]
                    if "publication_date" in observable_data
                    else None
                ),
            }
        elif type == "Persona":
            input_variables["Persona"] = {
                "persona_name": (
                    observable_data["persona_name"]
                    if "persona_name" in observable_data
                    else None
                ),
                "persona_type": (
                    observable_data["persona_type"]
                    if "persona_type" in observable_data
                    else None
                ),
            }
        elif type == "Payment-Card" or type.lower() == "x-opencti-payment-card":
            input_variables["PaymentCard"] = {
                "card_number": (
                    observable_data["card_number"]
                    if "card_number" in observable_data
                    else None
                ),
                "expiration_date": (
                    observable_data["expiration_date"]
                    if "expiration_date" in observable_data
                    else None
                ),
                "cvv": observable_data["cvv"] if "cvv" in observable_data else None,
                "holder_name": (
                    observable_data["holder_name"]
                    if "holder_name" in observable_data
                    else None
                ),
            }
        elif (
            type == "Cryptocurrency-Wallet"
            or type.lower() == "x-opencti-cryptocurrency-wallet"
        ):
            input_variables["CryptocurrencyWallet"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif type == "Credential" or type.lower() == "x-opencti-credential":
            input_variables["Credential"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        elif (
            type == "Tracking-Number" or type.lower() == "x-opencti-tracking-number"
        ):
            input_variables["TrackingNumber"] = {
                "value": (
                    observable_data["value"] if "value" in observable_data else None
                ),
            }
        return input_variables