def is_success_response(gvm_response: dict, key: str) -> bool:
    """
    Check if a greenbone response is a successful response
    :param gvm_response: GVM response
    :param key: response xml key
    :return:
    """
    return gvm_response is not None and gvm_response.get(key) is not None \
        and (gvm_response.get(key).get("@status") == "200" or gvm_response.get(key).get(
            "@status") == "201" or gvm_response.get(key).get("@status") == "202")
