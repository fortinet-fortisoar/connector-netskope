"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import json
from datetime import datetime
from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('netskope')


class Netskope:
    def __init__(self, config):
        self.base_url = config.get('server_url').strip('/')
        if not self.base_url.startswith('https://'):
            self.base_url = f'https://{self.base_url}'
        self.base_url = self.base_url + "/api/v2"
        self.api_token = config['api_token']
        self.verify_ssl = config['verify_ssl']

    def make_rest_call(self, endpoint, method="GET", params=None, data=None, json_data=None):
        headers = {'Netskope-Api-Token': self.api_token}
        service_endpoint = self.base_url + endpoint
        if json_data is not None:
            headers['Content-Type'] = 'application/json'
        try:
            logger.debug(f"\n{method} {service_endpoint}\nparams: {params}\ndata: {data}")
            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, service_endpoint, params=params, data=data, headers=headers,
                          verify_ssl=self.verify_ssl)
            except Exception:
                pass
            response = request(method, service_endpoint, params=params, data=data, json=json_data, headers=headers,
                               verify=self.verify_ssl)
            if response.ok:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.text
                    error_msg = 'Response [{0}:Details: {1}]'.format(response.status_code, err_resp)
                else:
                    error_msg = 'Response [{0}:Details: {1}]'.format(response.status_code, response.content)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def convert_datetime_to_epoch(date_time):
    unix_epoch = datetime(1970, 1, 1)
    d1 = datetime.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = (d1 - unix_epoch).total_seconds()
    return int(epoch)


def get_alerts_list(config, params):
    ob = Netskope(config)
    start_time = params.get("starttime")
    if start_time:
        start_time = convert_datetime_to_epoch(start_time)
    end_time = params.get("endtime")
    if end_time:
        end_time = convert_datetime_to_epoch(end_time)
    insertion_start_time = params.get("insertionstarttime")
    if insertion_start_time:
        insertion_start_time = convert_datetime_to_epoch(insertion_start_time)
    insertion_end_time = params.get("insertionendtime")
    if insertion_end_time:
        insertion_end_time = convert_datetime_to_epoch(insertion_end_time)
    payload = {
        "query": params.get("query"),
        "type": ALERT_TYPE.get(params.get("type")) if params.get("type") else "",
        "acked": params.get("acked") if params.get("acked") else "",
        "starttime": start_time,
        "endtime": end_time,
        "insertionstarttime": insertion_start_time,
        "insertionendtime": insertion_end_time,
        "limit": params.get("limit"),
        "offset": params.get("offset")
    }
    query_parameters = check_payload(payload)
    response = ob.make_rest_call("/events/data/alert", params=query_parameters)
    return response


def get_events_list(config, params):
    ob = Netskope(config)
    endpoint = "/events/data/{0}".format(params.get('type').lower())
    start_time = params.get("starttime")
    if start_time:
        start_time = convert_datetime_to_epoch(start_time)
    end_time = params.get("endtime")
    if end_time:
        end_time = convert_datetime_to_epoch(end_time)
    insertion_start_time = params.get("insertionstarttime")
    if insertion_start_time:
        insertion_start_time = convert_datetime_to_epoch(insertion_start_time)
    insertion_end_time = params.get("insertionendtime")
    if insertion_end_time:
        insertion_end_time = convert_datetime_to_epoch(insertion_end_time)
    payload = {
        "query": params.get("query"),
        "starttime": start_time,
        "endtime": end_time,
        "insertionstarttime": insertion_start_time,
        "insertionendtime": insertion_end_time,
        "limit": params.get("limit"),
        "offset": params.get("offset")
    }
    query_parameters = check_payload(payload)
    response = ob.make_rest_call(endpoint=endpoint, params=query_parameters)
    return response


def create_url_list(config, params):
    ob = Netskope(config)
    payload = {
        "data": {
            "type": params.get("type").lower(),
            "urls": params.get("urls").split(",")
        },
        "name": params.get("name")
    }
    data = check_payload(payload)
    response = ob.make_rest_call("/policy/urllist", "POST", data=json.dumps(data))
    return response


def apply_url_list(config, params):
    ob = Netskope(config)
    endpoint = "/policy/urllist/deploy"
    response = ob.make_rest_call(endpoint=endpoint, method="POST")
    return response


def get_url_list(config, params):
    ob = Netskope(config)
    payload = {
        "pending": params.get("pending") if params.get("pending") else "",
        "field": params.get("field").split(",") if params.get("field") else ""
    }
    query_parameters = check_payload(payload)
    response = ob.make_rest_call("/policy/urllist", params=query_parameters)
    return response


def get_url_list_details(config, params):
    ob = Netskope(config)
    endpoint = "/policy/urllist/{0}".format(params.get("url_list_id"))
    response = ob.make_rest_call(endpoint=endpoint)
    return response


def add_url_list(config, params):
    ob = Netskope(config)
    endpoint = "/policy/urllist/{0}/append".format(params.get("url_list_id"))
    payload = {
        "data": {
            "type": params.get("type").lower(),
            "urls": params.get("urls").split(",") if params.get("urls") else ""
        }
    }
    data = check_payload(payload)
    response = ob.make_rest_call(endpoint=endpoint, method="PATCH", data=json.dumps(data), json_data=data)
    return response


def update_url_list(config, params):
    ob = Netskope(config)
    endpoint = "/policy/urllist/{0}".format(params.get("url_list_id"))
    payload = {
        "data": {
            "type": params.get("type").lower(),
            "urls": params.get("urls").split(",") if params.get("urls") else ""
        },
        "name": params.get("name")
    }
    data = check_payload(payload)
    response = ob.make_rest_call(endpoint=endpoint, method="PUT", data=json.dumps(data), json_data=data)
    return response


def delete_url_list(config, params):
    ob = Netskope(config)
    endpoint = "/policy/urllist/{0}".format(params.get("url_list_id"))
    response = ob.make_rest_call(endpoint=endpoint, method="DELETE")
    return response


def get_client_list(config, params):
    ob = Netskope(config)
    payload = {
        "count": params.get("count"),
        "startIndex": params.get("startIndex"),
        "filter": params.get("filter")
    }
    query_parameters = check_payload(payload)
    response = ob.make_rest_call("/scim/Users", params=query_parameters)
    return response


def send_custom_request(config, params):
    try:
        ob = Netskope(config)
        endpoint = params.get("endpoint")
        http_method = params.get("method")
        if params.get("query_params"):
            query_params = params.get("query_params")
        else:
            query_params = None
        if params.get("payload"):
            payload = params.get("payload")
        else:
            payload = None
        response = ob.make_rest_call(endpoint=endpoint, method=http_method, params=query_params,
                                     data=json.dumps(payload), json_data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def _check_health(config):
    res = get_client_list(config, {"count": 1})
    return True


operations = {
    "get_alerts_list": get_alerts_list,
    "get_events_list": get_events_list,
    "create_url_list": create_url_list,
    "apply_url_list": apply_url_list,
    "get_url_list": get_url_list,
    "get_url_list_details": get_url_list_details,
    "add_url_list": add_url_list,
    "update_url_list": update_url_list,
    "delete_url_list": delete_url_list,
    "get_client_list": get_client_list,
    "send_custom_request": send_custom_request
}
