import json
import re


class SwaggerJsonFile(object):
    """
    Parse Swagger JSON file into Python dictionary plus resolve all references to other JSON files.
    """

    parsed_json_files = {}
    file_directory = "./"
    url_pattern = re.compile(
        r'^(([^:]+):\/\/)?(([^@\n\/?#]+)@)?(([^:\/\n]*)(:(\d+))?)(\/?([^\n?#]*))(\?([^\n#]+))?(#(.+))?$')
    curly_vars_pattern = re.compile(r'[^{]*?{([^}]+?)}')

    def __init__(self, file_path=None):
        if not file_path or type(file_path) is not str:
            raise RuntimeError("A string FilePath argument must be passed")
        self.file_path = file_path
        with open(file_path, 'r') as fd:
            self.swagger_dict = json.loads(fd.read())
        self.base_path = self.__get_base_path()

        if "/" in file_path:
            SwaggerJsonFile.file_directory = "/".join(file_path.split("/")[0:-1]) + "/"

        self.swagger_version = self.swagger_dict.get("swagger", None) or self.swagger_dict.get("openapi", None)
        if self.swagger_version is None:
            raise RuntimeError("Not a Swagger or OpenAPI JSON file")
        if self.swagger_version[0:3] not in ["2.0", "3.0"]:
            raise RuntimeError("Unsupported swagger version: {}. Currently, support 2.0 and 3.0.x only.".format(self.swagger_version))
        self.open_api = self.swagger_version != "2.0"
        SwaggerJsonFile.parsed_json_files[file_path] = self.swagger_dict
        SwaggerJsonFile.__recursive_traverse(self.swagger_dict, file_path, {})

    def __get_base_path(self):
        if "basePath" in self.swagger_dict:
            return self.swagger_dict["basePath"]
        for server in self.swagger_dict.get("servers", []):
            parsed_url = SwaggerJsonFile.get_parsed_url(server["url"])
            if parsed_url:
                return parsed_url["path"] or ""
        return ""

    def get_base_path(self, path_dict):
        for server in path_dict.get("servers", []):
            parsed_url = SwaggerJsonFile.get_parsed_url(server["url"])
            if parsed_url:
                return parsed_url["path"] or ""
        return self.base_path

    def get_expanded_json(self):
        return self.swagger_dict

    def pretty_print(self):
        print(json.dumps(self.swagger_dict, sort_keys=True, indent=4, separators=(',', ': ')))

    def get_all_hosts(self):
        all_hosts = []
        if self.open_api:       # OpenAPI version 3.0 and above
            hosts_dict = {}     # will be used to avoid duplicates
            for server_dict in self.swagger_dict.get("servers", []):
                hosts_dict.update(dict.fromkeys(SwaggerJsonFile.__resolve_host_variables(server_dict)))
            for path in self.swagger_dict.get("paths", {}):
                for server_dict in self.swagger_dict["paths"][path].get("servers", []):
                    hosts_dict.update(dict.fromkeys(SwaggerJsonFile.__resolve_host_variables(server_dict)))
            all_hosts = list(hosts_dict)
        else:                   # Swagger version 2.0
            parsed_url = SwaggerJsonFile.get_parsed_url(self.swagger_dict.get("host", None))
            if parsed_url and parsed_url["domain"]:
                all_hosts.append(parsed_url["domain"])
        return all_hosts

    def get_security_schemes(self):
        if self.open_api:                                               # OpenAPI version 3.0 and above
            components_dict = self.swagger_dict.get("components", {})
            return components_dict.get("securitySchemes", None)
        return self.swagger_dict.get("securityDefinitions", None)       # Swagger version 2.0

    @staticmethod
    def __resolve_host_variables(server_dict):
        parsed_url = SwaggerJsonFile.get_parsed_url(server_dict["url"])
        if parsed_url and parsed_url["domain"]:
            host = parsed_url["domain"]
            vars = SwaggerJsonFile.curly_vars_pattern.findall(host)
            if vars:
                hosts_list = [host]
                variables_dict = server_dict["variables"]
                for curly_var in vars:
                    var_dict = variables_dict[curly_var]
                    new_hosts_list = []
                    for enum_val in var_dict.get("enum", [var_dict["default"]]):
                        for new_host in hosts_list:
                            new_hosts_list.append(new_host.replace("{" + curly_var + "}", enum_val))
                    hosts_list = new_hosts_list
                return hosts_list
            return [host]

    @staticmethod
    def get_parsed_url(url):
        if url is None:
            return None
        url_match = SwaggerJsonFile.url_pattern.match(url)
        if url_match:
            url_dict = {
                "schema": url_match.group(2),
                "user": url_match.group(4),
                "domain": url_match.group(6),
                "port": url_match.group(8),
                "path": url_match.group(9),
                "query": url_match.group(12),
                "fragment": url_match.group(14)
            }
            if url_dict["path"] and len(url_dict["path"]) > 0 and url_dict["path"][-1] == "/":
                url_dict["path"] = url_dict["path"][0:-1]
            if url_dict["query"]:
                url_dict["query"] = url_dict["query"].split("&")
            return url_dict
        return None

    @staticmethod
    def __recursive_traverse(json_element, json_file_name, refs):
        cloned_refs = refs.copy()
        if type(json_element) is dict:
            curr_file_name = json_file_name
            json_ref = json_element.pop("$ref", None)
            if json_ref:
                cloned_refs[json_ref] = True
                if refs.get(json_ref, False):
                    print("Cyclic refs", refs)
                    return
                curr_file_name = SwaggerJsonFile.__resolve_reference(json_element, json_ref, json_file_name)
            for json_key in json_element:
                SwaggerJsonFile.__recursive_traverse(json_element[json_key], curr_file_name, cloned_refs)
        elif type(json_element) is list:
            for json_key in json_element:
                SwaggerJsonFile.__recursive_traverse(json_key, json_file_name, cloned_refs)

    @staticmethod
    def __resolve_reference(json_element, ref_string, json_file_name):
        if ref_string is None or type(json_element) is not dict:
            return json_file_name
        relative_file_path = None
        root_dict = SwaggerJsonFile.parsed_json_files[json_file_name]
        tokens = ref_string.split("#")
        if len(tokens[0]) > 0:
            relative_file_path = SwaggerJsonFile.file_directory + tokens[0]
            root_dict = SwaggerJsonFile.parsed_json_files.get(relative_file_path, None)
            if not root_dict:
                with open(relative_file_path, 'r') as fd:
                    root_dict = json.loads(fd.read())
                    SwaggerJsonFile.parsed_json_files[relative_file_path] = root_dict
        if len(tokens) == 2:
            for json_token in tokens[1].split("/"):
                if len(json_token) == 0:
                    continue
                root_dict = root_dict.get(json_token, None)
                if root_dict is None or type(root_dict) is not dict:
                    raise RuntimeError("Invalid reference {}.".format(ref_string))
        json_element.update(root_dict)
        return relative_file_path or json_file_name
